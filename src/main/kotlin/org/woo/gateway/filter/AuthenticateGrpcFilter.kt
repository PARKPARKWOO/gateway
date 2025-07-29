package org.woo.gateway.filter

import constant.AuthConstant.AUTHORIZATION_HEADER
import dto.Passport
import exception.ExpiredJwtException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.reactor.mono
import model.Role
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpRequestDecorator
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.gateway.service.AuthenticateService
import org.woo.mapper.Jackson
import java.time.Duration
import java.util.UUID

@Component
class AuthenticateGrpcFilter(
    private val authenticateService: AuthenticateService,
) : AbstractGatewayFilterFactory<AuthenticateGrpcFilter.Config>(Config::class.java) {
    class Config

    override fun apply(config: Config): GatewayFilter =
        GatewayFilter { exchange, chain ->
            val request: ServerHttpRequest = exchange.request
            val response = exchange.response
            return@GatewayFilter mono {
                val (accessToken, refreshToken) = authenticateService.extractToken(request)
                if (accessToken == null && refreshToken == null) {
                    return@mono exchange
                }

                val passport: AuthProto.Passport =
                    try {
                        accessToken?.let {
                            authenticateService.getPassport(accessToken) ?: return@mono exchange
                        } ?: rotationToken(refreshToken!!, response) ?: return@mono exchange
                    } catch (e: ExpiredJwtException) {
                        refreshToken?.let {
                            rotationToken(refreshToken, response)
                        } ?: return@mono exchange
                    }

                val mutatedRequest =
                    object : ServerHttpRequestDecorator(request) {
                        override fun getHeaders(): HttpHeaders {
                            val newHeaders = HttpHeaders()
                            newHeaders.putAll(super.getHeaders())
                            newHeaders.add(AUTHORIZATION_HEADER, accessToken)
                            return newHeaders
                        }
                    }
                val mutatedExchange = exchange.mutate().request(mutatedRequest).build()
                log().info("authenticate userId = ${passport.id}")
                mutatedExchange.setPassportToHeader(passport)
            }.flatMap { newExchange ->
                chain.filter(newExchange)
            }
        }

    fun ServerWebExchange.setPassportToHeader(passportProto: AuthProto.Passport): ServerWebExchange {
        val passport =
            Passport(
                userId = UUID.fromString(passportProto.id),
                role = Role.valueOf(passportProto.role),
                signInApplicationId = passportProto.applicationId.toString(),
                userContext = null,
            )
        val userContextString = Jackson.writeValueAsString(passport)

        val modifiedRequest =
            object : ServerHttpRequestDecorator(this.request) {
                override fun getHeaders(): HttpHeaders {
                    val newHeaders = HttpHeaders()
                    newHeaders.putAll(super.getHeaders())
                    newHeaders.add("X-User-Passport", userContextString)
                    return newHeaders
                }
            }
        return this.mutate().request(modifiedRequest).build()
    }

    private suspend fun rotationToken(
        refreshToken: String,
        response: ServerHttpResponse,
    ): AuthProto.Passport? =
        coroutineScope {
            val reissueToken = authenticateService.reissueToken(refreshToken)
            response.apply {
                addCookie(createCookie("accessToken", reissueToken.accessToken, reissueToken.accessTokenExpiresIn))
                addCookie(createCookie("refreshToken", reissueToken.refreshToken, reissueToken.refreshTokenExpiresIn))
            }
            authenticateService.getPassport(reissueToken.accessToken)
        }

    private fun createCookie(
        name: String,
        value: String,
        maxAge: Long,
    ): ResponseCookie =
        ResponseCookie
            .from(name, value)
            .httpOnly(false)
            .secure(true)
            .path("/")
            .domain(".platformholder.site")
            .maxAge(Duration.ofMillis(maxAge))
            .sameSite("None")
            .build()
}
