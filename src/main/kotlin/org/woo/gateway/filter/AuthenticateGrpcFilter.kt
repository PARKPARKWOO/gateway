package org.woo.gateway.filter

import constant.AuthConstant.AUTHORIZATION_HEADER
import dto.Passport
import exception.ExpiredJwtException
import kotlinx.coroutines.reactor.mono
import model.Role
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.stereotype.Component
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
    companion object {
        val NO_AUTHENTICATE_ROUTE_IDS: Array<String> = arrayOf("oauth-route")
    }

    class Config

    override fun apply(config: Config): GatewayFilter =
        GatewayFilter { exchange, chain ->
            val routeId = exchange.getAttribute<Route>(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR)?.id
            val request: ServerHttpRequest = exchange.request
            val response = exchange.response
            if (NO_AUTHENTICATE_ROUTE_IDS.contains(routeId)) {
                return@GatewayFilter chain.filter(exchange)
            }

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

                val mutatedRequest = request.mutate().header(AUTHORIZATION_HEADER, accessToken).build()
                val includePassportHeader = mutatedRequest.setPassportToHeader(passport)
                log().info("authenticate userId = ${passport.id}")
                exchange.mutate().request(includePassportHeader).build()
            }.flatMap { newExchange ->
                chain.filter(newExchange)
            }
        }

    fun ServerHttpRequest.setPassportToHeader(passportProto: AuthProto.Passport): ServerHttpRequest {
        val passport =
            Passport(
                userId = UUID.fromString(passportProto.id),
                role = Role.valueOf(passportProto.role),
                signInApplicationId = passportProto.applicationId.toString(),
                userContext = null,
            )
        val userContextString = Jackson.writeValueAsString(passport)
        return this
            .mutate()
            .header("X-User-Passport", userContextString)
            .build()
    }

    private suspend fun rotationToken(
        refreshToken: String,
        response: ServerHttpResponse,
    ): AuthProto.Passport? =
        runCatching {
            val reissueToken = authenticateService.reissueToken(refreshToken)
            response.apply {
                addCookie(createCookie("accessToken", reissueToken.accessToken, reissueToken.accessTokenExpiresIn))
                addCookie(
                    createCookie(
                        "refreshToken",
                        reissueToken.refreshToken,
                        reissueToken.refreshTokenExpiresIn,
                    ),
                )
            }
            authenticateService.getPassport(reissueToken.accessToken)
        }.onFailure {
            response.clearAuthCookie()
        }.getOrNull()

    private fun ServerHttpResponse.clearAuthCookie() {
        this.addCookie(
            ResponseCookie
                .from("accessToken", "")
                .path("/")
                .maxAge(Duration.ZERO) // 삭제
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .build(),
        )

        this.addCookie(
            ResponseCookie
                .from("refreshToken", "")
                .path("/")
                .maxAge(Duration.ZERO) // 삭제
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .build(),
        )
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
