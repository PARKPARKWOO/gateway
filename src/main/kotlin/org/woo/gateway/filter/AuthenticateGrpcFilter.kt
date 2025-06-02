package org.woo.gateway.filter

import constant.AuthConstant.AUTHORIZATION_HEADER
import dto.Passport
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.mono
import kotlinx.coroutines.runBlocking
import model.Role
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpRequestDecorator
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.gateway.client.GrpcAuthClient
import org.woo.mapper.Jackson
import java.util.UUID

@Component
class AuthenticateGrpcFilter(
    val authClient: GrpcAuthClient,
) : AbstractGatewayFilterFactory<AuthenticateGrpcFilter.Config>(Config::class.java) {
    class Config

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        val request: ServerHttpRequest = exchange.request
        val bearerToken = request.headers[AUTHORIZATION_HEADER]?.firstOrNull()
            ?: request.cookies?.get("accessToken")?.firstOrNull()
                ?.value
                ?.let { token -> "Bearer $token" }
        val hasToken = bearerToken != null
        return@GatewayFilter if (hasToken) {
            val modifiedExchange: ServerWebExchange = runBlocking {
                runCatching {
                    exchange.requestAuthAndSetPassport(bearerToken!!)
                }.onFailure { exception ->
                    log().warn("Authentication failed ${exception.message}")
                }.getOrElse {
                    exchange
                }
            }
            chain.filter(modifiedExchange)
        } else {
            chain.filter(exchange)
        }
    }

    suspend fun ServerWebExchange.requestAuthAndSetPassport(bearerToken: String): ServerWebExchange = mono {
        val passport = authClient.getUserInfo(bearerToken)
        log().info("authenticate userId = ${passport.id}")
        setPassportToHeader(passport)
    }.awaitSingle()

    fun ServerWebExchange.setPassportToHeader(passportProto: AuthProto.Passport): ServerWebExchange {
        val passport = Passport(
            userId = UUID.fromString(passportProto.id),
            role = Role.valueOf(passportProto.role),
            signInApplicationId = passportProto.applicationId.toString(),
            userContext = null,
        )
        val userContextString = Jackson.writeValueAsString(passport)
        val headers = HttpHeaders()
        headers.putAll(this.request.headers)
        headers.add("X-User-Passport", userContextString)

        val modifiedRequest = object : ServerHttpRequestDecorator(this.request) {
            override fun getHeaders(): HttpHeaders = headers
        }
        return this.mutate().request(modifiedRequest).build()
    }
}