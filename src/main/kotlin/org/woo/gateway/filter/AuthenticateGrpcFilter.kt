package org.woo.gateway.filter

import dto.UserContext
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
import org.woo.auth.grpc.AuthProto.UserInfoResponse
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
        val bearerToken = request.headers["Authorization"]?.firstOrNull()
        val hasToken = bearerToken != null && bearerToken.startsWith("Bearer ")
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

    suspend fun ServerWebExchange.requestAuthAndSetPassport(bearerToken: String):ServerWebExchange = mono {
        val passport = authClient.getUserInfo(bearerToken)
        log().info("authenticate userId = ${passport.id}")
        setPassport(passport)
    }.awaitSingle()

    fun ServerWebExchange.setPassport(passport: UserInfoResponse): ServerWebExchange {
        val userContext = UserContext(
            userId = UUID.fromString(passport.id),
            userName = passport.name,
            role = Role.valueOf(passport.role),
            email = passport.email,
        )
        val userContextString = Jackson.writeValueAsString(userContext)
        val headers = HttpHeaders()
        headers.putAll(this.request.headers)
        headers.add("X-User-Passport", userContextString)

        val modifiedRequest = object : ServerHttpRequestDecorator(this.request) {
            override fun getHeaders(): HttpHeaders = headers
        }
        return this.mutate().request(modifiedRequest).build()
    }
}