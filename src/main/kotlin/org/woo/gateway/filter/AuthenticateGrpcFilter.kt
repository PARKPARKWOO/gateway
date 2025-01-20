package org.woo.gateway.filter

import dto.UserContext
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.mono
import kotlinx.coroutines.runBlocking
import model.Role
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
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
            runBlocking {
                runCatching {
                    request.requestAuthAndSetPassport(bearerToken!!)
                }.onFailure { exception ->
                    log().warn("Authentication failed ${exception.message}")
                }
            }
            chain.filter(exchange)
        } else {
            chain.filter(exchange)
        }
    }

    suspend fun ServerHttpRequest.requestAuthAndSetPassport(bearerToken: String) = mono {
        val passport = authClient.getUserInfo(bearerToken)
        log().info("authenticate userId = ${passport.id}")
        setPassport(passport)
    }.awaitSingle()

    fun ServerHttpRequest.setPassport(passport: UserInfoResponse) {
        val userContext = UserContext(
            userId = UUID.fromString(passport.id),
            userName = passport.name,
            role = Role.valueOf(passport.role),
            email = passport.email,
        )
        val userContextString = Jackson.writeValueAsString(userContext)
        this.headers.add("X-User-Passport", userContextString)
    }
}