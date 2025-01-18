package org.woo.gateway.filter

import io.grpc.ManagedChannelBuilder
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.mono
import kotlinx.coroutines.runBlocking
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import org.woo.auth.grpc.AuthProto.UserInfoResponse
import org.woo.gateway.client.GrpcAuthClient

@Component
class GrpcAuthFilterFactory(
    val authClient: GrpcAuthClient,
) : AbstractGatewayFilterFactory<GrpcAuthFilterFactory.Config>(Config::class.java) {
    class Config

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        val request: ServerHttpRequest = exchange.request
        val bearerToken = request.headers["Authorization"]?.firstOrNull()
        val hasToken = bearerToken != null && bearerToken.startsWith("Bearer ")
        return@GatewayFilter if (hasToken) {
            runBlocking {
                request.test(bearerToken!!)
            }
            chain.filter(exchange)
        } else {
            chain.filter(exchange)
        }
    }

    suspend fun ServerHttpRequest.test(bearerToken: String) = mono {
        val passport = authClient.getUserInfo(bearerToken)
        setPassport(passport)
    }.awaitSingle()

    fun ServerHttpRequest.setPassport(passport: UserInfoResponse) {

    }
}