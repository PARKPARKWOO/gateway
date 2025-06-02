package org.woo.gateway.filter

import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.woo.apm.log.log
import reactor.core.publisher.Mono

@Component
class HostRewriteFilter: GatewayFilter {
    override fun filter(exchange: ServerWebExchange?, chain: GatewayFilterChain?): Mono<Void> {
        val originalHost = exchange!!.request.headers.getFirst("Host")

        val internalHost = "auth.platformholder.site"

        val mutatedRequest: ServerHttpRequest = exchange.request
            .mutate()
            .header("Host", internalHost)
            .build()
        log().info("origin request $originalHost rewrite $internalHost")
        return chain!!.filter(exchange.mutate().request(mutatedRequest).build())
    }
}