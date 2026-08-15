package org.woo.gateway.filter

import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
class VerifiedClientIpFilter : WebFilter {
    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        val verifiedIp = exchange.request.remoteAddress?.address?.hostAddress ?: "unknown"
        val request =
            exchange.request.mutate().headers { headers ->
                headers.remove("X-Verified-Client-IP")
                headers.set("X-Verified-Client-IP", verifiedIp)
            }.build()
        return chain.filter(exchange.mutate().request(request).build())
    }
}
