package org.woo.gateway

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
@Order(Ordered.LOWEST_PRECEDENCE)
class RequestLoggingFilter : GlobalFilter, Ordered {
    private val logger = LoggerFactory.getLogger(this::class.java)
    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val request = exchange.request

        // 요청 정보를 로깅
        logger.info(
            "Incoming request: method={}, path={}, headers={}",
            request.method,
            request.path,
            request.headers,
        )
        // 필터 체인을 통해 요청을 다음으로 전달
        return chain.filter(exchange)
    }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
}
