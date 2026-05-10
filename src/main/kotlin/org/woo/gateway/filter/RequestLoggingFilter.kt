package org.woo.gateway.filter

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * 모든 요청/응답을 로깅한다.
 *  - incoming: INFO (method, path, headers)
 *  - 완료 시: status/durationMs. status>=500 → ERROR, status>=400 → WARN, 그 외 → DEBUG.
 *
 * brave.Tracer 가 server span 을 따로 기록하지만 zipkin 형식이라 사람이 빠르게 grep 하기 어렵다.
 * 이 필터의 ERROR/WARN 라인은 Loki 에서 `{app="gateway"} |~ "request-completed"` 로 일관 추적 가능.
 *
 * @Order: GlobalFilter 이므로 `getOrder()` 가 적용됨. HIGHEST_PRECEDENCE 로 가장 앞단 진입,
 * doFinally 로 응답 완료 시점 후크.
 */
@Component
class RequestLoggingFilter :
    GlobalFilter,
    Ordered {
    private val logger = LoggerFactory.getLogger(this::class.java)

    override fun filter(
        exchange: ServerWebExchange,
        chain: GatewayFilterChain,
    ): Mono<Void> {
        val request = exchange.request
        val startNanos = System.nanoTime()
        val method = request.method?.name() ?: "?"
        val path = runCatching { request.path.value() }.getOrDefault("?")
        val requestId = request.headers.getFirst("X-Request-ID") ?: "-"

        logger.info(
            "Incoming request: method={}, path={}, headers={}",
            request.method,
            request.path,
            request.headers,
        )

        return chain.filter(exchange).doFinally {
            val response = exchange.response
            val status = response.statusCode?.value() ?: 0
            val durationMs = (System.nanoTime() - startNanos) / 1_000_000
            val msg = "request-completed: method={} path={} status={} durationMs={} reqId={}"
            when {
                status >= 500 -> logger.error(msg, method, path, status, durationMs, requestId)
                status >= 400 -> logger.warn(msg, method, path, status, durationMs, requestId)
                else -> logger.debug(msg, method, path, status, durationMs, requestId)
            }
        }
    }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
}
