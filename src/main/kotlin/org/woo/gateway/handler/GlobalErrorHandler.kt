package org.woo.gateway.handler

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.ResponseStatusException
import org.woo.apm.log.log
import reactor.core.publisher.Mono

/**
 * F-AUTH-LOG (2026-05-11): gateway 의 reactive chain 어디에서 throw 된 throwable 이라도
 * 무조건 ERROR 로 stack trace 와 함께 기록한다. 이전에는 `ErrorWebExceptionHandler` 빈이
 * 없어서 unhandled throwable 이 Spring 의 default handler 로 흘러가 응답만 만들고
 * **stack trace 가 어디에도 안 남았다** (5/9 forest 500 사고를 게이트웨이 단에서
 * 재구성 못 한 진짜 원인 중 하나).
 *
 * 우선순위: `@Order(-2)` — Spring 의 기본 `DefaultErrorWebExceptionHandler`(order=-1) 보다 앞.
 * 즉 default handler 가 응답을 만들기 전에 우리가 먼저 잡아 로깅한다.
 *
 * 정책:
 *  - throwable 종류 무관 무조건 ERROR 로 stack trace 기록
 *  - path / method / X-Request-ID / Origin / Referer 메타데이터 포함
 *  - 클라이언트 응답은 throwable 의 종류에 따라 200/4xx/5xx 그대로 (기존 default handler 와 동일 동작)
 *  - response 가 이미 commit 되었으면 로깅만 하고 통과
 */
@Component
@Order(-2)
class GlobalErrorHandler : ErrorWebExceptionHandler {
    override fun handle(
        exchange: ServerWebExchange,
        ex: Throwable,
    ): Mono<Void> {
        val request = exchange.request
        val path = runCatching { request.path.value() }.getOrDefault("?")
        val method = request.method?.name() ?: "?"
        val requestId = request.headers.getFirst("X-Request-ID") ?: "?"
        val origin = request.headers.getFirst("Origin") ?: "-"
        val referer = request.headers.getFirst("Referer") ?: "-"

        // logger.error 는 throwable 을 두 번째 인자로 넘기면 logback pattern 의 %ex 또는 자동 stack trace 부착.
        log().error(
            "gateway-error: method={} path={} reqId={} origin={} referer={} ex={}: {}",
            method, path, requestId, origin, referer,
            ex.javaClass.simpleName, ex.message, ex,
        )

        if (exchange.response.isCommitted) {
            return Mono.error(ex)
        }

        val status = resolveStatus(ex)
        exchange.response.statusCode = status
        exchange.response.headers.contentType = MediaType.APPLICATION_JSON
        return exchange.response.setComplete()
    }

    private fun resolveStatus(ex: Throwable): HttpStatus =
        when (ex) {
            is ResponseStatusException -> HttpStatus.resolve(ex.statusCode.value()) ?: HttpStatus.INTERNAL_SERVER_ERROR
            else -> HttpStatus.INTERNAL_SERVER_ERROR
        }
}
