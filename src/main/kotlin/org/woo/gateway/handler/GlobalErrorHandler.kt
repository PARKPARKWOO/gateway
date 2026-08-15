package org.woo.gateway.handler

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.ResponseStatusException
import org.woo.apm.log.log
import org.woo.gateway.logging.RequestLogSanitizer
import reactor.core.publisher.Mono

/**
 * F-AUTH-LOG (2026-05-11): gateway 의 reactive chain 어디에서 throw 된 throwable 이라도
 * 무조건 ERROR 로 안전한 진단 메타데이터와 함께 기록한다. 이전에는 `ErrorWebExceptionHandler` 빈이
 * 없어서 unhandled throwable 이 Spring 의 default handler 로 흘러가 응답만 만들고
 * **stack trace 가 어디에도 안 남았다** (5/9 forest 500 사고를 게이트웨이 단에서
 * 재구성 못 한 진짜 원인 중 하나).
 *
 * 우선순위: `@Order(-2)` — Spring 의 기본 `DefaultErrorWebExceptionHandler`(order=-1) 보다 앞.
 * 즉 default handler 가 응답을 만들기 전에 우리가 먼저 잡아 로깅한다.
 *
 * 정책:
 *  - throwable 종류 무관 무조건 ERROR 로 예외 클래스와 최대 64개의 stack frame 기록
 *  - 원본 throwable 의 message/cause/suppressed 는 기록하지 않고 메시지 없는 복사본만 logger 에 전달
 *  - query 를 제외한 path / method / 형식 검증된 X-Request-ID 메타데이터만 포함
 *  - Origin / Referer / 그 밖의 요청 헤더와 query 는 기록하지 않음
 *  - 클라이언트 응답은 throwable 의 종류에 따라 200/4xx/5xx 그대로 (기존 default handler 와 동일 동작)
 *  - response 가 이미 commit 되었으면 안전한 로그를 남기고 메시지 없는 진단 예외만 재전파
 *  - raw query 를 포함하는 `HttpWebHandlerAdapter` fallback ERROR logger 는 logback 에서 비활성화
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
        val requestId = RequestLogSanitizer.requestId(request.headers.getFirst("X-Request-ID"))
        val diagnosticStackTrace = messageFreeStackTrace(ex)

        log().error(
            "gateway-error: method={} path={} reqId={} ex={}",
            method,
            path,
            requestId,
            ex.javaClass.simpleName,
            diagnosticStackTrace,
        )

        if (exchange.response.isCommitted) {
            return Mono.error(diagnosticStackTrace)
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

    private fun messageFreeStackTrace(ex: Throwable): Throwable =
        MessageFreeDiagnosticException().apply {
            stackTrace = ex.stackTrace.take(MAX_DIAGNOSTIC_STACK_FRAMES).toTypedArray()
        }

    private class MessageFreeDiagnosticException : RuntimeException()

    private companion object {
        const val MAX_DIAGNOSTIC_STACK_FRAMES = 64
    }
}
