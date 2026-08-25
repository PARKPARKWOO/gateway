package org.woo.gateway

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.spi.IThrowableProxy
import ch.qos.logback.core.read.ListAppender
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.http.server.reactive.MockServerHttpResponse
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebHandler
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.adapter.HttpWebHandlerAdapter
import org.springframework.web.server.handler.ExceptionHandlingWebHandler
import org.woo.gateway.handler.GlobalErrorHandler
import reactor.core.publisher.Mono
import reactor.test.StepVerifier

class GlobalErrorHandlerTest {
    private val handler = GlobalErrorHandler()

    @Test
    fun `error logs omit request and throwable secrets while preserving response semantics`() {
        val responseExchange = exchange()
        val responseException = ResponseStatusException(
            HttpStatus.UNPROCESSABLE_ENTITY,
            "exception-token-sentinel",
            IllegalArgumentException("cause-answer-sentinel"),
        ).also {
            it.addSuppressed(IllegalStateException("suppressed-ip-cookie-sentinel"))
        }
        val committedExchange = exchange()
        committedExchange.response.setComplete().block()
        val committedException = IllegalStateException(
            "committed-token-sentinel",
            IllegalArgumentException("committed-answer-ip-sentinel"),
        ).also {
            it.addSuppressed(IllegalStateException("committed-cookie-sentinel"))
        }

        val events = captureEvents {
            handler.handle(responseExchange, responseException).block()
            StepVerifier.create(handler.handle(committedExchange, committedException))
                .expectErrorSatisfies {
                    assertSanitizedDiagnostic(it, committedException)
                }
                .verify()
        }.filter { it.formattedMessage.startsWith("gateway-error:") }

        assertThat(responseExchange.response.statusCode).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY)
        assertThat(responseExchange.response.headers.contentType).isEqualTo(MediaType.APPLICATION_JSON)
        assertThat(responseExchange.response.isCommitted).isTrue()
        assertThat(committedExchange.response.isCommitted).isTrue()
        assertThat(events).hasSize(2)
        assertThat(events.map { it.formattedMessage }).anySatisfy {
            assertThat(it).contains(
                "gateway-error: method=POST path=/api/v1/cbt/attempts/attempt-123",
                "reqId=-",
                "ex=ResponseStatusException",
            )
        }
        assertThat(events.map { it.formattedMessage }).anySatisfy {
            assertThat(it).contains(
                "gateway-error: method=POST path=/api/v1/cbt/attempts/attempt-123",
                "reqId=-",
                "ex=IllegalStateException",
            )
        }
        events.forEach { event ->
            assertThat(event.throwableProxy).isNotNull
            val throwable = requireNotNull(event.throwableProxy)
            assertThat(throwable.message).isNull()
            assertThat(throwable.cause).isNull()
            assertThat(throwable.suppressed.orEmpty()).isEmpty()
            assertThat(throwable.stackTraceElementProxyArray).isNotEmpty()
            assertThat(render(event))
                .doesNotContain(
                    "authorization-token-sentinel",
                    "request-cookie-sentinel",
                    "request-auth-cookie-sentinel",
                    "installation-secret-sentinel",
                    "attempt-token-secret-sentinel",
                    "printable-token-secret-sentinel",
                    "verified-ip-sentinel",
                    "passport-secret-sentinel",
                    "query-answer-sentinel",
                    "request-id-token-sentinel",
                    "origin-ip-sentinel",
                    "referer-cookie-sentinel",
                    "exception-token-sentinel",
                    "cause-answer-sentinel",
                    "suppressed-ip-cookie-sentinel",
                    "committed-token-sentinel",
                    "committed-answer-ip-sentinel",
                    "committed-cookie-sentinel",
                    "origin=",
                    "referer=",
                )
        }
    }

    @Test
    fun `committed errors are handled before the HTTP adapter can log raw query or throwable text`() {
        val response = MockServerHttpResponse()
        val adapterException = IllegalStateException(
            "adapter-exception-token-sentinel",
            IllegalArgumentException("adapter-cause-answer-sentinel"),
        ).also {
            it.addSuppressed(IllegalStateException("adapter-suppressed-cookie-ip-sentinel"))
        }
        val failingHandler = WebHandler { exchange ->
            exchange.response.setComplete().then(Mono.error(adapterException))
        }
        val adapter = HttpWebHandlerAdapter(
            ExceptionHandlingWebHandler(failingHandler, listOf(handler)),
        )
        val adapterLogger = LoggerFactory.getLogger(HttpWebHandlerAdapter::class.java) as Logger
        val previousLevel = adapterLogger.level

        val events = try {
            adapterLogger.level = Level.OFF
            captureEvents {
                StepVerifier.create(adapter.handle(request(), response))
                    .expectErrorSatisfies {
                        assertSanitizedDiagnostic(it, adapterException)
                    }
                    .verify()
            }
        } finally {
            adapterLogger.level = previousLevel
        }

        assertThat(response.isCommitted).isTrue()
        assertThat(events)
            .noneSatisfy {
                assertThat(it.loggerName)
                    .isEqualTo(HttpWebHandlerAdapter::class.java.name)
                assertThat(it.level.levelStr).isEqualTo("ERROR")
            }
        events.forEach { event ->
            assertThat(render(event))
                .doesNotContain(
                    "query-answer-sentinel",
                    "request-id-token-sentinel",
                    "origin-ip-sentinel",
                    "referer-cookie-sentinel",
                    "adapter-exception-token-sentinel",
                    "adapter-cause-answer-sentinel",
                    "adapter-suppressed-cookie-ip-sentinel",
                )
        }
    }

    private fun assertSanitizedDiagnostic(
        diagnostic: Throwable,
        original: Throwable,
    ) {
        assertThat(diagnostic).isNotSameAs(original)
        assertThat(diagnostic.message).isNull()
        assertThat(diagnostic.cause).isNull()
        assertThat(diagnostic.suppressed).isEmpty()
        assertThat(diagnostic.stackTrace)
            .isNotEmpty()
            .hasSizeLessThanOrEqualTo(64)
            .containsExactly(*original.stackTrace.take(64).toTypedArray())
    }

    private fun exchange(): MockServerWebExchange =
        MockServerWebExchange.from(request())

    private fun request(): MockServerHttpRequest =
        MockServerHttpRequest.post(
            "/api/v1/cbt/attempts/attempt-123?answer=query-answer-sentinel",
        )
            .header("Authorization", "Bearer authorization-token-sentinel")
            .header(
                "Cookie",
                "cbt_device=request-cookie-sentinel; auth=request-auth-cookie-sentinel",
            )
            .header("X-CBT-Installation-Id", "installation-secret-sentinel")
            .header("X-CBT-Attempt-Token", "attempt-token-secret-sentinel")
            .header("X-CBT-Printable-Token", "printable-token-secret-sentinel")
            .header("X-Verified-Client-IP", "verified-ip-sentinel")
            .header("X-User-Passport", "passport-secret-sentinel")
            .header("X-Request-ID", "request-id-token-sentinel invalid")
            .header("Origin", "https://origin-ip-sentinel.example")
            .header("Referer", "https://referer-cookie-sentinel.example/source")
            .build()

    private fun captureEvents(block: () -> Unit): List<ILoggingEvent> {
        val rootLogger = LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME) as Logger
        val appender = ListAppender<ILoggingEvent>().also {
            it.start()
            rootLogger.addAppender(it)
        }

        return try {
            block()
            appender.list.toList()
        } finally {
            rootLogger.detachAppender(appender)
            appender.stop()
        }
    }

    private fun render(event: ILoggingEvent): String =
        buildString {
            append(event.formattedMessage)
            event.throwableProxy?.let {
                append('\n')
                append(render(it))
            }
        }

    private fun render(throwable: IThrowableProxy): String =
        buildString {
            append(throwable.className)
            append(':')
            append(throwable.message)
            throwable.stackTraceElementProxyArray?.forEach {
                append('\n')
                append(it.steAsString)
            }
            throwable.cause?.let {
                append('\n')
                append(render(it))
            }
            throwable.suppressed?.forEach {
                append('\n')
                append(render(it))
            }
        }
}
