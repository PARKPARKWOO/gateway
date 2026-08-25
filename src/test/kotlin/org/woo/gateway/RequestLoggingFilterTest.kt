package org.woo.gateway

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.spi.IThrowableProxy
import ch.qos.logback.core.read.ListAppender
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.woo.gateway.filter.RequestLoggingFilter

class RequestLoggingFilterTest {
    private val filter = RequestLoggingFilter()

    @Test
    fun `request logs omit sensitive headers query answers and invalid request ids`() {
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post(
                "/api/v1/cbt/attempts/attempt-123?answer=query-answer-sentinel",
            )
                .header("Authorization", "Bearer authorization-secret-sentinel")
                .header(
                    "Cookie",
                    "cbt_device=cookie-device-secret-sentinel; auth=cookie-auth-secret-sentinel",
                )
                .header("X-CBT-Installation-Id", "installation-secret-sentinel")
                .header("X-CBT-Attempt-Token", "attempt-token-secret-sentinel")
                .header("X-CBT-Printable-Token", "printable-token-secret-sentinel")
                .header("X-Verified-Client-IP", "verified-ip-sentinel")
                .header("X-User-Passport", "passport-secret-sentinel")
                .header("X-Request-ID", "request-id-secret-sentinel invalid")
                .build(),
        )
        var chainInvoked = false
        var responseCompleted = false
        val events = captureEvents {
            val chain = GatewayFilterChain { received ->
                chainInvoked = true
                received.response.statusCode = HttpStatus.BAD_REQUEST
                received.response.setComplete().doOnSuccess {
                    responseCompleted = received.response.isCommitted
                }
            }

            filter.filter(exchange, chain).block()
        }

        assertThat(chainInvoked).isTrue()
        assertThat(responseCompleted).isTrue()
        assertThat(exchange.response.isCommitted).isTrue()
        assertThat(events).anySatisfy {
            assertThat(it).contains(
                "Incoming request: method=POST, path=/api/v1/cbt/attempts/attempt-123",
            )
        }
        assertThat(events).anySatisfy {
            assertThat(it).contains(
                "request-completed: method=POST path=/api/v1/cbt/attempts/attempt-123 " +
                    "status=400 durationMs=",
                "reqId=-",
            )
        }
        events.forEach { event ->
            assertThat(event)
                .doesNotContain(
                    "authorization-secret-sentinel",
                    "cookie-device-secret-sentinel",
                    "cookie-auth-secret-sentinel",
                    "installation-secret-sentinel",
                    "attempt-token-secret-sentinel",
                    "printable-token-secret-sentinel",
                    "verified-ip-sentinel",
                    "passport-secret-sentinel",
                    "query-answer-sentinel",
                    "request-id-secret-sentinel",
                    "Authorization",
                    "Cookie",
                    "X-CBT-Installation-Id",
                    "X-CBT-Attempt-Token",
                    "X-CBT-Printable-Token",
                    "X-Verified-Client-IP",
                    "X-User-Passport",
                    "headers=",
                )
        }
    }

    @Test
    fun `completion logs preserve only allowlisted request ids from one through 128 characters`() {
        val validRequestIds = listOf("A", "AazZ09._:-", "a".repeat(128))
        val invalidRequestIds = listOf("b".repeat(129), "request/id", "request id")
        val completionEvents = captureEvents {
            (validRequestIds + invalidRequestIds).forEach(::completeRequest)
        }.filter { it.startsWith("request-completed:") }

        assertThat(completionEvents).hasSize(validRequestIds.size + invalidRequestIds.size)
        validRequestIds.forEachIndexed { index, requestId ->
            assertThat(completionEvents[index]).contains("reqId=$requestId")
        }
        invalidRequestIds.forEachIndexed { index, requestId ->
            assertThat(completionEvents[validRequestIds.size + index])
                .contains("reqId=-")
                .doesNotContain(requestId)
        }
    }

    private fun completeRequest(requestId: String) {
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/cbt/attempts/attempt-123")
                .header("X-Request-ID", requestId)
                .build(),
        )
        val chain = GatewayFilterChain { received ->
            received.response.statusCode = HttpStatus.BAD_REQUEST
            received.response.setComplete()
        }

        filter.filter(exchange, chain).block()
    }

    private fun captureEvents(block: () -> Unit): List<String> {
        val logger = LoggerFactory.getLogger(RequestLoggingFilter::class.java) as Logger
        val appender = ListAppender<ILoggingEvent>().also {
            it.start()
            logger.addAppender(it)
        }

        return try {
            block()
            appender.list.map(::render)
        } finally {
            logger.detachAppender(appender)
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
