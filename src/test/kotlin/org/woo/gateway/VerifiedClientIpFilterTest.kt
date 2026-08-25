package org.woo.gateway

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import org.springframework.core.Ordered
import org.springframework.core.annotation.OrderUtils
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.filter.VerifiedClientIpFilter
import reactor.core.publisher.Mono
import java.net.InetSocketAddress

class VerifiedClientIpFilterTest {
    private val filter = VerifiedClientIpFilter()

    @Test
    fun `gateway strips spoofed verified client ip and replaces it with remote address`() {
        val downstream = applyFilter(
            MockServerHttpRequest.get("/api/v1/cbt/attempts")
                .header("X-Verified-Client-IP", "203.0.113.99")
                .remoteAddress(InetSocketAddress("198.51.100.10", 443))
                .build(),
        )

        assertThat(downstream.request.headers.get("X-Verified-Client-IP"))
            .containsExactly("198.51.100.10")
    }

    @Test
    fun `gateway replaces every spoofed verified client ip value with one connection address`() {
        val downstream = applyFilter(
            MockServerHttpRequest.get("/api/v1/cbt/attempts")
                .header("X-Verified-Client-IP", "203.0.113.99", "203.0.113.100")
                .remoteAddress(InetSocketAddress("198.51.100.10", 443))
                .build(),
        )

        assertThat(downstream.request.headers.get("X-Verified-Client-IP"))
            .containsExactly("198.51.100.10")
    }

    @Test
    fun `gateway ignores forwarded address headers when setting verified client ip`() {
        val downstream = applyFilter(
            MockServerHttpRequest.get("/api/v1/cbt/attempts")
                .header("Forwarded", "for=203.0.113.30")
                .header("X-Forwarded-For", "203.0.113.31", "203.0.113.32")
                .header("X-Verified-Client-IP", "203.0.113.33")
                .remoteAddress(InetSocketAddress("198.51.100.10", 443))
                .build(),
        )

        assertThat(downstream.request.headers.get("X-Verified-Client-IP"))
            .containsExactly("198.51.100.10")
    }

    @Test
    fun `gateway filter does not log raw client address or header values`() {
        val rootLogger = LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME) as Logger
        val appender = ListAppender<ILoggingEvent>().also {
            it.start()
            rootLogger.addAppender(it)
        }

        try {
            applyFilter(
                MockServerHttpRequest.get("/api/v1/cbt/attempts")
                    .header("Forwarded", "for=forwarded-ip-sentinel")
                    .header("X-Forwarded-For", "xff-ip-sentinel-a", "xff-ip-sentinel-b")
                    .header("X-Verified-Client-IP", "verified-ip-sentinel")
                    .remoteAddress(InetSocketAddress("198.51.100.77", 443))
                    .build(),
            )

            val output = appender.list.joinToString("\n") { it.formattedMessage }
            assertThat(output).doesNotContain(
                "forwarded-ip-sentinel",
                "xff-ip-sentinel-a",
                "xff-ip-sentinel-b",
                "verified-ip-sentinel",
                "198.51.100.77",
                "Forwarded",
                "X-Forwarded-For",
                "X-Verified-Client-IP",
            )
        } finally {
            rootLogger.detachAppender(appender)
            appender.stop()
        }
    }

    @Test
    fun `gateway preserves IPv6 connection address as the only verified client ip`() {
        val downstream = applyFilter(
            MockServerHttpRequest.get("/api/v1/cbt/attempts")
                .remoteAddress(InetSocketAddress("2001:db8::10", 443))
                .build(),
        )

        assertThat(downstream.request.headers.get("X-Verified-Client-IP"))
            .containsExactly("2001:db8:0:0:0:0:0:10")
    }

    @Test
    fun `gateway marks unavailable connection address as unknown`() {
        val downstream = applyFilter(MockServerHttpRequest.get("/api/v1/cbt/attempts").build())

        assertThat(downstream.request.headers.get("X-Verified-Client-IP")).containsExactly("unknown")
    }

    @Test
    fun `gateway client ip filter runs before application filters`() {
        assertThat(OrderUtils.getOrder(VerifiedClientIpFilter::class.java, Ordered.LOWEST_PRECEDENCE))
            .isEqualTo(Ordered.HIGHEST_PRECEDENCE + 5)
    }

    private fun applyFilter(request: MockServerHttpRequest): ServerWebExchange {
        val exchange = MockServerWebExchange.from(request)
        var downstream: ServerWebExchange? = null
        filter.filter(exchange, WebFilterChain { received ->
            downstream = received
            Mono.empty()
        }).block()
        return requireNotNull(downstream)
    }
}
