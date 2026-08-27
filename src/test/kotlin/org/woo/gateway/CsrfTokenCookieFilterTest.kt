package org.woo.gateway

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.core.Ordered
import org.springframework.core.annotation.OrderUtils
import org.springframework.http.HttpCookie
import org.springframework.http.HttpMethod
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CsrfTokenProperties
import org.woo.gateway.filter.CsrfTokenCookieFilter
import org.woo.gateway.security.CsrfTokenService
import org.woo.gateway.security.SecureCsrfTokenService
import reactor.core.publisher.Mono
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class CsrfTokenCookieFilterTest {
    @Test
    fun `generated token is canonical URL safe base64 for exactly 32 random bytes`() {
        val service = SecureCsrfTokenService(CsrfTokenProperties())

        val first = service.generate()
        val second = service.generate()

        assertThat(first).matches("[A-Za-z0-9_-]{43}")
        assertThat(first).doesNotContain("=")
        assertThat(Base64.getUrlDecoder().decode(first)).hasSize(32)
        assertThat(second).isNotEqualTo(first)
    }

    @Test
    fun `token matching accepts equal values and rejects unequal values`() {
        val service = SecureCsrfTokenService(CsrfTokenProperties())
        val token = service.generate()

        assertThat(service.matches(token, token)).isTrue()
        assertThat(service.matches(token, "${token}x")).isFalse()
        assertThat(service.matches("", "")).isFalse()
    }

    @Test
    fun `token matching implementation uses the JDK constant time comparison primitive`() {
        val source =
            Files.readString(
                Path.of("src/main/kotlin/org/woo/gateway/security/CsrfTokenService.kt"),
            )

        assertThat(source).contains("MessageDigest.isEqual")
    }

    @Test
    fun `GET without CSRF cookie passes and sets exact readable production session cookie`() {
        val generated = "generated-csrf-token"
        val filter = CsrfTokenCookieFilter(CsrfTokenProperties(), fixedService(generated))
        val exchange = exchange(HttpMethod.GET)

        assertThat(execute(filter, exchange)).isTrue()
        val cookie = exchange.response.cookies.getFirst("XSRF-TOKEN")
        requireNotNull(cookie)
        assertThat(cookie.value).isEqualTo(generated)
        assertThat(cookie.domain).isEqualTo(".platformholder.site")
        assertThat(cookie.path).isEqualTo("/")
        assertThat(cookie.isSecure).isTrue()
        assertThat(cookie.sameSite).isEqualTo("None")
        assertThat(cookie.isHttpOnly).isFalse()
        assertThat(cookie.maxAge).isEqualTo(Duration.ofSeconds(-1))
        assertThat(cookie.toString()).doesNotContain("HttpOnly")
    }

    @Test
    fun `local and test GET cookies omit domain and secure and remain readable with Lax`() {
        listOf("local", "test").forEach { profile ->
            val properties =
                CsrfTokenProperties(
                    cookieDomain = "  ",
                    secure = false,
                    sameSite = "Lax",
                )
            val filter = CsrfTokenCookieFilter(properties, fixedService("$profile-csrf-token"))
            val exchange = exchange(HttpMethod.GET)

            assertThat(execute(filter, exchange)).isTrue()
            val cookie = requireNotNull(exchange.response.cookies.getFirst("XSRF-TOKEN"))
            assertThat(cookie.domain).isNull()
            assertThat(cookie.path).isEqualTo("/")
            assertThat(cookie.isSecure).isFalse()
            assertThat(cookie.sameSite).isEqualTo("Lax")
            assertThat(cookie.isHttpOnly).isFalse()
            assertThat(cookie.maxAge).isEqualTo(Duration.ofSeconds(-1))
            assertThat(cookie.toString())
                .doesNotContain("Domain=")
                .doesNotContain("Secure")
                .doesNotContain("HttpOnly")
        }
    }

    @Test
    fun `GET with a non empty client token passes without rotation across profile tuples`() {
        val generatedCount = AtomicInteger()
        val service =
            object : CsrfTokenService {
                override fun generate(): String {
                    generatedCount.incrementAndGet()
                    return "replacement-token"
                }

                override fun matches(
                    cookieValue: String,
                    headerValue: String,
                ): Boolean = cookieValue == headerValue
            }
        val localProperties =
            CsrfTokenProperties(
                cookieDomain = "",
                secure = false,
                sameSite = "Lax",
            )
        val filter = CsrfTokenCookieFilter(localProperties, service)
        val validClientToken = SecureCsrfTokenService(CsrfTokenProperties()).generate()
        val exchange = exchange(HttpMethod.GET, csrfCookie = validClientToken)

        assertThat(execute(filter, exchange)).isTrue()
        assertThat(exchange.response.cookies).isEmpty()
        assertThat(generatedCount.get()).isZero()
    }

    @Test
    fun `unsafe request does not issue a token cookie`() {
        val filter = CsrfTokenCookieFilter(CsrfTokenProperties(), fixedService("generated-csrf-token"))
        val exchange = exchange(HttpMethod.POST)

        assertThat(execute(filter, exchange)).isTrue()
        assertThat(exchange.response.cookies).isEmpty()
    }

    @Test
    fun `empty client cookie is replaced on a safe request`() {
        val filter = CsrfTokenCookieFilter(CsrfTokenProperties(), fixedService("generated-csrf-token"))
        val exchange = exchange(HttpMethod.HEAD, csrfCookie = "")

        assertThat(execute(filter, exchange)).isTrue()
        assertThat(exchange.response.cookies.getFirst("XSRF-TOKEN")?.value).isEqualTo("generated-csrf-token")
    }

    @Test
    fun `cookie filter executes immediately before origin verification`() {
        assertThat(OrderUtils.getOrder(CsrfTokenCookieFilter::class.java, Ordered.LOWEST_PRECEDENCE))
            .isEqualTo(Ordered.HIGHEST_PRECEDENCE + 9)
    }

    @Test
    fun `HttpOnly true is rejected because the web client must copy the token`() {
        assertThrows<IllegalArgumentException> {
            CsrfTokenCookieFilter(
                CsrfTokenProperties(httpOnly = true),
                fixedService("generated-csrf-token"),
            )
        }
    }

    private fun exchange(
        method: HttpMethod,
        csrfCookie: String? = null,
    ): MockServerWebExchange {
        val request = MockServerHttpRequest.method(method, "/api/v1/cbt/catalog")
        csrfCookie?.let { request.cookie(HttpCookie("XSRF-TOKEN", it)) }
        return MockServerWebExchange.from(request.build())
    }

    private fun execute(
        filter: CsrfTokenCookieFilter,
        exchange: MockServerWebExchange,
    ): Boolean {
        val passed = AtomicBoolean(false)
        val chain =
            WebFilterChain {
                passed.set(true)
                Mono.empty()
            }
        filter.filter(exchange, chain).block()
        return passed.get()
    }

    private fun fixedService(value: String): CsrfTokenService =
        object : CsrfTokenService {
            override fun generate(): String = value

            override fun matches(
                cookieValue: String,
                headerValue: String,
            ): Boolean = cookieValue == headerValue
        }
}
