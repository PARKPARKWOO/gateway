package org.woo.gateway

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.core.Ordered
import org.springframework.core.annotation.OrderUtils
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsWebFilter
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CbtCorsProperties
import org.woo.gateway.filter.CbtCorsOriginFilter
import org.woo.gateway.security.CbtWebOriginMatcher
import reactor.core.publisher.Mono
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean

class CbtCorsOriginFilterTest {
    private val matcher = CbtWebOriginMatcher(CbtCorsProperties())
    private val filter = CbtCorsOriginFilter(matcher)
    private val downstreamCors =
        CorsWebFilter(
            UrlBasedCorsConfigurationSource().also { source ->
                source.registerCorsConfiguration(
                    "/**",
                    CorsConfiguration().also { cors ->
                        cors.allowedOriginPatterns = listOf("*")
                        cors.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
                        cors.allowedHeaders = listOf("*")
                        cors.allowCredentials = true
                    },
                )
            },
        )

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://mirror-view.platformholder.site",
            "http://localhost:5173",
            "http://127.0.0.1:4173",
            "https://mirror-view.platformholder.site:443",
        ],
    )
    fun `exact canonical origins pass ordinary CBT requests`(origin: String) {
        listOf(CBT_PATH, ADMIN_CBT_PATH).forEach { path ->
            val exchange = ordinaryExchange(path, origin)

            assertThat(execute(exchange)).describedAs("$origin to $path").isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://mirror-view.platformholder.site",
            "http://localhost:5173",
            "http://127.0.0.1:4173",
        ],
    )
    fun `credentialed preflight echoes each exact origin with the fixed CBT contract`(origin: String) {
        val exchange = preflightExchange(CBT_PATH, origin, "content-type,idempotency-key,x-xsrf-token")

        executeWithGlobalCors(exchange)

        assertThat((exchange.response.statusCode ?: HttpStatus.OK).is2xxSuccessful)
            .describedAs("status=%s headers=%s", exchange.response.statusCode, exchange.response.headers)
            .isTrue()
        assertThat(exchange.response.headers.accessControlAllowOrigin).isEqualTo(origin)
        assertThat(exchange.response.headers.accessControlAllowOrigin).isNotEqualTo("*")
        assertThat(exchange.response.headers.accessControlAllowCredentials).isTrue()
        assertThat(exchange.response.headers.accessControlAllowMethods).contains(HttpMethod.POST)
        assertThat(exchange.response.headers.accessControlAllowHeaders)
            .contains("content-type", "idempotency-key", "x-xsrf-token")
        assertThat(exchange.response.headers.accessControlExposeHeaders).isEmpty()
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://web.mirror-view.platformholder.site",
            "https://mirror-view.platformholder.site.attacker.example",
            "http://mirror-view.platformholder.site",
            "https://mirror-view.platformholder.site:8443",
            "https://mirror-view.platformholder.site:",
            "https://localhost:5173",
            "http://localhost:4173",
            "https://127.0.0.1:4173",
            "http://127.0.0.1:5173",
            "https://mirror-view-pr-123.vercel.app",
            "https://user@mirror-view.platformholder.site",
            "null",
            "mirror-view.platformholder.site",
            "https://mirror-view.platformholder.site/cbt/exam",
            "https://mirror-view.platformholder.site?next=attacker",
            "https://mirror-view.platformholder.site#fragment",
        ],
    )
    fun `non-exact origins are forbidden for ordinary and preflight CBT requests`(origin: String) {
        listOf(CBT_PATH, ADMIN_CBT_PATH).forEach { path ->
            val ordinary = ordinaryExchange(path, origin)
            val preflight = preflightExchange(path, origin, "content-type,idempotency-key,x-xsrf-token")

            assertThat(execute(ordinary)).describedAs("ordinary $origin to $path").isFalse()
            assertForbiddenWithoutCredentialedCors(ordinary)
            executeWithGlobalCors(preflight)
            assertForbiddenWithoutCredentialedCors(preflight)
        }
    }

    @Test
    fun `preflight allows CBT guest operation headers but not the native installation header`() {
        val allowed =
            preflightExchange(
                CBT_PATH,
                PRODUCTION_ORIGIN,
                "content-type,idempotency-key,x-xsrf-token,x-cbt-attempt-token,x-cbt-printable-token",
            )
        val forbidden = preflightExchange(CBT_PATH, PRODUCTION_ORIGIN, "content-type,x-cbt-installation-id")

        executeWithGlobalCors(allowed)
        executeWithGlobalCors(forbidden)

        assertThat((allowed.response.statusCode ?: HttpStatus.OK).is2xxSuccessful)
            .describedAs("status=%s headers=%s", allowed.response.statusCode, allowed.response.headers)
            .isTrue()
        assertThat(allowed.response.headers.accessControlAllowHeaders)
            .contains("x-cbt-attempt-token", "x-cbt-printable-token")
        assertForbiddenWithoutCredentialedCors(forbidden)
    }

    @Test
    fun `CBT request without Origin remains available to native and server clients`() {
        val exchange = ordinaryExchange(CBT_PATH, origin = null)

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `non CBT traffic retains the legacy downstream CORS policy`() {
        val exchange = ordinaryExchange("/api/v1/program/information", "https://sibling.platformholder.site")

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `matcher lowercases and IDNA normalizes configured origins`() {
        val idnaMatcher =
            CbtWebOriginMatcher(
                CbtCorsProperties(setOf(URI("https://b\u00fccher.example"))),
            )

        assertThat(idnaMatcher.matchesOrigin("HTTPS://XN--BCHER-KVA.EXAMPLE:443")).isTrue()
        assertThat(idnaMatcher.matchesOrigin("https://xn--bcher-kva.example:8443")).isFalse()
    }

    @Test
    fun `filter runs before CSRF issuance and origin verification`() {
        assertThat(OrderUtils.getOrder(CbtCorsOriginFilter::class.java, Ordered.LOWEST_PRECEDENCE))
            .isEqualTo(Ordered.HIGHEST_PRECEDENCE + 8)
    }

    private fun ordinaryExchange(
        path: String,
        origin: String?,
    ): MockServerWebExchange {
        val builder = MockServerHttpRequest.get("https://api.platformholder.site$path")
        origin?.let { builder.header(HttpHeaders.ORIGIN, it) }
        return MockServerWebExchange.from(builder.build())
    }

    private fun preflightExchange(
        path: String,
        origin: String,
        requestedHeaders: String,
    ): MockServerWebExchange =
        MockServerWebExchange.from(
            MockServerHttpRequest
                .options("https://api.platformholder.site$path")
                .header(HttpHeaders.ORIGIN, origin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, requestedHeaders)
                .build(),
        )

    private fun execute(exchange: MockServerWebExchange): Boolean {
        val passed = AtomicBoolean(false)
        val chain =
            WebFilterChain {
                passed.set(true)
                Mono.empty()
            }
        filter.filter(exchange, chain).block()
        return passed.get()
    }

    private fun executeWithGlobalCors(exchange: MockServerWebExchange) {
        filter
            .filter(exchange) { filteredExchange ->
                downstreamCors.filter(filteredExchange) { Mono.empty() }
            }.block()
    }

    private fun assertForbiddenWithoutCredentialedCors(exchange: MockServerWebExchange) {
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        assertThat(exchange.response.headers.accessControlAllowOrigin).isNull()
        assertThat(exchange.response.headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS)).isNull()
    }

    private companion object {
        const val CBT_PATH = "/api/v1/cbt/attempts"
        const val ADMIN_CBT_PATH = "/api/v1/admin/cbt/exams"
        const val PRODUCTION_ORIGIN = "https://mirror-view.platformholder.site"
    }
}
