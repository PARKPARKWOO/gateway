package org.woo.gateway

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CsrfOriginProperties
import org.woo.gateway.filter.OriginVerificationFilter
import reactor.core.publisher.Mono

class OriginVerificationFilterTest {
    private val props =
        CsrfOriginProperties(
            allowedHostSuffixes = listOf(".platformholder.site"),
            allowedExactHosts = listOf("forest-front-psi.vercel.app"),
            allowedLocalhostHosts = listOf("localhost", "127.0.0.1"),
        )
    private val filter = OriginVerificationFilter(props)

    private fun build(
        method: HttpMethod,
        path: String = "/api/v1/program/information",
        origin: String? = null,
        referer: String? = null,
        authorization: String? = null,
    ): MockServerWebExchange {
        val builder = MockServerHttpRequest.method(method, path)
        origin?.let { builder.header("Origin", it) }
        referer?.let { builder.header("Referer", it) }
        authorization?.let { builder.header("Authorization", it) }
        return MockServerWebExchange.from(builder.build())
    }

    private val passthroughChain = WebFilterChain { Mono.empty() }

    @Test
    fun `safe method passes regardless of origin`() {
        val exchange = build(method = HttpMethod.GET, origin = "https://evil.example.com")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `oauth callback path bypasses origin check`() {
        val exchange = build(method = HttpMethod.POST, path = "/login/oauth2/code/google")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `authorization header bypasses origin check`() {
        val exchange = build(method = HttpMethod.POST, authorization = "Bearer token")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `platformholder subdomain origin is allowed via suffix`() {
        val exchange = build(method = HttpMethod.POST, origin = "https://forest.platformholder.site")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `forest vercel host is allowed via exact match`() {
        val exchange = build(method = HttpMethod.POST, origin = "https://forest-front-psi.vercel.app")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `unrelated vercel host is rejected`() {
        val exchange = build(method = HttpMethod.POST, origin = "https://attacker.vercel.app")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `missing origin and referer is rejected`() {
        val exchange = build(method = HttpMethod.POST)
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `localhost origin is allowed`() {
        val exchange = build(method = HttpMethod.POST, origin = "http://localhost:3000")
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `referer is used when origin missing`() {
        val exchange =
            build(
                method = HttpMethod.POST,
                referer = "https://forest-front-psi.vercel.app/programs/create",
            )
        filter.filter(exchange, passthroughChain).block()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }
}
