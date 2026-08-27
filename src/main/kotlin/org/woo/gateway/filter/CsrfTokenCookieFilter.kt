package org.woo.gateway.filter

import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CsrfTokenProperties
import org.woo.gateway.security.CsrfTokenService
import reactor.core.publisher.Mono

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 9)
class CsrfTokenCookieFilter(
    private val properties: CsrfTokenProperties,
    private val tokenService: CsrfTokenService,
) : WebFilter {
    private val domain = properties.cookieDomain?.trim()?.takeIf { it.isNotEmpty() }
    private val sameSite = properties.sameSite.trim()

    init {
        require(!properties.httpOnly) {
            "gateway.security.csrf.token.http-only must be false so the web client can copy the token"
        }
        require(sameSite in ALLOWED_SAME_SITE_VALUES) {
            "gateway.security.csrf.token.same-site must be one of Lax, Strict, or None"
        }
    }

    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        if (exchange.request.method !in SAFE_METHODS) {
            return chain.filter(exchange)
        }

        val currentToken = exchange.request.cookies.getFirst(properties.cookieName)?.value
        if (currentToken.isNullOrEmpty()) {
            exchange.response.addCookie(buildCookie(tokenService.generate()))
        }
        return chain.filter(exchange)
    }

    private fun buildCookie(value: String): ResponseCookie {
        val builder =
            ResponseCookie
                .from(properties.cookieName, value)
                .httpOnly(false)
                .secure(properties.secure)
                .path(properties.path)
                .sameSite(sameSite)
        domain?.let(builder::domain)
        return builder.build()
    }

    private companion object {
        val SAFE_METHODS = setOf(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS)
        val ALLOWED_SAME_SITE_VALUES = setOf("Lax", "Strict", "None")
    }
}
