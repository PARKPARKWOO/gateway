package org.woo.gateway.filter

import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.woo.apm.log.log
import org.woo.gateway.security.CbtWebOriginMatcher
import reactor.core.publisher.Mono
import java.util.Locale

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 8)
class CbtCorsOriginFilter(
    private val originMatcher: CbtWebOriginMatcher,
) : WebFilter {
    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        val request = exchange.request
        val path = request.path.value()
        if (!isCbtPath(path)) return chain.filter(exchange)

        val originValues = request.headers[HttpHeaders.ORIGIN].orEmpty()
        if (originValues.isEmpty()) return chain.filter(exchange)
        if (originValues.size != 1 || !originMatcher.matchesOrigin(originValues.single())) {
            return reject(exchange, "disallowed CBT CORS origin for ${request.method} $path")
        }
        if (isPreflight(exchange) && !hasAllowedPreflightContract(exchange)) {
            return reject(exchange, "disallowed CBT CORS preflight for ${request.method} $path")
        }
        return chain.filter(exchange)
    }

    private fun isCbtPath(path: String): Boolean =
        CBT_PATH_PREFIXES.any { prefix -> path == prefix || path.startsWith("$prefix/") }

    private fun isPreflight(exchange: ServerWebExchange): Boolean =
        exchange.request.method == HttpMethod.OPTIONS &&
            exchange.request.headers.containsKey(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD)

    private fun hasAllowedPreflightContract(exchange: ServerWebExchange): Boolean {
        val requestedMethod = exchange.request.headers.accessControlRequestMethod ?: return false
        if (requestedMethod !in ALLOWED_METHODS) return false
        return exchange.request.headers.accessControlRequestHeaders.all { header ->
            header.lowercase(Locale.ROOT) in ALLOWED_HEADERS
        }
    }

    private fun reject(
        exchange: ServerWebExchange,
        reason: String,
    ): Mono<Void> {
        log().warn(reason)
        exchange.response.statusCode = HttpStatus.FORBIDDEN
        return exchange.response.setComplete()
    }

    private companion object {
        val CBT_PATH_PREFIXES = listOf("/api/v1/cbt", "/api/v1/admin/cbt")
        val ALLOWED_METHODS =
            setOf(
                HttpMethod.GET,
                HttpMethod.HEAD,
                HttpMethod.POST,
                HttpMethod.PUT,
                HttpMethod.PATCH,
                HttpMethod.DELETE,
                HttpMethod.OPTIONS,
            )
        val ALLOWED_HEADERS =
            setOf(
                "content-type",
                "idempotency-key",
                "x-xsrf-token",
                "x-cbt-attempt-token",
                "x-cbt-printable-token",
            )
    }
}
