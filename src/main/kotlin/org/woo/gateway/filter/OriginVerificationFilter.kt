package org.woo.gateway.filter

import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.woo.apm.log.log
import reactor.core.publisher.Mono
import java.net.URI

/**
 * CSRF-1: 상태 변경 메서드(POST/PUT/PATCH/DELETE)에 대해 Origin/Referer 헤더가
 * 화이트리스트에 있는지 검증. SameSite=None + credentialed cookie 환경의 CSRF 방어.
 *
 * 게이트웨이 globalcors 의 allowedOriginPatterns 와 정책 일치.
 *
 * skip 조건:
 *  - safe method (GET/HEAD/OPTIONS)
 *  - OAuth provider 콜백 (외부 IdP → 게이트웨이로 들어오는 redirect, Origin 없음)
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
class OriginVerificationFilter : WebFilter {
    companion object {
        private val UNSAFE_METHODS =
            setOf(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)

        private val ALLOWED_HOST_SUFFIXES = listOf(".platformholder.site")
        private val ALLOWED_LOCALHOST_HOSTS = setOf("localhost", "127.0.0.1")

        /**
         * 외부 IdP 콜백 등 Origin 헤더 없이 들어와도 정상인 경로.
         * Spring Security 의 oauth2Login 콜백은 GET 이지만, 자체 토큰 교환 등 POST 로 외부에서
         * 들어오는 경로가 추가되면 여기에 등록.
         */
        private val ORIGIN_CHECK_BYPASS_PATHS =
            listOf(
                "/oauth2/authorization/",
                "/login/oauth2/code/",
            )
    }

    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        val request = exchange.request
        val method = request.method
        if (method !in UNSAFE_METHODS) {
            return chain.filter(exchange)
        }
        val path = request.path.value()
        if (ORIGIN_CHECK_BYPASS_PATHS.any { path.startsWith(it) }) {
            return chain.filter(exchange)
        }

        val origin = request.headers.getFirst("Origin")
        val referer = request.headers.getFirst("Referer")
        val candidate = origin ?: referer

        if (candidate == null) {
            return reject(exchange, "missing Origin/Referer for $method $path")
        }
        if (!isAllowed(candidate)) {
            return reject(exchange, "disallowed origin '$candidate' for $method $path")
        }
        return chain.filter(exchange)
    }

    private fun isAllowed(originOrReferer: String): Boolean {
        val host =
            try {
                URI.create(originOrReferer).host ?: return false
            } catch (e: IllegalArgumentException) {
                return false
            }
        if (host in ALLOWED_LOCALHOST_HOSTS) return true
        return ALLOWED_HOST_SUFFIXES.any { suffix ->
            host == suffix.removePrefix(".") || host.endsWith(suffix)
        }
    }

    private fun reject(
        exchange: ServerWebExchange,
        reason: String,
    ): Mono<Void> {
        log().warn("CSRF block: $reason")
        exchange.response.statusCode = HttpStatus.FORBIDDEN
        return exchange.response.setComplete()
    }
}
