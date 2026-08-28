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
import org.woo.gateway.config.CsrfOriginProperties
import org.woo.gateway.config.CsrfTokenProperties
import org.woo.gateway.security.CbtWebOriginMatcher
import org.woo.gateway.security.CsrfTokenService
import reactor.core.publisher.Mono
import java.net.URI

/**
 * CSRF-1: 상태 변경 메서드(POST/PUT/PATCH/DELETE)에 대해 Origin/Referer 헤더가
 * 화이트리스트에 있는지 검증. SameSite=None + credentialed cookie 환경의 CSRF 방어.
 *
 * CBT 경로는 [CbtWebOriginMatcher]의 exact scheme/host/effective-port 정책을 사용한다.
 * 비-CBT 경로는 호환성을 위해 [CsrfOriginProperties]의 기존 host 정책을 유지한다.
 *
 * skip 조건:
 *  - safe method (GET/HEAD/OPTIONS)
 *  - OAuth provider 콜백 (외부 IdP → 게이트웨이로 들어오는 redirect, Origin 없음)
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
class OriginVerificationFilter(
    private val props: CsrfOriginProperties,
    private val tokenProperties: CsrfTokenProperties,
    private val tokenService: CsrfTokenService,
    private val cbtWebOriginMatcher: CbtWebOriginMatcher,
) : WebFilter {
    companion object {
        private val UNSAFE_METHODS =
            setOf(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)

        /**
         * 외부 IdP 콜백 등 Origin 헤더 없이 들어와도 정상인 경로.
         * Spring Security 의 oauth2Login 콜백은 GET 이지만, 자체 토큰 교환 등 POST 로 외부에서
         * 들어오는 경로가 추가되면 여기에 등록.
         *
         * BBR/MV 모바일 앱의 자체 토큰 교환·재발급은 native client 라 Origin 헤더가 없고
         * 첫 호출이라 Authorization 헤더도 없어서 CSRF 가드를 통과하지 못함 — bypass 등록.
         * (둘 다 인증 entry point: oauth/token=최초 발급, token/reissue=refreshToken 으로 재발급)
         */
        private val ORIGIN_CHECK_BYPASS_PATHS =
            listOf(
                "/oauth2/authorization/",
                "/login/oauth2/code/",
                "/api/v1/auth/oauth/token",
                "/api/v1/auth/token/reissue",
            )

        private const val PUBLIC_CBT_PATH_PREFIX = "/api/v1/cbt"
        private val CBT_PATH_PREFIXES = listOf(PUBLIC_CBT_PATH_PREFIX, "/api/v1/admin/cbt")
        private const val INSTALLATION_ID_HEADER = "X-CBT-Installation-Id"
        private val AUTH_COOKIE_NAMES = setOf("accessToken", "refreshToken")
        private val INSTALLATION_ID_PATTERN = Regex("[A-Za-z0-9_-]{20,128}")
        private val BEARER_PATTERN = Regex("Bearer [^\\s]+", RegexOption.IGNORE_CASE)
        private const val POSITIVE_ID_GROUP = "([1-9][0-9]*)"
        private val GUEST_ANSWER_PATH =
            Regex("^/api/v1/cbt/attempts/$POSITIVE_ID_GROUP/answers/$POSITIVE_ID_GROUP$")
        private val GUEST_CHECK_PATH =
            Regex("^/api/v1/cbt/attempts/$POSITIVE_ID_GROUP/answers/$POSITIVE_ID_GROUP/check$")
        private val GUEST_SUBMIT_PATH =
            Regex("^/api/v1/cbt/attempts/$POSITIVE_ID_GROUP/submit$")
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

        // CSRF 는 "쿠키 자동 첨부" 때문에 발생. Authorization 헤더 인증은 다른 사이트가 헤더를
        // 박을 수 없으므로 CSRF 노출 X. 따라서 토큰 헤더 인증은 Origin 검증을 면제한다.
        // 모바일 앱(BBR/mirror-view) 등 native 클라이언트는 Origin 헤더를 안 보내지만 Authorization
        // 헤더로 인증하므로 이 분기로 통과.
        val authorization = request.headers.getFirst("Authorization")
        val hasInstallationIdHeader = request.headers.containsKey(INSTALLATION_ID_HEADER)
        if (authorization != null && BEARER_PATTERN.matches(authorization) && !hasInstallationIdHeader) {
            return chain.filter(exchange)
        }

        val origin = request.headers.getFirst(HttpHeaders.ORIGIN)
        val referer = request.headers.getFirst(HttpHeaders.REFERER)
        val candidate = origin ?: referer

        if (candidate == null) {
            if (
                isAllowedGuestMutation(method, path) &&
                authorization.isNullOrBlank() &&
                !hasAuthCookie(exchange) &&
                hasValidInstallationId(exchange)
            ) {
                return chain.filter(exchange)
            }
            return reject(exchange, "missing Origin/Referer for $method $path")
        }
        val allowed =
            if (isCbtPath(path)) {
                when {
                    origin != null ->
                        request.headers[HttpHeaders.ORIGIN].orEmpty().size == 1 &&
                            cbtWebOriginMatcher.matchesOrigin(origin)
                    else -> cbtWebOriginMatcher.matchesReferer(candidate)
                }
            } else {
                isAllowed(candidate)
            }
        if (!allowed) {
            return reject(exchange, "disallowed Origin/Referer for $method $path")
        }
        if (isCbtPath(path) && !hasMatchingToken(exchange)) {
            return reject(exchange, "missing or mismatched CBT CSRF token for $method $path")
        }
        return chain.filter(exchange)
    }

    private fun isCbtPath(path: String): Boolean =
        CBT_PATH_PREFIXES.any { prefix -> path == prefix || path.startsWith("$prefix/") }

    private fun isAllowedGuestMutation(
        method: HttpMethod,
        path: String,
    ): Boolean =
        when (method) {
            HttpMethod.POST ->
                path == "$PUBLIC_CBT_PATH_PREFIX/attempts" ||
                    matchesPositiveIdPath(GUEST_CHECK_PATH, path) ||
                    matchesPositiveIdPath(GUEST_SUBMIT_PATH, path)
            HttpMethod.PUT -> matchesPositiveIdPath(GUEST_ANSWER_PATH, path)
            else -> false
        }

    private fun matchesPositiveIdPath(
        pattern: Regex,
        path: String,
    ): Boolean =
        pattern
            .matchEntire(path)
            ?.groupValues
            ?.drop(1)
            ?.all { value -> value.toLongOrNull()?.let { it > 0 } == true } == true

    private fun hasAuthCookie(exchange: ServerWebExchange): Boolean =
        AUTH_COOKIE_NAMES.any(exchange.request.cookies::containsKey)

    private fun hasValidInstallationId(exchange: ServerWebExchange): Boolean =
        exchange.request.headers
            .getFirst(INSTALLATION_ID_HEADER)
            ?.let(INSTALLATION_ID_PATTERN::matches) == true

    private fun hasMatchingToken(exchange: ServerWebExchange): Boolean {
        val cookieValues = exchange.request.cookies[tokenProperties.cookieName].orEmpty()
        val headerValues = exchange.request.headers[tokenProperties.headerName].orEmpty()
        if (cookieValues.size != 1 || headerValues.size != 1) return false
        val cookieValue = cookieValues.single().value
        val headerValue = headerValues.single()
        return tokenService.matches(cookieValue, headerValue)
    }

    private fun isAllowed(originOrReferer: String): Boolean {
        val host =
            try {
                URI.create(originOrReferer).host ?: return false
            } catch (e: IllegalArgumentException) {
                return false
            }
        if (host in props.allowedLocalhostHosts) return true
        if (host in props.allowedExactHosts) return true
        return props.allowedHostSuffixes.any { suffix ->
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
