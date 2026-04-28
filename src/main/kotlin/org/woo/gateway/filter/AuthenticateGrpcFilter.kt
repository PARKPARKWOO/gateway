package org.woo.gateway.filter

import constant.AuthConstant.AUTHORIZATION_HEADER
import dto.Passport
import dto.UserContext
import exception.ExpiredJwtException
import kotlinx.coroutines.reactor.mono
import model.Role
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.gateway.service.AuthenticateService
import org.woo.mapper.Jackson
import java.time.Duration
import java.util.UUID

@Component
class AuthenticateGrpcFilter(
    private val authenticateService: AuthenticateService,
) : AbstractGatewayFilterFactory<AuthenticateGrpcFilter.Config>(Config::class.java) {
    companion object {
        private const val PASSPORT_HEADER = "X-User-Passport"
        private val NO_AUTHENTICATE_ROUTE_IDS = setOf("oauth-route")
        private val NO_AUTHENTICATE_PATH_PREFIXES =
            setOf(
                "/swagger-ui.html",
                "/swagger-ui/",
                "/v3/api-docs",
                "/webjars/",
                "/login",
            )

        // LOGOUT-4: oauth-route 가 인증 skip 대상이라도 이 prefix 는 강제 인증.
        // revoke 는 자기 토큰 무효화이므로 Passport 가 반드시 필요.
        private val AUTH_ENFORCED_PATH_PREFIXES =
            setOf(
                "/api/v1/auth/token/revoke",
            )
    }

    class Config

    override fun apply(config: Config): GatewayFilter =
        GatewayFilter { exchange, chain ->
            if (shouldSkipAuthentication(exchange)) {
                return@GatewayFilter chain.filter(exchange.stripPassportHeader())
            }

            return@GatewayFilter mono {
                val sanitizedExchange = exchange.stripPassportHeader()
                val request = sanitizedExchange.request
                val response = sanitizedExchange.response
                val (accessToken, refreshToken) = authenticateService.extractToken(request)
                if (accessToken == null && refreshToken == null) {
                    return@mono sanitizedExchange
                }

                val (passport, newAccessToken) =
                    try {
                        accessToken?.let {
                            val passport = authenticateService.getPassport(accessToken) ?: return@mono sanitizedExchange
                            Pair(passport, accessToken)
                        } ?: rotationToken(refreshToken!!, response) ?: return@mono sanitizedExchange
                    } catch (e: ExpiredJwtException) {
                        refreshToken?.let {
                            rotationToken(refreshToken, response)
                        } ?: return@mono sanitizedExchange
                    }

                val mutatedRequest = request.mutate().header(AUTHORIZATION_HEADER, newAccessToken).build()
                val includePassportHeader = mutatedRequest.setPassportToHeader(passport)
                log().info("authenticate userId = ${passport.id}")
                sanitizedExchange.mutate().request(includePassportHeader).build()
            }.flatMap { newExchange ->
                chain.filter(newExchange)
            }
        }

    private fun ServerWebExchange.stripPassportHeader(): ServerWebExchange {
        if (!request.headers.containsKey(PASSPORT_HEADER)) return this
        val sanitized = request.mutate().headers { it.remove(PASSPORT_HEADER) }.build()
        return mutate().request(sanitized).build()
    }

    private fun shouldSkipAuthentication(exchange: ServerWebExchange): Boolean {
        val path =
            try {
                exchange.request.path
                    .pathWithinApplication()
                    .value()
            } catch (e: Exception) {
                return false
            }

        // LOGOUT-4: revoke 는 자기 토큰 무효화이므로 인증 필요. oauth-route 매칭이라도 강제 인증.
        if (AUTH_ENFORCED_PATH_PREFIXES.any { path.startsWith(it) }) {
            return false
        }

        val routeId = exchange.getAttribute<Route>(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR)?.id
        if (routeId in NO_AUTHENTICATE_ROUTE_IDS) {
            return true
        }

        return NO_AUTHENTICATE_PATH_PREFIXES.any { path.startsWith(it) }
    }

    fun ServerHttpRequest.setPassportToHeader(passportProto: AuthProto.Passport): ServerHttpRequest {
        val userContext =
            if (passportProto.hasUserInfo()) {
                UserContext(
                    email = passportProto.userInfo.email.takeIf { passportProto.userInfo.hasEmail() },
                    userName = passportProto.userInfo.name.takeIf { passportProto.userInfo.hasName() },
                    applicationRole = passportProto.userInfo.applicationRole,
                    accessLevel = passportProto.userInfo.accessLevel,
                )
            } else {
                null
            }
        val passport =
            Passport(
                userId = UUID.fromString(passportProto.id),
                role = Role.valueOf(passportProto.role),
                signInApplicationId = passportProto.applicationId.toString(),
                userContext = userContext,
            )
        val userContextString = Jackson.writeValueAsString(passport)
        return this
            .mutate()
            .header(PASSPORT_HEADER, userContextString)
            .build()
    }

    private suspend fun rotationToken(
        refreshToken: String,
        response: ServerHttpResponse,
    ): Pair<AuthProto.Passport, String>? =
        runCatching {
            val reissueToken = authenticateService.reissueToken(refreshToken)
            val newAccessToken = reissueToken.accessToken
            response.apply {
                addCookie(createCookie("accessToken", newAccessToken, reissueToken.accessTokenExpiresIn))
                addCookie(
                    createCookie(
                        "refreshToken",
                        reissueToken.refreshToken,
                        reissueToken.refreshTokenExpiresIn,
                    ),
                )
            }
            authenticateService.getPassport(newAccessToken)?.let { passport ->
                Pair(passport, newAccessToken)
            }
        }.onFailure {
            response.clearAuthCookie()
        }.getOrNull()

    private fun ServerHttpResponse.clearAuthCookie() {
        // LOGOUT-3: createCookie 와 (name, domain, path, secure, sameSite) 를 동일하게 맞춰야
        // 브라우저가 같은 쿠키로 인식하고 삭제.
        this.addCookie(buildClearedCookie("accessToken"))
        this.addCookie(buildClearedCookie("refreshToken"))
    }

    private fun buildClearedCookie(name: String): ResponseCookie =
        ResponseCookie
            .from(name, "")
            .path("/")
            .domain(".platformholder.site")
            .maxAge(Duration.ZERO)
            .httpOnly(true)
            .secure(true)
            .sameSite("None")
            .build()

    private fun createCookie(
        name: String,
        value: String,
        maxAge: Long,
    ): ResponseCookie =
        ResponseCookie
            .from(name, value)
            // P0-#2: httpOnly. JS 가 토큰을 만지지 않는 정책 (axios withCredentials + 게이트웨이 자동 회전).
            .httpOnly(true)
            .secure(true)
            .path("/")
            .domain(".platformholder.site")
            .maxAge(Duration.ofMillis(maxAge))
            .sameSite("None")
            .build()
}
