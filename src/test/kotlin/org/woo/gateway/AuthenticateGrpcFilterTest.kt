package org.woo.gateway

import exception.ErrorCode
import exception.ExpiredJwtException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.route.Route
import org.springframework.http.HttpCookie
import org.springframework.http.HttpHeaders
import org.springframework.mock.env.MockEnvironment
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.http.server.RequestPath
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.web.server.ServerWebExchange
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.TokenProto
import org.woo.gateway.config.GatewayAuthCookieProperties
import org.woo.gateway.filter.AuthenticateGrpcFilter
import org.woo.gateway.security.GatewayAuthCookieFactory
import org.woo.gateway.service.AuthenticateService
import reactor.core.publisher.Mono
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@OptIn(ExperimentalCoroutinesApi::class)
class AuthenticateGrpcFilterTest {
    private val authenticateService: AuthenticateService = mock(AuthenticateService::class.java)
    private val cookieFactory =
        GatewayAuthCookieFactory(
            GatewayAuthCookieProperties(
                domain = null,
                secure = false,
                sameSite = "Lax",
            ),
            MockEnvironment().apply { setActiveProfiles("test") },
        )
    private val filter = AuthenticateGrpcFilter(authenticateService, cookieFactory)

    private fun stubExchange(
        passportHeaderPresent: Boolean = false,
        path: String = "/api/v1/forest/posts",
    ): Triple<ServerWebExchange, ServerHttpRequest, ServerHttpResponse> {
        val mockExchange = mock(ServerWebExchange::class.java)
        val mockRequest = mock(ServerHttpRequest::class.java)
        val mockResponse = mock(ServerHttpResponse::class.java)
        val headers = HttpHeaders()
        if (passportHeaderPresent) headers.add("X-User-Passport", "{}")
        val mockPath = mock(RequestPath::class.java)
        `when`(mockPath.value()).thenReturn(path)

        `when`(mockExchange.request).thenReturn(mockRequest)
        `when`(mockExchange.response).thenReturn(mockResponse)
        `when`(mockExchange.getAttribute<Route>(any())).thenReturn(null)
        `when`(mockRequest.headers).thenReturn(headers)
        `when`(mockRequest.path).thenReturn(mockPath)
        return Triple(mockExchange, mockRequest, mockResponse)
    }

    @Test
    fun `should pass through original exchange when access token is null`() =
        runTest {
            val (mockExchange, mockRequest, _) = stubExchange()
            val mockChain = mock(GatewayFilterChain::class.java)
            `when`(authenticateService.extractToken(mockRequest)).thenReturn(Pair(null, null))
            `when`(mockChain.filter(any())).thenReturn(Mono.empty())

            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            verify(mockChain).filter(mockExchange)
        }

    @Test
    fun `should pass through original exchange when access token is expired and refresh token is null`() =
        runTest {
            val (mockExchange, mockRequest, _) = stubExchange()
            val mockChain = mock(GatewayFilterChain::class.java)
            val accessToken = "expired-access-token"
            `when`(authenticateService.extractToken(mockRequest)).thenReturn(Pair(accessToken, null))
            `when`(authenticateService.getPassport(accessToken)).thenThrow(ExpiredJwtException(ErrorCode.EXPIRED_JWT, null))
            `when`(mockChain.filter(any())).thenReturn(Mono.empty())

            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            verify(authenticateService).extractToken(mockRequest)
            verify(authenticateService).getPassport(accessToken)
            verify(mockChain).filter(mockExchange)
        }

    @Test
    fun `should pass through original exchange when passport is null`() =
        runTest {
            val (mockExchange, mockRequest, _) = stubExchange()
            val mockChain = mock(GatewayFilterChain::class.java)
            val accessToken = "valid-access-token"
            val refreshToken = "valid-refresh-token"
            `when`(authenticateService.extractToken(mockRequest)).thenReturn(Pair(accessToken, refreshToken))
            `when`(authenticateService.getPassport(accessToken)).thenReturn(null)
            `when`(mockChain.filter(any())).thenReturn(Mono.empty())

            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            verify(authenticateService).extractToken(mockRequest)
            verify(authenticateService).getPassport(accessToken)
            verify(mockChain).filter(mockExchange)
        }

    /**
     * GW-1: 클라이언트가 X-User-Passport 헤더를 위조해 보내도 게이트웨이가 진입 시점에 strip.
     * 토큰이 없는 unauthenticated 흐름에서도 strip 이 적용되는지 검증.
     */
    @Test
    fun `should strip client-supplied X-User-Passport header even when no token`() =
        runTest {
            val (mockExchange, mockRequest, _) = stubExchange(passportHeaderPresent = true)
            val mockMutator = mock(ServerHttpRequest.Builder::class.java)
            `when`(mockRequest.mutate()).thenReturn(mockMutator)
            `when`(mockMutator.headers(any())).thenReturn(mockMutator)
            val sanitizedRequest = mock(ServerHttpRequest::class.java)
            `when`(sanitizedRequest.headers).thenReturn(HttpHeaders())
            val sanitizedPath = mock(RequestPath::class.java)
            `when`(sanitizedPath.value()).thenReturn("/api/v1/forest/posts")
            `when`(sanitizedRequest.path).thenReturn(sanitizedPath)
            `when`(mockMutator.build()).thenReturn(sanitizedRequest)

            val mockExchangeMutator = mock(ServerWebExchange.Builder::class.java)
            `when`(mockExchange.mutate()).thenReturn(mockExchangeMutator)
            `when`(mockExchangeMutator.request(any(ServerHttpRequest::class.java))).thenReturn(mockExchangeMutator)
            val sanitizedExchange = mock(ServerWebExchange::class.java)
            val sanitizedResponse = mock(ServerHttpResponse::class.java)
            `when`(sanitizedExchange.request).thenReturn(sanitizedRequest)
            `when`(sanitizedExchange.response).thenReturn(sanitizedResponse)
            `when`(mockExchangeMutator.build()).thenReturn(sanitizedExchange)

            `when`(authenticateService.extractToken(sanitizedRequest)).thenReturn(Pair(null, null))

            val mockChain = mock(GatewayFilterChain::class.java)
            `when`(mockChain.filter(any())).thenReturn(Mono.empty())

            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            // strip 이 일어났음 — 다운스트림에는 sanitizedExchange 가 전달
            verify(mockChain).filter(sanitizedExchange)
        }

    @Test
    fun `refresh cookie rotation enriches the original request and writes one cookie pair`() =
        runTest {
            val oldRefreshToken = "refresh-token-sentinel"
            val newAccessToken = "rotated-access-token-sentinel"
            val newRefreshToken = "rotated-refresh-token-sentinel"
            val exchange =
                MockServerWebExchange.from(
                    MockServerHttpRequest
                        .get("/api/v1/cbt/history")
                        .cookie(HttpCookie("refreshToken", oldRefreshToken))
                        .build(),
                )
            val passport =
                AuthProto.Passport
                    .newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setRole("ROLE_USER")
                    .setApplicationId("mirror-view")
                    .build()
            val rotated =
                TokenProto.JwtTokenResponse
                    .newBuilder()
                    .setAccessToken(newAccessToken)
                    .setRefreshToken(newRefreshToken)
                    .setAccessTokenExpiresIn(1_500)
                    .setRefreshTokenExpiresIn(2_500)
                    .build()
            `when`(authenticateService.extractToken(exchange.request)).thenReturn(Pair(null, oldRefreshToken))
            `when`(authenticateService.reissueToken(oldRefreshToken)).thenReturn(rotated)
            `when`(authenticateService.getPassport(newAccessToken)).thenReturn(passport)

            val routedExchange = AtomicReference<ServerWebExchange>()
            val chain = GatewayFilterChain { routed ->
                routedExchange.set(routed)
                Mono.empty()
            }

            filter.apply(AuthenticateGrpcFilter.Config()).filter(exchange, chain).block()

            val routed = assertNotNull(routedExchange.get())
            assertEquals(newAccessToken, routed.request.headers.getFirst(HttpHeaders.AUTHORIZATION))
            assertNotNull(routed.request.headers.getFirst("X-User-Passport"))
            assertEquals(1, exchange.response.cookies["accessToken"]?.size)
            assertEquals(1, exchange.response.cookies["refreshToken"]?.size)
            assertEquals(newAccessToken, exchange.response.cookies.getFirst("accessToken")?.value)
            assertEquals(newRefreshToken, exchange.response.cookies.getFirst("refreshToken")?.value)
        }
}
