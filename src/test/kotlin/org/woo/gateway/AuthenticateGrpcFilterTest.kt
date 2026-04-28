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
import org.springframework.http.HttpHeaders
import org.springframework.http.server.RequestPath
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.web.server.ServerWebExchange
import org.woo.gateway.filter.AuthenticateGrpcFilter
import org.woo.gateway.service.AuthenticateService
import reactor.core.publisher.Mono

@OptIn(ExperimentalCoroutinesApi::class)
class AuthenticateGrpcFilterTest {
    private val authenticateService: AuthenticateService = mock(AuthenticateService::class.java)
    private val filter = AuthenticateGrpcFilter(authenticateService)

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
}
