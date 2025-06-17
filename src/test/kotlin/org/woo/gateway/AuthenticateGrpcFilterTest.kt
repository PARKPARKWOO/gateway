package org.woo.gateway

import exception.ErrorCode
import exception.ExpiredJwtException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.springframework.cloud.gateway.filter.GatewayFilterChain
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

    @Test
    fun `should pass through original exchange when access token is null`() =
        runTest {
            // Arrange
            val mockExchange = mock(ServerWebExchange::class.java)
            val mockRequest = mock(ServerHttpRequest::class.java)
            val mockResponse = mock(ServerHttpResponse::class.java)
            val mockChain = mock(GatewayFilterChain::class.java)

            `when`(mockExchange.request).thenReturn(mockRequest)
            `when`(mockExchange.response).thenReturn(mockResponse)
            `when`(authenticateService.extractToken(mockRequest)).thenReturn(Pair(null, null))
            `when`(mockChain.filter(mockExchange)).thenReturn(Mono.empty())

            // Act
            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            // Assert
            verify(mockChain).filter(mockExchange)
        }

    @Test
    fun `should pass through original exchange when access token is expired and refresh token is null`() =
        runTest {
            // Arrange
            val mockExchange = mock(ServerWebExchange::class.java)
            val mockRequest = mock(ServerHttpRequest::class.java)
            val mockResponse = mock(ServerHttpResponse::class.java)
            val mockChain = mock(GatewayFilterChain::class.java)

            val accessToken = "expired-access-token"

            `when`(mockExchange.request).thenReturn(mockRequest)
            `when`(mockExchange.response).thenReturn(mockResponse)
            `when`(authenticateService.extractToken(mockRequest)).thenReturn(Pair(accessToken, null))
            `when`(authenticateService.getPassport(accessToken)).thenThrow(ExpiredJwtException(ErrorCode.EXPIRED_JWT, null))
            `when`(mockChain.filter(mockExchange)).thenReturn(Mono.empty())

            // Act
            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            // Assert
            verify(authenticateService).extractToken(mockRequest)
            verify(authenticateService).getPassport(accessToken)
            verify(mockChain).filter(mockExchange) // 원본 exchange가 그대로 전달되어야 함
        }

    @Test
    fun `should pass through original exchange when passport is null`() =
        runTest {
            // Arrange
            val mockExchange = mock(ServerWebExchange::class.java)
            val mockRequest = mock(ServerHttpRequest::class.java)
            val mockResponse = mock(ServerHttpResponse::class.java)
            val mockChain = mock(GatewayFilterChain::class.java)

            val accessToken = "valid-access-token"
            val refreshToken = "valid-refresh-token"

            `when`(mockExchange.request).thenReturn(mockRequest)
            `when`(mockExchange.response).thenReturn(mockResponse)
            `when`(authenticateService.extractToken(mockRequest)).thenReturn(Pair(accessToken, refreshToken))
            `when`(authenticateService.getPassport(accessToken)).thenReturn(null)
            `when`(mockChain.filter(mockExchange)).thenReturn(Mono.empty())

            // Act
            val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
            filterFunction.filter(mockExchange, mockChain).block()

            // Assert
            verify(authenticateService).extractToken(mockRequest)
            verify(authenticateService).getPassport(accessToken)
            verify(mockChain).filter(mockExchange) // 원본 exchange가 그대로 전달되어야 함
        }
}
