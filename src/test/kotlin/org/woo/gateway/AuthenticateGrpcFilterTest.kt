package org.woo.gateway

import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.awaitSingleOrNull
import org.woo.gateway.filter.AuthenticateGrpcFilter
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.mockito.ArgumentMatchers
import org.mockito.Mockito.*
import org.mockito.kotlin.whenever
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.server.ServerWebExchange
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.AuthProto.Passport
import org.woo.gateway.client.GrpcAuthClient
import reactor.core.publisher.Mono
import java.util.UUID

@OptIn(ExperimentalCoroutinesApi::class)
class AuthenticateGrpcFilterTest {

    // Mock dependencies
    private val authClient: GrpcAuthClient = mock(GrpcAuthClient::class.java)
    private val filter = AuthenticateGrpcFilter(authClient)

    @Test
    fun `should modify exchange when token is valid`() = runTest {
        // Arrange
        val mockExchange = mock(ServerWebExchange::class.java)
        val mockRequest = mock(ServerHttpRequest::class.java)
        val mockChain = mock(GatewayFilterChain::class.java)
        val headers = HttpHeaders()
        val token = "Bearer valid-token"
        headers.add(HttpHeaders.AUTHORIZATION, token)

        val passport = Passport.newBuilder()
            .setRole("USER_ROLE")
            .setApplicationId("example-application")
            .setId(UUID.randomUUID().toString())
            .build()

        `when`(mockExchange.request).thenReturn(mockRequest)
        `when`(mockRequest.headers).thenReturn(headers)

        // Suspend 함수 모킹: `Mono`에서 반환될 값을 제대로 설정해야 한다.
        `when`(authClient.getUserInfo("valid-token")).thenReturn(passport)

        `when`(mockChain.filter(any(ServerWebExchange::class.java))).thenReturn(Mono.empty())

        // Act
        val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
        filterFunction.filter(mockExchange, mockChain).block()

        // Assert
        verify(mockChain).filter(any(ServerWebExchange::class.java)) // Modified exchange를 검증
    }

    @Test
    fun `should not modify exchange when token is missing`() = runTest {
        // Arrange
        val mockExchange = mock(ServerWebExchange::class.java)
        val mockRequest = mock(ServerHttpRequest::class.java)
        val mockChain = mock(GatewayFilterChain::class.java)
        val headers = HttpHeaders() // No Authorization header

        `when`(mockExchange.request).thenReturn(mockRequest)
        `when`(mockRequest.headers).thenReturn(headers)
        `when`(mockChain.filter(mockExchange)).thenReturn(Mono.empty())

        // Act
        val filterFunction = filter.apply(AuthenticateGrpcFilter.Config())
        filterFunction.filter(mockExchange, mockChain).awaitSingleOrNull()

        // Assert
        verify(mockChain).filter(mockExchange)
    }
}