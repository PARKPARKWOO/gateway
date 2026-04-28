package org.woo.gateway.service

import constant.AuthConstant.AUTHORIZATION_HEADER
import exception.ErrorCode
import exception.ExpiredJwtException
import io.grpc.StatusException
import io.grpc.StatusRuntimeException
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Service
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.TokenProto
import org.woo.gateway.client.GrpcAuthClient
import java.util.UUID

@Service
class AuthenticateService(
    private val authClient: GrpcAuthClient,
) {
    /**
     * gRPC kotlin coroutine stub 은 `io.grpc.StatusException` (checked) 를 던지지만,
     * 이전 구현은 `StatusRuntimeException` 만 catch 해서 만료 토큰/auth 에러가 모두 unhandled 로
     * propagate → SCG 가 500 반환. 두 타입 모두 처리하도록 통합.
     */
    suspend fun getPassport(accessToken: String): AuthProto.Passport? =
        try {
            authClient.getUserInfo(accessToken)
        } catch (e: StatusException) {
            handleAuthGrpcError(e.message)
        } catch (e: StatusRuntimeException) {
            handleAuthGrpcError(e.message)
        }

    private fun handleAuthGrpcError(message: String?): AuthProto.Passport? {
        if (message != null && message.contains(ErrorCode.EXPIRED_JWT.message)) {
            throw ExpiredJwtException(ErrorCode.EXPIRED_JWT, null)
        }
        return null
    }

    /**
     * return first: accessToken, second: RefreshToken
     */

    suspend fun extractToken(request: ServerHttpRequest): Pair<String?, String?> {
        val accessToken =
            request.headers[AUTHORIZATION_HEADER]?.firstOrNull()
                ?: request.cookies
                    ?.get("accessToken")
                    ?.firstOrNull()
                    ?.value
                    ?.let { token -> "Bearer $token" }
        val refreshToken =
            request.cookies
                ?.get("refreshToken")
                ?.firstOrNull()
                ?.value
        return Pair(accessToken, refreshToken)
    }

    suspend fun reissueToken(refreshToken: String): TokenProto.JwtTokenResponse =
        authClient.reissueToken(refreshToken, UUID.randomUUID().toString())
}
