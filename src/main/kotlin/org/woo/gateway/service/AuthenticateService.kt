package org.woo.gateway.service

import constant.AuthConstant.AUTHORIZATION_HEADER
import exception.ErrorCode
import exception.ExpiredJwtException
import io.grpc.StatusException
import io.grpc.StatusRuntimeException
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Service
import org.woo.apm.log.log
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
            handleAuthGrpcError(e, e.message)
        } catch (e: StatusRuntimeException) {
            handleAuthGrpcError(e, e.message)
        }

    /**
     * gRPC 실패를 두 갈래로 분기:
     *  - EXPIRED_JWT 메시지 포함 → `ExpiredJwtException` 으로 변환 (호출부에서 rotation 처리)
     *  - 그 외 → null 반환. 단 silent 가 되지 않도록 **반드시 WARN 로 stack trace 와 함께 기록**.
     *    이전엔 auth-server 다운/INTERNAL/네트워크 오류가 흔적 없이 사라져 다운스트림 NPE 의
     *    원인 추적이 불가능했다 (5/9 사고 회고).
     */
    private fun handleAuthGrpcError(
        cause: Throwable,
        message: String?,
    ): AuthProto.Passport? {
        if (message != null && message.contains(ErrorCode.EXPIRED_JWT.message)) {
            throw ExpiredJwtException(ErrorCode.EXPIRED_JWT, null)
        }
        log().warn(
            "auth: gRPC getUserInfo failed (non-expiry) — returning null passport. ex={}: {}",
            cause.javaClass.simpleName, message, cause,
        )
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
