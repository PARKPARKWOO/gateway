package org.woo.gateway.service

import constant.AuthConstant.AUTHORIZATION_HEADER
import exception.ErrorCode
import exception.ExpiredJwtException
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
    suspend fun getPassport(accessToken: String): AuthProto.Passport? =
        try {
            authClient.getUserInfo(accessToken)
        } catch (e: StatusRuntimeException) {
            if (e.message == ErrorCode.EXPIRED_JWT.message) {
                throw ExpiredJwtException(ErrorCode.EXPIRED_JWT, null)
            }
            null
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
