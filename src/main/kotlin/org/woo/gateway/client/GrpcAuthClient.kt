package org.woo.gateway.client

import com.google.protobuf.Empty
import io.grpc.StatusRuntimeException
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.TokenProto
import org.woo.auth.grpc.TokenProto.ReissueTokenRequest
import org.woo.auth.grpc.TokenServiceGrpcKt
import org.woo.auth.grpc.UserInfoServiceGrpcKt
import org.woo.gateway.factory.NettyChannelFactory
import org.woo.grpc.interceptor.TokenInitializeInMetadata

@Component
class GrpcAuthClient(
    @Value("\${network.services.auth.host}")
    private val authHost: String,
    private val channelFactory: NettyChannelFactory,
) {
    private lateinit var userInfoService: UserInfoServiceGrpcKt.UserInfoServiceCoroutineStub
    private lateinit var tokenService: TokenServiceGrpcKt.TokenServiceCoroutineStub

    init {
        channelFactory.getChannel(authHost)?.let { channel ->
            userInfoService = UserInfoServiceGrpcKt.UserInfoServiceCoroutineStub(channel)
            tokenService = TokenServiceGrpcKt.TokenServiceCoroutineStub(channel)
        } ?: throw IllegalStateException("Channels must be initialized before use")
    }

    suspend fun getUserInfo(token: String): AuthProto.Passport =
        try {
            userInfoService
                .withInterceptors(TokenInitializeInMetadata(token))
                .getPassportByBearer(Empty.newBuilder().build())
        } catch (e: StatusRuntimeException) {
            log().error("Failed to fetch user info: ${e.message}", e)
            throw e
        }

    suspend fun reissueToken(
        refreshToken: String,
        idempotentKey: String,
    ): TokenProto.JwtTokenResponse {
        val request =
            ReissueTokenRequest
                .newBuilder()
                .setRefreshToken(refreshToken)
                .setIdempotentKey(idempotentKey)
                .build()
        return tokenService.reissueToken(request)
    }
}
