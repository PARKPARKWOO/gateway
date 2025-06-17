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
import org.woo.grpc.TokenInitializeInMetadata

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
            // 코루틴 스텁의 메서드는 이미 suspend 함수이므로 직접 호출하면 됩니다.
            userInfoService
                .withInterceptors(TokenInitializeInMetadata(token))
                .getPassportByBearer(Empty.newBuilder().build())
        } catch (e: StatusRuntimeException) {
            log().error("Failed to fetch user info: ${e.message}", e)
            throw e // 예외를 다시 던져서 호출한 쪽에서 처리하도록 함
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
