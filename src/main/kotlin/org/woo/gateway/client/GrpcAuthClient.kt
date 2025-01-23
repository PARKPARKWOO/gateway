package org.woo.gateway.client

import com.google.protobuf.Empty
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.yield
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.UserInfoServiceGrpc
import org.woo.gateway.factory.NettyChannelFactory
import org.woo.grpc.TokenInitializeInMetadata
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

@Component
class GrpcAuthClient(
    @Value("\${network.services.auth.host}")
    private val authHost: String,
    private val channelFactory: NettyChannelFactory,
) {
    private lateinit var stub: UserInfoServiceGrpc.UserInfoServiceFutureStub

    init {
        channelFactory.getChannel(authHost)?.let { channel ->
            stub = UserInfoServiceGrpc.newFutureStub(channel)
        } ?: throw IllegalStateException("Channels must be initialized before use")
    }


    suspend fun getUserInfo(token: String): AuthProto.UserInfoResponse =
        suspendCancellableCoroutine { continuation ->
            runCatching {
                stub.withInterceptors(TokenInitializeInMetadata(token))
                    .getUserInfoByBearer(Empty.newBuilder().build())
            }.onFailure { exception ->
                log().error("Failed to fetch user info: ${exception.message}", exception)
                continuation.resumeWithException(exception)
            }.onSuccess { response ->
                continuation.resume(response.get())
            }
        }

}