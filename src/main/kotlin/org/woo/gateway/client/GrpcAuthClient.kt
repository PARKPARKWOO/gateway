package org.woo.gateway.client

import com.google.protobuf.Empty
import io.grpc.ManagedChannel
import kotlinx.coroutines.suspendCancellableCoroutine
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.UserInfoServiceGrpc
import org.woo.grpc.TokenInitializeInMetadata
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

@Component
class GrpcAuthClient(
    @Qualifier("authChannel")
    private val channel: ManagedChannel,
) {
    private val stub = UserInfoServiceGrpc.newFutureStub(channel)

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