package org.woo.gateway.client

import com.google.protobuf.Empty
import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ClientInterceptor
import io.grpc.ForwardingClientCall
import io.grpc.ManagedChannel
import io.grpc.Metadata
import io.grpc.MethodDescriptor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import org.woo.apm.log.log
import org.woo.auth.grpc.AuthProto
import org.woo.auth.grpc.AuthProto.Passport
import org.woo.auth.grpc.AuthProto.UserInfoResponse
import org.woo.auth.grpc.UserInfoServiceGrpc
import org.woo.grpc.AuthMetadata
import org.woo.grpc.TokenInitializeInMetadata
import java.util.concurrent.TimeUnit
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