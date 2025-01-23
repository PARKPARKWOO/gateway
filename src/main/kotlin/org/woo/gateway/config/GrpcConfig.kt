package org.woo.gateway.config

import io.grpc.ManagedChannel
import io.grpc.netty.NettyChannelBuilder
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.config.GrpcSslConfigurer
import org.springframework.cloud.gateway.filter.factory.JsonToGrpcGatewayFilterFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ResourceLoader
import org.woo.gateway.factory.ChannelWrapper

@Configuration
class GrpcConfig(
    @Value("\${network.services.auth.host}")
    val authHost: String,
) {
    @Bean("authChannel")
    fun grpcChannel(): ManagedChannel = NettyChannelBuilder
        .forAddress(authHost, 9090)
        .usePlaintext()
        .build()

    @Bean("auth")
    fun authWrapper(
        @Qualifier("authChannel")
        channel: ManagedChannel,
    ): ChannelWrapper = ChannelWrapper(authHost, channel)


    @Bean
    fun jsonToGrpc(
        resourceLoader: ResourceLoader,
        grpcSslConfigurer: GrpcSslConfigurer,
    ): JsonToGrpcGatewayFilterFactory {
        return JsonToGrpcGatewayFilterFactory(grpcSslConfigurer, resourceLoader)
    }
}