package org.woo.gateway.config

import io.grpc.Channel
import io.grpc.ManagedChannel
import io.grpc.ManagedChannelBuilder
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import org.apache.hc.client5.http.ssl.TrustAllStrategy
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ssl.SslBundle
import org.springframework.boot.ssl.SslBundles
import org.springframework.cloud.gateway.config.GrpcSslConfigurer
import org.springframework.cloud.gateway.config.HttpClientProperties
import org.springframework.cloud.gateway.config.HttpClientProperties.Ssl
import org.springframework.cloud.gateway.config.HttpClientSslConfigurer
import org.springframework.cloud.gateway.filter.factory.JsonToGrpcGatewayFilterFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ResourceLoader
import org.springframework.scheduling.quartz.ResourceLoaderClassLoadHelper
import javax.net.ssl.TrustManager


@Configuration
class GrpcConfig(
    @Value("\${network.services.auth.host}")
    val authHost: String,
){
    @Bean("authChannel")
    fun grpcChannel(): ManagedChannel = ManagedChannelBuilder
        .forAddress(authHost, 9090)
        .usePlaintext()
        .build()

    @Bean
    fun jsonToGrpc(resourceLoader: ResourceLoader, grpcSslConfigurer: GrpcSslConfigurer): JsonToGrpcGatewayFilterFactory {
        return JsonToGrpcGatewayFilterFactory(grpcSslConfigurer, resourceLoader)
    }

//    @Bean
//    fun configurer(properties: HttpClientProperties, bundles: SslBundles): GrpcSslConfigurer {
//        properties.ssl.isUseInsecureTrustManager = true
//        return GrpcSslConfigurer(properties.ssl, bundles)
//    }
}