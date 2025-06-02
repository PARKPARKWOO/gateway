package org.woo.gateway.config

import io.netty.channel.ChannelOption
import io.netty.channel.WriteBufferWaterMark
import io.netty.handler.timeout.ReadTimeoutHandler
import io.netty.handler.timeout.WriteTimeoutHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.ReactorResourceFactory
import org.springframework.http.client.reactive.ClientHttpConnector
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import reactor.netty.http.client.HttpClient
import reactor.netty.resources.ConnectionProvider

@Configuration
class GatewayBackpressureConfig {
    //TODO: Backpressure 설정을 한다.
//    @Bean
//    fun httpClient(resourceFactory: ReactorResourceFactory): HttpClient {
//        val provider = resourceFactory.connectionProvider
//        // ConnectionProvider 설정 예시 (최대 커넥션, 대기 큐 등)
//            ?: ConnectionProvider.builder("limited-provider")
//                .maxConnections(50)
//                .pendingAcquireMaxCount(500)
//                .build()
//        return HttpClient.create(provider)
//            .option(
//                ChannelOption.WRITE_BUFFER_WATER_MARK,
//                WriteBufferWaterMark(
//                    32 * 1024,
//                    64 * 1024
//                )
//            ).doOnConnected{ conn ->
//                conn.addHandlerLast(ReadTimeoutHandler(1))
//                conn.addHandlerLast(WriteTimeoutHandler(1))
//            }.http2Settings { http2Settings ->
//
//            }
//    }
//
//    @Bean
//    fun clientHttpConnector(httpClient: HttpClient): ClientHttpConnector =
//        ReactorClientHttpConnector(httpClient)
}