package org.woo.gateway.factory

import io.grpc.ManagedChannel
import io.grpc.netty.NettyChannelBuilder
import org.springframework.stereotype.Component

@Component
class NettyChannelFactory(
    val channels: List<ChannelWrapper>,
) {
    fun getChannel(host: String): ManagedChannel? {
        return channels.firstOrNull { it.service == host }?.channel
    }
}