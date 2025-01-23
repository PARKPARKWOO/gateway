package org.woo.gateway.factory

import io.grpc.ManagedChannel

data class ChannelWrapper(
    val service: String,
    val channel: ManagedChannel,
)