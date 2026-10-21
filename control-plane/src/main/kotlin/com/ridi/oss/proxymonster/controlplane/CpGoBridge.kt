package com.ridi.oss.proxymonster.controlplane

import io.grpc.ClientInterceptors
import io.grpc.ManagedChannel
import io.grpc.Metadata
import io.grpc.Channel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.grpc.stub.MetadataUtils
import java.util.concurrent.TimeUnit

/**
 * The channel to cp-go's Go services (cpgo/gobridge), for a Kotlin caller whose slice is half-moved: build
 * a service's coroutine stub on [channel]. Each call carries the per-boot internal token cp-go checks.
 */
class CpGoBridge(config: CpGoBridgeConfig) : AutoCloseable {
    private val managed: ManagedChannel = NettyChannelBuilder.forTarget(config.address).usePlaintext().build()

    val channel: Channel = ClientInterceptors.intercept(
        managed,
        MetadataUtils.newAttachHeadersInterceptor(Metadata().apply { put(TOKEN_KEY, config.token) }),
    )

    override fun close() {
        managed.shutdown().awaitTermination(5, TimeUnit.SECONDS)
    }

    private companion object {
        val TOKEN_KEY: Metadata.Key<String> = Metadata.Key.of("x-pm-internal-token", Metadata.ASCII_STRING_MARSHALLER)
    }
}
