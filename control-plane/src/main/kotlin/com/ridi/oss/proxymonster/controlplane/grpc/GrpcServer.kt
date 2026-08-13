package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import io.grpc.Server
import io.grpc.ServerInterceptors
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

/**
 * Boots the control-plane's gRPC surface (docs/datasource-registration.md) alongside the Ktor HTTP
 * server. The proxy talks to this; the web UI keeps talking HTTP/JSON. Netty is the grpc-netty-shaded
 * transport, relocated so it can't clash with Ktor's own Netty on the classpath.
 *
 * Lifecycle (start/shutdown) is owned by the caller — [start] does not register a JVM shutdown hook as
 * a side effect (Main does, matching the proxy's Main; tests drain via their own teardown).
 */
class GrpcServer(
    private val port: Int,
    // Typed against the generated base, not the concrete impl — the server only needs "a ControlPlane
    // service", which lets tests bind a probe handler without opening the production class.
    service: ControlPlaneGrpcKt.ControlPlaneCoroutineImplBase,
    secretToken: String?,
) {
    private val log = LoggerFactory.getLogger(GrpcServer::class.java)
    private val secretTokenConfigured = secretToken != null

    private val server: Server = NettyServerBuilder.forPort(port)
        // A full PushCatalog (every column, system schemas included) can exceed gRPC's 4 MiB default inbound
        // limit on a large database — raise it so a big catalog pushes in one unary call instead of failing
        // and falling into the proxy's empty-catalog fail-closed boot state.
        .maxInboundMessageSize(MAX_INBOUND_MESSAGE_BYTES)
        // HTTP/2 keepalive for the long-lived, mostly-idle Events stream. The server pings idle connections
        // (so a dead proxy's stream closes → awaitClose deregisters it, no ghost in the liveness view) and
        // permits the proxy's own 30s keepalive pings (permit <= client interval, and without-calls, or the
        // server would GOAWAY the idle stream for "too_many_pings").
        .keepAliveTime(KEEPALIVE_SECONDS, TimeUnit.SECONDS)
        .keepAliveTimeout(KEEPALIVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .permitKeepAliveTime(PERMIT_KEEPALIVE_SECONDS, TimeUnit.SECONDS)
        .permitKeepAliveWithoutCalls(true)
        // The secret-token gate wraps the single service so it runs on every RPC.
        .addService(ServerInterceptors.intercept(service, SecretTokenInterceptor(secretToken)))
        .build()

    fun start() {
        server.start()
        log.info(
            "control-plane gRPC listening on :{} (secret-token gate {})",
            port,
            if (secretTokenConfigured) "enabled" else "OPEN — dev only",
        )
    }

    /** Begin graceful shutdown: send HTTP/2 GOAWAY and stop accepting new calls, while existing streams keep
     * running. GOAWAY is what lets a client re-home cleanly — it marks this connection draining, so the
     * client's next RPC opens on a FRESH connection instead of reusing this one (re-homing to a live instance
     * where a load balancer fronts several; otherwise reconnecting once the replacement process is up). Split
     * from [awaitTerminated] so the caller can drain the Events streams IN BETWEEN: the reopen a closed Events
     * stream triggers only dials fresh once GOAWAY is already in flight. */
    fun beginShutdown() {
        server.shutdown()
    }

    /** Wait (bounded) for in-flight RPCs to finish after [beginShutdown], then force-cancel stragglers. A
     * long-lived Events stream never finishes on its own (its handler awaits the client forever), so without
     * the force an orderly shutdown would block indefinitely and the streams would never deregister. */
    fun awaitTerminated() {
        if (!server.awaitTermination(5, TimeUnit.SECONDS)) {
            server.shutdownNow()
            server.awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    /** Begin-and-await in one call — used by tests that do not drain streams in between. */
    fun shutdown() {
        beginShutdown()
        awaitTerminated()
    }

    /** The actually-bound port, valid after [start]. Equals [port] unless [port] was 0 (ephemeral). */
    val boundPort: Int get() = server.port

    private companion object {
        // 64 MiB: generous headroom over the 4 MiB default for a large introspected catalog (PushCatalog).
        const val MAX_INBOUND_MESSAGE_BYTES = 64 * 1024 * 1024
        // Keepalive for the Events stream. permit (15s) must be <= the proxy client's keepAliveTime (30s).
        const val KEEPALIVE_SECONDS = 30L
        const val KEEPALIVE_TIMEOUT_SECONDS = 10L
        const val PERMIT_KEEPALIVE_SECONDS = 15L
    }
}
