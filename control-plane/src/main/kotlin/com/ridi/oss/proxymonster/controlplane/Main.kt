package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger("com.ridi.oss.proxymonster.controlplane.Main")

/** How long shutdown waits for signalled proxies to detach after a drain broadcast before it stops the gRPC
 * server anyway. Detach is near-instant (the proxy closes on the event); this only bounds a straggler. */
private const val DRAIN_TIMEOUT_MS = 3_000L

/** How long shutdown waits for the closed console SSE streams to flush their reconnect hint and deregister.
 * The flush is near-instant; the wait keeps this hook (and so the process, and Netty) alive long enough for it
 * to land before the HTTP server stops. A straggler falls through to the browser's default reconnect. */
private const val SSE_DRAIN_TIMEOUT_MS = 2_000L

/**
 * How long one proxy-dialed run stream may live.
 *
 * The stream is opened before the proxy reports ready, so its lifetime has to cover the dial as well as the
 * exchange that follows. Leave the dial out and the cap falls short of the work it wraps once
 * PM_QUERY_TIMEOUT is large: the stream then dies under a statement that is still legitimately running, and
 * the caller sees a stream-closed error rather than the timeout it actually is.
 */
fun runStreamTimeoutMs(queryExchangeTimeoutMs: Long): Long =
    maxOf(15 * 60_000L, DIAL_TIMEOUT_MS + queryExchangeTimeoutMs + 30_000)

/**
 * Control-plane entry point: load config, bring up the Postgres store (with migrations),
 * then serve the HTTP API (DESIGN.md).
 */
fun main() {
    val config = Config.fromEnv()
    if (config.authDebug) {
        // PM_AUTH_DEBUG is a full authentication bypass (/auth/debug + a dev-resolved device flow
        // accept any principal). Config.fromEnv() already refuses to start with it on in a
        // production-looking context (see the guard there); this is the loud reminder for the
        // remaining case — a real dev box where it's legitimately on.
        log.warn(
            "\n" +
                "############################################################\n" +
                "# AUTH DEBUG ENABLED (PM_AUTH_DEBUG=true)                  #\n" +
                "# Anyone reaching this control-plane can debug-login as    #\n" +
                "# ANY principal with ANY roles. NEVER use this in          #\n" +
                "# production or on an untrusted network.                  #\n" +
                "############################################################",
        )
    }
    val db = Db(config)
    db.migrate()

    // The single shared enforcement dependency graph — used by BOTH the gRPC service and the HTTP
    // module below. Sharing is mandatory (see ControlPlaneCore): Cedar's policy-cache invalidation is
    // per-instance in-memory, so a second graph would silently go stale on a policy edit.
    val core = ControlPlaneCore(db.dataSource)
    core.accessStore.reconcileOrphanedExecutions()

    // Bring up the gRPC surface the proxy talks to (docs/datasource-registration.md) before the HTTP
    // server takes over the main thread. `secretToken` (PM_SECRET_TOKEN) is the shared secret gating every
    // proxy↔control-plane RPC. Fail-fast on purpose: a control-plane that can't bind its required
    // gRPC port is misconfigured — like a bad DB or a taken HTTP port — and must not come up serving
    // only HTTP while the data plane is silently dead.
    val runStreamTimeoutMs = runStreamTimeoutMs(config.queryExchangeTimeoutMs)
    val grpcServer = GrpcServer(
        config.grpcPort,
        ControlPlaneGrpcService(core, runStreamTimeoutMs),
        config.secretToken,
    )
    grpcServer.start()
    Runtime.getRuntime().addShutdownHook(
        Thread {
            // Graceful drain on SIGTERM, so a rolling restart re-homes both the proxies (gRPC Events streams)
            // and the console (SSE task-event streams) to the replacement rather than leaving them on the
            // departing instance until an LB timer cuts them. Ktor installs its OWN shutdown hook that stops
            // the HTTP server, and JVM hooks run concurrently in an unspecified order — so the SSE reconnect
            // hint only lands if it flushes before that stop. This hook must therefore not just close the SSE
            // streams but WAIT for their handlers to flush and deregister (step 4): the JVM keeps every hook's
            // thread — and so Netty's I/O threads — alive until all hooks return. Order:
            //   1. close both hubs to new streams/dispatches;
            //   2. begin gRPC shutdown — GOAWAY, so a proxy's reopen dials a fresh connection (re-homing to a
            //      live instance where an LB fronts several) instead of reusing this one;
            //   3. signal + close the open streams so clients reopen now (the SSE close makes each browser's
            //      EventSource reconnect; no GOAWAY equivalent is needed — a reconnect is a fresh request);
            //   4. wait (bounded) for the proxies to detach and the SSE streams to flush their hint + deregister;
            //   5. finish gRPC shutdown (force-cancel any straggler), then exit.
            core.proxyEventsHub.beginDraining()
            core.taskCompletionHub.beginDraining()
            grpcServer.beginShutdown()
            val closed = core.proxyEventsHub.broadcastDraining()
            val sseClosed = core.taskCompletionHub.broadcastDraining()
            if (sseClosed > 0) {
                val flushed = core.taskCompletionHub.awaitDrained(SSE_DRAIN_TIMEOUT_MS)
                log.info("drain: closed {} console SSE stream(s); {}", sseClosed, if (flushed) "hint flushed" else "flush timed out")
            }
            if (closed > 0) {
                val clean = core.proxyEventsHub.awaitDrained(DRAIN_TIMEOUT_MS)
                log.info("drain: closed {} proxy stream(s); {}", closed, if (clean) "all detached" else "timed out waiting")
            }
            grpcServer.awaitTerminated()
        },
    )

    embeddedServer(Netty, port = config.httpPort) {
        module(config, core)
    }.start(wait = true)
}
