package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.DecisionRequest
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.WireDecision
import com.ridi.oss.proxymonster.grpc.WireMetadata
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.verdict
import com.ridi.oss.proxymonster.grpc.wireDecision
import io.grpc.Metadata
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.runBlocking
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The gRPC transport + `x-pm-secret-token` gate, tested in isolation from the real handlers' DB work
 * via a probe service that only reaches the gRPC [io.grpc.Context] and echoes what it observed. This
 * keeps the interceptor test fast + DB-free; the real Decide/OpenConnection handler behavior is covered
 * by the DB-backed [GrpcDecideHandlerDbTest]. Two properties are asserted: the gate is fail-closed
 * (wrong/missing secret → UNAUTHENTICATED before the handler), and it propagates exactly the presented
 * token into the handler Context (a null on the open-gate path — never a stale or wrong value).
 */
class GrpcServerTest {
    private val servers = mutableListOf<GrpcServer>()

    private fun startServer(secret: String?): GrpcServer =
        GrpcServer(0, CtxProbeService(), secret).also {
            it.start()
            servers += it
        }

    /** Fire one Decide with the given call secret against [port]; returns the handler's response. */
    private fun callDecide(port: Int, callSecret: String?): WireDecision {
        val channel = NettyChannelBuilder.forAddress("localhost", port).usePlaintext().build()
        return try {
            val stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(channel)
            val md = Metadata().apply { if (callSecret != null) put(WireMetadata.SECRET_TOKEN_KEY, callSecret) }
            runBlocking {
                stub.decide(decisionRequest { token = "t"; datasourceName = "ds"; sql = "select 1" }, md)
            }
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    /** Same call, expecting the gate to reject before the handler — returns the resulting status code. */
    private fun decideStatus(port: Int, callSecret: String?): Status.Code =
        try {
            callDecide(port, callSecret)
            error("expected a StatusException, got a normal return")
        } catch (e: StatusException) {
            e.status.code
        }

    /** A handler that reaches the Context and echoes the propagated secret, so propagation is testable. */
    private class CtxProbeService : ControlPlaneGrpcKt.ControlPlaneCoroutineImplBase() {
        override suspend fun decide(request: DecisionRequest): WireDecision = wireDecision {
            verdict = verdict {
                decision = EnfAction.DENY
                denyReason = "ctx:" + (WireMetadata.SECRET_TOKEN_CTX.get() ?: "<null>")
            }
        }
    }

    @AfterTest
    fun tearDown() = servers.forEach { it.shutdown() }

    @Test
    fun `correct secret passes the gate and reaches the handler with the token propagated`() {
        val server = startServer(secret = "s3cret")
        assertEquals("ctx:s3cret", callDecide(server.boundPort, callSecret = "s3cret").verdict.denyReason)
    }

    @Test
    fun `wrong secret is rejected UNAUTHENTICATED before the handler`() {
        val server = startServer(secret = "s3cret")
        assertEquals(Status.Code.UNAUTHENTICATED, decideStatus(server.boundPort, callSecret = "wrong"))
    }

    @Test
    fun `missing secret is rejected UNAUTHENTICATED when a secret is configured`() {
        val server = startServer(secret = "s3cret")
        assertEquals(Status.Code.UNAUTHENTICATED, decideStatus(server.boundPort, callSecret = null))
    }

    @Test
    fun `open gate (no secret configured) reaches the handler with a null token context`() {
        val server = startServer(secret = null)
        assertEquals("ctx:<null>", callDecide(server.boundPort, callSecret = null).verdict.denyReason)
    }
}
