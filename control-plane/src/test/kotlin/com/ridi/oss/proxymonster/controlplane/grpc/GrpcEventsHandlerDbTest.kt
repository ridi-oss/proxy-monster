package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.registerRequest
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * DB-backed coverage for the `events` streaming handler (docs/datasource-registration.md):
 * an open stream marks the datasource attached + stamps last_seen_at, relays an admin-pushed RefreshCatalog,
 * deregisters on client cancel, NOT_FOUNDs an unregistered name, and rejects a wire-protocol-version mismatch.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcEventsHandlerDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: io.grpc.ManagedChannel

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_grpc_events"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun teardown() {
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private suspend fun awaitUntil(what: String, predicate: () -> Boolean) =
        withTimeout(5_000) { while (!predicate()) delay(20) } .also { require(predicate()) { "timed out awaiting: $what" } }

    @Test
    fun `an open events stream marks attached, stamps last_seen_at, and relays a RefreshCatalog`() = runBlocking {
        stub.register(registerRequest { protocolVersion = CONTROL_PROTOCOL_VERSION; name = "evt-ds"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" })
        // `.first()` collects exactly one event then cancels the stream (→ server awaitClose → deregister).
        val firstEvent = async { stub.events(eventsRequest { datasourceName = "evt-ds"; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }

        awaitUntil("stream registered") { core.proxyEventsHub.attached().contains("evt-ds") }
        assertTrue(core.datasourceStore.getByName("evt-ds")!!.lastSeenAt != null, "opening the stream stamps last_seen_at")

        assertEquals(1, core.proxyEventsHub.requestRefresh("evt-ds"), "one attached stream is notified")
        val event = withTimeout(5_000) { firstEvent.await() }
        assertTrue(event.hasRefreshCatalog(), "the proxy receives the admin's RefreshCatalog")

        awaitUntil("stream deregistered") { !core.proxyEventsHub.attached().contains("evt-ds") }
        assertEquals(0, core.proxyEventsHub.requestRefresh("evt-ds"), "a detached datasource notifies nobody")
    }

    @Test
    fun `events for an unregistered datasource is NOT_FOUND`() {
        val code = assertFailsWith<StatusException> {
            runBlocking { stub.events(eventsRequest { datasourceName = "never-registered"; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
        }.status.code
        assertEquals(Status.Code.NOT_FOUND, code)
    }

    @Test
    fun `events rejects a proxy on a different wire-protocol version and never attaches it`() = runBlocking {
        // The registered datasource row outlives a rejected Register, so an old proxy (predates the field →
        // sends 0) or a skewed one can open the liveness stream against the persisted row. events() must reject
        // it the same way Register does, so the incompatible proxy never counts as attached — the gap #158 closes.
        stub.register(registerRequest { protocolVersion = CONTROL_PROTOCOL_VERSION; name = "ver-ds"; engine = Engine.POSTGRES; host = "h"; port = 1; dbName = "d" })
        val lastSeenBefore = core.datasourceStore.getByName("ver-ds")!!.lastSeenAt

        val failure = assertFailsWith<StatusException> {
            stub.events(eventsRequest { datasourceName = "ver-ds"; protocolVersion = 0 }).first()
        }
        assertEquals(Status.Code.FAILED_PRECONDITION, failure.status.code)
        val description = failure.status.description ?: ""
        assertTrue(
            description.contains("wire-protocol version") && description.contains("same server-v* release"),
            "the events version rejection carries the same actionable, proxy-recognizable message as Register: $description",
        )

        // A skewed (non-zero) version is rejected too.
        assertFailsWith<StatusException> {
            stub.events(eventsRequest { datasourceName = "ver-ds"; protocolVersion = CONTROL_PROTOCOL_VERSION + 1 }).first()
        }
        assertTrue(!core.proxyEventsHub.attached().contains("ver-ds"), "an incompatible proxy is never attached")
        // The rejection happens before markSeen, so an incompatible proxy never even refreshes liveness:
        // last_seen_at is unchanged. (Moving the check after markSeen would falsely record it as recently live.)
        assertEquals(
            lastSeenBefore, core.datasourceStore.getByName("ver-ds")!!.lastSeenAt,
            "a rejected proxy must not stamp last_seen_at",
        )
    }
}
