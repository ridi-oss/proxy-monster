package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.AuditCanonical
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.completionReport
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * DB-backed coverage for the ReportCompletion gRPC handler: the proxy's post-relay result-volume report
 * lands as a chained `kind="completion"` audit event referencing the decision id, and the handler rejects
 * a report that names no decision. Runs against a real control-plane Postgres + [ControlPlaneCore] + a
 * running gRPC server (gate open — the secret-token interceptor is covered by [GrpcServerTest]).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcReportCompletionHandlerDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: io.grpc.ManagedChannel

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_grpc_completion"))
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

    private fun statusOf(block: suspend () -> Unit): Status.Code =
        assertFailsWith<StatusException> { runBlocking { block() } }.status.code

    @Test
    fun `a completion report inserts a chained completion event referencing the decision`() = runBlocking {
        // The decision the completion measures — inserted first so the completion chains directly onto it.
        val decisionId = core.auditStore.insert(
            AuditEvent(
                principal = "analyst@example.com",
                roles = listOf("analyst"),
                datasource = "sales-mysql",
                statement = "SELECT name FROM users",
                decision = Decision.ALLOW,
                channel = "wire",
            ),
        )
        val decisionRowHash = chainColumns(decisionId).rowHash

        stub.reportCompletion(
            completionReport {
                this.decisionId = decisionId
                rowsReturned = 50_000
                bytesReturned = 262_144
                status = "ok"
                durationMs = 42
            },
        )

        val completionId = completionIdFor(decisionId)
        val completion = core.auditStore.get(completionId)!!
        assertEquals("completion", completion.kind)
        assertEquals(decisionId, completion.decisionId)
        assertEquals(50_000, completion.rowsReturned)
        assertEquals(262_144, completion.bytesReturned)
        assertEquals("ok", completion.outcome)
        assertEquals(42, completion.latencyMs)
        // The completion mirrors the decision's identity fields (so the mass-export rule keys on datasource).
        assertEquals("analyst@example.com", completion.principal)
        assertEquals("sales-mysql", completion.datasource)
        assertEquals("SELECT name FROM users", completion.statement)
        assertEquals(Decision.ALLOW, completion.decision)

        // It chained: prev_hash is the decision's row_hash and the stored row_hash recomputes from the
        // persisted bytes under the canonical format — exactly what an off-box verifier re-walks.
        val chain = chainColumns(completionId)
        assertContentEquals(decisionRowHash, chain.prevHash, "completion must chain onto the decision")
        assertEquals(AuditCanonical.CHAIN_VERSION, chain.chainVersion)
        val micros = AuditCanonical.epochMicros(Instant.parse(completion.ts!!))
        assertContentEquals(
            AuditCanonical.rowHash(completionId, completion, micros, chain.prevHash),
            chain.rowHash,
            "persisted completion must reproduce its stored hash",
        )
        // The chain head advanced to the completion.
        val head = chainHead()
        assertEquals(completionId, head.first)
        assertContentEquals(chain.rowHash, head.second)
    }

    @Test
    fun `a completion for a decision without a wire task stays audit-only`() = runBlocking {
        val decisionId = core.auditStore.insert(
            AuditEvent(
                principal = "editor@example.com",
                datasource = "sales-mysql",
                statement = "SELECT id FROM users",
                decision = Decision.ALLOW,
                channel = "editor",
            ),
        )
        val before = accessRequestCount()

        stub.reportCompletion(
            completionReport {
                this.decisionId = decisionId
                status = "ok"
                rowsReturned = 1
                bytesReturned = 8
                durationMs = 1
            },
        )

        assertEquals(before, accessRequestCount())
        assertEquals("completion", core.auditStore.get(completionIdFor(decisionId))?.kind)
    }

    @Test
    fun `a completion carries the terminal error status and partial counts`() = runBlocking {
        val decisionId = core.auditStore.insert(
            AuditEvent(
                principal = "analyst@example.com",
                datasource = "sales-mysql",
                statement = "SELECT * FROM big",
                decision = Decision.ALLOW,
            ),
        )
        stub.reportCompletion(
            completionReport {
                this.decisionId = decisionId
                rowsReturned = 7
                bytesReturned = 512
                status = "error"
                durationMs = 3
            },
        )
        val completion = core.auditStore.get(completionIdFor(decisionId))!!
        assertEquals("error", completion.outcome)
        assertEquals(7, completion.rowsReturned)
    }

    @Test
    fun `a completion with decision_id 0 is rejected INVALID_ARGUMENT`() {
        assertEquals(
            Status.Code.INVALID_ARGUMENT,
            statusOf { stub.reportCompletion(completionReport { decisionId = 0; status = "ok" }) },
        )
    }

    @Test
    fun `a completion for an unknown decision is rejected NOT_FOUND`() {
        assertEquals(
            Status.Code.NOT_FOUND,
            statusOf { stub.reportCompletion(completionReport { decisionId = Long.MAX_VALUE; status = "ok" }) },
        )
    }

    @Test
    fun `a completion with an unknown status is rejected INVALID_ARGUMENT`() = runBlocking {
        val decisionId = core.auditStore.insert(
            AuditEvent(principal = "p", datasource = "d", statement = "s", decision = Decision.ALLOW),
        )
        assertEquals(
            Status.Code.INVALID_ARGUMENT,
            statusOf { stub.reportCompletion(completionReport { this.decisionId = decisionId; status = "weird" }) },
        )
    }

    private fun accessRequestCount(): Int = dataSource.connection.use { connection ->
        connection.prepareStatement("SELECT count(*) FROM access_request").use { statement ->
            statement.executeQuery().use { result -> result.next(); result.getInt(1) }
        }
    }

    private data class ChainColumns(val chainVersion: Int, val prevHash: ByteArray, val rowHash: ByteArray)

    private fun chainColumns(id: Long): ChainColumns = dataSource.connection.use { connection ->
        connection.prepareStatement(
            "SELECT chain_version, prev_hash, row_hash FROM audit_event WHERE id = ?",
        ).use { statement ->
            statement.setLong(1, id)
            statement.executeQuery().use { result ->
                check(result.next()) { "audit_event $id not found" }
                ChainColumns(result.getInt("chain_version"), result.getBytes("prev_hash"), result.getBytes("row_hash"))
            }
        }
    }

    private fun completionIdFor(decisionId: Long): Long = dataSource.connection.use { connection ->
        connection.prepareStatement(
            "SELECT id FROM audit_event WHERE kind = 'completion' AND decision_id = ? ORDER BY id DESC LIMIT 1",
        ).use { statement ->
            statement.setLong(1, decisionId)
            statement.executeQuery().use { result ->
                check(result.next()) { "no completion row for decision $decisionId" }
                result.getLong(1)
            }
        }
    }

    private fun chainHead(): Pair<Long, ByteArray> = dataSource.connection.use { connection ->
        connection.prepareStatement("SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1").use { statement ->
            statement.executeQuery().use { result -> result.next(); result.getLong(1) to result.getBytes(2) }
        }
    }
}
