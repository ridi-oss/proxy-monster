package com.ridi.oss.proxymonster.controlplane.grpc

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.Binding
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.TokenKind
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import com.ridi.oss.proxymonster.grpc.closeConnectionRequest
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import com.ridi.oss.proxymonster.grpc.validateTokenRequest
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcPerConnectionCatalogDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var server: GrpcServer
    private lateinit var channel: io.grpc.ManagedChannel
    private lateinit var stub: com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var ds: Datasource
    private lateinit var token: String

    @BeforeAll
    fun setup() {
        requireDocker()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_grpc_pccat"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        ds = core.datasourceStore.create(DatasourceInput("pccat-ds", "postgres", "", 0, "app"))
        token = core.tokenStore.issue(TokenKind.USER,"pccat-user@example.com", emptyList(), null, 3600).token
        startServer()
    }

    @AfterAll
    fun teardown() {
        stopServer()
    }

    private fun startServer() {
        server = GrpcServer(0, ControlPlaneGrpcService(core), null).also { it.start() }
        channel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt.ControlPlaneCoroutineStub(channel)
    }

    private fun stopServer() {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private fun status(block: suspend () -> Unit) =
        assertFailsWith<StatusException> { runBlocking { block() } }.status.code

    private suspend fun push(
        connectionId: ByteString,
        schema: String,
        hash: String,
        datasourceName: String = ds.name,
        backendGeneration: Long = 1,
        unchanged: Boolean = false,
    ) = stub.pushSchemaFragment(schemaFragmentPush {
        this.connectionId = connectionId
        this.datasourceName = datasourceName
        this.schema = schema
        contentHash = ByteString.copyFromUtf8(hash)
        this.backendGeneration = backendGeneration
        this.unchanged = unchanged
    })

    private suspend fun satisfyOnOpen(identity: com.ridi.oss.proxymonster.grpc.WireIdentity) {
        identity.onOpenList.forEachIndexed { index, command ->
            push(identity.connectionId, command.refetch.schema, "open:${command.refetch.schema}", backendGeneration = 1L + index)
        }
    }

    private fun auditCount(): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM audit_event").use { ps ->
            ps.executeQuery().use { rs -> check(rs.next()); rs.getLong(1) }
        }
    }

    @Test
    fun `validate mints connection id and system on-open commands`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        assertEquals(16, identity.connectionId.size())
        assertEquals(setOf("pg_catalog", "information_schema"), identity.onOpenList.map { it.refetch.schema }.toSet())
    }

    @Test
    fun `push accepts observation fields and applies the fragment as before`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        val schema = identity.onOpenList.first().refetch.schema
        val ack = stub.pushSchemaFragment(schemaFragmentPush {
            connectionId = identity.connectionId
            datasourceName = ds.name
            this.schema = schema
            contentHash = ByteString.copyFromUtf8("new-wire-hash")
            backendGeneration = 42
            dbClockMicros = 1_234_567
            measuredInTransaction = true
            backendId = "backend-identity"
            hashTrusted = true
            columns.add(column { this.schema = schema; table = "wire_fields"; this.column = "id"; dataType = "bigint"; ordinal = 1; nullable = false })
        })

        assertTrue(ack.generation > 0)
        val rows = core.connectionCatalog.structuralRows(core.connectionCatalog.find(identity.connectionId)!!)
        val stored = rows.single { it.schema == schema && it.table == "wire_fields" && it.column == "id" }
        assertEquals("bigint", stored.dataType)
        assertEquals(1, stored.ordinal)
        assertFalse(stored.nullable)
    }

    @Test
    fun `forged push and close reject not-found and live datasource mismatch rejects precondition`() = runBlocking {
        val forged = ByteString.copyFrom(ByteArray(16) { 9 })
        assertEquals(Status.Code.NOT_FOUND, status { push(forged, "public", "h") })
        assertEquals(
            Status.Code.NOT_FOUND,
            status { stub.closeConnection(closeConnectionRequest { connectionId = forged; datasourceName = ds.name }) },
        )

        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        val schema = identity.onOpenList.first().refetch.schema
        assertEquals(Status.Code.FAILED_PRECONDITION, status { push(identity.connectionId, schema, "h", datasourceName = "other-datasource") })
    }

    @Test
    fun `push rejects old backend generation and unchanged hash mismatch`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        satisfyOnOpen(identity)
        val schema = identity.onOpenList.first().refetch.schema
        val connection = core.connectionCatalog.find(identity.connectionId)!!
        core.connectionCatalog.markAfterStatement(connection, listOf(schema))
        assertEquals(Status.Code.FAILED_PRECONDITION, status { push(identity.connectionId, schema, "old", backendGeneration = 0) })
        assertEquals(Status.Code.FAILED_PRECONDITION, status { push(identity.connectionId, schema, "wrong", backendGeneration = 10, unchanged = true) })
    }

    @Disabled("a replayed full push can satisfy a newer pending REFETCH because the command has no nonce")
    @Test
    fun `replayed full push cannot satisfy a newer pending refetch`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        satisfyOnOpen(identity)
        val schema = identity.onOpenList.first().refetch.schema
        val connection = core.connectionCatalog.find(identity.connectionId)!!
        core.connectionCatalog.markAfterStatement(connection, listOf(schema))
        assertEquals(Status.Code.FAILED_PRECONDITION, status { push(identity.connectionId, schema, "open:$schema", backendGeneration = 10) })
    }

    @Test
    fun `current replay behavior accepts an old full push for a newer pending command`() = runBlocking {
        // Defect characterization: this is intentionally loud and paired with the disabled expected-reject test.
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        satisfyOnOpen(identity)
        val schema = identity.onOpenList.first().refetch.schema
        val connection = core.connectionCatalog.find(identity.connectionId)!!
        core.connectionCatalog.markAfterStatement(connection, listOf(schema))
        val ack = push(identity.connectionId, schema, "open:$schema", backendGeneration = 10)
        assertTrue(ack.generation > 0)
    }

    @Test
    fun `cross-principal Decide on a live id rejects binding mismatch`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        val otherToken = core.tokenStore.issue(TokenKind.USER,"other@example.com", emptyList(), null, 3600).token
        assertEquals(
            Status.Code.FAILED_PRECONDITION,
            status {
                stub.decide(decisionRequest {
                    token = otherToken
                    datasourceName = ds.name
                    connectionId = identity.connectionId
                    sql = "select 1"
                    searchPath.add("public")
                })
            },
        )
    }

    @Test
    fun `post-close late push rejects not-found`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        val schema = identity.onOpenList.first().refetch.schema
        stub.closeConnection(closeConnectionRequest { connectionId = identity.connectionId; datasourceName = ds.name })
        assertEquals(Status.Code.NOT_FOUND, status { push(identity.connectionId, schema, "late") })
    }

    @Disabled("closed/forged connection_id is recovered by Decide — no tombstone/mint-evidence")
    @Test
    fun `post-close Decide reuse is rejected`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        stub.closeConnection(closeConnectionRequest { connectionId = identity.connectionId; datasourceName = ds.name })
        assertEquals(
            Status.Code.NOT_FOUND,
            status {
                stub.decide(decisionRequest {
                    token = this@GrpcPerConnectionCatalogDbTest.token
                    datasourceName = ds.name
                    connectionId = identity.connectionId
                    sql = "select 1"
                    searchPath.add("public")
                })
            },
        )
    }

    @Test
    fun `current post-close Decide behavior recovers the closed id`() = runBlocking {
        // Defect characterization: restart recovery and a closed/forged id are indistinguishable today.
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        stub.closeConnection(closeConnectionRequest { connectionId = identity.connectionId; datasourceName = ds.name })
        val recovered = stub.decide(decisionRequest {
            token = this@GrpcPerConnectionCatalogDbTest.token
            datasourceName = ds.name
            connectionId = identity.connectionId
            sql = "select 1"
            searchPath.add("public")
        })
        assertTrue(recovered.hasBeforeDecide())
        assertFalse(recovered.hasVerdict())
        assertTrue(recovered.beforeDecide.commandsCount > 0)
    }

    @Test
    fun `real restart recovers original id and token then anchors the principal`() = runBlocking {
        val identity = stub.validateToken(validateTokenRequest { token = this@GrpcPerConnectionCatalogDbTest.token; datasourceName = ds.name })
        satisfyOnOpen(identity)
        stopServer()
        core = ControlPlaneCore(dataSource)
        startServer()

        val beforeAudit = auditCount()
        val recovered = stub.decide(decisionRequest {
            token = this@GrpcPerConnectionCatalogDbTest.token
            datasourceName = ds.name
            connectionId = identity.connectionId
            sql = "select 1"
            searchPath.add("public")
        })
        assertTrue(recovered.hasBeforeDecide())
        assertFalse(recovered.hasVerdict())
        assertTrue(recovered.beforeDecide.commandsCount > 0)
        assertEquals(beforeAudit, auditCount())
        recovered.beforeDecide.commandsList.forEachIndexed { index, command ->
            push(identity.connectionId, command.refetch.schema, "restart:${command.refetch.schema}", backendGeneration = 100L + index)
        }
        val verdict = stub.decide(decisionRequest {
            token = this@GrpcPerConnectionCatalogDbTest.token
            datasourceName = ds.name
            connectionId = identity.connectionId
            sql = "select 1"
            searchPath.add("public")
        })
        assertTrue(verdict.hasVerdict())

        val otherToken = core.tokenStore.issue(TokenKind.USER,"restart-other@example.com", emptyList(), null, 3600).token
        assertEquals(
            Status.Code.FAILED_PRECONDITION,
            status {
                stub.decide(decisionRequest {
                    token = otherToken
                    datasourceName = ds.name
                    connectionId = identity.connectionId
                    sql = "select 1"
                    searchPath.add("public")
                })
            },
        )
    }

    @Test
    fun `unknown connection Decide recovers with before-decide only and no audit`() = runBlocking {
        val unknown = ByteString.copyFrom(ByteArray(16) { 4 })
        val beforeAudit = auditCount()
        val before = stub.decide(decisionRequest {
            token = this@GrpcPerConnectionCatalogDbTest.token
            datasourceName = ds.name
            connectionId = unknown
            sql = "select 1"
            searchPath.add("public")
        })
        assertTrue(before.hasBeforeDecide())
        assertFalse(before.hasVerdict())
        assertTrue(before.beforeDecide.commandsCount > 0)
        assertEquals(beforeAudit, auditCount())
    }
}
