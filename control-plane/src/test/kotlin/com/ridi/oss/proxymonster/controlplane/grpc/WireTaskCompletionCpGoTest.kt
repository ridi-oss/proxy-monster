package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.EnforcementOutcome
import com.ridi.oss.proxymonster.controlplane.OpenConnection
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.catalogName
import com.ridi.oss.proxymonster.controlplane.columnRef
import com.ridi.oss.proxymonster.controlplane.decideConnection
import com.ridi.oss.proxymonster.controlplane.decideQuery
import com.ridi.oss.proxymonster.controlplane.functionCatalog
import com.ridi.oss.proxymonster.controlplane.sqlTypeFor
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.WireDecision
import com.ridi.oss.proxymonster.grpc.completionReport
import io.grpc.ManagedChannel
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * A wire task opened by Kotlin's Decide and settled by Go's ReportCompletion, reached through cp-go's gRPC
 * port (support/CpGoStack.kt).
 */
abstract class WireTaskCompletionCpGoContract {
    private lateinit var enforcement: EnforcementFixture
    private lateinit var fixture: PerConnectionCatalogFixture
    private lateinit var stack: CpGoStack
    private lateinit var channel: ManagedChannel
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var lastOpened: OpenConnection

    private val principal = "analyst@example.com"

    protected abstract fun createEnforcement(): EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDocker()
        enforcement = createEnforcement()
        fixture = PerConnectionCatalogFixture(enforcement)
        val database = fixture.core.dataSource.connection.use { c ->
            c.createStatement().use { s -> s.executeQuery("SELECT current_database()").use { rs -> rs.next(); rs.getString(1) } }
        }
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "wire-task-completion-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        stack = CpGoStack(config, fixture.core, database, withGrpc = true)
        channel = stack.channel()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(channel)
    }

    @AfterAll
    fun teardown() {
        if (::channel.isInitialized) channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        if (::stack.isInitialized) stack.close()
    }

    private fun schemas(): List<String> = fixture.datasource.defaultSchemas

    private suspend fun openAndPush(): OpenConnection =
        fixture.openAndPush(principal = principal, schemas = schemas()).also { lastOpened = it }

    private suspend fun decide(opened: OpenConnection, sql: String): EnforcementOutcome = decideConnection(
        core = fixture.core,
        connectionId = opened.connectionId,
        principal = principal,
        ds = fixture.datasource,
        sql = sql,
        searchPath = schemas(),
        clientAddr = "127.0.0.1:54321",
        channel = Channel.WIRE,
    ) ?: fail("connection disappeared during decision")

    private fun preChangeWireDecision(sql: String): WireDecision {
        val connection = fixture.core.connectionCatalog.find(lastOpened.connectionId)
            ?: fail("connection disappeared before baseline decision")
        val catalogName = fixture.datasource.engine.catalogName(fixture.datasource.dbName)
        val classifications = fixture.core.datasourceStore.classificationsFor(fixture.datasource.id)
        val catalog = fixture.core.connectionCatalog.structuralRows(connection).map { row ->
            CatalogColumn(
                catalog = catalogName,
                schema = row.schema,
                table = row.table,
                column = row.column,
                dataType = row.dataType,
                sqlType = sqlTypeFor(row.dataType),
                ordinal = row.ordinal,
                nullable = row.nullable,
                classification = classifications[columnRef(row.catalog, row.schema, row.table, row.column)],
            )
        }
        val ctx = decideQuery(
            principal = principal,
            ds = fixture.datasource,
            sql = sql,
            channel = Channel.WIRE,
            catalog = fixture.core.datasourceStore.connectionCatalog(
                fixture.datasource.id,
                catalog,
                fixture.datasource.engine.functionCatalog(fixture.core.connectionCatalog.heldRoutines(connection), fixture.datasource.engineVersion),
            ),
            policyStore = fixture.core.policyStore,
            accessStore = fixture.core.accessStore,
            userGroupStore = fixture.core.userGroupStore,
            roleResolver = fixture.core.roleResolver,
            authz = fixture.core.authz,
            context = AuthzContext(requesterIp = "127.0.0.1"),
            liveSearchPath = schemas(),
            systemClassification = fixture.core.systemClassification,
        )
        return ctx.toWireDecision(0, connection.generation, emptyList())
    }

    private fun assertWireBytesUnchanged(expected: WireDecision, verdict: EnforcementOutcome.Verdict) {
        val actual = verdict.ctx.toWireDecision(0, verdict.generation, verdict.afterStatement)
        assertContentEquals(expected.toByteArray(), actual.toByteArray())
    }

    private fun wireTasks(): List<AccessRequest> = fixture.core.dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT id FROM access_request WHERE kind = 'QUERY' AND creator_kind = 'WIRE' AND principal = ? ORDER BY id",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> val ids = ArrayList<Long>(); while (rs.next()) ids += rs.getLong(1); ids }
        }
    }.map { fixture.core.accessStore.getRequest(it)!! }

    private fun wireTaskForDecision(decisionId: Long) = wireTasks().single { it.sourceDecisionId == decisionId }

    private fun childCount(taskId: Long): Int = fixture.core.dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private suspend fun complete(decisionId: Long, status: String) {
        stub.reportCompletion(
            completionReport {
                this.decisionId = decisionId
                this.status = status
                rowsReturned = 1
                bytesReturned = 10
                durationMs = 1
            },
        )
    }

    @Test
    fun `ALLOW stays approved until a clean completion executes it and preserves relay bytes`() = runBlocking<Unit> {
        val opened = openAndPush()
        val expected = preChangeWireDecision("select id from users")

        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))

        assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
        assertWireBytesUnchanged(expected, verdict)
        val task = wireTaskForDecision(verdict.decisionId)
        assertEquals("APPROVED", task.status)
        assertEquals(verdict.decisionId, task.sourceDecisionId)
        assertEquals(listOf(enforcement.role), task.executeAs)
        assertEquals(0, childCount(task.id))

        complete(verdict.decisionId, "ok")

        val executed = fixture.core.accessStore.getRequest(task.id)!!
        assertEquals("EXECUTED", executed.status)
        assertTrue(executed.executingAt != null)
        assertTrue(executed.executedAt != null)
    }

    @Test
    fun `error and canceled completions fail their wire tasks`() = runBlocking<Unit> {
        val opened = openAndPush()
        for (status in listOf("error", "canceled")) {
            val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))
            val task = wireTaskForDecision(verdict.decisionId)
            assertEquals("APPROVED", task.status)

            complete(verdict.decisionId, status)

            val failed = fixture.core.accessStore.getRequest(task.id)!!
            assertEquals("FAILED", failed.status)
            assertTrue(failed.executingAt != null)
            assertEquals(null, failed.executedAt)
        }
    }

    @Test
    fun `only the completed decision executes in a prepare then execute pair`() = runBlocking<Unit> {
        val opened = openAndPush()
        val before = wireTasks().map { it.id }.toSet()
        val prepared = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))
        val executed = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))

        complete(executed.decisionId, "ok")

        assertEquals("APPROVED", wireTaskForDecision(prepared.decisionId).status)
        assertEquals("EXECUTED", wireTaskForDecision(executed.decisionId).status)
        assertEquals(1, wireTasks().count { it.id !in before && it.status == "EXECUTED" })
    }

    @Test
    fun `MASK stays approved until completion and preserves mask relay bytes`() = runBlocking<Unit> {
        val opened = openAndPush()
        val expected = preChangeWireDecision("select ssn from users")

        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select ssn from users"))

        assertEquals(EnfAction.MASK, verdict.ctx.action, verdict.ctx.denyReason)
        assertWireBytesUnchanged(expected, verdict)
        assertEquals(expected.verdict.masksList, verdict.ctx.masks)
        assertEquals(expected.verdict.rewrittenSql, verdict.ctx.rewrittenSql.orEmpty())
        val task = wireTaskForDecision(verdict.decisionId)
        assertEquals("APPROVED", task.status)
        assertEquals(listOf(enforcement.role), task.executeAs)
        assertEquals(0, childCount(task.id))

        complete(verdict.decisionId, "ok")

        assertEquals("EXECUTED", fixture.core.accessStore.getRequest(task.id)?.status)
    }

    @Test
    fun `duplicate clean completions leave the wire task executed`() = runBlocking<Unit> {
        val opened = openAndPush()
        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))
        val task = wireTaskForDecision(verdict.decisionId)

        complete(verdict.decisionId, "ok")
        complete(verdict.decisionId, "ok")

        assertEquals("EXECUTED", fixture.core.accessStore.getRequest(task.id)?.status)
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WireTaskCompletionMysqlCpGoTest : WireTaskCompletionCpGoContract() {
    override fun createEnforcement() = EnforcementFixture.mysql()
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WireTaskCompletionPostgresCpGoTest : WireTaskCompletionCpGoContract() {
    override fun createEnforcement() = EnforcementFixture.postgres()
}
