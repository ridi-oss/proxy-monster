package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.Binding
import com.ridi.oss.proxymonster.controlplane.CatalogColumn
import com.ridi.oss.proxymonster.controlplane.Channel
import com.ridi.oss.proxymonster.controlplane.EnforcementOutcome
import com.ridi.oss.proxymonster.controlplane.OpenConnection
import com.ridi.oss.proxymonster.controlplane.catalogName
import com.ridi.oss.proxymonster.controlplane.decideConnection
import com.ridi.oss.proxymonster.controlplane.decideQuery
import com.ridi.oss.proxymonster.controlplane.sqlTypeFor
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.WireDecision
import com.ridi.oss.proxymonster.grpc.completionReport
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

abstract class WireTaskDecideDbContract {
    protected lateinit var enforcement: EnforcementFixture
    protected lateinit var fixture: PerConnectionCatalogFixture
    private lateinit var service: ControlPlaneGrpcService

    private val principal = "analyst@example.com"
    private val createdPolicies = ArrayList<Long>()

    protected abstract fun createEnforcement(): EnforcementFixture

    @BeforeAll
    fun setupWireTaskFixture() {
        requireDocker()
        enforcement = createEnforcement()
        fixture = PerConnectionCatalogFixture(enforcement)
        service = ControlPlaneGrpcService(fixture.core)
    }

    @AfterEach
    fun disableTestPolicies() {
        createdPolicies.forEach { fixture.core.cedarPolicyStore.setEnabled(it, false, "test-cleanup") }
        createdPolicies.clear()
    }

    private fun schemas(): List<String> = fixture.datasource.defaultSchemas

    private suspend fun decide(
        opened: OpenConnection,
        sql: String,
        channel: Channel = Channel.WIRE,
    ): EnforcementOutcome = decideConnection(
        core = fixture.core,
        connectionId = opened.connectionId,
        principal = principal,
        ds = fixture.datasource,
        sql = sql,
        searchPath = schemas(),
        clientAddr = "127.0.0.1:54321",
        channel = channel,
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
                classification = classifications[Triple(row.schema, row.table, row.column)],
            )
        }
        val ctx = decideQuery(
            principal = principal,
            ds = fixture.datasource,
            sql = sql,
            channel = Channel.WIRE,
            catalog = catalog,
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

    private lateinit var lastOpened: OpenConnection

    private suspend fun openAndPush(): OpenConnection = fixture.openAndPush(
        principal = principal,
        schemas = schemas(),
    ).also { lastOpened = it }

    // WIRE tasks are internal lifecycle rows, deliberately kept OFF the /api/approvals human feed
    // (listQueryRequests returns WORKFLOW rows only), so list them straight from the table here.
    private fun wireTasks(): List<AccessRequest> = fixture.core.dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT id FROM access_request WHERE kind = 'QUERY' AND creator_kind = 'WIRE' AND principal = ? ORDER BY id",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> val ids = ArrayList<Long>(); while (rs.next()) ids += rs.getLong(1); ids }
        }
    }.map { fixture.core.accessStore.getRequest(it)!! }

    private fun wireTaskForDecision(decisionId: Long) = wireTasks().single { it.sourceDecisionId == decisionId }

    private suspend fun complete(decisionId: Long, status: String) {
        service.reportCompletion(
            completionReport {
                this.decisionId = decisionId
                this.status = status
                rowsReturned = 1
                bytesReturned = 10
                durationMs = 1
            },
        )
    }

    private fun childCount(taskId: Long): Int = fixture.core.dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun assertWireBytesUnchanged(expected: WireDecision, verdict: EnforcementOutcome.Verdict) {
        val actual = verdict.ctx.toWireDecision(0, verdict.generation, verdict.afterStatement)
        assertContentEquals(expected.toByteArray(), actual.toByteArray())
    }

    private fun addForbid(name: String, source: String) {
        val policy = fixture.core.cedarPolicyStore.create(CedarPolicyInput(name, source), "wire-task-test")
        createdPolicies += policy.id
    }

    @Test
    fun `ALLOW stays approved until a clean completion executes it and preserves relay bytes`() = runBlocking {
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
    fun `error and canceled completions fail their wire tasks`() = runBlocking {
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
    fun `only the completed decision executes in a prepare then execute pair`() = runBlocking {
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
    fun `MASK stays approved until completion and preserves mask relay bytes`() = runBlocking {
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
    fun `policy DENY fails its wire task inline and preserves deny relay bytes`() = runBlocking {
        val opened = openAndPush()
        val expected = preChangeWireDecision("select id from orders")

        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from orders"))

        assertEquals(EnfAction.DENY, verdict.ctx.action)
        assertWireBytesUnchanged(expected, verdict)
        val task = wireTaskForDecision(verdict.decisionId)
        assertEquals("FAILED", task.status)
        assertEquals(listOf(enforcement.role), task.executeAs)
        assertEquals(0, childCount(task.id))
        assertEquals("FAILED", fixture.core.accessStore.getRequest(task.id)?.status)
    }

    @Test
    fun `duplicate clean completions leave the wire task executed`() = runBlocking {
        val opened = openAndPush()
        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))
        val task = wireTaskForDecision(verdict.decisionId)

        complete(verdict.decisionId, "ok")
        complete(verdict.decisionId, "ok")

        assertEquals("EXECUTED", fixture.core.accessStore.getRequest(task.id)?.status)
    }

    @Test
    fun `task request forbid overrides enforcement to deny without creating a task`() = runBlocking {
        addForbid(
            "wire-task-request-forbid",
            """forbid(principal, action == Action::"task.request", resource == Datasource::"${fixture.datasource.name}");""",
        )
        val opened = openAndPush()
        val before = wireTasks().size

        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))

        assertEquals(EnfAction.DENY, verdict.ctx.action)
        assertEquals("policy", verdict.ctx.failedStage)
        assertTrue(verdict.afterStatement.isEmpty())
        assertEquals(before, wireTasks().size)
    }

    @Test
    fun `datasource-scoped task approve forbid overrides enforcement to deny without creating a task`() = runBlocking {
        addForbid(
            "wire-task-approve-forbid",
            """forbid(principal, action == Action::"task.approve", resource) when { resource in Datasource::"${fixture.datasource.name}" };""",
        )
        val opened = openAndPush()
        val before = wireTasks().size

        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users"))

        assertEquals(EnfAction.DENY, verdict.ctx.action)
        assertTrue(verdict.afterStatement.isEmpty())
        assertEquals(before, wireTasks().size)
    }

    @Test
    fun `stale catalog before-decide creates no wire task`() = runBlocking {
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, principal, "USER"),
            emptyList(),
        )
        val before = wireTasks().size

        val outcome = decide(opened, "select id from users")

        assertIs<EnforcementOutcome.BeforeDecide>(outcome)
        assertEquals(before, wireTasks().size)
    }

    @Test
    fun `non-wire decide creates no wire task`() = runBlocking {
        val opened = openAndPush()
        val before = wireTasks().size

        val verdict = assertIs<EnforcementOutcome.Verdict>(decide(opened, "select id from users", Channel.EDITOR))

        assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
        assertEquals(before, wireTasks().size)
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WireTaskDecideMysqlDbTest : WireTaskDecideDbContract() {
    override fun createEnforcement() = EnforcementFixture.mysql()
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WireTaskDecidePostgresDbTest : WireTaskDecideDbContract() {
    override fun createEnforcement() = EnforcementFixture.postgres()
}
