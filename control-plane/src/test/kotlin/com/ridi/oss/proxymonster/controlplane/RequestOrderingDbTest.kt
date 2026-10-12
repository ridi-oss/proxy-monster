package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.Timestamp
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The per-scope gate inside [AccessStore.claimExecution], against a migrated PostgreSQL store. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestOrderingDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var ds: Datasource
    private lateinit var role: Role
    private lateinit var appScope: CoroutineScope
    private val seq = AtomicInteger()

    private val requester = "orderer@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_request_ordering"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        ds = core.datasourceStore.create(
            DatasourceInput(name = "ordering-ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        )
        role = core.policyStore.createRole(RoleInput("ordering-role"))
        appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    @AfterAll
    fun close() {
        appScope.cancel()
    }

    private fun scope() = "scope-${seq.incrementAndGet()}"

    private fun request(
        status: String,
        scope: String? = null,
        changeKey: String? = null,
        source: String = "console",
        mergedAt: Instant? = null,
    ): Long {
        val id = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = ds.id, statements = listOf("select 1"), denyReason = null,
            sourceDecisionId = null, reason = "r", title = null, evaluatedDecision = "ALLOW", roleId = role.id,
        ).id
        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE access_request
                   SET status = ?, scope = ?, change_key = ?, source = ?, merged_at = ?
                   WHERE id = ?""",
            ).use { ps ->
                ps.setString(1, status)
                ps.setString(2, scope)
                ps.setString(3, changeKey)
                ps.setString(4, source)
                ps.setTimestamp(5, mergedAt?.let(Timestamp::from))
                ps.setLong(6, id)
                ps.executeUpdate()
            }
        }
        return id
    }

    private fun status(id: Long): String? = core.accessStore.getRequest(id)?.status

    private fun assertRefused(code: String, id: Long) {
        val e = assertFailsWith<TaskServiceException> { core.accessStore.claimExecution(id) }
        assertEquals(409, e.status.value)
        assertEquals(code, e.error.code)
        assertEquals("APPROVED", status(id))
    }

    @Test
    fun `an executing request in the scope makes it busy`() {
        val s = scope()
        request("EXECUTING", s, changeKey = "k0")
        val id = request("APPROVED", s, changeKey = "k1")
        assertRefused("approval.scope_busy", id)
    }

    @Test
    fun `an unmerged github run keeps the scope busy until it merges`() {
        val unmerged = scope()
        request("EXECUTED", unmerged, changeKey = "k0", source = "github")
        assertRefused("approval.scope_busy", request("APPROVED", unmerged, changeKey = "k1"))

        val merged = scope()
        request("EXECUTED", merged, changeKey = "k0", source = "github", mergedAt = Instant.now())
        assertTrue(core.accessStore.claimExecution(request("APPROVED", merged, changeKey = "k1")))

        val console = scope()
        request("EXECUTED", console, changeKey = "k0", source = "console")
        assertTrue(core.accessStore.claimExecution(request("APPROVED", console, changeKey = "k1")))
    }

    @Test
    fun `a forced request claims past an unmerged github run in its scope`() {
        val s = scope()
        request("EXECUTED", s, changeKey = "k0", source = "github")
        val id = request("APPROVED", s, changeKey = "k1", source = "github")
        assertRefused("approval.scope_busy", id)

        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET force_run = TRUE WHERE id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertTrue(core.accessStore.claimExecution(id))
        assertEquals("EXECUTING", status(id))
    }

    private fun onPullRequest(id: Long, repository: String, pr: Int): Long {
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET repository = ?, pr = ? WHERE id = ?").use { ps ->
                ps.setString(1, repository)
                ps.setInt(2, pr)
                ps.setLong(3, id)
                ps.executeUpdate()
            }
        }
        return id
    }

    @Test
    fun `an executed unmerged sibling of the same pull request does not block`() {
        val s = scope()
        onPullRequest(request("EXECUTED", s, changeKey = "k1", source = "github"), "acme/shop", 7)
        val id = onPullRequest(request("APPROVED", s, changeKey = "k2", source = "github"), "acme/shop", 7)
        assertTrue(core.accessStore.claimExecution(id))
    }

    @Test
    fun `an executed unmerged request of another pull request blocks`() {
        val s = scope()
        onPullRequest(request("EXECUTED", s, changeKey = "k1", source = "github"), "acme/shop", 7)
        val id = onPullRequest(request("APPROVED", s, changeKey = "k2", source = "github"), "acme/shop", 8)
        assertRefused("approval.scope_busy", id)
    }

    @Test
    fun `a pull request with a failed file does not hold the scope`() {
        val s = scope()
        onPullRequest(request("EXECUTED", s, changeKey = "k1", source = "github"), "acme/shop", 7)
        onPullRequest(request("FAILED", s, changeKey = "k2", source = "github"), "acme/shop", 7)
        val id = onPullRequest(request("APPROVED", s, changeKey = "k3", source = "github"), "acme/shop", 8)
        assertTrue(core.accessStore.claimExecution(id))
    }

    @Test
    fun `a request without a scope claims as before`() {
        val id = request("APPROVED", scope = null)
        assertTrue(core.accessStore.claimExecution(id))
        assertFalse(core.accessStore.claimExecution(id))
    }

    @Test
    fun `a second claim on a scoped executing request loses without throwing`() {
        val s = scope()
        val id = request("APPROVED", s, changeKey = "k1")
        assertTrue(core.accessStore.claimExecution(id))
        assertFalse(core.accessStore.claimExecution(id))
    }

    @Test
    fun `MCP-created requests carry source mcp and console ones carry console`() {
        val approvals = ApprovalService(
            testConfig(), core.accessStore, core.auditStore, core.datasourceStore, core.policyStore, core.userGroupStore,
            null, core.roleResolver, core.authz, RunExecService(core), appScope,
        )
        val actor = AuditActor(requester, channel = AuditSource.MCP)
        fun create(source: String?): AccessRequest {
            val decisionId = core.auditStore.insert(
                AuditEvent(principal = requester, datasource = ds.name, statement = "select ${seq.incrementAndGet()}", decision = Decision.DENY),
            )
            val input = CreateQueryRequestInput(sourceDecisionId = decisionId, reason = "r", roleId = role.id)
            val created = if (source == null) {
                approvals.create(requester, null, actor, input)
            } else {
                approvals.create(requester, null, actor, input, source = source)
            }
            return created.request
        }
        assertEquals("mcp", core.accessStore.getRequest(create("mcp").id)?.source)
        assertEquals("console", core.accessStore.getRequest(create(null).id)?.source)
    }

    private fun testConfig() = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
        sessionSecret = "request-ordering-test-secret", oidc = null, resultKey = null, scimToken = null,
        sessionWindowSeconds = 3_600, idpRecheckIntervalSeconds = 600, devMarker = false,
    )
}
