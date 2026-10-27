package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Approve, unapprove, reject after approval, close, and expiry, under the seeded policies only. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalLifecycleDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var approvals: ApprovalService
    private lateinit var datasource: Datasource

    private val requester = "req@example.com"
    private val adminA = "admin-a@example.com"
    private val adminB = "admin-b@example.com"
    private val outsider = "out@example.com"

    private fun actor(p: String) = AuditActor(p, channel = "console")

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_approval_lifecycle"))
        core = ControlPlaneCore(dataSource)
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "lifecycle-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        val admin = core.policyStore.getRoleByName("system:admin")!!.id
        for (p in listOf(adminA, adminB)) core.policyStore.createAssignment(RoleAssignmentInput(p, admin))
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "lifecycle-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3_600, idpRecheckIntervalSeconds = 600, devMarker = false,
        )
        approvals = ApprovalService(
            config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore, core.userGroupStore,
            QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() })), core.roleResolver,
            core.authz, EditorExecService(core), CoroutineScope(Dispatchers.Unconfined),
        )
    }

    private fun approved(): Long {
        val roleId = core.policyStore.createRole(RoleInput("lifecycle-${System.nanoTime()}")).id
        val id = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = datasource.id, statements = listOf("select 1"),
            denyReason = null, sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "DENY",
            roleId = roleId,
        ).id
        approvals.approve(adminA, null, actor(adminA), id, 1)
        return id
    }

    private fun status(id: Long) = core.accessStore.getRequest(id)!!.status

    @Test
    fun `the requester and any approver may run an approved request, an outsider may not`() {
        val id = approved()
        assertTrue(approvals.detail(requester, null, id).canExecute)
        assertTrue(approvals.detail(adminB, null, id).canExecute, "an approver who did not approve may run it")
        assertFalse(approvals.mayDecide(outsider, null, com.ridi.oss.proxymonster.controlplane.authz.AuthzAction.TASK_RUN, core.accessStore.getRequest(id)!!))
        val e = assertFailsWith<TaskServiceException> { approvals.execute(outsider, null, id) }
        assertEquals("approval.not_runner", e.error.code)
    }

    @Test
    fun `approve and run is offered only to an approver who may also run`() {
        val roleId = core.policyStore.createRole(RoleInput("lifecycle-approve-only-${System.nanoTime()}")).id
        val id = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = datasource.id, statements = listOf("select 1"),
            denyReason = null, sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "DENY", roleId = roleId,
        ).id
        val reviewer = "reviewer-${System.nanoTime()}@example.com"
        core.cedarPolicyStore.create(
            com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput(
                name = "lifecycle-reviewer-${System.nanoTime()}",
                cedarSrc = """permit(principal == User::"$reviewer", action in [Action::"task.approve", Action::"task.read"], resource);""",
            ),
            updatedBy = null,
        )
        val asReviewer = approvals.detail(reviewer, null, id)
        assertTrue(asReviewer.canDecide)
        assertFalse(asReviewer.canApproveAndRun)
        assertTrue(approvals.detail(adminA, null, id).canApproveAndRun)
    }

    @Test
    fun `any approver can unapprove, which returns the request to pending`() {
        val id = approved()
        assertTrue(approvals.detail(adminB, null, id).canUnapprove)
        assertFalse(approvals.detail(requester, null, id).canUnapprove)
        assertFailsWith<TaskServiceException> { approvals.unapprove(requester, null, actor(requester), id) }

        val reopened = approvals.unapprove(adminB, null, actor(adminB), id)
        assertEquals("PENDING", reopened.status)
        assertNull(reopened.decidedBy)
        assertEquals("APPROVED", approvals.approve(adminB, null, actor(adminB), id, reopened.revision).status)
    }

    @Test
    fun `an approved request can still be rejected`() {
        val id = approved()
        assertEquals("REJECTED", approvals.reject(adminB, null, actor(adminB), id, "changed my mind").status)
    }

    @Test
    fun `the requester can close a pending or approved request`() = runBlocking {
        val id = approved()
        assertTrue(approvals.detail(requester, null, id).canClose)
        assertFailsWith<TaskServiceException> { approvals.cancel(outsider, null, actor(outsider), id) }
        assertEquals("CANCELLED", approvals.cancel(requester, null, actor(requester), id).status)
    }

    @Test
    fun `a CC can read, comment and LGTM, and any participant manages the CCs`() {
        val id = approved()
        val cc = "cc@example.com"
        core.userGroupStore.createUser(AppUserInput(principal = cc), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null))
        assertFailsWith<TaskServiceException> { approvals.detail(cc, null, id) }
        assertFailsWith<TaskServiceException> { approvals.threads.setCc(outsider, null, actor(outsider), id, cc, add = true) }

        approvals.threads.setCc(requester, null, actor(requester), id, cc, add = true)
        val asCc = approvals.detail(cc, null, id)
        assertTrue(asCc.canComment && asCc.canCc)
        assertFalse(asCc.canExecute, "a CC cannot run it")
        approvals.threads.comment(cc, null, actor(cc), id, "looks fine to me")
        approvals.threads.comment(cc, null, actor(cc), id, null, lgtm = true)
        assertEquals("APPROVED", status(id), "an LGTM never changes the status")
        assertFailsWith<TaskServiceException> { approvals.threads.comment(outsider, null, actor(outsider), id, "hi") }

        approvals.threads.setCc(adminB, null, actor(adminB), id, cc, add = false)
        assertFailsWith<TaskServiceException> { approvals.detail(cc, null, id) }

        val kinds = approvals.detail(requester, null, id).timeline.map { it.kind }
        assertEquals(listOf("requested", "approved", "cc_added", "comment", "lgtm", "cc_removed"), kinds)
    }

    @Test
    fun `an approval older than a day returns to pending and is no longer runnable`() {
        val id = approved()
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET approved_at = now() - interval '25 hours' WHERE id = ?").use { ps ->
                ps.setLong(1, id); ps.executeUpdate()
            }
        }
        assertFalse(approvals.detail(requester, null, id).canExecute)
        val e = assertFailsWith<TaskServiceException> { approvals.execute(requester, null, id) }
        assertEquals("approval.expired", e.error.code)

        approvals.expireApprovals()
        assertEquals("PENDING", status(id))
        assertEquals("expired", approvals.detail(requester, null, id).timeline.last().kind)
        val audit = dataSource.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM audit_event WHERE statement LIKE ?").use { ps ->
                ps.setString(1, "%withdraw the approval of query request #$id (approval expired)%")
                ps.executeQuery().use { it.next(); it.getInt(1) }
            }
        }
        assertEquals(1, audit, "the expiry is audited")
    }
}
