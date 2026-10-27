package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ApprovalService
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.EditorExecService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import com.ridi.oss.proxymonster.controlplane.ParticipantKind
import com.ridi.oss.proxymonster.controlplane.RequestEdit
import com.ridi.oss.proxymonster.controlplane.RequestParticipants
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.FakeTransport
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Collections
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A Slack button click turned into a task decision, on real PostgreSQL + real Cedar. The handler is an
 * ADAPTER over the same `task.approve` Cedar decision and the same CAS the console uses — so the interesting
 * cases are the security ones: an unauthorized clicker is refused, and the requester cannot self-approve
 * from Slack because the click decides on the `slack` channel, which the no-self-approval forbid does NOT
 * exempt (only the server-attested editor/wire channels are).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SlackDecisionHandlerDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var handler: SlackDecisionHandler
    private lateinit var threads: SlackThreadHandler
    private lateinit var approvalService: ApprovalService
    private lateinit var access: com.ridi.oss.proxymonster.controlplane.AccessService

    private val requester = "requester@example.com"
    private val approver = "admin@example.com"
    private val outsider = "outsider@example.com"
    private var roleId: Long = 0

    private val approvedRuns = Collections.synchronizedList(mutableListOf<AccessRequest>())
    @Volatile private var onApprovedThrows = false

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        val roles = fx.policyStore.listRoles().associateBy { it.name }
        fx.policyStore.createAssignment(RoleAssignmentInput(approver, roles.getValue("system:admin").id))
        roleId = roles.getValue(fx.role).id

        val notifications = NotificationService(
            store = NotificationStore(fx.dataSource),
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { emptyList() },
            transports = listOf(FakeTransport()),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.FULL,
            defaultLocale = "en",
        )
        val approvals = ApprovalService(
            Config(
                httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
                sessionSecret = "slack-decision-test-secret", oidc = null, resultKey = null, scimToken = null,
                sessionWindowSeconds = 3_600, idpRecheckIntervalSeconds = 600, devMarker = false,
            ),
            fx.accessStore, fx.auditStore, fx.datasourceStore, fx.policyStore, fx.userGroupStore,
            null, fx.roleResolver, fx.authz, EditorExecService(ControlPlaneCore(fx.dataSource)),
            CoroutineScope(Dispatchers.Unconfined), notifications = notifications,
        )
        approvalService = approvals
        threads = SlackThreadHandler(NotificationStore(fx.dataSource), fx.accessStore, { approvals }, notifications)
        access = com.ridi.oss.proxymonster.controlplane.AccessService(
            fx.accessStore, fx.datasourceStore, fx.auditStore, fx.roleResolver, fx.authz, ManagementAuditRecorder(fx.auditStore), notifications,
        )
        handler = SlackDecisionHandler(fx.accessStore, { approvals }, { access }, notifications, "en") { _, taskId ->
            if (onApprovedThrows) throw RuntimeException("run failed")
            approvedRuns += fx.accessStore.getRequest(taskId)!!
        }
    }

    private fun pendingRequest(): Long = fx.accessStore.createQueryRequest(
        principal = requester, datasourceId = fx.datasource.id, statements = listOf("SELECT id FROM users"),
        denyReason = null, sourceDecisionId = null, reason = "need it", title = "read users",
        evaluatedDecision = "ALLOW", roleId = roleId,
    ).id

    private fun click(taskId: Long, principal: String, actionId: String, revision: Int = 1) = SlackInteraction(
        principal = principal, actionId = actionId, taskId = taskId, revision = revision,
        responseUrl = null, triggerChannel = "C_MOCK", triggerTs = "1.1",
    )

    private fun statusOf(id: Long) = fx.accessStore.getRequest(id)!!.status

    @Test
    fun `an authorized approve transitions the request and runs it`() = runBlocking {
        val id = pendingRequest()
        val reply = handler.handle(click(id, approver, SlackTransport.ACTION_APPROVE))

        assertEquals("", reply, "success says nothing back to the clicker")
        assertEquals("APPROVED", statusOf(id))
        assertTrue(approvedRuns.any { it.id == id }, "approving from Slack also runs it")
    }

    @Test
    fun `an approve from a message older than the request's last edit is refused`() = runBlocking {
        val id = pendingRequest()
        fx.accessStore.editQueryRequest(
            id, listOf("SELECT id FROM users WHERE id = 1"), RequestEdit("h", null, "ALLOW", false),
            AuditActor(requester, clientAddr = null, channel = "console"), ManagementAuditRecorder(fx.auditStore),
        )
        val reply = handler.handle(click(id, approver, SlackTransport.ACTION_APPROVE, revision = 1))

        assertTrue(reply.contains("changed"), "got: $reply")
        assertEquals("PENDING", statusOf(id))
        assertTrue(handler.handle(click(id, approver, SlackTransport.ACTION_DENY, revision = 1)).contains("changed"))
        assertEquals("PENDING", statusOf(id), "a deny from before the edit rejects nothing")
        assertEquals("", handler.handle(click(id, approver, SlackTransport.ACTION_APPROVE, revision = 2)))
        assertEquals("APPROVED", statusOf(id))
    }

    @Test
    fun `a deny transitions to rejected with the Slack reason`() = runBlocking {
        val id = pendingRequest()
        val reply = handler.handle(click(id, approver, SlackTransport.ACTION_DENY))

        assertEquals("", reply)
        assertEquals("REJECTED", statusOf(id))
        assertEquals(SlackDecisionHandler.SLACK_REJECT_REASON, fx.accessStore.getRequest(id)!!.rejectionReason)
        assertTrue(approvedRuns.none { it.id == id }, "a denial never runs the query")
    }

    @Test
    fun `an unauthorized clicker is refused and nothing transitions`() = runBlocking {
        val id = pendingRequest()
        val reply = handler.handle(click(id, outsider, SlackTransport.ACTION_APPROVE))

        assertTrue(reply.contains("not authorized"), "got: $reply")
        assertEquals("PENDING", statusOf(id), "an unauthorized click must not decide")
    }

    /** The security case the `slack` channel exists for: no-self-approval exempts only editor/wire. */
    @Test
    fun `the requester cannot self-approve from Slack`() = runBlocking {
        val id = pendingRequest()
        val reply = handler.handle(click(id, requester, SlackTransport.ACTION_APPROVE))

        assertTrue(reply.contains("not authorized"), "self-approval on the slack channel is forbidden; got: $reply")
        assertEquals("PENDING", statusOf(id))
    }

    @Test
    fun `an already-decided request reports what happened instead of deciding again`() = runBlocking {
        val id = pendingRequest()
        handler.handle(click(id, approver, SlackTransport.ACTION_DENY)) // now REJECTED
        val reply = handler.handle(click(id, approver, SlackTransport.ACTION_APPROVE))

        assertTrue(reply.contains("Already rejected"), "got: $reply")
        assertEquals("REJECTED", statusOf(id), "the second click changed nothing")
    }

    @Test
    fun `Review opens a modal with only the buttons the clicker may use`() = runBlocking {
        val id = pendingRequest()
        fun actionIds(principal: String): Set<String> {
            val reply = runBlocking { handler.respond(click(id, principal, SlackTransport.ACTION_REVIEW).copy(triggerId = "T1")) }
            val view = (reply as SlackReply.OpenView).view.toString()
            return SlackTransport.ACTION_IDS.values.filter { "\"$it\"" in view }.toSet()
        }
        // The seeded system:admin policy also grants task.cancel and task.comment. With no result storage there is
        // nothing to run, so Approve and run is not offered.
        assertEquals(
            setOf(
                SlackTransport.ACTION_APPROVE_ONLY, SlackTransport.ACTION_DENY, SlackTransport.ACTION_CLOSE,
                SlackTransport.ACTION_LGTM,
            ),
            actionIds(approver),
        )
        assertEquals(setOf(SlackTransport.ACTION_CLOSE), actionIds(requester))
        assertEquals(emptySet(), actionIds(outsider), "someone without task.read gets no buttons")
    }

    @Test
    fun `a click inside the modal redraws it with the outcome`() = runBlocking {
        val id = pendingRequest()
        val reply = handler.respond(click(id, approver, SlackTransport.ACTION_APPROVE_ONLY).copy(viewId = "V1"))
        assertTrue(reply is SlackReply.UpdateView && "approved" in reply.view.toString(), "got: $reply")
        assertEquals("APPROVED", statusOf(id))
    }

    @Test
    fun `a channel reply is a comment under its Slack author, a DM reply needs task comment`() = runBlocking {
        val id = pendingRequest()
        val store = NotificationStore(fx.dataSource)
        store.rememberMessage(id, SlackTransport.TRANSPORT_CHANNEL, "C1", NotificationKind.APPROVER, "C1:1.0")
        store.rememberMessage(id, SlackTransport.TRANSPORT, outsider, NotificationKind.APPROVER, "D1:1.0")
        store.rememberMessage(id, SlackTransport.TRANSPORT, approver, NotificationKind.APPROVER, "D2:1.0")
        val msg = SlackThreadMessage(SlackThreadMessage.Kind.NEW, "C1", "2.0", "1.0", null, "Pat", "who is this for?")

        threads.onMessage(msg)
        threads.onMessage(msg.copy(ts = "3.0", threadTs = "9.9"))
        threads.onMessage(SlackThreadMessage(SlackThreadMessage.Kind.NEW, "D1", "2.0", "1.0", outsider, "o", "let me see"))
        threads.onMessage(SlackThreadMessage(SlackThreadMessage.Kind.NEW, "D2", "2.0", "1.0", approver, "a", "looks fine"))

        val comments = approvalService.detail(approver, null, id).timeline.filter { it.kind == "comment" }
        assertEquals(listOf("slack:Pat" to "who is this for?", approver to "looks fine"), comments.map { it.actor to it.body })
    }

    @Test
    fun `a role request is approved, denied and reviewed from Slack like a query request`() = runBlocking {
        val role = fx.policyStore.createRole(com.ridi.oss.proxymonster.controlplane.RoleInput("slack-role-${System.nanoTime()}"))
        val mk = {
            fx.accessStore.createRequest(
                requester, com.ridi.oss.proxymonster.controlplane.AccessRequestInput(roleId = role.id, reason = "on call"),
                AuditActor(requester, channel = "console"), ManagementAuditRecorder(fx.auditStore),
            ).id
        }
        val approved = mk()
        val review = handler.respond(click(approved, approver, SlackTransport.ACTION_REVIEW).copy(triggerId = "T1"))
        val view = (review as SlackReply.OpenView).view.toString()
        assertTrue(SlackTransport.ACTION_APPROVE_ONLY in view && SlackTransport.ACTION_DENY in view, view)
        assertTrue(SlackTransport.ACTION_APPROVE !in view.replace(SlackTransport.ACTION_APPROVE_ONLY, ""), "a role request has nothing to run")
        assertEquals("", handler.handle(click(approved, approver, SlackTransport.ACTION_APPROVE_ONLY)))
        assertEquals("APPROVED", statusOf(approved))
        assertTrue(fx.accessStore.listGrants(requester, true).any { it.roleName == role.name }, "approving from Slack grants the role")
        assertTrue(handler.handle(click(approved, approver, SlackTransport.ACTION_DENY)).contains("Already approved"))

        val denied = mk()
        assertEquals("", handler.handle(click(denied, approver, SlackTransport.ACTION_DENY)))
        assertEquals("REJECTED", statusOf(denied))

        val closed = mk()
        assertTrue(handler.handle(click(closed, requester, SlackTransport.ACTION_APPROVE_ONLY)).contains("not authorized"))
        assertEquals("", handler.handle(click(closed, requester, SlackTransport.ACTION_CLOSE)))
        assertEquals("CANCELLED", statusOf(closed))
    }

    @Test
    fun `a role click is decided on the slack channel, so a slack-only forbid refuses it`() = runBlocking {
        val role = fx.policyStore.createRole(com.ridi.oss.proxymonster.controlplane.RoleInput("slack-forbidden-${System.nanoTime()}"))
        fx.cedarPolicyStore.create(
            com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput(
                name = "no-slack-approvals-${role.id}",
                cedarSrc = """forbid(principal, action == Action::"task.approve", resource)
                    when { resource in Role::"${role.name}" && context has channel && context.channel == "slack" };""",
            ),
            updatedBy = null,
        )
        val id = fx.accessStore.createRequest(
            requester, com.ridi.oss.proxymonster.controlplane.AccessRequestInput(roleId = role.id, reason = "x"),
            AuditActor(requester, channel = "console"), ManagementAuditRecorder(fx.auditStore),
        ).id
        assertTrue(handler.handle(click(id, approver, SlackTransport.ACTION_APPROVE_ONLY)).contains("not authorized"))
        assertEquals("PENDING", statusOf(id))
        access.approve(approver, null, AuditActor(approver, channel = "console"), id, null)
        assertEquals("APPROVED", statusOf(id), "the console channel is not forbidden")
    }

    @Test
    fun `a participant who mentions someone in a thread adds them as a CC, a bystander does not`() = runBlocking {
        val id = pendingRequest()
        val store = NotificationStore(fx.dataSource)
        store.rememberMessage(id, SlackTransport.TRANSPORT_CHANNEL, "C9", NotificationKind.APPROVER, "C9:1.0")
        val reply = SlackThreadMessage(SlackThreadMessage.Kind.NEW, "C9", "2.0", "1.0", null, "Pat", "ping", listOf(approver))
        threads.onMessage(reply)
        assertEquals(emptyList(), fx.accessStore.getRequest(id)!!.ccs, "a reply from no active user adds nobody")
        threads.onMessage(reply.copy(ts = "2.5", principal = "outsider@example.com"))
        assertEquals(emptyList(), fx.accessStore.getRequest(id)!!.ccs, "a user denied task.cc adds nobody")
        val bystander = "bystander-${System.nanoTime()}@example.com"
        fx.policyStore.createAssignment(RoleAssignmentInput(bystander, fx.policyStore.listRoles().first { it.name == "system:admin" }.id))
        fx.dataSource.connection.use { c -> RequestParticipants.add(c, id, listOf(approver), ParticipantKind.APPROVER) }
        threads.onMessage(reply.copy(ts = "3.0", principal = requester, mentions = listOf(bystander, approver, requester)))
        assertEquals(listOf(bystander), fx.accessStore.getRequest(id)!!.ccs, "an approver or the requester is not made a CC")
    }

    @Test
    fun `a click for a request that does not exist is rejected`() = runBlocking {
        val reply = handler.handle(click(999_999, approver, SlackTransport.ACTION_APPROVE))
        assertTrue(reply.contains("no longer exists"), "got: $reply")
    }

    @Test
    fun `a failed run is reported as a retry hint, and the decision still stands`() = runBlocking {
        val id = pendingRequest()
        onApprovedThrows = true
        try {
            val reply = handler.handle(click(id, approver, SlackTransport.ACTION_APPROVE))
            assertTrue(reply.contains("could not be started"), "got: $reply")
            assertEquals("APPROVED", statusOf(id), "the approval committed even though the run failed to start")
        } finally {
            onApprovedThrows = false
        }
    }
}
