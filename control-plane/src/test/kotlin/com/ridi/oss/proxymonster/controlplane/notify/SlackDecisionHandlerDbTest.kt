package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
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
            statementMaxChars = 10_000,
            defaultLocale = "en",
        )
        handler = SlackDecisionHandler(
            accessStore = fx.accessStore,
            datasourceStore = fx.datasourceStore,
            authz = fx.authz,
            auditRecorder = ManagementAuditRecorder(fx.auditStore),
            notifications = notifications,
            defaultLocale = "en",
            onApproved = { req ->
                if (onApprovedThrows) throw RuntimeException("run failed")
                approvedRuns += req
            },
        )
    }

    private fun pendingRequest(): Long = fx.accessStore.createQueryRequest(
        principal = requester, datasourceId = fx.datasource.id, sql = "SELECT id FROM users",
        denyReason = null, sourceDecisionId = null, reason = "need it", title = "read users",
        evaluatedDecision = "ALLOW", roleId = roleId,
    ).id

    private fun click(taskId: Long, principal: String, actionId: String) = SlackInteraction(
        principal = principal, actionId = actionId, taskId = taskId,
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
