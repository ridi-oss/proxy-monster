package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.MockSlack
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The whole Slack notification loop, end to end, against a real mock Slack and real PostgreSQL + Cedar: a
 * request is created → the approver is notified with a chat.postMessage carrying an approve button → the
 * approver clicks → the click returns over the Socket Mode WebSocket → the same Cedar `task.approve` decision
 * runs on the `slack` channel → the request is approved and run → the ORIGINAL message is edited in place
 * (chat.update on the stored handle), so the buttons the user tapped disappear.
 *
 * Nothing here is stubbed except Slack itself; every proxy-monster component is the production class.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SlackNotificationE2eDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var slack: MockSlack
    private lateinit var http: HttpClient
    private lateinit var svc: NotificationService
    private lateinit var socket: SlackSocketMode

    private val requester = "requester@example.com"
    private val approver = "admin@example.com"
    private var roleId: Long = 0
    private val approved = CompletableDeferred<AccessRequest>()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        val roles = fx.policyStore.listRoles().associateBy { it.name }
        fx.policyStore.createAssignment(RoleAssignmentInput(approver, roles.getValue("system:admin").id))
        roleId = roles.getValue(fx.role).id

        slack = MockSlack.start()
        slack.userIdByEmail[approver] = "U_ADMIN"
        slack.usersById["U_ADMIN"] = MockSlack.SlackUser(email = approver)

        http = slackHttpClient()
        val transport = SlackTransport(http, "xoxb-e2e", "https://console.example", NotificationRenderer(), api = slack.apiBase)
        svc = NotificationService(
            store = NotificationStore(fx.dataSource),
            // The candidate pool is just the admin; routing keeps them because Cedar says they may approve.
            recipients = RecipientResolver(fx.authz, fx.roleResolver) { listOf(approver) },
            transports = listOf(transport),
            accessStore = fx.accessStore,
            queryResultStore = null,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.FULL,
            statementMaxChars = 10_000,
            defaultLocale = "en",
        )
        val handler = SlackDecisionHandler(
            accessStore = fx.accessStore,
            datasourceStore = fx.datasourceStore,
            authz = fx.authz,
            auditRecorder = ManagementAuditRecorder(fx.auditStore),
            notifications = svc,
            defaultLocale = "en",
            onApproved = { approved.complete(it) },
        )
        socket = SlackSocketMode(http, "xoxb-e2e", "xapp-e2e", onInteraction = { handler.handle(it) }, api = slack.apiBase)
    }

    @AfterAll
    fun teardown() {
        http.close()
        slack.close()
    }

    @Test
    fun `a request is announced to Slack, approved by a click, and its message edited in place`() = runBlocking {
        // 1. A pending request, and the "needs approval" notification queued for it.
        val req = fx.accessStore.createQueryRequest(
            principal = requester, datasourceId = fx.datasource.id, sql = "SELECT id FROM users",
            denyReason = null, sourceDecisionId = null, reason = "monthly audit", title = "read users",
            evaluatedDecision = "ALLOW", roleId = roleId,
        )
        fx.dataSource.connection.use { c -> svc.emit(c, NotificationEvent.TASK_REQUESTED, req) }

        // 2. Drain: the approver is addressed (email → user → DM) and the message posted with an approve button.
        svc.drainOnce()
        val post = slack.lastRequest("chat.postMessage")!!
        assertTrue(post.isJson, "the message body is JSON")
        val elements = post.json!!["blocks"]!!.jsonArray.map { it.jsonObject }
            .first { it["type"]?.jsonPrimitive?.content == "actions" }["elements"]!!.jsonArray.map { it.jsonObject }
        assertTrue(
            elements.any { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_APPROVE },
            "a pending request with a clean statement offers approve-and-run",
        )

        // 3. The approver clicks approve — the click returns over Socket Mode. The decision keys off the
        // button's task-id value, not the message ts, so the ts here is just what Slack would carry along.
        val pump = launch(Dispatchers.IO) { socket.run() }
        try {
            slack.awaitConnection()
            slack.pushEnvelope(
                """
                {"envelope_id":"env-e2e","type":"interactive",
                 "payload":{"type":"block_actions","team":{"id":"${slack.teamId}"},"user":{"id":"U_ADMIN"},
                   "actions":[{"action_id":"${SlackTransport.ACTION_APPROVE}","value":"${req.id}"}],
                   "response_url":"${slack.responseUrl}","channel":{"id":"C_MOCK"},
                   "message":{"ts":"1700000000001.000100"}}}
                """.trimIndent(),
            )

            // 4. The decision runs and the request is approved (and run).
            val ranReq = withTimeout(10_000) { approved.await() }
            assertEquals(req.id, ranReq.id)
        } finally {
            pump.cancel()
        }

        assertEquals("APPROVED", fx.accessStore.getRequest(req.id)!!.status)

        // 5. Draining the decided event edits the SAME message rather than posting a new one.
        svc.drainOnce()
        val update = slack.lastRequest("chat.update")!!
        assertEquals("C_MOCK", update.json!!["channel"]!!.jsonPrimitive.content, "the original message is edited in place")
        assertTrue(slack.requestsFor("chat.postMessage").size == 1, "no second message was posted — the first was edited")
    }
}
