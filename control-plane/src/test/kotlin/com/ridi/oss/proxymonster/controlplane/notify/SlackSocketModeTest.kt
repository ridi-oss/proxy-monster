package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.support.MockSlack
import io.ktor.client.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The inbound Socket Mode path against a real WebSocket the mock Slack serves: a button click arrives as an
 * envelope, is ACKed, its workspace is pinned to the bot token's own, and the clicker's identity is resolved
 * FRESH through users.info before it becomes a decision.
 *
 * Negative cases push the ignored envelope FIRST and a valid one SECOND, then await the valid dispatch: the
 * socket pump processes frames in order, so a valid dispatch proves the earlier one was fully handled — no
 * sleeps, no races.
 */
class SlackSocketModeTest {
    private lateinit var slack: MockSlack
    private lateinit var http: HttpClient
    private val received = Channel<SlackInteraction>(Channel.UNLIMITED)
    private val messages = Channel<SlackThreadMessage>(Channel.UNLIMITED)
    private val principalByEmail = mutableMapOf<String, String>()

    private val botToken = "xoxb-test"
    private val appToken = "xapp-test"

    @BeforeEach
    fun setup() {
        slack = MockSlack.start()
        http = slackHttpClient()
        slack.usersById["U_CLICKER"] = MockSlack.SlackUser(email = "clicker@example.com")
        slack.usersById["U_VALID"] = MockSlack.SlackUser(email = "valid@example.com")
        // The directory maps a verified Slack email to THAT user's principal — which is NOT the email itself
        // (a principal can be an OIDC subject id).
        principalByEmail["clicker@example.com"] = "okta|clicker"
        principalByEmail["valid@example.com"] = "valid@example.com"
    }

    @AfterEach
    fun teardown() {
        http.close()
        slack.close()
    }

    private fun socket(reply: String = ""): SlackSocketMode = SlackSocketMode(
        http = http,
        botToken = botToken,
        appToken = appToken,
        principalForEmail = { principalByEmail[it] },
        onInteraction = { received.send(it); SlackReply.Ephemeral(reply) },
        onMessage = { messages.send(it) },
        api = slack.apiBase,
    )

    private fun envelope(
        envelopeId: String,
        team: String = "T_WORKSPACE",
        user: String = "U_CLICKER",
        actionId: String = SlackTransport.ACTION_APPROVE,
        value: String = "42",
        payloadType: String = "block_actions",
    ) = """
        {"envelope_id":"$envelopeId","type":"interactive",
         "payload":{"type":"$payloadType","team":{"id":"$team"},"user":{"id":"$user"},
           "actions":[{"action_id":"$actionId","value":"$value"}],
           "response_url":"${slack.responseUrl}","channel":{"id":"C_MOCK"},
           "message":{"ts":"1700000000001.000100"}}}
    """.trimIndent()

    /** Run [body] with the socket connected; cancels the pump when done. */
    private fun withSocket(reply: String = "", body: suspend (Job) -> Unit) = runBlocking {
        val job = launch(Dispatchers.IO) { socket(reply).run() }
        try {
            slack.awaitConnection()
            body(job)
        } finally {
            job.cancel()
        }
    }

    private suspend fun awaitDispatch() = withTimeout(5_000) { received.receive() }

    // The client acks before it dispatches, but the mock records an ack only once its reader gets to the frame.
    private suspend fun awaitAck(envelopeId: String): Boolean = withTimeoutOrNull(5_000) {
        while (slack.acks().none { it["envelope_id"]?.jsonPrimitive?.content == envelopeId }) delay(10)
        true
    } ?: false

    private fun messageEvent(id: String, event: String) =
        """{"envelope_id":"$id","type":"events_api","payload":{"team_id":"T_WORKSPACE","type":"event_callback","event":$event}}"""

    @Test
    fun `a thread reply is dispatched with its author, and bot posts and top-level messages are not`() = withSocket { _ ->
        slack.pushEnvelope(messageEvent("m-bot", """{"type":"message","channel":"C1","ts":"2.0","thread_ts":"1.0","bot_id":"B1","text":"copy"}"""))
        slack.pushEnvelope(messageEvent("m-top", """{"type":"message","channel":"C1","ts":"3.0","user":"U_CLICKER","text":"hi"}"""))
        slack.pushEnvelope(messageEvent("m-reply", """{"type":"message","channel":"C1","ts":"4.0","thread_ts":"1.0","user":"U_CLICKER","text":"why?"}"""))
        slack.pushEnvelope(
            messageEvent("m-edit", """{"type":"message","subtype":"message_changed","channel":"C1","message":{"ts":"4.0","user":"U_CLICKER","text":"why not?"}}"""),
        )
        val reply = withTimeout(5_000) { messages.receive() }
        assertEquals(SlackThreadMessage(SlackThreadMessage.Kind.NEW, "C1", "4.0", "1.0", "okta|clicker", "U_CLICKER", "why?"), reply)
        val edit = withTimeout(5_000) { messages.receive() }
        assertEquals(SlackThreadMessage(SlackThreadMessage.Kind.EDITED, "C1", "4.0", text = "why not?"), edit)
    }

    @Test
    fun `a click carries the revision its message showed`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-rev", value = "42:3"))
        val it = awaitDispatch()
        assertEquals(42L, it.taskId)
        assertEquals(3, it.revision)
    }

    @Test
    fun `a valid click is acked and dispatched with the resolved principal`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-1"))
        val it = awaitDispatch()

        assertEquals("okta|clicker", it.principal, "the verified Slack email is mapped to the directory principal, not trusted raw")
        assertEquals(SlackTransport.ACTION_APPROVE, it.actionId)
        assertEquals(42L, it.taskId)
        assertNull(it.revision, "a button from before revisions names none")
        assertEquals("C_MOCK", it.triggerChannel)
        assertEquals("1700000000001.000100", it.triggerTs)
        assertTrue(awaitAck("env-1"), "every envelope must be acked so Slack does not redeliver it")
        assertTrue(slack.requestsFor("auth.test").isNotEmpty(), "the workspace was resolved from the bot token")
    }

    @Test
    fun `a click from another workspace is refused`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-bad", team = "T_INTRUDER"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))
        val it = awaitDispatch()

        assertEquals(99L, it.taskId, "only the correct-workspace click dispatched")
        assertEquals("valid@example.com", it.principal)
    }

    @Test
    fun `an unlinked Slack user is refused ephemerally and never dispatched`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-unlinked", user = "U_UNKNOWN", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))
        val it = awaitDispatch()

        assertEquals(99L, it.taskId, "the unlinked click did not dispatch")
        assertTrue(
            slack.ephemeralReplies().any { r -> r["text"]?.jsonPrimitive?.content?.contains("not linked") == true },
            "the clicker is told privately their account is not linked",
        )
    }

    @Test
    fun `a deactivated Slack account is refused`() = withSocket { _ ->
        slack.usersById["U_DEAD"] = MockSlack.SlackUser(email = "dead@example.com", deleted = true)
        slack.pushEnvelope(envelope("env-dead", user = "U_DEAD", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))

        assertEquals(99L, awaitDispatch().taskId, "a deactivated account never acts on a task")
    }

    @Test
    fun `a verified Slack user with no active directory match is refused`() = withSocket { _ ->
        // A real, verified Slack account whose email belongs to no active app_user — the email is not itself
        // an identity we accept.
        slack.usersById["U_STRANGER"] = MockSlack.SlackUser(email = "stranger@example.com")
        slack.pushEnvelope(envelope("env-stranger", user = "U_STRANGER", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))

        assertEquals(99L, awaitDispatch().taskId, "an email that maps to no active user never dispatches")
        assertTrue(
            slack.ephemeralReplies().any { r -> r["text"]?.jsonPrimitive?.content?.contains("not linked") == true },
            "the clicker is told privately their account is not linked",
        )
    }

    @Test
    fun `an unverified Slack email is refused even when it would match a principal`() = withSocket { _ ->
        // clicker@example.com DOES map to a principal, but the Slack email is unverified — reject before the map.
        slack.usersById["U_UNVERIFIED"] = MockSlack.SlackUser(email = "clicker@example.com", emailConfirmed = false)
        slack.pushEnvelope(envelope("env-unverified", user = "U_UNVERIFIED", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))

        assertEquals(99L, awaitDispatch().taskId, "an unverified email is not an identity claim we accept")
    }

    @Test
    fun `a Slack user with no email-confirmation field is refused`() = withSocket { _ ->
        // The response OMITS is_email_confirmed. Absence is not a confirmation — reject, even though the email
        // would otherwise map to a principal (fail-closed, like an unanalyzable statement).
        slack.usersById["U_NOFIELD"] = MockSlack.SlackUser(email = "clicker@example.com", emailConfirmed = null)
        slack.pushEnvelope(envelope("env-nofield", user = "U_NOFIELD", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))

        assertEquals(99L, awaitDispatch().taskId, "a missing confirmation flag is not accepted as verified")
    }

    @Test
    fun `a non-decision action id is ignored`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-noise", actionId = "some_other_button", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))

        assertEquals(99L, awaitDispatch().taskId, "only pm_approve/pm_deny dispatch")
    }

    @Test
    fun `a non-block_actions payload is ignored`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-view", payloadType = "view_submission", value = "7"))
        slack.pushEnvelope(envelope("env-ok", value = "99", user = "U_VALID"))

        assertEquals(99L, awaitDispatch().taskId)
    }

    @Test
    fun `the handler's reply is sent back as an ephemeral message`() = withSocket(reply = "You are not authorized to decide this request.") { _ ->
        slack.pushEnvelope(envelope("env-1"))
        awaitDispatch()
        // The reply is posted after dispatch; await it appearing rather than sleeping.
        val reply = withTimeout(5_000) {
            var seen: String? = null
            while (seen == null) {
                seen = slack.ephemeralReplies().firstOrNull()?.get("text")?.jsonPrimitive?.content
                if (seen == null) kotlinx.coroutines.delay(20)
            }
            seen
        }
        assertEquals("You are not authorized to decide this request.", reply)
    }
}
