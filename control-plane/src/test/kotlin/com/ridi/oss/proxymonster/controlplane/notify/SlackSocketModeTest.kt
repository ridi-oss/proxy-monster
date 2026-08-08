package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.support.MockSlack
import io.ktor.client.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
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

    private val botToken = "xoxb-test"
    private val appToken = "xapp-test"

    @BeforeEach
    fun setup() {
        slack = MockSlack.start()
        http = slackHttpClient()
        // The clicker Slack account maps to a verified email = the principal.
        slack.usersById["U_CLICKER"] = MockSlack.SlackUser(email = "clicker@example.com")
        slack.usersById["U_VALID"] = MockSlack.SlackUser(email = "valid@example.com")
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
        onInteraction = { received.send(it); reply },
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

    @Test
    fun `a valid click is acked and dispatched with the resolved principal`() = withSocket { _ ->
        slack.pushEnvelope(envelope("env-1"))
        val it = awaitDispatch()

        assertEquals("clicker@example.com", it.principal, "identity resolved fresh via users.info")
        assertEquals(SlackTransport.ACTION_APPROVE, it.actionId)
        assertEquals(42L, it.taskId)
        assertEquals("C_MOCK", it.triggerChannel)
        assertEquals("1700000000001.000100", it.triggerTs)
        assertTrue(
            slack.acks().any { a -> a["envelope_id"]?.jsonPrimitive?.content == "env-1" },
            "every envelope must be acked so Slack does not redeliver it",
        )
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
