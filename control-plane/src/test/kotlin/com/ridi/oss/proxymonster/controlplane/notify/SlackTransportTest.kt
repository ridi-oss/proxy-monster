package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.support.MockSlack
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Slack transport against a real mock Slack server, so the wire encoding is what is actually asserted.
 *
 * The load-bearing case is `read methods are form-encoded`: Slack's read/utility methods reject a JSON body
 * with `invalid_arguments`, and the first deploy shipped them as JSON — every notification went out DEAD with
 * no address. Only the `chat.*` methods, which carry a `blocks` array, take JSON. This pins both halves.
 */
class SlackTransportTest {
    private lateinit var slack: MockSlack
    private lateinit var http: HttpClient
    private lateinit var transport: SlackTransport

    private val botToken = "xoxb-test-token"

    @BeforeEach
    fun setup() {
        slack = MockSlack.start()
        http = slackHttpClient()
        transport = SlackTransport(
            http = http,
            botToken = botToken,
            webBaseUrl = "https://console.example",
            renderer = NotificationRenderer(),
            api = slack.apiBase,
        )
    }

    @AfterEach
    fun teardown() {
        http.close()
        slack.close()
    }

    private fun message(
        event: NotificationEvent = NotificationEvent.TASK_REQUESTED,
        taskId: Long = 42,
        actions: Set<NotificationAction> = setOf(NotificationAction.OPEN, NotificationAction.DENY, NotificationAction.APPROVE_AND_RUN),
        statement: RenderedStatement = RenderedStatement("SELECT 1", complete = true),
    ) = NotificationMessage(
        event = event,
        taskId = taskId,
        requester = "requester@example.com",
        datasource = "prod-db",
        roleName = "reader",
        reason = "need it",
        statement = statement,
        decidedBy = null,
        approved = null,
        deepLink = "https://console.example/workflows/$taskId",
        actions = actions,
    )

    private fun MockSlack.Recorded.blocks(): List<JsonObject> =
        json!!["blocks"]!!.jsonArray.map { it.jsonObject }

    private fun List<JsonObject>.actionElements(): List<JsonObject> =
        first { it["type"]?.jsonPrimitive?.content == "actions" }["elements"]!!.jsonArray.map { it.jsonObject }

    // ---- addressing: the form-encoding regression ---------------------------------------------

    @Test
    fun `read methods are form-encoded, never JSON`() = runBlocking {
        slack.userIdByEmail["sam@example.com"] = "U_SAM"

        val address = transport.addressOf("sam@example.com", null)

        assertEquals("D_U_SAM", address, "conversations.open returns the DM channel id")
        val lookup = slack.lastRequest("users.lookupByEmail")!!
        assertTrue(lookup.isForm, "users.lookupByEmail must be form-encoded, not JSON — a JSON body is invalid_arguments")
        assertEquals("sam@example.com", lookup.form["email"])
        assertEquals("Bearer $botToken", lookup.authorization)
        val open = slack.lastRequest("conversations.open")!!
        assertTrue(open.isForm, "conversations.open must be form-encoded")
        assertEquals("U_SAM", open.form["users"])
    }

    @Test
    fun `addressing returns null when the email resolves to no Slack user`() = runBlocking {
        assertNull(transport.addressOf("ghost@example.com", null), "users_not_found drops the row, no address")
    }

    @Test
    fun `addressing falls back to the directory email for a non-address principal`() = runBlocking {
        slack.userIdByEmail["real@example.com"] = "U_REAL"
        // The principal is an opaque subject id, not an email; the app_user email is the fallback lookup key.
        val address = transport.addressOf("okta|abc123", "real@example.com")
        assertEquals("D_U_REAL", address)
        assertEquals("real@example.com", slack.lastRequest("users.lookupByEmail")!!.form["email"])
    }

    @Test
    fun `a transient failure resolving an address throws so delivery retries, not null`() = runBlocking {
        slack.close() // server gone → the lookup POST throws at the socket: a transient condition, not "no user"
        assertTrue(
            runCatching { transport.addressOf("sam@example.com", null) }.isFailure,
            "a transient address-resolution failure must throw (→ retry), never return null (→ drop)",
        )
    }

    // ---- delivery: chat.postMessage as JSON ---------------------------------------------------

    @Test
    fun `deliver posts chat_postMessage as JSON and returns a channel-ts ref`() = runBlocking {
        val result = transport.deliver("D_U_SAM", message(), "en")

        assertTrue(result is DeliveryResult.Sent, "delivered; got $result")
        val ref = (result as DeliveryResult.Sent).externalRef
        assertTrue(ref.startsWith("C_MOCK:"), "ref is channel:ts, got $ref")
        val post = slack.lastRequest("chat.postMessage")!!
        assertTrue(post.isJson, "chat.postMessage carries a blocks array and must be JSON")
        assertEquals("D_U_SAM", post.json!!["channel"]!!.jsonPrimitive.content)
        assertTrue(post.blocks().isNotEmpty(), "the message has Block Kit content")
    }

    @Test
    fun `a pending request renders approve-and-run, deny, and open buttons with their action ids`() = runBlocking {
        transport.deliver("D_U_SAM", message(taskId = 7), "en")
        val elements = slack.lastRequest("chat.postMessage")!!.blocks().actionElements()

        val approve = elements.first { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_APPROVE }
        assertEquals("7", approve["value"]?.jsonPrimitive?.content, "the button carries the task id")
        assertEquals("primary", approve["style"]?.jsonPrimitive?.content)

        val deny = elements.first { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_DENY }
        assertEquals("danger", deny["style"]?.jsonPrimitive?.content)

        val open = elements.first { it["url"] != null }
        assertEquals("https://console.example/workflows/7", open["url"]?.jsonPrimitive?.content)
    }

    @Test
    fun `a message with only open offers no decision buttons`() = runBlocking {
        transport.deliver("D_U_SAM", message(actions = setOf(NotificationAction.OPEN)), "en")
        val elements = slack.lastRequest("chat.postMessage")!!.blocks().actionElements()

        assertTrue(elements.none { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_APPROVE })
        assertTrue(elements.none { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_DENY })
        assertTrue(elements.any { it["url"] != null }, "open is always there")
    }

    // ---- the body names people as Slack mentions ----------------------------------------------

    private fun List<JsonObject>.sectionText(): String =
        first { it["type"]?.jsonPrimitive?.content == "section" }["text"]!!.jsonObject["text"]!!.jsonPrimitive.content

    @Test
    fun `a requester whose email resolves is rendered as a Slack mention`() = runBlocking {
        slack.userIdByEmail["requester@example.com"] = "U_REQ"
        transport.deliver("D_U_SAM", message(), "en")
        val text = slack.lastRequest("chat.postMessage")!!.blocks().sectionText()
        assertTrue(text.contains("<@U_REQ>"), "the requester resolves to a mention; was: $text")
        assertTrue(!text.contains("requester@example.com"), "the raw email is replaced by the mention")
    }

    @Test
    fun `a principal with no Slack match renders as the plain identity`() = runBlocking {
        // requester@example.com is absent from the directory → users_not_found → shown unchanged.
        transport.deliver("D_U_SAM", message(), "en")
        val text = slack.lastRequest("chat.postMessage")!!.blocks().sectionText()
        assertTrue(text.contains("requester@example.com"), "no Slack match → the principal is unchanged; was: $text")
    }

    @Test
    fun `a non-email principal is never looked up`() = runBlocking {
        transport.deliver("D_U_SAM", message().copy(requester = "okta|abc123"), "en")
        assertTrue(slack.requestsFor("users.lookupByEmail").isEmpty(), "a subject id is not an email; no lookup")
        assertTrue(slack.lastRequest("chat.postMessage")!!.blocks().sectionText().contains("okta|abc123"))
    }

    @Test
    fun `the decider is resolved to a mention too`() = runBlocking {
        slack.userIdByEmail["approver@example.com"] = "U_APP"
        transport.deliver(
            "D_U_SAM",
            message(event = NotificationEvent.TASK_DECIDED).copy(decidedBy = "approver@example.com", approved = true),
            "en",
        )
        val text = slack.lastRequest("chat.postMessage")!!.blocks().sectionText()
        assertTrue(text.contains("<@U_APP>"), "the decider resolves to a mention; was: $text")
    }

    // ---- update: edit by handle ---------------------------------------------------------------

    @Test
    fun `update edits by channel-ts and returns the same ref`() = runBlocking {
        val result = transport.update("C_MOCK:1700000000001.000100", message(event = NotificationEvent.TASK_DECIDED), "en")

        assertEquals(DeliveryResult.Sent("C_MOCK:1700000000001.000100"), result)
        val update = slack.lastRequest("chat.update")!!
        assertTrue(update.isJson)
        assertEquals("C_MOCK", update.json!!["channel"]!!.jsonPrimitive.content)
        assertEquals("1700000000001.000100", update.json!!["ts"]!!.jsonPrimitive.content)
    }

    @Test
    fun `update drops a malformed message ref without calling Slack`() = runBlocking {
        val result = transport.update("not-a-ref", message(), "en")
        assertTrue(result is DeliveryResult.Drop, "a ref with no ':' cannot address an edit; got $result")
        assertTrue(slack.requestsFor("chat.update").isEmpty(), "nothing should have gone to Slack")
    }

    // ---- Slack's error taxonomy decides retry vs drop -----------------------------------------

    @Test
    fun `a retryable Slack error retries and a permanent one drops`() = runBlocking {
        slack.postMessageError = "ratelimited"
        assertTrue(transport.deliver("D_X", message(), "en") is DeliveryResult.Retry, "ratelimited can clear")

        slack.postMessageError = "channel_not_found"
        assertTrue(transport.deliver("D_X", message(), "en") is DeliveryResult.Drop, "channel_not_found fails forever")
    }

    @Test
    fun `a transport-level failure retries rather than dropping`() = runBlocking {
        slack.close() // server gone: the POST throws at the socket, which is transient by nature
        assertTrue(transport.deliver("D_X", message(), "en") is DeliveryResult.Retry)
    }

    @Test
    fun `a 5xx with a permanent-looking body still retries, never dead-letters an outage`() = runBlocking {
        slack.httpStatus = 503
        slack.postMessageError = "unknown" // a body the taxonomy alone would read as a permanent drop
        assertTrue(
            transport.deliver("D_X", message(), "en") is DeliveryResult.Retry,
            "the transport-level 503 proves the failure is transient whatever the body says",
        )
    }

    @Test
    fun `a 429 retries`() = runBlocking {
        slack.httpStatus = 429
        slack.retryAfter = "600"
        assertTrue(transport.deliver("D_X", message(), "en") is DeliveryResult.Retry, "a rate limit clears")
    }

    @Test
    fun `a 5xx resolving an address throws so delivery retries, not drops`() = runBlocking {
        slack.userIdByEmail["sam@example.com"] = "U_SAM"
        slack.httpStatus = 500
        assertTrue(
            runCatching { transport.addressOf("sam@example.com", null) }.isFailure,
            "a 5xx on a read method is transient — throw (→ retry), never return null (→ drop)",
        )
    }

    @Test
    fun `addressing prefers the current directory email over an email-shaped principal`() = runBlocking {
        slack.userIdByEmail["current@example.com"] = "U_CUR"
        // The principal is itself an old email address; the directory email is the current one and must win —
        // an email-shaped principal can be stale, and its address may since have been reassigned.
        val address = transport.addressOf("old@example.com", "current@example.com")
        assertEquals("D_U_CUR", address)
        assertEquals("current@example.com", slack.lastRequest("users.lookupByEmail")!!.form["email"])
    }
}
