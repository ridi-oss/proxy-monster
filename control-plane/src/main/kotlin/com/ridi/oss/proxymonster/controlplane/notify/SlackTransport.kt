package com.ridi.oss.proxymonster.controlplane.notify

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.slf4j.LoggerFactory

/**
 * Slack delivery (docs/notifications.md, "Slack").
 *
 * Outbound only: this class calls the Web API, and button clicks arrive over the Socket Mode WebSocket
 * [SlackSocketMode] opens — so no inbound ingress performs privileged actions.
 *
 * Addressing goes through email, the same directory the IdP uses: principal → `users.lookupByEmail` →
 * `conversations.open` → a DM channel. The same lookup turns a principal NAMED in the body (the requester,
 * the decider) into an `<@id>` mention, falling back to the plain identity when it does not resolve.
 */
class SlackTransport(
    private val http: HttpClient,
    private val botToken: String,
    private val webBaseUrl: String,
    private val renderer: NotificationRenderer,
    private val api: String = "https://slack.com/api",
) : NotificationTransport {

    private val log = LoggerFactory.getLogger(SlackTransport::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    // Resolved principal → Slack user id, so a requester named across many notifications is looked up once.
    // Misses are NOT cached: a principal that gains a Slack account later resolves on its next notification.
    private val userIdCache = java.util.concurrent.ConcurrentHashMap<String, String>()

    override val name = TRANSPORT

    /** A section block's `text` caps at 3000 characters; the statement shares that block with its label. */
    override val statementHardLimit = 2800

    override val supportsUpdate = true

    override suspend fun addressOf(principal: String, email: String?): String? {
        // The principal IS usually the address (auth-model.md: principal = email ?? sub); app_user.email is
        // the fallback for a principal that is not one.
        val candidate = listOfNotNull(principal.takeIf { it.contains('@') }, email).firstOrNull() ?: return null
        val lookup = call("users.lookupByEmail", mapOf("email" to candidate)) ?: return null
        val userId = lookup["user"]?.jsonObject?.get("id")?.jsonPrimitive?.contentOrNullSafe() ?: return null
        val opened = call("conversations.open", mapOf("users" to userId)) ?: return null
        return opened["channel"]?.jsonObject?.get("id")?.jsonPrimitive?.contentOrNullSafe()
    }

    /**
     * The Slack display for a principal NAMED in the body: its `<@id>` mention when the principal is an email
     * that resolves to a Slack user, else the principal unchanged — a service account, an SSO subject id, or an
     * email with no Slack match stays literal. This never gates delivery; a name that will not resolve still
     * renders, it just is not clickable.
     */
    private suspend fun mentionFor(principal: String): String {
        userIdCache[principal]?.let { return "<@$it>" }
        if (!principal.contains('@')) return principal
        val userId = call("users.lookupByEmail", mapOf("email" to principal))
            ?.get("user")?.jsonObject?.get("id")?.jsonPrimitive?.contentOrNullSafe() ?: return principal
        userIdCache[principal] = userId
        return "<@$userId>"
    }

    /** The message with every principal it NAMES (the requester, the decider) resolved to a Slack mention. */
    private suspend fun withMentions(message: NotificationMessage): NotificationMessage =
        message.copy(
            requester = mentionFor(message.requester),
            decidedBy = message.decidedBy?.let { mentionFor(it) },
        )

    override suspend fun deliver(to: String, message: NotificationMessage, locale: String): DeliveryResult {
        val rendered = withMentions(message)
        val body = buildJsonObject {
            put("channel", to)
            put("text", renderer.fallbackText(rendered, locale))
            put("blocks", blocksFor(rendered, locale))
        }
        return send("chat.postMessage", body) { resp ->
            val channel = resp["channel"]?.jsonPrimitive?.contentOrNullSafe()
            val ts = resp["ts"]?.jsonPrimitive?.contentOrNullSafe()
            if (channel != null && ts != null) "$channel:$ts" else null
        }
    }

    override suspend fun update(externalRef: String, message: NotificationMessage, locale: String): DeliveryResult {
        val channel = externalRef.substringBefore(':', "")
        val ts = externalRef.substringAfter(':', "")
        if (channel.isEmpty() || ts.isEmpty()) return DeliveryResult.Drop("malformed message ref")
        val rendered = withMentions(message)
        val body = buildJsonObject {
            put("channel", channel)
            put("ts", ts)
            put("text", renderer.fallbackText(rendered, locale))
            put("blocks", blocksFor(rendered, locale))
        }
        return send("chat.update", body) { externalRef }
    }

    /** The Block Kit body: one context-free summary section, then the actions the message is allowed to offer. */
    private fun blocksFor(message: NotificationMessage, locale: String) = kotlinx.serialization.json.buildJsonArray {
        add(
            buildJsonObject {
                put("type", "section")
                putJsonObject("text") {
                    put("type", "mrkdwn")
                    put("text", renderer.summary(message, locale))
                }
            },
        )
        val buttons = message.actions.filter { it != NotificationAction.OPEN }
        if (buttons.isNotEmpty() || message.actions.contains(NotificationAction.OPEN)) {
            add(
                buildJsonObject {
                    put("type", "actions")
                    putJsonArray("elements") {
                        for (action in NotificationAction.entries) {
                            if (action !in message.actions) continue
                            add(buttonFor(action, message, locale))
                        }
                    }
                },
            )
        }
    }

    private fun buttonFor(action: NotificationAction, message: NotificationMessage, locale: String): JsonObject =
        buildJsonObject {
            put("type", "button")
            putJsonObject("text") {
                put("type", "plain_text")
                put("text", renderer.actionLabel(action, locale))
            }
            when (action) {
                NotificationAction.OPEN -> put("url", message.deepLink)
                NotificationAction.APPROVE_AND_RUN -> {
                    put("action_id", ACTION_APPROVE)
                    put("value", message.taskId.toString())
                    put("style", "primary")
                }
                NotificationAction.DENY -> {
                    put("action_id", ACTION_DENY)
                    put("value", message.taskId.toString())
                    put("style", "danger")
                }
            }
        }

    private suspend fun send(
        method: String,
        body: JsonObject,
        refOf: (JsonObject) -> String?,
    ): DeliveryResult {
        val resp = try {
            callRaw(method, body)
        } catch (t: Throwable) {
            return DeliveryResult.Retry("transport error: ${t.message}")
        }
        val ok = resp["ok"]?.jsonPrimitive?.booleanOrNullSafe() == true
        if (!ok) {
            val error = resp["error"]?.jsonPrimitive?.contentOrNullSafe() ?: "unknown"
            // Slack's own taxonomy decides retry-vs-drop: only it knows whether the condition can clear.
            return if (error in RETRYABLE) DeliveryResult.Retry(error) else DeliveryResult.Drop(error)
        }
        val ref = refOf(resp) ?: return DeliveryResult.Drop("response carried no message ref")
        return DeliveryResult.Sent(ref)
    }

    /**
     * A Web API call taking simple parameters, form-encoded. Slack's read/utility methods
     * (`users.lookupByEmail`, `conversations.open`, `users.info`) reject a JSON body with
     * `invalid_arguments` — only the methods that carry a `blocks` array (`chat.*`) accept JSON. Returns the
     * payload on `ok`, or null on any failure. A failure is logged at WARN, not DEBUG: a silent address
     * lookup is how a whole recipient is dropped with no trace.
     */
    private suspend fun call(method: String, params: Map<String, String>): JsonObject? {
        val resp = runCatching { callForm(method, params) }.getOrElse {
            log.warn("slack {} threw", method, it)
            return null
        }
        if (resp["ok"]?.jsonPrimitive?.booleanOrNullSafe() != true) {
            log.warn("slack {} returned error {}", method, resp["error"]?.jsonPrimitive?.contentOrNullSafe())
            return null
        }
        return resp
    }

    private suspend fun callForm(method: String, params: Map<String, String>): JsonObject {
        val response = http.post("$api/$method") {
            header(HttpHeaders.Authorization, "Bearer $botToken")
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(params.entries.joinToString("&") { (k, v) -> "$k=${v.encodeURLParameter()}" })
        }
        return json.parseToJsonElement(response.bodyAsText()).jsonObject
    }

    /** JSON-bodied call, for the `chat.*` methods whose `blocks` array requires it. */
    private suspend fun callRaw(method: String, body: JsonObject): JsonObject {
        val response = http.post("$api/$method") {
            header(HttpHeaders.Authorization, "Bearer $botToken")
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        return json.parseToJsonElement(response.bodyAsText()).jsonObject
    }

    companion object {
        const val TRANSPORT = "slack"
        const val ACTION_APPROVE = "pm_approve_and_run"
        const val ACTION_DENY = "pm_deny"

        /**
         * Slack errors worth another attempt. Everything else — `channel_not_found`, `not_in_channel`, a
         * malformed payload — will fail identically forever, so it drops rather than burning retries.
         */
        private val RETRYABLE = setOf("ratelimited", "rate_limited", "service_unavailable", "internal_error", "fatal_error")
    }
}

private fun kotlinx.serialization.json.JsonPrimitive.contentOrNullSafe(): String? =
    runCatching { content }.getOrNull()?.takeIf { it.isNotEmpty() && it != "null" }

private fun kotlinx.serialization.json.JsonPrimitive.booleanOrNullSafe(): Boolean? =
    runCatching { content.toBooleanStrictOrNull() }.getOrNull()

