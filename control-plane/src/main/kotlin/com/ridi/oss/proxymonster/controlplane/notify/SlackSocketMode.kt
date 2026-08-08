package com.ridi.oss.proxymonster.controlplane.notify

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory

/** One button click, already resolved to the acting principal. */
data class SlackInteraction(
    val principal: String,
    val actionId: String,
    val taskId: Long,
    val responseUrl: String?,
    val triggerChannel: String?,
    val triggerTs: String?,
)

/**
 * Slack Socket Mode (docs/notifications.md, "How it connects").
 *
 * The control plane opens an OUTBOUND WebSocket and button clicks arrive on it. The alternative — giving
 * Slack a public URL to POST to — would mean a new internet-reachable endpoint that approves database
 * queries; this keeps the control plane doing what it already does, only outbound calls.
 *
 * Identity is resolved FRESH on every click via `users.info`, never from a cached mapping: that mapping is
 * what authenticates the actor, so a stale row would be an authentication bypass.
 *
 * The workspace is pinned to the one the BOT TOKEN belongs to, read once from `auth.test` at connect. It is
 * derived rather than configured because a token authenticates to exactly one workspace: asking an operator
 * to restate it adds a value they can get wrong, and a value they can leave unset — which would turn the
 * check off entirely. A click from any other workspace is refused.
 */
class SlackSocketMode(
    private val http: HttpClient,
    private val botToken: String,
    private val appToken: String,
    private val onInteraction: suspend (SlackInteraction) -> String,
    private val api: String = "https://slack.com/api",
) {
    private val log = LoggerFactory.getLogger(SlackSocketMode::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    /** The workspace this bot token belongs to. Resolved at connect; a click from anywhere else is refused. */
    @Volatile private var teamId: String? = null

    /** Connect and pump forever, reconnecting with backoff. Cancelled with its coroutine scope. */
    suspend fun run() {
        var failures = 0
        while (true) {
            val url = runCatching { openConnection() }.getOrNull()
            if (url == null) {
                failures++
                delay(backoff(failures))
                continue
            }
            failures = 0
            runCatching { pump(url) }
                .onFailure { log.info("slack socket closed ({}), reconnecting", it.message) }
            delay(RECONNECT_DELAY_MS)
        }
    }

    /** `apps.connections.open` mints a short-lived wss URL; the app-level token buys only this. */
    private suspend fun openConnection(): String? {
        val response = http.post("$api/apps.connections.open") {
            header(HttpHeaders.Authorization, "Bearer $appToken")
        }
        val body = json.parseToJsonElement(response.bodyAsText()).jsonObject
        if (body["ok"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() != true) {
            log.warn("slack apps.connections.open failed: {}", body["error"]?.jsonPrimitive?.content)
            return null
        }
        return body["url"]?.jsonPrimitive?.content
    }

    /**
     * The workspace the bot token authenticates to. Resolved once and cached — a token cannot move between
     * workspaces, so re-asking per click would be a round-trip for a constant.
     */
    private suspend fun resolveTeamId(): String? {
        teamId?.let { return it }
        val response = runCatching {
            http.post("$api/auth.test") { header(HttpHeaders.Authorization, "Bearer $botToken") }
        }.getOrNull() ?: return null
        val body = runCatching { json.parseToJsonElement(response.bodyAsText()).jsonObject }.getOrNull() ?: return null
        if (body["ok"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() != true) {
            log.warn("slack auth.test failed: {}", body["error"]?.jsonPrimitive?.content)
            return null
        }
        return body["team_id"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }?.also {
            teamId = it
            log.info("slack socket bound to workspace {}", it)
        }
    }

    private suspend fun pump(url: String) {
        http.webSocket(url) {
            for (frame in incoming) {
                val text = (frame as? Frame.Text)?.readText() ?: continue
                val envelope = runCatching { json.parseToJsonElement(text).jsonObject }.getOrNull() ?: continue

                // Slack disconnects a socket periodically by design; treat it as a normal reconnect.
                if (envelope["type"]?.jsonPrimitive?.content == "disconnect") return@webSocket

                val envelopeId = envelope["envelope_id"]?.jsonPrimitive?.content
                if (envelopeId != null) {
                    // ACK first and always. Slack retries an unacknowledged envelope, which would re-run the
                    // action; the CAS behind approve makes that safe, but the duplicate message is noise.
                    runCatching { send(Frame.Text(buildJsonObject { put("envelope_id", envelopeId) }.toString())) }
                }
                runCatching { handle(envelope) }
                    .onFailure { log.warn("slack interaction handling failed", it) }
            }
        }
    }

    private suspend fun handle(envelope: JsonObject) {
        val payload = envelope["payload"]?.jsonObject ?: return
        if (payload["type"]?.jsonPrimitive?.content != "block_actions") return

        // Fails CLOSED: an unresolved workspace refuses every click rather than accepting all of them.
        val expectedTeam = resolveTeamId()
        val actualTeam = payload["team"]?.jsonObject?.get("id")?.jsonPrimitive?.content
        if (expectedTeam == null || actualTeam != expectedTeam) {
            log.warn("slack interaction from unexpected workspace {} (expected {})", actualTeam, expectedTeam)
            return
        }

        val action = payload["actions"]?.jsonArray?.firstOrNull()?.jsonObject ?: return
        val actionId = action["action_id"]?.jsonPrimitive?.content ?: return
        if (actionId != SlackTransport.ACTION_APPROVE && actionId != SlackTransport.ACTION_DENY) return
        val taskId = action["value"]?.jsonPrimitive?.content?.toLongOrNull() ?: return

        val slackUserId = payload["user"]?.jsonObject?.get("id")?.jsonPrimitive?.content ?: return
        val principal = resolvePrincipal(slackUserId) ?: run {
            respondEphemeral(payload, "Your Slack account is not linked to a proxy-monster user.")
            return
        }

        val reply = onInteraction(
            SlackInteraction(
                principal = principal,
                actionId = actionId,
                taskId = taskId,
                responseUrl = payload["response_url"]?.jsonPrimitive?.content,
                triggerChannel = payload["channel"]?.jsonObject?.get("id")?.jsonPrimitive?.content,
                triggerTs = payload["message"]?.jsonObject?.get("ts")?.jsonPrimitive?.content,
            ),
        )
        if (reply.isNotEmpty()) respondEphemeral(payload, reply)
    }

    /**
     * The Slack user's verified email → the principal. Resolved on EVERY click rather than cached: this
     * mapping is the authentication, and an unverified email is not an identity claim we accept.
     */
    private suspend fun resolvePrincipal(slackUserId: String): String? {
        val response = http.post("$api/users.info") {
            header(HttpHeaders.Authorization, "Bearer $botToken")
            header(HttpHeaders.ContentType, "application/x-www-form-urlencoded")
            setBody("user=$slackUserId")
        }
        val body = runCatching { json.parseToJsonElement(response.bodyAsText()).jsonObject }.getOrNull() ?: return null
        if (body["ok"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() != true) return null
        val profile = body["user"]?.jsonObject ?: return null
        // A deactivated or bot account never acts on a task.
        if (profile["deleted"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() == true) return null
        if (profile["is_bot"]?.jsonPrimitive?.content?.toBooleanStrictOrNull() == true) return null
        return profile["profile"]?.jsonObject?.get("email")?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }
    }

    /** A private reply only the clicker sees — refusals and outcomes, never rows. */
    private suspend fun respondEphemeral(payload: JsonObject, text: String) {
        val responseUrl = payload["response_url"]?.jsonPrimitive?.content ?: return
        runCatching {
            http.post(responseUrl) {
                header(HttpHeaders.ContentType, "application/json")
                setBody(
                    buildJsonObject {
                        put("response_type", "ephemeral")
                        put("replace_original", false)
                        put("text", text)
                    }.toString(),
                )
            }
        }.onFailure { log.debug("slack ephemeral reply failed", it) }
    }

    private fun backoff(failures: Int): Long =
        minOf(BACKOFF_CAP_MS, BACKOFF_BASE_MS shl minOf(failures, 6))

    companion object {
        private const val RECONNECT_DELAY_MS = 1_000L
        private const val BACKOFF_BASE_MS = 2_000L
        private const val BACKOFF_CAP_MS = 120_000L
    }
}
