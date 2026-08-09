package com.ridi.oss.proxymonster.controlplane.support

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder
import java.util.Collections
import java.util.concurrent.atomic.AtomicLong

/**
 * A stand-in for the Slack Web API + Socket Mode gateway, run as a REAL embedded server on an ephemeral
 * port so the transport and socket exercise their true wire encoding — the form-vs-JSON split, the auth
 * header, the WebSocket handshake and ack — rather than a stubbed client that would let an encoding bug
 * through.
 *
 * It records every HTTP request ([requests]) so a test can assert HOW a method was called, is programmable
 * per method (which user an email resolves to, whether a post fails), and drives Socket Mode from the test
 * side: [pushEnvelope] sends a frame to the connected client and [acks] captures what it sent back.
 */
class MockSlack private constructor() : AutoCloseable {

    /** One recorded HTTP call. [contentType] and [authorization] are what actually went on the wire. */
    data class Recorded(
        val method: String,
        val contentType: String?,
        val authorization: String?,
        val rawBody: String,
    ) {
        /** The body parsed as a form (empty when it was not form-encoded). */
        val form: Map<String, String> by lazy {
            if (rawBody.isBlank()) emptyMap()
            else rawBody.split('&').mapNotNull { pair ->
                val eq = pair.indexOf('=')
                if (eq < 0) null
                else URLDecoder.decode(pair.substring(0, eq), "UTF-8") to URLDecoder.decode(pair.substring(eq + 1), "UTF-8")
            }.toMap()
        }

        /** The body parsed as JSON, or null when it was not JSON. */
        val json: JsonObject? by lazy { runCatching { JSON.parseToJsonElement(rawBody).jsonObject }.getOrNull() }

        val isForm: Boolean get() = contentType?.startsWith(ContentType.Application.FormUrlEncoded.toString()) == true
        val isJson: Boolean get() = contentType?.startsWith(ContentType.Application.Json.toString()) == true
    }

    // ---- programmable behavior ----------------------------------------------------------------

    /** The workspace auth.test reports; SlackSocketMode pins clicks to it. */
    var teamId: String = "T_WORKSPACE"

    /** users.lookupByEmail: an email present here resolves to its Slack user id; absent → users_not_found. */
    val userIdByEmail: MutableMap<String, String> = Collections.synchronizedMap(mutableMapOf())

    data class SlackUser(
        val email: String?,
        val deleted: Boolean = false,
        val isBot: Boolean = false,
        // Nullable so a test can OMIT the field entirely (an older workspace / partial response), not just
        // set it false.
        val emailConfirmed: Boolean? = true,
    )

    /** users.info: the profile a Slack user id resolves to; absent → user_not_found. */
    val usersById: MutableMap<String, SlackUser> = Collections.synchronizedMap(mutableMapOf())

    /** When set, chat.postMessage answers ok:false with this error instead of delivering. */
    @Volatile var postMessageError: String? = null

    /** When set, chat.update answers ok:false with this error. */
    @Volatile var updateError: String? = null

    /** When set, every /api response carries this HTTP status (a 429/5xx transient-status test), plus an
     *  optional Retry-After header. */
    @Volatile var httpStatus: Int? = null
    @Volatile var retryAfter: String? = null

    // ---- recording ----------------------------------------------------------------------------

    private val recorded = Collections.synchronizedList(mutableListOf<Recorded>())
    private val ackFrames = Collections.synchronizedList(mutableListOf<JsonObject>())
    private val ephemeral = Collections.synchronizedList(mutableListOf<JsonObject>())
    private val tsSeq = AtomicLong(1_700_000_000_000)

    /** Every HTTP call the client made, in order. */
    fun requests(): List<Recorded> = recorded.toList()
    fun requestsFor(method: String): List<Recorded> = recorded.filter { it.method == method }
    fun lastRequest(method: String): Recorded? = recorded.lastOrNull { it.method == method }

    /** The envelope_id acknowledgements the client sent back over the socket. */
    fun acks(): List<JsonObject> = ackFrames.toList()

    /** Bodies POSTed to a response_url (the ephemeral, clicker-only replies). */
    fun ephemeralReplies(): List<JsonObject> = ephemeral.toList()

    // ---- socket-mode control ------------------------------------------------------------------

    // Outbound frames the test wants delivered to whichever client is currently connected. UNLIMITED so a
    // test can queue an envelope before the client has connected without blocking.
    private val outbound = Channel<String>(Channel.UNLIMITED)
    private val connectionSignals = Channel<Unit>(Channel.UNLIMITED)

    /** Suspend until a Socket Mode client has connected and been greeted with `hello`. */
    suspend fun awaitConnection() = connectionSignals.receive()

    /** Send a raw text frame (an interaction envelope, or `{"type":"disconnect"}`) to the connected client. */
    suspend fun pushEnvelope(json: String) = outbound.send(json)

    // ---- wiring -------------------------------------------------------------------------------

    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>
    var port: Int = 0
        private set

    /** Pass as the transport/socket `api` so calls hit this server. */
    val apiBase: String get() = "http://127.0.0.1:$port/api"

    /** The URL apps.connections.open hands back; where the client opens its Socket Mode WebSocket. */
    val socketUrl: String get() = "ws://127.0.0.1:$port/socket"

    /** A response_url the test can put in an envelope so ephemeral replies land in [ephemeralReplies]. */
    val responseUrl: String get() = "http://127.0.0.1:$port/response"

    private fun start() {
        server = embeddedServer(Netty, port = 0) {
            install(WebSockets)
            routing {
                post("/api/{method}") {
                    val method = call.parameters["method"] ?: ""
                    val body = call.receiveText()
                    recorded += Recorded(
                        method = method,
                        contentType = call.request.headers[HttpHeaders.ContentType],
                        authorization = call.request.headers[HttpHeaders.Authorization],
                        rawBody = body,
                    )
                    retryAfter?.let { call.response.headers.append(HttpHeaders.RetryAfter, it) }
                    val status = httpStatus?.let(HttpStatusCode::fromValue) ?: HttpStatusCode.OK
                    call.respondText(responseFor(method, body), ContentType.Application.Json, status)
                }
                post("/response") {
                    runCatching { ephemeral += JSON.parseToJsonElement(call.receiveText()).jsonObject }
                    call.respondText("""{"ok":true}""", ContentType.Application.Json)
                }
                webSocket("/socket") {
                    send(Frame.Text("""{"type":"hello","num_connections":1}"""))
                    connectionSignals.send(Unit)
                    val pump = launch { for (msg in outbound) send(Frame.Text(msg)) }
                    try {
                        for (frame in incoming) {
                            val text = (frame as? Frame.Text)?.readText() ?: continue
                            runCatching { JSON.parseToJsonElement(text).jsonObject }.getOrNull()?.let { ackFrames += it }
                        }
                    } finally {
                        pump.cancel()
                    }
                }
            }
        }.start(wait = false)
        port = runBlocking { server.engine.resolvedConnectors().first().port }
    }

    private fun formParam(body: String, key: String): String? = Recorded("", null, null, body).form[key]

    private fun responseFor(method: String, body: String): String = when (method) {
        "auth.test" -> """{"ok":true,"team_id":"$teamId","user_id":"UBOT","team":"mock"}"""
        "apps.connections.open" -> """{"ok":true,"url":"$socketUrl"}"""
        "users.lookupByEmail" -> {
            val email = formParam(body, "email")
            val id = email?.let { userIdByEmail[it] }
            if (id != null) """{"ok":true,"user":{"id":"$id"}}""" else """{"ok":false,"error":"users_not_found"}"""
        }
        "conversations.open" -> {
            val user = formParam(body, "users") ?: "U?"
            """{"ok":true,"channel":{"id":"D_$user"}}"""
        }
        "users.info" -> {
            val user = formParam(body, "user")
            val u = user?.let { usersById[it] }
            if (u == null) """{"ok":false,"error":"user_not_found"}"""
            else buildString {
                append("""{"ok":true,"user":{"id":"$user","deleted":${u.deleted},"is_bot":${u.isBot}""")
                if (u.emailConfirmed != null) append(""","is_email_confirmed":${u.emailConfirmed}""")
                append(""","profile":{""")
                if (u.email != null) append(""""email":"${u.email}"""")
                append("}}}")
            }
        }
        "chat.postMessage" -> postMessageError?.let { """{"ok":false,"error":"$it"}""" }
            ?: """{"ok":true,"channel":"C_MOCK","ts":"${tsSeq.incrementAndGet()}.000100"}"""
        "chat.update" -> updateError?.let { """{"ok":false,"error":"$it"}""" }
            ?: run {
                val json = runCatching { JSON.parseToJsonElement(body).jsonObject }.getOrNull()
                val channel = json?.get("channel")?.let { it.toString().trim('"') } ?: "C_MOCK"
                val ts = json?.get("ts")?.let { it.toString().trim('"') } ?: "0"
                """{"ok":true,"channel":"$channel","ts":"$ts"}"""
            }
        else -> """{"ok":false,"error":"unknown_method:$method"}"""
    }

    override fun close() {
        outbound.close()
        connectionSignals.close()
        server.stop(gracePeriodMillis = 0, timeoutMillis = 200)
    }

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true }

        /** Start a mock Slack on an ephemeral port. Close it (or use [use]) to stop the server. */
        fun start(): MockSlack = MockSlack().also { it.start() }
    }
}
