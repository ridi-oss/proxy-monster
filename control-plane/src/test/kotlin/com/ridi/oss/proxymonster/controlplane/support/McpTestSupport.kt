package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.grpc.EditorQuery
import com.ridi.oss.proxymonster.grpc.openConnectionRequest
import com.ridi.oss.proxymonster.grpc.ConnectionDoor
import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.WireIdentity
import com.ridi.oss.proxymonster.controlplane.grpc.CONTROL_PROTOCOL_VERSION
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.module
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.CpTableDetailMsg
import com.ridi.oss.proxymonster.grpc.OpenEditorSession
import com.ridi.oss.proxymonster.grpc.OpenTableDetailChannel
import com.ridi.oss.proxymonster.grpc.ProxyEditorMsg
import com.ridi.oss.proxymonster.grpc.ProxyTableDetailMsg
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyEditorMsg
import com.ridi.oss.proxymonster.grpc.editorReady
import com.ridi.oss.proxymonster.grpc.editorServing
import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

const val MCP_TEST_RESOURCE = "http://localhost/mcp"
private const val CLIENT_ID = "https://client.example/mcp.json"
private val rpcIds = AtomicInteger()

val MCP_TEST_JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }

/** Every scope a tool can require. */
val ALL_MCP_SCOPES: Set<String> get() = McpCapabilityRegistry.supportedScopes

/** A config for the whole [module] under test: MCP on [MCP_TEST_RESOURCE], X-Forwarded-For trusted from the test peer. */
fun mcpTestConfig(resultKey: ByteArray? = null) = Config(
    httpPort = 0,
    dbUrl = "",
    dbUser = "",
    dbPassword = "",
    authDebug = false,
    secretToken = null,
    sessionSecret = "mcp-parity-test-secret-0123456789abcdef",
    oidc = null,
    resultKey = resultKey,
    scimToken = null,
    sessionWindowSeconds = 3_600,
    idpRecheckIntervalSeconds = 600,
    devMarker = true,
    mcpResource = MCP_TEST_RESOURCE,
    trustedProxies = setOf("localhost"),
)

/** Writes MCP access tokens the way cp-go's consent flow leaves them: a live consent and an access token under it. */
class McpTokens(private val dataSource: DataSource, private val resource: String = MCP_TEST_RESOURCE) {
    fun token(principal: String, scopes: Set<String>): String {
        val scope = scopes.toSortedSet().joinToString(" ")
        val token = "pma_" + java.util.UUID.randomUUID()
        dataSource.connection.use { c ->
            val consent = c.prepareStatement(
                """INSERT INTO oauth_consent (principal, client_id, resource, scope) VALUES (?, ?, ?, ?)
                   ON CONFLICT (principal, client_id, resource, scope) WHERE revoked_at IS NULL DO UPDATE SET updated_at = now()
                   RETURNING id""",
            ).use { ps ->
                listOf(principal, CLIENT_ID, resource, scope).forEachIndexed { i, v -> ps.setString(i + 1, v) }
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            c.prepareStatement(
                """INSERT INTO proxy_token (token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id)
                   VALUES (?, 'MCP_ACCESS', ?, '[]'::jsonb, now() + interval '10 minutes', ?, ?, ?, ?, ?)""",
            ).use { ps ->
                listOf(sha256Hex(token), principal, resource, CLIENT_ID, scope, "pmf_$token").forEachIndexed { i, v -> ps.setString(i + 1, v) }
                ps.setLong(7, consent)
                ps.executeUpdate()
            }
        }
        return token
    }
}

/**
 * Installs the production [module] (REST and MCP over the same shared services) plus the test login route, and
 * returns a cookie-carrying client, so one test can drive a tool and its REST route as the same principal.
 */
fun ApplicationTestBuilder.installControlPlane(config: Config, core: ControlPlaneCore): HttpClient {
    application {
        module(config, core)
        routing { testLoginRoute(PrincipalSessionStore(core.dataSource, null), config) }
    }
    return createClient {
        expectSuccess = false
        install(HttpCookies)
    }
}

suspend fun HttpClient.login(principal: String) {
    assertEquals(HttpStatusCode.NoContent, post("/test/session/$principal").status)
}

suspend fun HttpClient.mcpRaw(
    token: String,
    tool: String,
    args: JsonObject = JsonObject(emptyMap()),
    forwardedFor: String? = null,
): HttpResponse = post("/mcp") {
    forwardedFor?.let { header("X-Forwarded-For", it) }
    header(HttpHeaders.Accept, "application/json, text/event-stream")
    contentType(ContentType.Application.Json)
    header("MCP-Protocol-Version", "2025-06-18")
    header(HttpHeaders.Authorization, "Bearer $token")
    setBody(
        buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", rpcIds.incrementAndGet())
            put("method", "tools/call")
            put("params", buildJsonObject { put("name", tool); put("arguments", args) })
        }.toString(),
    )
}

/** The JSON-RPC `result` of one tool call: `structuredContent`, and `isError` on a failure. */
suspend fun HttpClient.mcpCall(
    token: String,
    tool: String,
    args: JsonObject = JsonObject(emptyMap()),
    forwardedFor: String? = null,
): JsonObject = mcpResult(mcpRaw(token, tool, args, forwardedFor).bodyAsText())

fun mcpResult(body: String): JsonObject = MCP_TEST_JSON.parseToJsonElement(body).jsonObject.getValue("result").jsonObject

/** The structured content of a successful call. */
fun JsonObject.ok(): JsonObject {
    assertTrue(this["isError"]?.jsonPrimitive?.content != "true", toString())
    return getValue("structuredContent").jsonObject
}

/** The `structuredContent.result` of a successful call. */
fun JsonObject.okResult(): JsonElement = ok().getValue("result")

/** The error code of a failed call. */
fun JsonObject.errorCode(): String? {
    assertEquals("true", this["isError"]?.jsonPrimitive?.content, toString())
    return getValue("structuredContent").jsonObject["code"]?.jsonPrimitive?.content
}

fun JsonObject.errorParams(): JsonObject = getValue("structuredContent").jsonObject.getValue("params").jsonObject

fun JsonObject.str(name: String): String? = (this[name] as? JsonPrimitive)?.content

fun parseJson(body: String): JsonElement = MCP_TEST_JSON.parseToJsonElement(body)

/** Opens a connection on the editor door, as goproxy does when it admits an editor session, and returns its ID. */
suspend fun ControlPlaneGrpcKt.ControlPlaneCoroutineStub.openEditorConnection(open: OpenEditorSession, datasourceName: String): ByteString =
    openConnection(
        openConnectionRequest {
            token = open.ephemeralToken
            this.datasourceName = datasourceName
            door = ConnectionDoor.CONNECTION_DOOR_EDITOR
        },
    ).connectionId

/**
 * Attaches a fake proxy to [datasourceName] over the real gRPC Events stream while [body] runs. Each run the
 * control plane opens is answered with [respond]'s frames, and each table-detail request with [tableDetail]'s
 * reply (when given).
 */
suspend fun withFakeProxy(
    core: ControlPlaneCore,
    stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub,
    datasourceName: String,
    respond: suspend (WireIdentity?, EditorQuery, OpenEditorSession) -> List<ProxyEditorMsg>,
    tableDetail: ((OpenTableDetailChannel) -> ProxyTableDetailMsg)? = null,
    body: suspend () -> Unit,
) = supervisorScope {
    val proxy = launch {
        stub.events(eventsRequest { this.datasourceName = datasourceName; protocolVersion = CONTROL_PROTOCOL_VERSION })
            .collect { event ->
                if (event.hasOpenTableDetailChannel() && tableDetail != null) {
                    val open = event.openTableDetailChannel
                    launch {
                        val outbound = Channel<CpTableDetailMsg>(Channel.BUFFERED)
                        val attached = core.tableDetailChannels.attach(open.sessionId, outbound) ?: return@launch
                        attached.inbound.send(tableDetail(open))
                        outbound.receive()
                        attached.inbound.close()
                        outbound.close()
                    }
                    return@collect
                }
                if (!event.hasOpenEditorSession()) return@collect
                val open = event.openEditorSession
                val identity = core.tokenStore.resolve(open.ephemeralToken)
                launch {
                    val out = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
                    out.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
                    out.send(proxyEditorMsg { serving = editorServing {} })
                    stub.editorExec(out.receiveAsFlow()).collect { control ->
                        when {
                            control.hasQuery() -> respond(identity, control.query, open).forEach { out.send(it) }
                            control.hasClose() -> out.close()
                        }
                    }
                }
            }
    }
    try {
        withTimeout(5_000) { while (datasourceName !in core.proxyEventsHub.attached()) delay(20) }
        body()
    } finally {
        proxy.cancel()
        withTimeout(5_000) { while (datasourceName in core.proxyEventsHub.attached()) delay(20) }
    }
}
