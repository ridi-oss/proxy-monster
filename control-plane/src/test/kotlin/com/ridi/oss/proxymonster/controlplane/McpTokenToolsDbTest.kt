package com.ridi.oss.proxymonster.controlplane

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import com.ridi.oss.proxymonster.controlplane.oauth.MCPA_SCOPES
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpRaw
import com.ridi.oss.proxymonster.controlplane.support.mcpResult
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** list_tokens, mint_token and revoke_token: the owner is always the caller, and the secret leaves exactly once. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpTokenToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private val seq = AtomicInteger()
    private val config = mcpTestConfig()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_token_tools"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource)
    }

    @Test
    fun `a minted secret is returned once and never stored, logged or replayed`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("mint")
        val token = tokens.token(caller, setOf("mcp:tokens", "mcp:read"))
        val root = LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME) as Logger
        val logs = ListAppender<ILoggingEvent>().also { it.start() }
        root.addAppender(logs)
        val issued = try {
            client.mcpCall(token, "mint_token", buildJsonObject { put("name", "laptop") }).okResult().jsonObject
        } finally {
            root.detachAppender(logs)
        }
        val secret = assertNotNull(issued.str("token"))
        assertTrue(secret.startsWith("pmk_"))
        assertEquals("USER", issued.str("kind"))
        assertEquals("laptop", issued.str("name"))
        assertEquals(caller, core.tokenStore.resolve(secret)?.principal)

        assertEquals(0L, count("SELECT count(*) FROM audit_event WHERE statement LIKE ? OR detail LIKE ?", "%$secret%", "%$secret%"))
        assertEquals(0L, count("SELECT count(*) FROM mcp_mutation_idempotency WHERE response_json::text LIKE ?", "%$secret%"))
        assertTrue(logs.list.none { secret in it.formattedMessage }, "the secret reached a log line")
        assertEquals(1L, count("SELECT count(*) FROM audit_event WHERE principal=? AND action='auth.token.mint' AND channel='mcp'", caller))

        val listed = client.mcpCall(token, "list_tokens").okResult().jsonArray
        val row = listed.single().jsonObject
        assertEquals(issued.getValue("id"), row.getValue("id"))
        assertTrue(secret !in listed.toString())

        val withKey = client.mcpCall(token, "mint_token", buildJsonObject { put("idempotencyKey", "k") })
        assertEquals("mcp.invalid_request", withKey.errorCode())
    }

    @Test
    fun `the TTL is clamped to the token window`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("ttl")
        val token = tokens.token(caller, setOf("mcp:tokens"))
        for ((requested, expected) in listOf(10L to TOKEN_MIN_TTL_SECONDS, 999_999L to TOKEN_MAX_TTL_SECONDS, null to DEFAULT_USER_TTL_SECONDS)) {
            val before = Instant.now()
            val issued = client.mcpCall(token, "mint_token", buildJsonObject { requested?.let { put("ttlSeconds", it) } }).okResult().jsonObject
            val ttl = Duration.between(before, Instant.parse(issued.str("expiresAt"))).seconds
            assertTrue(ttl in (expected - 30)..(expected + 30), "requested $requested, lived $ttl")
        }
    }

    @Test
    fun `no argument names another owner, so a caller only ever mints its own`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("owner")
        val victim = principal("victim")
        val token = tokens.token(caller, setOf("mcp:tokens"))

        val refused = client.mcpCall(token, "mint_token", buildJsonObject { put("principal", victim) })
        assertEquals("mcp.invalid_request", refused.errorCode())
        assertEquals(0, core.tokenStore.list(victim).size)

        val minted = client.mcpCall(token, "mint_token").okResult().jsonObject
        assertEquals(caller, core.tokenStore.resolve(assertNotNull(minted.str("token")))?.principal)
        val forbid = assertNotNull(core.cedarPolicyStore.get(-20))
        assertTrue(forbid.enabled, "the shipped token.mint owner forbid is in force")
    }

    @Test
    fun `an owner lists and revokes own tokens, a stranger cannot, an admin can`() = testApplication {
        val client = installControlPlane(config, core)
        val owner = principal("revoke-owner")
        val stranger = principal("revoke-stranger")
        val admin = admin()
        val ownerToken = tokens.token(owner, setOf("mcp:tokens", "mcp:read"))
        val first = client.mcpCall(ownerToken, "mint_token").okResult().jsonObject.getValue("id").jsonPrimitive.long
        val second = client.mcpCall(ownerToken, "mint_token").okResult().jsonObject.getValue("id").jsonPrimitive.long

        assertEquals(
            "common.forbidden",
            client.mcpCall(tokens.token(stranger, setOf("mcp:read")), "list_tokens", buildJsonObject { put("principal", owner) }).errorCode(),
        )
        val strangerRevoke = client.mcpCall(tokens.token(stranger, setOf("mcp:tokens")), "revoke_token", buildJsonObject { put("id", first) })
        assertEquals("common.forbidden", strangerRevoke.errorCode())
        assertNull(core.tokenStore.get(first)?.revokedAt)

        assertEquals("true", client.mcpCall(ownerToken, "revoke_token", buildJsonObject { put("id", first) }).okResult().jsonObject.str("deleted"))
        assertNotNull(core.tokenStore.get(first)?.revokedAt)
        assertEquals("common.not_found", client.mcpCall(ownerToken, "revoke_token", buildJsonObject { put("id", first) }).errorCode())
        assertEquals("common.not_found", client.mcpCall(ownerToken, "revoke_token", buildJsonObject { put("id", Long.MAX_VALUE) }).errorCode())

        val adminToken = tokens.token(admin, setOf("mcp:tokens", "mcp:read"))
        val adminList = client.mcpCall(adminToken, "list_tokens", buildJsonObject { put("principal", owner) }).okResult()
        assertEquals(setOf(first, second), adminList.ids())
        assertEquals("true", client.mcpCall(adminToken, "revoke_token", buildJsonObject { put("id", second) }).okResult().jsonObject.str("deleted"))
        assertEquals(1L, count("SELECT count(*) FROM audit_event WHERE principal=? AND action='auth.token.revoke' AND channel='mcp' AND resource=?", admin, "Token::\"$second\""))

        val direct = APP_JSON.encodeToJsonElement(ListSerializer(WireTokenInfo.serializer()), service().list(owner, null, null))
        assertEquals(direct, client.mcpCall(ownerToken, "list_tokens").okResult())
        val strangerList = assertFailsWith<TaskServiceException> { service().list(stranger, null, owner) }
        assertEquals(HttpStatusCode.Forbidden, strangerList.status)
        assertEquals("common.forbidden", strangerList.error.code)
    }

    @Test
    fun `a deprovisioned principal gets no token`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("gone")
        val token = tokens.token(caller, setOf("mcp:tokens"))
        core.userGroupStore.createUser(AppUserInput(caller, active = false), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null))

        // The bearer is refused before any tool runs, so the service's own locked check is asserted directly too.
        assertEquals(HttpStatusCode.Unauthorized, client.mcpRaw(token, "mint_token").status)
        val refused = assertFailsWith<TaskServiceException> {
            service().mintUser(caller, null, emptyList(), AuditActor(caller, channel = AuditSource.MCP), null, null)
        }
        assertEquals("auth.principal_deprovisioned", refused.error.code)
        assertEquals(0, core.tokenStore.list(caller).size)
    }

    @Test
    fun `mcp read alone cannot mint, and every metadata document advertises mcp tokens`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("readonly")
        val response = client.mcpRaw(tokens.token(caller, setOf("mcp:read")), "mint_token")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertContains(assertNotNull(response.headers[HttpHeaders.WWWAuthenticate]), "scope=\"mcp:tokens\"")
        assertEquals("mcp.insufficient_scope", mcpResult(response.bodyAsText()).errorCode())
        assertEquals(0, core.tokenStore.list(caller).size)

        assertTrue("mcp:tokens" in MCPA_SCOPES)
        for (path in listOf("/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp")) {
            val scopes = parseJson(client.get(path).bodyAsText()).jsonObject.getValue("scopes_supported").jsonArray.map { it.jsonPrimitive.content }
            assertContains(scopes, "mcp:tokens", path)
        }
    }

    private fun service() = TokenService(core.tokenStore, core.userGroupStore, core.authz, core.authAudit)

    private fun JsonElement.ids() = (this as JsonArray).map { it.jsonObject.getValue("id").jsonPrimitive.long }.toSet()

    private fun principal(label: String) = "mcp-token-$label-${seq.incrementAndGet()}@example.com"

    private fun admin(): String {
        val principal = principal("admin")
        core.policyStore.createAssignment(RoleAssignmentInput(principal, assertNotNull(core.policyStore.getRoleByName("system:admin")).id))
        return principal
    }

    private fun count(sql: String, vararg values: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(sql).use { ps ->
            values.forEachIndexed { i, v -> ps.setString(i + 1, v) }
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private companion object {
        // The console's response encoding (App.kt appJson).
        val APP_JSON = Json { encodeDefaults = true; explicitNulls = false }
    }
}
