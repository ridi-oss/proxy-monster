package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.errorParams
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpWorkloadBindingToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var cpGo: CpGoStack
    private val seq = AtomicInteger()
    private val config = mcpTestConfig().copy(mcpResource = "http://127.0.0.1/mcp")
    private val role = "arn:aws:iam::111122223333:role/batch-settlement"

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_mcp_workload_bindings")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource, config.mcpResource)
        cpGo = CpGoStack(
            config, core, database,
            extraEnv = mapOf("PM_CI_OIDC_ISSUERS" to "aws-prod=https://issuer.example.com"),
            withBridge = true,
        ) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun tearDown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun admin(principal: String = "mcp-wb-admin-${seq.incrementAndGet()}@example.com"): String {
        val admin = assertNotNull(core.policyStore.getRoleByName("system:admin"))
        core.policyStore.createAssignment(RoleAssignmentInput(principal, admin.id))
        return principal
    }

    private fun binding(name: String, extra: JsonObject.() -> JsonObject = { this }) = buildJsonObject {
        put("name", name); put("issuer", "aws-prod"); put("subject", role)
        put("conditions", buildJsonObject { put("aws_account", "111122223333") })
        put("purposes", buildJsonArray { add(JsonPrimitive("mcp")) })
        put("mcpScopes", buildJsonArray { add(JsonPrimitive("mcp:read")) })
        put("idempotencyKey", "k-$name-${seq.incrementAndGet()}")
    }.extra()

    @Test
    fun `create list update and delete a binding through MCP, as the REST route sees it`() = testApplication {
        val client = cpGo.client()
        val admin = admin()
        val token = tokens.token(admin, setOf("mcp:read", "mcp:identity:write"))
        client.login(admin)

        val created = client.mcpCall(token, "create_workload_binding", binding("tf-pmon")).okResult().jsonObject
        assertEquals("svc:tf-pmon", created.str("principal"))
        assertEquals(listOf("111122223333"), created.getValue("conditions").jsonObject.getValue("aws_account").jsonArray.map { it.jsonPrimitive.content })

        val listed = client.mcpCall(token, "list_workload_bindings").okResult().jsonObject.getValue("bindings")
        assertEquals(parseJson(client.get("/api/workload-bindings").bodyAsText()), listed)

        val disabled = client.mcpCall(
            token, "update_workload_binding",
            binding("tf-pmon") { JsonObject(this + ("enabled" to JsonPrimitive(false))) },
        ).okResult().jsonObject
        assertEquals(false, disabled.getValue("enabled").jsonPrimitive.boolean)
        assertEquals(created.getValue("id"), disabled.getValue("id"))

        val invalid = client.mcpCall(token, "create_workload_binding", binding("other") { JsonObject(this + ("issuer" to JsonPrimitive("gitlab"))) })
        assertEquals("common.invalid_value", invalid.errorCode())
        assertEquals("issuer", invalid.errorParams().str("field"))
        val duplicate = client.mcpCall(token, "create_workload_binding", binding("tf-pmon"))
        assertEquals("common.already_exists", duplicate.errorCode())

        val deleted = client.mcpCall(token, "delete_workload_binding", buildJsonObject { put("name", "tf-pmon"); put("idempotencyKey", "del-1") })
        assertEquals(true, deleted.okResult().jsonObject.getValue("deleted").jsonPrimitive.boolean)
        assertEquals("common.not_found", client.mcpCall(token, "delete_workload_binding", buildJsonObject { put("name", "tf-pmon") }).errorCode())
        assertEquals(JsonArray(emptyList()), client.mcpCall(token, "list_workload_bindings").okResult().jsonObject.getValue("bindings"))
        assertEquals(3L, adminRows(admin))
    }

    @Test
    fun `binding writes need the identity scope and the admin role`() = testApplication {
        val client = cpGo.client()
        val admin = admin()
        val readOnly = tokens.token(admin, setOf("mcp:read"))
        assertEquals("mcp.insufficient_scope", client.mcpCall(readOnly, "create_workload_binding", binding("scoped")).errorCode())
        val plain = "mcp-wb-plain-${seq.incrementAndGet()}@example.com"
        val plainToken = tokens.token(plain, setOf("mcp:read", "mcp:identity:write"))
        assertEquals("common.forbidden", client.mcpCall(plainToken, "list_workload_bindings").errorCode())
        assertEquals("common.forbidden", client.mcpCall(plainToken, "create_workload_binding", binding("denied")).errorCode())
    }

    @Test
    fun `an MCP token minted by a workload exchange serves its service principal`() = testApplication {
        val client = cpGo.client()
        val principal = admin("svc:tf-${seq.incrementAndGet()}")
        val token = "pma_" + java.util.UUID.randomUUID()
        dataSource.connection.use { c ->
            val binding = c.prepareStatement(
                """INSERT INTO workload_binding (name, issuer, subject, principal, purposes, mcp_scopes)
                   VALUES (?, 'aws-prod', ?, ?, ARRAY['mcp'], ARRAY['mcp:read']) RETURNING id""",
            ).use { ps ->
                ps.setString(1, principal.removePrefix("svc:")); ps.setString(2, role); ps.setString(3, principal)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            val clientId = "workload:" + principal.removePrefix("svc:")
            val consent = c.prepareStatement(
                "INSERT INTO oauth_consent (principal, client_id, resource, scope) VALUES (?, ?, ?, 'mcp:read') RETURNING id",
            ).use { ps ->
                ps.setString(1, principal); ps.setString(2, clientId); ps.setString(3, config.mcpResource)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            c.prepareStatement(
                """INSERT INTO proxy_token (token_hash, kind, principal, expires_at, resource, client_id, scope, refresh_family, consent_id, workload_binding_id)
                   VALUES (?, 'MCP_ACCESS', ?, now() + interval '10 minutes', ?, ?, 'mcp:read', ?, ?, ?)""",
            ).use { ps ->
                ps.setString(1, sha256Hex(token)); ps.setString(2, principal); ps.setString(3, config.mcpResource)
                ps.setString(4, clientId); ps.setString(5, "pmf_$token"); ps.setLong(6, consent); ps.setLong(7, binding)
                ps.executeUpdate()
            }
        }
        val listed = client.mcpCall(token, "list_workload_bindings").okResult().jsonObject.getValue("bindings").jsonArray
        assertEquals(principal, listed.single { it.jsonObject.str("principal") == principal }.jsonObject.str("principal"))
        assertEquals("mcp.insufficient_scope", client.mcpCall(token, "create_workload_binding", binding("nope")).errorCode())
    }

    private fun adminRows(principal: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT count(*) FROM audit_event WHERE kind='admin' AND channel='mcp' AND principal=? AND action='admin.identity' AND resource LIKE 'WorkloadBinding::%'",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }
}
