package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** The admin MCP tools against their REST routes, which cp-go (support/CpGoStack.kt) serves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpAdminParityToolsCpGoTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var stack: CpGoStack
    private val seq = AtomicInteger()
    private val config = mcpTestConfig().copy(mcpResource = "http://127.0.0.1/mcp")

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_mcp_admin_parity_cpgo")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource, config.mcpResource)
        stack = CpGoStack(config, core, database) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    @Test
    fun `group members and roles match the REST listing`() = runBlocking<Unit> {
        val client = stack.client()
        val admin = admin()
        val n = seq.incrementAndGet()
        val group = core.userGroupStore.createGroup(AppGroupInput("mcp-parity-group-$n"))
        val user = core.userGroupStore.createUser(
            AppUserInput("mcp-parity-member-$n@example.com"), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null),
        )
        core.userGroupStore.addMember(group.id, user.id)
        val role = core.policyStore.createRole(RoleInput("mcp-parity-group-role-$n"))
        core.userGroupStore.addGroupRole(group.id, role.id)
        val token = tokens.token(admin, setOf("mcp:read"))
        client.login(admin)

        val members = client.mcpCall(token, "list_group_members", buildJsonObject { put("groupName", group.name) }).okResult()
        assertEquals(user.principal, members.jsonArray.single().jsonObject.str("principal"))
        assertEquals(parseJson(client.get("/api/groups/${group.id}/members").bodyAsText()), members)

        val roles = client.mcpCall(token, "list_group_roles", buildJsonObject { put("groupName", group.name) }).okResult()
        assertEquals(role.name, roles.jsonArray.single().jsonObject.str("roleName"))
        assertEquals(parseJson(client.get("/api/groups/${group.id}/roles").bodyAsText()), roles)

        val missing = client.mcpCall(token, "list_group_members", buildJsonObject { put("groupName", "no-such-group") })
        assertEquals("common.not_found", missing.errorCode())
        assertEquals("common.not_found", restCode(client.get("/api/groups/${Long.MAX_VALUE}/members")))
    }

    @Test
    fun `a principal rate reset is audited on mcp and read back like REST`() = runBlocking<Unit> {
        val client = stack.client()
        val admin = admin()
        val target = "mcp-rate-target-${seq.incrementAndGet()}@example.com"
        val token = tokens.token(admin, setOf("mcp:read", "mcp:identity:write"))
        client.login(admin)

        val never = client.mcpCall(token, "get_principal_rate", buildJsonObject { put("principal", target) }).okResult()
        assertEquals(JsonNull, never)
        assertEquals(HttpStatusCode.NoContent, client.get("/api/access/principals/$target/rate-reset").status)

        val blank = client.mcpCall(token, "reset_principal_rate", buildJsonObject { put("principal", target); put("reason", " ") })
        assertEquals("common.field_required", blank.errorCode())

        val reset = client.mcpCall(token, "reset_principal_rate", buildJsonObject {
            put("principal", target); put("reason", "support ticket")
        }).okResult().jsonObject
        assertEquals(target, reset.str("principal"))
        assertEquals(admin, reset.str("resetBy"))
        assertEquals(1L, adminRows(admin, "admin.identity", "User::\"$target\""))

        val read = client.mcpCall(token, "get_principal_rate", buildJsonObject { put("principal", target) }).okResult()
        assertEquals(reset, read)
        assertEquals(parseJson(client.get("/api/access/principals/$target/rate-reset").bodyAsText()), read)
    }

    private fun admin(): String {
        val principal = "mcp-admin-${seq.incrementAndGet()}@example.com"
        val role = assertNotNull(core.policyStore.getRoleByName("system:admin"))
        core.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        return principal
    }

    private fun adminRows(principal: String, action: String, resource: String): Long = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT count(*) FROM audit_event WHERE kind='admin' AND channel='mcp' AND principal=? AND action=? AND resource=?",
        ).use { ps ->
            ps.setString(1, principal); ps.setString(2, action); ps.setString(3, resource)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    private suspend fun restCode(response: HttpResponse): String? =
        parseJson(response.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content

    private fun io.ktor.client.request.HttpRequestBuilder.json(body: String) {
        contentType(ContentType.Application.Json)
        setBody(body)
    }
}
