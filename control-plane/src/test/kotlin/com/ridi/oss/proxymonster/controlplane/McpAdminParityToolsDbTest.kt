package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpRaw
import com.ridi.oss.proxymonster.controlplane.support.mcpResult
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import io.ktor.server.routing.routing
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** The admin tools for group members and roles, and datasource CRUD, each against its REST route. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpAdminParityToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var cpGo: CpGoStack
    private val seq = AtomicInteger()
    private val config = mcpTestConfig().copy(mcpResource = "http://127.0.0.1/mcp")

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_mcp_admin_parity")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource, config.mcpResource)
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun tearDown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    @Test
    fun `group members and roles match the REST listing`() = testApplication {
        val client = cpGo.client()
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
    fun `datasource refresh test and delete through MCP`() = testApplication {
        val client = cpGo.client()
        val admin = admin()
        val name = "mcp-crud-${seq.incrementAndGet()}"
        val token = tokens.token(admin, setOf("mcp:read", "mcp:datasources:write"))
        client.login(admin)
        val id = core.datasourceStore.registerOnly(name, "mysql").id

        val refreshed = client.mcpCall(token, "refresh_datasource", buildJsonObject { put("datasource", name) }).okResult()
        assertEquals(parseJson(client.post("/api/datasources/$id/refresh").bodyAsText()), refreshed)
        val tested = client.mcpCall(token, "test_datasource", buildJsonObject { put("datasource", name) }).okResult()
        assertEquals(parseJson(client.post("/api/datasources/$id/test").bodyAsText()), tested)
        assertEquals("false", tested.jsonObject.str("ok"))

        val deleted = client.mcpCall(token, "delete_datasource", buildJsonObject { put("datasource", name) }).okResult()
        assertEquals("true", deleted.jsonObject.str("deleted"))
        assertEquals(null, core.datasourceStore.get(id))
        assertEquals("common.not_found", client.mcpCall(token, "delete_datasource", buildJsonObject { put("datasource", name) }).errorCode())
    }

    @Test
    fun `in-use delete answers REST's code`() = testApplication {
        val client = cpGo.client()
        val admin = admin()
        val n = seq.incrementAndGet()
        val token = tokens.token(admin, setOf("mcp:read", "mcp:datasources:write"))
        client.login(admin)
        val ds = core.datasourceStore.registerOnly("mcp-in-use-$n", "postgres")

        val role = core.policyStore.createRole(RoleInput("mcp-in-use-role-$n"))
        core.accessStore.createRequest("requester-$n@example.com", AccessRequestInput(roleId = role.id, datasourceId = ds.id))
        val inUse = client.mcpCall(token, "delete_datasource", buildJsonObject { put("datasource", ds.name) })
        assertEquals("datasource.in_use_active_requests", inUse.errorCode())
        val restInUse = client.delete("/api/datasources/${ds.id}")
        assertEquals(HttpStatusCode.Conflict, restInUse.status)
        assertEquals("datasource.in_use_active_requests", restCode(restInUse))
        assertNotNull(core.datasourceStore.get(ds.id))
    }

    @Test
    fun `scope is a ceiling on every new admin tool`() = testApplication {
        val client = cpGo.client()
        val admin = admin()
        val queryOnly = tokens.token(admin, setOf("mcp:query"))
        val readOnly = tokens.token(admin, setOf("mcp:read"))
        for ((tool, scope) in READS.map { it to "mcp:read" } + WRITES.toList()) {
            val response = client.mcpRaw(if (scope == "mcp:read") queryOnly else readOnly, tool, argsFor(tool))
            assertEquals(HttpStatusCode.Forbidden, response.status, tool)
            assertContains(assertNotNull(response.headers[HttpHeaders.WWWAuthenticate]), "scope=\"$scope\"", message = tool)
            assertEquals("mcp.insufficient_scope", mcpResult(response.bodyAsText()).errorCode(), tool)
        }
    }

    @Test
    fun `a non-admin is refused by Cedar on MCP exactly as on REST`() = testApplication {
        val client = cpGo.client()
        val outsider = "mcp-outsider-${seq.incrementAndGet()}@example.com"
        val token = tokens.token(outsider, setOf("mcp:read", "mcp:identity:write", "mcp:datasources:write"))
        client.login(outsider)
        val group = core.userGroupStore.createGroup(AppGroupInput("mcp-outsider-group-${seq.incrementAndGet()}"))
        val ds = core.datasourceStore.registerOnly("mcp-outsider-ds-${seq.incrementAndGet()}", "postgres")

        for (tool in READS + WRITES.keys) {
            val response = client.mcpRaw(token, tool, argsFor(tool, group.name, ds.name))
            assertEquals(HttpStatusCode.Forbidden, response.status, tool)
            assertEquals("common.forbidden", mcpResult(response.bodyAsText()).errorCode(), tool)
        }
        val rest = listOf(
            client.get("/api/groups/${group.id}/members"),
            client.get("/api/groups/${group.id}/roles"),
            client.delete("/api/datasources/${ds.id}"),
            client.post("/api/datasources/${ds.id}/refresh"),
            client.post("/api/datasources/${ds.id}/test"),
        )
        for (response in rest) {
            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertEquals("common.forbidden", restCode(response))
        }
        assertNotNull(core.datasourceStore.get(ds.id))
    }

    private fun argsFor(tool: String, group: String = "g", ds: String = "d"): JsonObject = buildJsonObject {
        when (tool) {
            "list_group_members", "list_group_roles" -> put("groupName", group)
            else -> put("datasource", ds)
        }
    }

    private fun admin(): String {
        val principal = "mcp-admin-${seq.incrementAndGet()}@example.com"
        val role = assertNotNull(core.policyStore.getRoleByName("system:admin"))
        core.policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        return principal
    }

    private suspend fun restCode(response: HttpResponse): String? =
        parseJson(response.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content

    private companion object {
        val READS = listOf("list_group_members", "list_group_roles")
        val WRITES = mapOf(
            "delete_datasource" to "mcp:datasources:write",
            "refresh_datasource" to "mcp:datasources:write",
            "test_datasource" to "mcp:datasources:write",
        )
    }
}

