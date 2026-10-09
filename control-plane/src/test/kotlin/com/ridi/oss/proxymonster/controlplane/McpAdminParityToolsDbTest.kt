package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpRaw
import com.ridi.oss.proxymonster.controlplane.support.mcpResult
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The admin tools for group members and roles, principal rates, and datasource CRUD, each against its REST route or service. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpAdminParityToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private val seq = AtomicInteger()
    private val config = mcpTestConfig()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_admin_parity"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource)
    }

    @Test
    fun `group members and roles match the REST listing`() = testApplication {
        val client = installControlPlane(config, core)
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
    fun `a principal rate reset is audited on mcp and read back like the service`() = testApplication {
        val client = installControlPlane(config, core)
        val admin = admin()
        val target = "mcp-rate-target-${seq.incrementAndGet()}@example.com"
        val token = tokens.token(admin, setOf("mcp:read", "mcp:identity:write"))
        val access = AccessService(core.accessStore, core.datasourceStore, core.auditStore, core.roleResolver, core.authz, ManagementAuditRecorder(core.auditStore))

        val never = client.mcpCall(token, "get_principal_rate", buildJsonObject { put("principal", target) }).okResult()
        assertEquals(JsonNull, never)
        assertNull(access.lastRateReset(target))

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
        assertEquals(Json.encodeToJsonElement(RateReset.serializer(), assertNotNull(access.lastRateReset(target))), read)
    }

    @Test
    fun `datasource create update refresh test and delete through MCP`() = testApplication {
        val client = installControlPlane(config, core)
        val admin = admin()
        val n = seq.incrementAndGet()
        val name = "mcp-crud-$n"
        val token = tokens.token(admin, setOf("mcp:read", "mcp:datasources:write"))
        client.login(admin)

        val created = client.mcpCall(token, "create_datasource", buildJsonObject {
            put("name", name); put("engine", "MySQL"); put("host", "db.internal"); put("port", 3306); put("dbName", "app")
        }).okResult().jsonObject
        assertEquals("mysql", created.str("engine"))
        val id = created.getValue("id").jsonPrimitive.long
        assertEquals("db.internal", core.datasourceStore.get(id)?.host)
        assertEquals(1L, adminRows(admin, "admin.datasources", "Datasource::\"$name\""))

        val rest = client.post("/api/datasources") { json("""{"name":"mcp-crud-rest-$n","engine":"mysql","host":"db.internal","port":3306,"dbName":"app"}""") }
        assertEquals(HttpStatusCode.Created, rest.status)
        val restCreated = parseJson(rest.bodyAsText()).jsonObject
        assertEquals(restCreated.keys, created.keys)

        val updated = client.mcpCall(token, "update_datasource", buildJsonObject {
            put("datasource", name); put("newName", "$name-renamed"); put("port", 3307)
        }).okResult().jsonObject
        assertEquals("$name-renamed", updated.str("name"))
        assertEquals(3307, updated.getValue("port").jsonPrimitive.int)
        assertEquals("db.internal", updated.str("host"), "an omitted field keeps its value")
        assertEquals("app", updated.str("dbName"))
        val restUpdated = client.put("/api/datasources/${restCreated.getValue("id").jsonPrimitive.long}") {
            json("""{"name":"mcp-crud-rest-$n","engine":"mysql","host":"db.internal","port":3307,"dbName":"app"}""")
        }
        assertEquals(HttpStatusCode.OK, restUpdated.status)
        assertEquals(parseJson(restUpdated.bodyAsText()).jsonObject.keys, updated.keys)

        val refreshed = client.mcpCall(token, "refresh_datasource", buildJsonObject { put("datasource", "$name-renamed") }).okResult()
        assertEquals(parseJson(client.post("/api/datasources/$id/refresh").bodyAsText()), refreshed)
        val tested = client.mcpCall(token, "test_datasource", buildJsonObject { put("datasource", "$name-renamed") }).okResult()
        assertEquals(parseJson(client.post("/api/datasources/$id/test").bodyAsText()), tested)
        assertEquals("false", tested.jsonObject.str("ok"))

        val deleted = client.mcpCall(token, "delete_datasource", buildJsonObject { put("datasource", "$name-renamed") }).okResult()
        assertEquals("true", deleted.jsonObject.str("deleted"))
        assertEquals(null, core.datasourceStore.get(id))
        assertEquals("common.not_found", client.mcpCall(token, "delete_datasource", buildJsonObject { put("datasource", "$name-renamed") }).errorCode())
    }

    @Test
    fun `invalid engine, engine change and in-use delete answer REST's codes`() = testApplication {
        val client = installControlPlane(config, core)
        val admin = admin()
        val n = seq.incrementAndGet()
        val token = tokens.token(admin, setOf("mcp:read", "mcp:datasources:write"))
        client.login(admin)

        val invalid = client.mcpCall(token, "create_datasource", buildJsonObject { put("name", "mcp-bad-$n"); put("engine", "oracle") })
        assertEquals("datasource.invalid_engine", invalid.errorCode())
        assertEquals("oracle", invalid.getValue("structuredContent").jsonObject.getValue("params").jsonObject.str("engine"))
        val restInvalid = client.post("/api/datasources") { json("""{"name":"mcp-bad-rest-$n","engine":"oracle"}""") }
        assertEquals(HttpStatusCode.BadRequest, restInvalid.status)
        assertEquals("datasource.invalid_engine", restCode(restInvalid))
        assertEquals(null, core.datasourceStore.getByName("mcp-bad-$n"))

        val ds = core.datasourceStore.create(DatasourceInput("mcp-immutable-$n", "postgres"))
        val immutable = client.mcpCall(token, "update_datasource", buildJsonObject { put("datasource", ds.name); put("engine", "mysql") })
        assertEquals("datasource.engine_immutable", immutable.errorCode())
        val restImmutable = client.put("/api/datasources/${ds.id}") { json("""{"name":"${ds.name}","engine":"mysql"}""") }
        assertEquals(HttpStatusCode.Conflict, restImmutable.status)
        assertEquals("datasource.engine_immutable", restCode(restImmutable))

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
        val client = installControlPlane(config, core)
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
        val client = installControlPlane(config, core)
        val outsider = "mcp-outsider-${seq.incrementAndGet()}@example.com"
        val token = tokens.token(outsider, setOf("mcp:read", "mcp:identity:write", "mcp:datasources:write"))
        client.login(outsider)
        val group = core.userGroupStore.createGroup(AppGroupInput("mcp-outsider-group-${seq.incrementAndGet()}"))
        val ds = core.datasourceStore.create(DatasourceInput("mcp-outsider-ds-${seq.incrementAndGet()}", "postgres"))

        for (tool in READS + WRITES.keys) {
            val response = client.mcpRaw(token, tool, argsFor(tool, group.name, ds.name))
            assertEquals(HttpStatusCode.Forbidden, response.status, tool)
            assertEquals("common.forbidden", mcpResult(response.bodyAsText()).errorCode(), tool)
        }
        val rest = listOf(
            client.get("/api/groups/${group.id}/members"),
            client.get("/api/groups/${group.id}/roles"),
            client.post("/api/datasources") { json("""{"name":"mcp-outsider-new"}""") },
            client.put("/api/datasources/${ds.id}") { json("""{"name":"${ds.name}"}""") },
            client.delete("/api/datasources/${ds.id}"),
            client.post("/api/datasources/${ds.id}/refresh"),
            client.post("/api/datasources/${ds.id}/test"),
        )
        for (response in rest) {
            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertEquals("common.forbidden", restCode(response))
        }
        assertEquals(null, core.datasourceStore.getByName("mcp-outsider-new"))
        assertNotNull(core.datasourceStore.get(ds.id))
    }

    private fun argsFor(tool: String, group: String = "g", ds: String = "d"): JsonObject = buildJsonObject {
        when (tool) {
            "list_group_members", "list_group_roles" -> put("groupName", group)
            "get_principal_rate" -> put("principal", "someone")
            "reset_principal_rate" -> { put("principal", "someone"); put("reason", "r") }
            "create_datasource" -> put("name", "mcp-outsider-new")
            else -> put("datasource", ds)
        }
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

    private companion object {
        val READS = listOf("list_group_members", "list_group_roles", "get_principal_rate")
        val WRITES = mapOf(
            "reset_principal_rate" to "mcp:identity:write",
            "create_datasource" to "mcp:datasources:write",
            "update_datasource" to "mcp:datasources:write",
            "delete_datasource" to "mcp:datasources:write",
            "refresh_datasource" to "mcp:datasources:write",
            "test_datasource" to "mcp:datasources:write",
        )
    }
}

