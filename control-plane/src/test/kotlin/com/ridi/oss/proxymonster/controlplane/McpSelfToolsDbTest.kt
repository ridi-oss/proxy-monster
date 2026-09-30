package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.errorCode
import com.ridi.oss.proxymonster.controlplane.support.installControlPlane
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.str
import io.ktor.client.request.get
import io.ktor.server.testing.testApplication
import io.ktor.client.statement.bodyAsText
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The caller-only tools: permissions, editor query history, rate-reset requests and editor task delete. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpSelfToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var history: QueryHistoryStore
    private lateinit var datasource: Datasource
    private val seq = AtomicInteger()
    private val config = mcpTestConfig()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_self_tools"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource)
        history = QueryHistoryStore(dataSource)
        datasource = core.datasourceStore.create(DatasourceInput("mcp-self-ds", "postgres"))
    }

    @Test
    fun `get_my_permissions carries the console's flags`() = testApplication {
        val client = installControlPlane(config, core)
        for (principal in listOf(principal("plain"), admin())) {
            val mcp = client.mcpCall(tokens.token(principal, setOf("mcp:read")), "get_my_permissions").okResult().jsonObject
            client.login(principal)
            val console = parseJson(client.get("/api/me/permissions").bodyAsText()).jsonObject
            assertEquals(console, JsonObject(mcp.filterKeys { it != "roles" }), principal)
        }
    }

    @Test
    fun `get_my_permissions lists each effective role with every source that grants it`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("roles")
        fun role(name: String) = assertNotNull(core.policyStore.getRoleByName(name))
        core.policyStore.createAssignment(RoleAssignmentInput(caller, role("system:production-viewer").id))
        val user = core.userGroupStore.createUser(AppUserInput(caller), core.tokenStore, core.accessStore, PrincipalSessionStore(dataSource, null))
        val group = core.userGroupStore.createGroup(AppGroupInput("roles-${seq.incrementAndGet()}"))
        core.userGroupStore.addMember(group.id, user.id)
        core.userGroupStore.addGroupRole(group.id, role("system:production-viewer").id)
        core.userGroupStore.addGroupRole(group.id, role("system:development-viewer").id)
        val request = core.accessStore.createRequest(caller, AccessRequestInput(role("system:production-pii-accessor").id))
        assertNotNull(core.accessStore.approve(request.id, 900, "approver@example.com"))
        val grantId = core.accessStore.listGrants(caller, activeOnly = true).single().id

        val roles = client.mcpCall(tokens.token(caller, setOf("mcp:read")), "get_my_permissions").okResult()
            .jsonObject.getValue("roles").jsonArray.associate { entry ->
                val o = entry.jsonObject
                o.str("role") to o.getValue("sources").jsonArray.map { it.jsonObject }
            }

        assertEquals(core.roleResolver.resolve(caller), roles.keys)
        assertEquals(listOf("direct", "group"), roles.getValue("system:production-viewer").map { it.str("kind") })
        assertEquals(listOf("group"), roles.getValue("system:development-viewer").map { it.str("kind") })
        val grant = roles.getValue("system:production-pii-accessor").single()
        assertEquals("grant", grant.str("kind"))
        assertEquals(grantId, grant.getValue("grantId").jsonPrimitive.long)
        assertNotNull(grant.str("expiresAt"))

        core.userGroupStore.setUserActive(caller, false)
        assertEquals(emptyList(), core.roleResolver.resolveWithSources(caller))
    }

    @Test
    fun `query history lists and clears only the caller's own rows`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("history")
        val other = principal("history-other")
        history.add(caller, datasource.id, "SELECT 1")
        history.add(caller, datasource.id, "SELECT 2")
        history.add(other, datasource.id, "SELECT 3")
        val token = tokens.token(caller, setOf("mcp:query"))

        val listed = client.mcpCall(token, "list_query_history").okResult()
        assertEquals(setOf("SELECT 1", "SELECT 2"), listed.jsonArray.map { it.jsonObject.str("sql") }.toSet())
        assertEquals(1, client.mcpCall(token, "list_query_history", buildJsonObject { put("limit", 1) }).okResult().jsonArray.size)
        client.login(caller)
        assertEquals(parseJson(client.get("/api/query-history").bodyAsText()), listed)

        val cleared = client.mcpCall(token, "clear_query_history").okResult()
        assertEquals(2, cleared.jsonObject.getValue("cleared").jsonPrimitive.int)
        assertEquals(0, history.recent(caller, 50).size)
        assertEquals(1, history.recent(other, 50).size)
    }

    @Test
    fun `reset_my_rate opens a rate-reset request and refuses a blank reason`() = testApplication {
        val client = installControlPlane(config, core)
        val caller = principal("rate")
        val token = tokens.token(caller, setOf("mcp:query"))

        val blank = client.mcpCall(token, "reset_my_rate", buildJsonObject { put("reason", " ") })
        assertEquals("common.field_required", blank.errorCode())

        val created = client.mcpCall(token, "reset_my_rate", buildJsonObject {
            put("reason", "month end"); put("denyReason", "rows per hour spent")
        }).okResult().jsonObject
        assertEquals("RATE_RESET", created.str("kind"))
        assertEquals("PENDING", created.str("status"))
        assertEquals(caller, created.str("principal"))
        assertEquals("rows per hour spent", created.str("denyReason"))
    }

    @Test
    fun `delete_query_task deletes only the caller's own task`() = testApplication {
        val client = installControlPlane(config, core)
        val owner = principal("task-owner")
        val stranger = principal("task-stranger")
        val task = core.accessStore.createEditorTask(owner, datasource.id, listOf("SELECT 1"), emptyList(), approver = owner)

        val refused = client.mcpCall(tokens.token(stranger, setOf("mcp:query")), "delete_query_task", buildJsonObject { put("taskId", task.id) })
        assertEquals("false", refused.okResult().jsonObject.str("deleted"))
        assertNotNull(core.accessStore.getRequest(task.id))

        val deleted = client.mcpCall(tokens.token(owner, setOf("mcp:query")), "delete_query_task", buildJsonObject { put("taskId", task.id) })
        assertEquals("true", deleted.okResult().jsonObject.str("deleted"))
        assertNull(core.accessStore.getRequest(task.id))
    }

    private fun principal(label: String) = "mcp-self-$label-${seq.incrementAndGet()}@example.com"

    private fun admin(): String {
        val principal = principal("admin")
        core.policyStore.createAssignment(RoleAssignmentInput(principal, assertNotNull(core.policyStore.getRoleByName("system:admin")).id))
        return principal
    }
}
