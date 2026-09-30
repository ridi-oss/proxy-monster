package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
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
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
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
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The JIT access tools: request, approve and reject, grants and revoke, each against its REST route. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpAccessToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var datasource: Datasource
    private var roleId = 0L
    private val roleName = "mcp-jit-role"
    private val seq = AtomicInteger()
    private val config = mcpTestConfig()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_access_tools"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource)
        roleId = core.policyStore.createRole(RoleInput(roleName)).id
        datasource = core.datasourceStore.create(DatasourceInput("mcp-jit-ds", "postgres"))
    }

    @Test
    fun `a JIT request is approved, listed as a grant and revoked`() = testApplication {
        val client = installControlPlane(config, core)
        val requester = principal("requester")
        val admin = admin()
        val requesterToken = tokens.token(requester, setOf("mcp:query", "mcp:approvals:write"))
        val adminToken = tokens.token(admin, setOf("mcp:query", "mcp:approvals:write"))

        val created = client.mcpCall(requesterToken, "request_access", buildJsonObject {
            put("roleName", roleName); put("reason", "on call"); put("datasource", datasource.name); put("durationSec", 600)
        }).okResult().jsonObject
        val id = created.getValue("id").jsonPrimitive.long
        assertEquals("PENDING", created.str("status"))
        assertEquals(datasource.name, created.str("datasourceName"))
        assertEquals(1L, adminRows(requester, "task.request", "AccessRequest::\"$id\""))

        val listed = client.mcpCall(requesterToken, "list_access_requests", buildJsonObject { put("status", "PENDING") }).okResult()
        assertTrue(listed.jsonArray.ids().contains(id))

        val approved = client.mcpCall(adminToken, "approve_access_request", buildJsonObject { put("id", id); put("durationSec", 300) })
            .okResult().jsonObject
        assertEquals("APPROVED", approved.str("status"))
        assertTrue(roleName in core.roleResolver.resolve(requester))

        val grants = client.mcpCall(requesterToken, "list_access_grants", buildJsonObject { put("active", true) }).okResult().jsonArray
        val grant = grants.single { it.jsonObject.str("roleName") == roleName }.jsonObject
        val grantId = grant.getValue("id").jsonPrimitive.long

        val revoked = client.mcpCall(requesterToken, "revoke_access_grant", buildJsonObject { put("id", grantId) }).okResult()
        assertEquals("true", revoked.jsonObject.str("deleted"))
        assertTrue(roleName !in core.roleResolver.resolve(requester))
        assertEquals(1L, adminRows(requester, "grant.revoke", "AccessGrant::\"$grantId\""))
        assertEquals("common.not_found", client.mcpCall(requesterToken, "revoke_access_grant", buildJsonObject { put("id", grantId) }).errorCode())
    }

    @Test
    fun `a requester cannot approve or reject their own request`() = testApplication {
        val client = installControlPlane(config, core)
        val requester = admin()
        val id = core.accessStore.createRequest(requester, AccessRequestInput(roleId = roleId)).id
        val token = tokens.token(requester, setOf("mcp:query", "mcp:approvals:write"))

        assertEquals("approval.not_approver", client.mcpCall(token, "approve_access_request", buildJsonObject { put("id", id) }).errorCode())
        assertEquals(
            "approval.not_approver",
            client.mcpCall(token, "reject_access_request", buildJsonObject { put("id", id); put("reason", "no") }).errorCode(),
        )
        assertEquals("PENDING", core.accessStore.getRequest(id)?.status)

        client.login(requester)
        val rest = client.post("/api/access-requests/$id/approve")
        assertEquals(HttpStatusCode.Forbidden, rest.status)
        assertEquals("approval.not_approver", code(rest))
    }

    @Test
    fun `an approver rejects with a reason the requester sees`() = testApplication {
        val client = installControlPlane(config, core)
        val requester = principal("rejected")
        val id = core.accessStore.createRequest(requester, AccessRequestInput(roleId = roleId, reason = "please")).id
        val token = tokens.token(admin(), setOf("mcp:approvals:write"))
        val rejected = client.mcpCall(token, "reject_access_request", buildJsonObject { put("id", id); put("reason", "not today") })
            .okResult().jsonObject
        assertEquals("REJECTED", rejected.str("status"))
        assertEquals("not today", rejected.str("rejectionReason"))
    }

    @Test
    fun `a query approval id is refused toward the query approval tools`() = testApplication {
        val client = installControlPlane(config, core)
        val requester = principal("query")
        val id = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = datasource.id, statements = listOf("SELECT 1"), denyReason = null,
            sourceDecisionId = null, reason = "r", title = "t", evaluatedDecision = "DENY", roleId = roleId,
        ).id
        val token = tokens.token(admin(), setOf("mcp:approvals:write"))
        assertEquals(
            "approval.use_query_approval_endpoint",
            client.mcpCall(token, "approve_access_request", buildJsonObject { put("id", id) }).errorCode(),
        )
        assertEquals(
            "approval.use_query_approval_endpoint",
            client.mcpCall(token, "reject_access_request", buildJsonObject { put("id", id); put("reason", "r") }).errorCode(),
        )
        assertEquals("common.not_found", client.mcpCall(token, "approve_access_request", buildJsonObject { put("id", Long.MAX_VALUE) }).errorCode())
    }

    @Test
    fun `a stranger sees neither the requests nor the grants of another, and principal does not widen it`() = testApplication {
        val client = installControlPlane(config, core)
        val owner = principal("owner")
        val stranger = principal("stranger")
        val request = core.accessStore.createRequest(owner, AccessRequestInput(roleId = roleId))
        core.accessStore.approve(request.id, 3600, "someone-else")
        val strangerToken = tokens.token(stranger, setOf("mcp:query"))
        val ownerToken = tokens.token(owner, setOf("mcp:query"))

        assertTrue(request.id !in client.mcpCall(strangerToken, "list_access_requests").okResult().jsonArray.ids())
        assertTrue(request.id in client.mcpCall(ownerToken, "list_access_requests").okResult().jsonArray.ids())
        val strangerGrants = client.mcpCall(strangerToken, "list_access_grants", buildJsonObject { put("principal", owner) }).okResult()
        assertEquals(JsonArray(emptyList()), strangerGrants)
        val ownerGrants = client.mcpCall(ownerToken, "list_access_grants", buildJsonObject { put("principal", owner) }).okResult()
        assertEquals(1, ownerGrants.jsonArray.size)

        client.login(stranger)
        assertEquals(parseJson(client.get("/api/access-grants?principal=$owner").bodyAsText()), strangerGrants)
        assertEquals(
            parseJson(client.get("/api/access-requests").bodyAsText()),
            client.mcpCall(strangerToken, "list_access_requests").okResult(),
        )
    }

    @Test
    fun `a denied task request answers request_not_permitted on both surfaces`() = testApplication {
        val client = installControlPlane(config, core)
        val requester = principal("forbidden")
        val policy = core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-no-request-${seq.incrementAndGet()}",
                """forbid(principal == User::"$requester", action == Action::"task.request", resource);""",
            ),
            "test",
        )
        try {
            val token = tokens.token(requester, setOf("mcp:query"))
            val refused = client.mcpCall(token, "request_access", buildJsonObject {
                put("roleName", roleName); put("reason", "r"); put("datasource", datasource.name)
            })
            assertEquals("approval.request_not_permitted", refused.errorCode())

            client.login(requester)
            val rest = client.post("/api/access-requests") { json("""{"roleId":$roleId,"datasourceId":${datasource.id},"reason":"r"}""") }
            assertEquals(HttpStatusCode.Forbidden, rest.status)
            assertEquals("approval.request_not_permitted", code(rest))
            assertTrue(core.accessStore.listRequests(null).none { it.principal == requester })
        } finally {
            core.cedarPolicyStore.delete(policy.id)
        }
        val unknownRole = client.mcpCall(tokens.token(requester, setOf("mcp:query")), "request_access", buildJsonObject {
            put("roleName", "no-such-role"); put("reason", "r")
        })
        assertEquals("common.not_found", unknownRole.errorCode())
    }

    @Test
    fun `a grant is revoked only by its owner or an admin`() = testApplication {
        val client = installControlPlane(config, core)
        val owner = principal("grant-owner")
        val other = principal("grant-other")
        val request = core.accessStore.createRequest(owner, AccessRequestInput(roleId = roleId))
        core.accessStore.approve(request.id, 3600, "someone-else")
        val grantId = core.accessStore.listGrants(owner, true).single().id

        val refused = client.mcpCall(tokens.token(other, setOf("mcp:approvals:write")), "revoke_access_grant", buildJsonObject { put("id", grantId) })
        assertEquals("common.forbidden", refused.errorCode())
        assertNull(core.accessStore.getGrant(grantId)?.revokedAt)

        client.login(other)
        val rest = client.post("/api/access-grants/$grantId/revoke")
        assertEquals(HttpStatusCode.Forbidden, rest.status)
        assertEquals("common.forbidden", code(rest))

        val byAdmin = client.mcpCall(tokens.token(admin(), setOf("mcp:approvals:write")), "revoke_access_grant", buildJsonObject { put("id", grantId) })
        assertEquals("true", byAdmin.okResult().jsonObject.str("deleted"))
        assertNotNull(core.accessStore.getGrant(grantId)?.revokedAt)
    }

    @Test
    fun `request and approve answer the same body as REST`() = testApplication {
        val client = installControlPlane(config, core)
        val requester = principal("parity")
        val admin = admin()
        client.login(requester)
        val rest = client.post("/api/access-requests") { json("""{"roleId":$roleId,"reason":"parity"}""") }
        assertEquals(HttpStatusCode.Created, rest.status)
        val restBody = parseJson(rest.bodyAsText()).jsonObject
        val mcp = client.mcpCall(tokens.token(requester, setOf("mcp:query")), "request_access", buildJsonObject {
            put("roleName", roleName); put("reason", "parity")
        }).okResult().jsonObject
        assertEquals(restBody - IGNORED, mcp - IGNORED)

        client.login(admin)
        val restApproved = parseJson(client.post("/api/access-requests/${restBody.getValue("id").jsonPrimitive.long}/approve").bodyAsText()).jsonObject
        val mcpApproved = client.mcpCall(tokens.token(admin, setOf("mcp:approvals:write")), "approve_access_request", buildJsonObject {
            put("id", mcp.getValue("id").jsonPrimitive.long)
        }).okResult().jsonObject
        assertEquals(restApproved - IGNORED, mcpApproved - IGNORED)
    }

    private fun JsonArray.ids() = map { it.jsonObject.getValue("id").jsonPrimitive.long }

    private operator fun JsonObject.minus(keys: Set<String>) = JsonObject(filterKeys { it !in keys })

    private fun principal(label: String) = "mcp-$label-${seq.incrementAndGet()}@example.com"

    private fun admin(): String {
        val principal = principal("admin")
        core.policyStore.createAssignment(RoleAssignmentInput(principal, assertNotNull(core.policyStore.getRoleByName("system:admin")).id))
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

    private suspend fun code(response: HttpResponse): String? = parseJson(response.bodyAsText()).jsonObject["code"]?.jsonPrimitive?.content

    private fun io.ktor.client.request.HttpRequestBuilder.json(body: String) {
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private companion object {
        val IGNORED = setOf("id", "createdAt", "decidedAt")
    }
}

