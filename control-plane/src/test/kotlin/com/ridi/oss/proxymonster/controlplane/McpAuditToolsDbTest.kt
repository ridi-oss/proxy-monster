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
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.server.testing.testApplication
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
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * list_audit and get_audit_event decide exactly as the REST audit routes do: own rows by default, every row
 * under an audit.read grant on the whole log, and a hidden record indistinguishable from a missing one.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpAuditToolsDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var aliceIds: Set<Long>
    private lateinit var bobIds: Set<Long>
    private val config = mcpTestConfig()

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_audit_tools"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource)
        core.policyStore.createAssignment(RoleAssignmentInput(AUDITOR, assertNotNull(core.policyStore.getRoleByName("system:admin")).id))
        aliceIds = setOf(insert(ALICE, "select alice_one"), insert(ALICE, "select alice_two"))
        bobIds = setOf(insert(BOB, "select bob_one"), insert(BOB, "select bob_two"))
    }

    @Test
    fun `an ordinary principal lists own rows and a hidden record reads as missing`() = testApplication {
        val client = installControlPlane(config, core)
        val token = tokens.token(ALICE, setOf("mcp:read"))

        val listed = client.mcpCall(token, "list_audit", buildJsonObject { put("limit", 500) }).okResult()
        assertTrue(listed.ids().containsAll(aliceIds))
        assertTrue(listed.ids().none { it in bobIds })
        assertTrue(listed.jsonArray.all { it.jsonObject.getValue("principal").jsonPrimitive.content == ALICE })

        val own = client.mcpCall(token, "get_audit_event", buildJsonObject { put("id", aliceIds.first()) }).okResult()
        assertEquals(aliceIds.first(), own.jsonObject.getValue("id").jsonPrimitive.long)

        val hidden = client.mcpCall(token, "get_audit_event", buildJsonObject { put("id", bobIds.first()) })
        val missing = client.mcpCall(token, "get_audit_event", buildJsonObject { put("id", Long.MAX_VALUE) })
        assertEquals("common.not_found", hidden.errorCode())
        assertEquals(hidden.getValue("structuredContent"), missing.getValue("structuredContent"))
        assertEquals("audit record", hidden.getValue("structuredContent").jsonObject.getValue("params").jsonObject.getValue("resource").jsonPrimitive.content)

    }

    @Test
    fun `a system admin sees every principal's rows`() = testApplication {
        val client = installControlPlane(config, core)
        val token = tokens.token(AUDITOR, setOf("mcp:read"))
        val listed = client.mcpCall(token, "list_audit", buildJsonObject { put("limit", 500) }).okResult()
        assertTrue(listed.ids().containsAll(aliceIds + bobIds))
        for (id in bobIds) {
            assertEquals(id, client.mcpCall(token, "get_audit_event", buildJsonObject { put("id", id) }).okResult().jsonObject.getValue("id").jsonPrimitive.long)
        }
    }

    @Test
    fun `an IP-gated audit read falls back to own rows`() = testApplication {
        val client = installControlPlane(config, core)
        val role = core.policyStore.createRole(RoleInput("mcp-ip-auditor"))
        core.policyStore.createAssignment(RoleAssignmentInput(EDGE_AUDITOR, role.id))
        val policy = core.cedarPolicyStore.create(
            CedarPolicyInput(
                "mcp-ip-gated-audit-read",
                """permit(principal in Role::"mcp-ip-auditor", action == Action::"audit.read", resource)
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            "test",
        )
        try {
            val token = tokens.token(EDGE_AUDITOR, setOf("mcp:read"))
            for ((ip, seesAll) in listOf("203.0.113.10" to true, "198.51.100.10" to false)) {
                val mcp = client.mcpCall(token, "list_audit", buildJsonObject { put("limit", 500) }, forwardedFor = ip).okResult()
                assertEquals(seesAll, mcp.ids().containsAll(aliceIds + bobIds), ip)
                val detail = client.mcpCall(token, "get_audit_event", buildJsonObject { put("id", bobIds.first()) }, forwardedFor = ip)
                if (seesAll) detail.okResult() else assertEquals("common.not_found", detail.errorCode())
            }
        } finally {
            core.cedarPolicyStore.delete(policy.id)
        }
    }

    @Test
    fun `limit is clamped like REST`() = testApplication {
        val client = installControlPlane(config, core)
        val token = tokens.token(AUDITOR, setOf("mcp:read"))
        assertEquals(1, client.mcpCall(token, "list_audit", buildJsonObject { put("limit", 1) }).okResult().jsonArray.size)
        assertEquals("mcp.invalid_request", client.mcpCall(token, "list_audit", buildJsonObject { put("limit", "ten") }).errorCode())
    }

    private fun JsonElement.ids() = jsonArray.map { it.jsonObject.getValue("id").jsonPrimitive.long }

    private fun insert(principal: String, statement: String): Long =
        core.auditStore.insert(AuditEvent(principal = principal, datasource = "acme", statement = statement, decision = Decision.ALLOW))

    private companion object {
        const val ALICE = "mcp-audit-alice"
        const val BOB = "mcp-audit-bob"
        const val AUDITOR = "mcp-audit-admin"
        const val EDGE_AUDITOR = "mcp-edge-auditor"
    }
}

