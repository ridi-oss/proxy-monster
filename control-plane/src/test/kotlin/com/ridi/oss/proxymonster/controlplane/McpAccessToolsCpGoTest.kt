package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.McpTokens
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.login
import com.ridi.oss.proxymonster.controlplane.support.mcpCall
import com.ridi.oss.proxymonster.controlplane.support.mcpTestConfig
import com.ridi.oss.proxymonster.controlplane.support.okResult
import com.ridi.oss.proxymonster.controlplane.support.parseJson
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
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

/** The JIT access tools against the REST routes cp-go (support/CpGoStack.kt) serves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpAccessToolsCpGoTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var tokens: McpTokens
    private lateinit var stack: CpGoStack
    private var roleId = 0L
    private val roleName = "mcp-jit-role"
    private val seq = AtomicInteger()
    private val config = mcpTestConfig().copy(mcpResource = "http://127.0.0.1/mcp")

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_mcp_access_tools_cpgo")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        tokens = McpTokens(dataSource, config.mcpResource)
        roleId = core.policyStore.createRole(RoleInput(roleName)).id
        stack = CpGoStack(config, core, database) { routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) } }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    @Test
    fun `request and approve answer the same body as REST`() = runBlocking<Unit> {
        val client = stack.client()
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
        assertEquals("console", restBody.getValue("source").jsonPrimitive.content)
        assertEquals("mcp", mcp.getValue("source").jsonPrimitive.content)

        client.login(admin)
        val restApproved = parseJson(client.post("/api/access-requests/${restBody.getValue("id").jsonPrimitive.long}/approve").bodyAsText()).jsonObject
        val mcpApproved = client.mcpCall(tokens.token(admin, setOf("mcp:approvals:write")), "approve_access_request", buildJsonObject {
            put("id", mcp.getValue("id").jsonPrimitive.long)
        }).okResult().jsonObject
        assertEquals(restApproved - IGNORED, mcpApproved - IGNORED)
    }

    private operator fun JsonObject.minus(keys: Set<String>) = JsonObject(filterKeys { it !in keys })

    private fun principal(label: String) = "mcp-$label-${seq.incrementAndGet()}@example.com"

    private fun admin(): String {
        val principal = principal("admin")
        core.policyStore.createAssignment(RoleAssignmentInput(principal, assertNotNull(core.policyStore.getRoleByName("system:admin")).id))
        return principal
    }

    private fun io.ktor.client.request.HttpRequestBuilder.json(body: String) {
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private companion object {
        val IGNORED = setOf("id", "createdAt", "decidedAt", "source")
    }
}
