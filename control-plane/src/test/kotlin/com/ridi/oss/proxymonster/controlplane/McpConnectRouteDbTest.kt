package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.mcp.mcpConnectRoute
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.flywaydb.core.Flyway
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals

class McpConnectRouteDbTest {
    private val dataSource: DataSource by lazy {
        requireDockerOrSkip()
        SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_mcp_connect"))
            .also { Flyway.configure().dataSource(it).load().migrate() }
    }

    private fun connect(env: Map<String, String>, login: Boolean): Pair<HttpStatusCode, String> {
        val config = Config.fromEnv { env[it] }
        var result: Pair<HttpStatusCode, String>? = null
        testApplication {
            val sessions = PrincipalSessionStore(dataSource, null)
            application {
                attributes.put(PRINCIPAL_SESSION_STORE, sessions)
                install(ContentNegotiation) { json(Json { encodeDefaults = true }) }
                install(Sessions) { webSessionCookie(sessions, config.sessionSecret) }
                routing {
                    testLoginRoute(sessions, config)
                    mcpConnectRoute(config)
                }
            }
            val client = createClient { expectSuccess = false; install(HttpCookies) }
            if (login) client.post("/test/session/agent-user@example.com")
            val response = client.get("/api/mcp/connect")
            result = response.status to response.bodyAsText()
        }
        return result!!
    }

    @Test
    fun `requires a session`() {
        val (status, body) = connect(emptyMap(), login = false)
        assertEquals(HttpStatusCode.Unauthorized, status)
        assertEquals("common.unauthenticated", (Json.parseToJsonElement(body).jsonObject["code"] as JsonPrimitive).content)
    }

    @Test
    fun `returns the configured instance and MCP resource`() {
        val (status, body) = connect(
            mapOf(
                "PM_MCP_RESOURCE" to "http://hr-pmon.example.com/mcp",
                "PM_INSTANCE_DESCRIPTION" to "HR and payroll data",
            ),
            login = true,
        )
        assertEquals(HttpStatusCode.OK, status)
        assertEquals(
            JsonObject(
                mapOf(
                    "instanceName" to JsonPrimitive("hr-pmon"),
                    "instanceDescription" to JsonPrimitive("HR and payroll data"),
                    "mcpUrl" to JsonPrimitive("http://hr-pmon.example.com/mcp"),
                    "installName" to JsonPrimitive("pmon-hr-pmon"),
                ),
            ),
            Json.parseToJsonElement(body),
        )
    }

    @Test
    fun `an unset instance name defaults to local for the loopback resource`() {
        val body = Json.parseToJsonElement(connect(emptyMap(), login = true).second).jsonObject
        assertEquals("pmon-local", (body["installName"] as JsonPrimitive).content)
        assertEquals("http://127.0.0.1:8080/mcp", (body["mcpUrl"] as JsonPrimitive).content)
        assertEquals("", (body["instanceDescription"] as JsonPrimitive).content)
    }
}
