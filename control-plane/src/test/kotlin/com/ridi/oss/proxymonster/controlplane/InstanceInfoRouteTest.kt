package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.mcp.instanceInfoRoute
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class InstanceInfoRouteTest {
    @Test
    fun `names the instance and its version without a session`() = testApplication {
        val config = Config.fromEnv { mapOf("PM_MCP_RESOURCE" to "https://hr-pmon.example.com/mcp")[it] }
        application {
            install(ContentNegotiation) { json() }
            routing { instanceInfoRoute(config) }
        }
        val response = client.get("/api/instance")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            JsonObject(
                mapOf(
                    "name" to JsonPrimitive("hr-pmon"),
                    "version" to JsonPrimitive(SERVER_VERSION),
                    "mcpUrl" to JsonPrimitive("https://hr-pmon.example.com/mcp"),
                    "installName" to JsonPrimitive("pmon-hr-pmon"),
                ),
            ),
            Json.parseToJsonElement(response.bodyAsText()),
        )
    }
}
