package com.ridi.oss.proxymonster.controlplane.mcp

import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.requireApi
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.serialization.Serializable

/** What the console's "Connect an agent" page needs to install this instance's MCP server. */
@Serializable
data class McpConnectInfo(
    val instanceName: String,
    val instanceDescription: String,
    val mcpUrl: String,
    val installName: String,
)

internal fun Route.mcpConnectRoute(config: Config) {
    get("/api/mcp/connect") {
        call.requireApi() ?: return@get
        call.respond(
            McpConnectInfo(
                instanceName = config.instanceName,
                instanceDescription = config.instanceDescription,
                mcpUrl = config.mcpResource,
                installName = "pmon-${config.instanceName}",
            ),
        )
    }
}
