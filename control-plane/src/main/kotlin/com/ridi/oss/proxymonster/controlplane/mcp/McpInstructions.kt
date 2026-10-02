package com.ridi.oss.proxymonster.controlplane.mcp

import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.authorizeMetadata
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.wireName

internal const val MAX_INSTRUCTION_DATASOURCES = 50

/** The `initialize` instructions: which instance this is, and the datasources this caller may connect to. */
internal fun mcpInstructions(config: Config, core: ControlPlaneCore, context: McpRequestContext): String {
    // The SDK builds these for every stateless request, not only initialize, so roles resolve once.
    val roles = core.roleResolver.resolve(context.principal)
    val authzContext = AuthzContext(requesterIp = context.requesterIp)
    val connectable = core.datasourceStore.list()
        .filter { authorizeMetadata(core.authz, context.principal, roles, it, authzContext) }
    return buildString {
        append("This MCP server is the proxy-monster instance \"").append(config.instanceName).append('"')
        if (config.instanceDescription.isNotBlank()) append(": ").append(config.instanceDescription)
        appendLine(if (config.instanceDescription.isBlank()) "." else "")
        appendLine(
            "Other pmon-* MCP servers are different proxy-monster instances, each with its own datasources " +
                "and access. Use this one only for the datasources listed here.",
        )
        appendLine(
            "For SQL clients or scripts, or to share one pmon login across agents, call get_pmon_guide.",
        )
        if (connectable.isEmpty()) {
            append("You cannot query any datasource here yet. request_access asks for a role that can.")
            return@buildString
        }
        appendLine("Datasources you can query here:")
        for (ds in connectable.take(MAX_INSTRUCTION_DATASOURCES)) {
            append("- ").append(ds.name).append(" (").append(ds.engine.wireName).append(')')
            if (ds.description.isNotBlank()) append(": ").append(ds.description)
            appendLine()
        }
        if (connectable.size > MAX_INSTRUCTION_DATASOURCES) {
            appendLine(
                "…and ${connectable.size - MAX_INSTRUCTION_DATASOURCES} more. " +
                    "Call list_connectable_datasources for the full list.",
            )
        }
    }.trimEnd()
}
