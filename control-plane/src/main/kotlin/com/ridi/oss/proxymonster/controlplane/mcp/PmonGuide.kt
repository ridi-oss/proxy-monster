package com.ridi.oss.proxymonster.controlplane.mcp

import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.PMON_DEFAULT_SCOPES
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry

/** pmon setup for this instance; the pmon server name is the instance name, so `pmon-hr` pairs with `pmon login hr`. */
internal fun pmonGuide(config: Config, connectable: List<String>): String {
    val name = config.instanceName
    val install = "pmon-$name"
    val sh = shellArg(name)
    val shInstall = shellArg(install)
    val extra = (McpCapabilityRegistry.supportedScopes - PMON_DEFAULT_SCOPES).sorted()
    return buildString {
        appendLine("pmon guide for the proxy-monster instance \"$name\".")
        appendLine("pmon logs in once in a browser, then SQL clients, scripts, and MCP agents on this machine all use that login.")
        appendLine()
        appendLine("Install (macOS, Homebrew):")
        appendLine("  brew trust --formula ridi-oss/tap/pmon")
        appendLine("  brew install ridi-oss/tap/pmon")
        appendLine()
        appendLine("Add this instance and log in:")
        appendLine("  pmon server set $sh --url ${shellArg(config.mcpIssuer)}")
        appendLine("  pmon login $sh")
        appendLine("The login prints a URL and a code. Open the URL in a browser on any machine and approve; this works when the agent runs on a remote machine.")
        appendLine()
        appendLine("Use this MCP server through the pmon login (a local stdio server named $install):")
        appendLine("  Claude Code:    claude mcp add --scope user $shInstall -- pmon mcp $sh")
        appendLine("  Codex:          codex mcp add $shInstall -- pmon mcp $sh")
        appendLine("  Claude Desktop: in claude_desktop_config.json, mcpServers.\"$install\" = {\"command\": \"pmon\", \"args\": [\"mcp\", \"$name\"]}")
        appendLine("If `pmon mcp` reports that you are not logged in, run `pmon login $sh`.")
        appendLine()
        if (connectable.isEmpty()) {
            appendLine("You cannot connect to any datasource here yet. request_access asks for a role that can.")
        } else {
            appendLine("Connection strings for SQL clients and scripts, one per datasource you may connect to:")
            connectable.forEach { appendLine("  pmon show $sh ${shellArg(it)} --cli") }
        }
        appendLine()
        appendLine("Other commands:")
        appendLine("  pmon status        logins, granted scopes, and brokered datasources")
        appendLine("  pmon logout $sh  end this login")
        appendLine()
        appendLine("Scopes: `pmon login $sh` grants ${PMON_DEFAULT_SCOPES.sorted().joinToString(" and ")}. To grant more, list every scope you want:")
        appendLine("  pmon login $sh --scopes ${(PMON_DEFAULT_SCOPES.sorted() + extra.take(1)).joinToString(",")}")
        appendLine(
            "Other scopes: ${extra.joinToString(", ")}. Scopes beyond the default pair last " +
                "${duration(config.elevatedScopeTtlSeconds)} after the browser approval; log in again to get them back.",
        )
    }.trimEnd()
}

/** `sales data` → `'sales data'`; datasource names are free text, and agents run these lines. */
internal fun shellArg(value: String): String =
    if (value.isNotEmpty() && value.all { it.isLetterOrDigit() || it in "-_.:/@%+=," }) value else "'" + value.replace("'", "'\\''") + "'"

private fun duration(seconds: Long): String = when {
    seconds % 3_600 == 0L -> (seconds / 3_600).let { "$it hour${if (it == 1L) "" else "s"}" }
    seconds % 60 == 0L -> (seconds / 60).let { "$it minute${if (it == 1L) "" else "s"}" }
    else -> "$seconds seconds"
}
