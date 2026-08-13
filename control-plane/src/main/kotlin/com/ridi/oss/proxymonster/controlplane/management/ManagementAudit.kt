package com.ridi.oss.proxymonster.controlplane.management

import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.AuditStore
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import java.sql.Connection

/**
 * Who performed an audited management mutation, and over which transport. The transport layer (the HTTP
 * admin routes, the MCP server) builds this and threads it into the service method, so a config-change
 * audit event names the actor who made the change rather than the process that carried the request. The
 * service never invents one: an audited mutation cannot be called without an actor.
 */
data class AuditActor(
    val principal: String,
    val roles: List<String> = emptyList(),
    val clientAddr: String? = null,
    val channel: String,
)

/**
 * Audit source labels for the `channel` of a management event. Deliberately its own vocabulary rather
 * than the Cedar [com.ridi.oss.proxymonster.controlplane.Channel]: that enum is overlaid onto the Cedar
 * `context.channel` a query policy conditions on, and a config change is not a query decision.
 */
object AuditSource {
    const val CONSOLE = "console"
    const val MCP = "mcp"
    const val SCIM = "scim"
}

/** A display label of the changed entity for the audit row (`Type::"id"`); never re-parsed as a Cedar UID. */
internal fun auditEntity(type: String, id: String): String = "$type::\"$id\""

/**
 * Writes a `kind="admin"` config-change event through the one [AuditStore] chain chokepoint, on the
 * caller's transaction so the record commits atomically with the mutation it describes — a mutation that
 * rolls back leaves no audit row, and a recorded row is a change that happened.
 *
 * Both the HTTP admin routes and the MCP server reach the config-mutation service methods that call this,
 * so a config change is audited once, the same way, regardless of transport.
 */
class ManagementAuditRecorder(private val auditStore: AuditStore) {
    fun record(c: Connection, actor: AuditActor, action: AuthzAction, resource: String, summary: String) {
        auditStore.insert(
            c,
            AuditEvent(
                principal = actor.principal,
                roles = actor.roles,
                datasource = DATASOURCE,
                clientAddr = actor.clientAddr,
                statement = summary,
                decision = Decision.ALLOW,
                channel = actor.channel,
                authzAction = action.cedarId,
                authzResource = resource,
                outcome = OUTCOME_ALLOW,
                kind = KIND_ADMIN,
            ),
        )
    }

    companion object {
        const val KIND_ADMIN = "admin"
        const val OUTCOME_ALLOW = "ALLOW"

        /** Admin events are instance-scoped, not tied to a target DB; the query-decision `datasource`
         *  slot carries the control plane itself, matching the existing SYSTEM-policy-toggle event. */
        private const val DATASOURCE = "control-plane"
    }
}
