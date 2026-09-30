package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource

/** Audit reads shared by the REST audit routes and the MCP audit tools. Failures throw [TaskServiceException]. */
class AuditService(private val authz: Authz, private val store: AuditStore) {
    /** An audit.read grant on the whole log returns every principal's rows; anything less returns own rows. */
    fun list(principal: String, requesterIp: String?, limit: Int?): List<AuditEvent> {
        val n = (limit ?: 100).coerceIn(1, 500)
        val decision = authz.authorize(principal, AuthzAction.AUDIT_READ, AuthzResource.AuditLog, AuthzContext(requesterIp = requesterIp))
        return if (decision == AuthzDecision.Allow) store.recent(n) else store.recent(n, principal)
    }

    // Denied and missing are the same not_found, so a caller cannot tell "exists but hidden" from "absent".
    fun get(principal: String, requesterIp: String?, id: Long): AuditEvent {
        val record = store.get(id) ?: throw serviceNotFound("audit record")
        val decision = authz.authorize(
            principal, AuthzAction.AUDIT_READ, AuthzResource.AuditRecord(record.principal), AuthzContext(requesterIp = requesterIp),
        )
        if (decision != AuthzDecision.Allow) throw serviceNotFound("audit record")
        return record
    }
}
