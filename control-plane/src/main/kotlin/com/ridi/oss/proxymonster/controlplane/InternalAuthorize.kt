package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable

const val INTERNAL_TOKEN_HEADER = "X-PM-Internal-Token"

/** [principal] is the resource's owner: an audit record's, a grant's, or an approval request's requester. */
@Serializable
data class InternalResource(
    val type: String,
    val principal: String? = null,
    val id: Long? = null,
    val approver: String? = null,
    val executedBy: String? = null,
    val datasourceName: String? = null,
    val roleName: String? = null,
)

@Serializable
data class InternalAuthorizeRequest(
    val principal: String,
    val action: String,
    val resource: InternalResource,
    val requesterIp: String? = null,
)

@Serializable
data class InternalAuthorizeResult(val allow: Boolean, val reason: String? = null)

@Serializable
data class InternalAuthorizeBatchRequest(
    val principal: String,
    val action: String,
    val resources: List<InternalResource>,
    val requesterIp: String? = null,
)

@Serializable
data class InternalAuthorizeBatchResult(val allow: List<Boolean>)

private fun InternalResource.toAuthz(): AuthzResource? = when (type) {
    "System" -> AuthzResource.System
    "AuditLog" -> AuthzResource.AuditLog
    "AuditRecord" -> principal?.let { AuthzResource.AuditRecord(it) }
    "AccessGrant" -> if (principal != null && id != null) AuthzResource.AccessGrant(principal, id, datasourceName, roleName) else null
    "ApprovalRequest" -> principal?.let { AuthzResource.ApprovalRequest(it, approver, executedBy, datasourceName, roleName) }
    else -> null
}

/**
 * The Cedar decision for routes cp-go serves, until Cedar itself moves to Go. cp-go never forwards
 * `/internal/` and starts this process with a per-boot [token]; without one the route does not exist.
 */
fun Route.internalAuthorizeRoute(token: String?, authz: Authz) {
    if (token.isNullOrEmpty()) return
    post("/internal/authorize") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        val request = call.receive<InternalAuthorizeRequest>()
        val action = AuthzAction.entries.firstOrNull { it.cedarId == request.action }
        val resource = request.resource.toAuthz()
        if (action == null || resource == null) {
            return@post call.respondError(HttpStatusCode.BadRequest, "common.invalid_value", mapOf("field" to "resource"))
        }
        val decision = authz.authorize(request.principal, action, resource, AuthzContext(requesterIp = request.requesterIp))
        call.respond(InternalAuthorizeResult(decision == AuthzDecision.Allow, (decision as? AuthzDecision.Deny)?.reason))
    }
    // One decision per resource, for a list route that filters its rows.
    post("/internal/authorize-batch") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        val request = call.receive<InternalAuthorizeBatchRequest>()
        val action = AuthzAction.entries.firstOrNull { it.cedarId == request.action }
        val resources = request.resources.map { it.toAuthz() }
        if (action == null || resources.any { it == null }) {
            return@post call.respondError(HttpStatusCode.BadRequest, "common.invalid_value", mapOf("field" to "resource"))
        }
        val context = AuthzContext(requesterIp = request.requesterIp)
        val roles = authz.rolesOf(request.principal)
        call.respond(InternalAuthorizeBatchResult(resources.map { authz.authorizeAs(request.principal, roles, action, it!!, context) == AuthzDecision.Allow }))
    }
}
