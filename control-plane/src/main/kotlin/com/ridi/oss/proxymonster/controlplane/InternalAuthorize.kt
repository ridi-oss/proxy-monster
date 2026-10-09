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

@Serializable
data class InternalResource(val type: String, val principal: String? = null)

@Serializable
data class InternalAuthorizeRequest(
    val principal: String,
    val action: String,
    val resource: InternalResource,
    val requesterIp: String? = null,
)

@Serializable
data class InternalAuthorizeResult(val allow: Boolean, val reason: String? = null)

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
        val resource = when (request.resource.type) {
            "System" -> AuthzResource.System
            "AuditLog" -> AuthzResource.AuditLog
            "AuditRecord" -> request.resource.principal?.let { AuthzResource.AuditRecord(it) }
            else -> null
        }
        if (action == null || resource == null) {
            return@post call.respondError(HttpStatusCode.BadRequest, "common.invalid_value", mapOf("field" to "resource"))
        }
        val decision = authz.authorize(request.principal, action, resource, AuthzContext(requesterIp = request.requesterIp))
        call.respond(InternalAuthorizeResult(decision == AuthzDecision.Allow, (decision as? AuthzDecision.Deny)?.reason))
    }
}
