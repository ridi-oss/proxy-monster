package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

const val INTERNAL_TOKEN_HEADER = "X-PM-Internal-Token"

/**
 * cp-go committed a policy change: rebuild this process's PolicySet on its next decision. cp-go never forwards
 * `/internal/` and starts this process with a per-boot [token]; without one the route does not exist.
 */
fun Route.internalPoliciesChangedRoute(token: String?, policiesChanged: () -> Unit) {
    if (token.isNullOrEmpty()) return
    post("/internal/policies-changed") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        policiesChanged()
        call.respond(HttpStatusCode.NoContent)
    }
}
