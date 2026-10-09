package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable

const val INTERNAL_TOKEN_HEADER = "X-PM-Internal-Token"

@Serializable
data class InternalRequestNotified(val id: Long, val event: String)

@Serializable
data class InternalPrincipalRequest(val principal: String)

/**
 * What cp-go tells this process after a commit, about state it holds in memory. cp-go never forwards `/internal/`
 * and starts this process with a per-boot [token]; without one the routes do not exist.
 */
fun Route.internalSignalRoutes(
    token: String?,
    policiesChanged: () -> Unit,
    requestNotified: (id: Long, event: String) -> Boolean = { _, _ -> false },
    sessionsEnded: (principal: String) -> Unit = {},
) {
    if (token.isNullOrEmpty()) return
    // A policy write committed: rebuild this process's PolicySet on its next decision.
    post("/internal/policies-changed") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        policiesChanged()
        call.respond(HttpStatusCode.NoContent)
    }
    // A write opened ("requested") or decided ("decided") a request: send its notification.
    post("/internal/request-notified") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        val request = call.receive<InternalRequestNotified>()
        if (!requestNotified(request.id, request.event)) {
            return@post call.respondError(HttpStatusCode.BadRequest, "common.invalid_value", mapOf("field" to "event"))
        }
        call.respond(HttpStatusCode.NoContent)
    }
    // A write ended the principal's web sessions: close their editor runs held in memory here.
    post("/internal/sessions-ended") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        sessionsEnded(call.receive<InternalPrincipalRequest>().principal)
        call.respond(HttpStatusCode.NoContent)
    }
}
