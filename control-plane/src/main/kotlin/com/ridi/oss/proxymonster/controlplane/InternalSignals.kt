package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.notify.NotificationEvent
import com.ridi.oss.proxymonster.controlplane.notify.NotificationService
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable

const val INTERNAL_TOKEN_HEADER = "X-PM-Internal-Token"

@Serializable
data class InternalRequestNotified(val id: Long, val event: String, val principal: String? = null)

@Serializable
data class InternalPrincipalRequest(val principal: String)

@Serializable
data class InternalNameRequest(val name: String)

@Serializable
data class InternalNamesResult(val names: List<String>)

/**
 * What cp-go tells or asks this process about state it holds in memory. cp-go never forwards `/internal/`
 * and starts this process with a per-boot [token]; without one the routes do not exist.
 */
fun Route.internalSignalRoutes(
    token: String?,
    policiesChanged: () -> Unit,
    requestNotified: (id: Long, event: String, principal: String?) -> Boolean = { _, _, _ -> false },
    sessionsEnded: (principal: String) -> Unit = {},
    proxiesAttached: () -> Set<String> = { emptySet() },
    datasourceDeleted: (name: String) -> Unit = {},
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
    // A write opened, decided, commented on, closed or CC'd a request: send its notification.
    post("/internal/request-notified") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        val request = call.receive<InternalRequestNotified>()
        if (!requestNotified(request.id, request.event, request.principal)) {
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
    // The datasources with a proxy on an open Events stream, which this process holds.
    post("/internal/proxies-attached") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        call.respond(InternalNamesResult(proxiesAttached().sorted()))
    }
    // A delete freed the datasource's name: drop the connection catalog keyed by it, which a new datasource may reuse.
    post("/internal/datasource-deleted") {
        if (!constantTimeEquals(call.request.headers[INTERNAL_TOKEN_HEADER], token)) {
            return@post call.respond(HttpStatusCode.NotFound)
        }
        datasourceDeleted(call.receive<InternalNameRequest>().name)
        call.respond(HttpStatusCode.NoContent)
    }
}

/** What cp-go's request-notified signal sends, per event; false for an event it does not know. */
fun requestNotifier(accessStore: AccessStore, notifications: NotificationService?): (Long, String, String?) -> Boolean =
    fun(id: Long, event: String, principal: String?): Boolean {
        val req = accessStore.getRequest(id)
        when (event) {
            "requested" -> req?.let { notifications?.emitRequestedEvent(it) }
            "decided" -> req?.let { notifications?.emitEvent(NotificationEvent.TASK_DECIDED, it) }
            "cancelled" -> req?.let { notifications?.emitEvent(NotificationEvent.TASK_CANCELLED, it) }
            "commented" -> notifications?.wake()
            "cc-added" -> {
                if (principal == null) return false
                req?.let { notifications?.emitCcAddedEvent(it, principal) }
            }
            else -> return false
        }
        return true
    }
