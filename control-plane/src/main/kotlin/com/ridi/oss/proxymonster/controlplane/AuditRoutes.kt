package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

internal fun Route.auditRoutes(
    config: Config,
    store: AuditStore,
    authz: Authz,
    service: AuditService = AuditService(authz, store),
) {
    get("/api/audit") {
        val principal = call.requireApi() ?: return@get
        val limit = call.request.queryParameters["limit"]?.toIntOrNull()
        call.respond(service.list(principal, call.httpRequesterIp(config), limit))
    }

    get("/api/audit/{id}") {
        val principal = call.requireApi() ?: return@get
        val id = call.idParam() ?: return@get call.badId()
        try {
            call.respond(service.get(principal, call.httpRequesterIp(config), id))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
}
