package com.ridi.oss.proxymonster.controlplane

import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

/** `POST /api/workload/token`: exchange a CI OIDC JWT for a WORKLOAD bearer token. */
fun Route.workloadTokenRoutes(config: Config, service: WorkloadTokenService) {
    post("/api/workload/token") {
        val body = runCatching { call.receive<WorkloadTokenExchangeRequest>() }.getOrNull()
        if (body == null || body.token.isBlank()) return@post call.fieldRequired("token")
        try {
            call.respond(service.exchange(body.token, call.httpRequesterIp(config)))
        } catch (e: TaskServiceException) {
            call.respondServiceError(e)
        }
    }
}
