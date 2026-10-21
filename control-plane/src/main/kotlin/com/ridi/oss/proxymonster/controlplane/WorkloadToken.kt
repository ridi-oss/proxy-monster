package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzPrincipal
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond

/**
 * Authenticate a call by a WORKLOAD bearer token, or respond 401 and return null. A token whose issuer
 * is no longer configured is rejected, so removing an issuer revokes its outstanding tokens.
 */
suspend fun ApplicationCall.requireWorkload(config: Config, tokenStore: TokenStore): AuthzPrincipal.Workload? {
    val header = request.headers[HttpHeaders.Authorization]
    val token = header?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }?.substring(7)?.trim()?.ifBlank { null }
    val identity = token?.let { tokenStore.resolveWorkload(it) }
    val cfg = identity?.let { id -> config.ciOidcIssuers.firstOrNull { it.name == id.name } }
    if (identity == null || cfg == null) {
        respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
        return null
    }
    return AuthzPrincipal.Workload(identity.name, cfg.issuer, identity.claims)
}
