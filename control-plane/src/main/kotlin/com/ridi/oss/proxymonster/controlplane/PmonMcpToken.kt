package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.auth.canonicalScopes
import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_SESSION_MCP_TOKEN
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_PMON
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import java.time.Clock
import java.time.Instant

/** The OAuth client id on every MCP token a pmon session mints, and on its consent row. */
const val PMON_MCP_CLIENT_ID = "pmon"

@Serializable
data class PmonMcpTokenResponse(val accessToken: String, val expiresAt: String, val scope: String)

/**
 * The MCP scopes daemon session [row] grants at [now]: every granted scope until its elevated window ends,
 * then only the default pair.
 */
internal fun pmonMcpScopes(row: DaemonSessionRow, now: Instant): Set<String> {
    val elevated = row.elevatedUntil?.let(now::isBefore) == true
    val granted = if (elevated) row.scopes else row.scopes.intersect(PMON_DEFAULT_SCOPES)
    return granted.intersect(McpCapabilityRegistry.supportedScopes)
}

/**
 * `POST /auth/session/mcp-token` — a pmon daemon trades its session's renewal bearer for a short-lived MCP
 * access token carrying that session's scopes. Refused once the login's own TTL has passed, its liveness went
 * INACTIVE, or the principal is deactivated. At `/mcp` the token is an ordinary MCP access token.
 */
internal fun Route.pmonMcpTokenRoute(
    config: Config,
    sessionStore: PrincipalSessionStore,
    userGroupStore: UserGroupStore,
    oauthStore: OAuthAuthorizationStore,
    authAudit: AuthAuditRecorder,
    clock: Clock,
) {
    post("/auth/session/mcp-token") {
        val authHeader = call.request.headers["Authorization"]
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            call.respond(HttpStatusCode.Unauthorized, ApiError("auth.missing_renewal_token"))
            return@post
        }
        val row = sessionStore.getByRenewalTokenHash(sha256Hex(authHeader.removePrefix("Bearer ").trim()))
        if (row == null) {
            call.respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
            return@post
        }
        val clientAddr = call.httpRequesterIp(config)
        var noScopes = false
        val minted = sessionStore.withLiveDaemonSessionLocked(
            row,
            isDeactivated = { principal, c -> userGroupStore.isDeactivated(principal, c) },
        ) { fresh, c ->
            val now = clock.instant()
            val loginExpiresAt = fresh.createdAt.plusSeconds(fresh.ttlSeconds)
            if (!now.isBefore(loginExpiresAt)) return@withLiveDaemonSessionLocked null
            val scopes = pmonMcpScopes(fresh, now)
            if (scopes.isEmpty()) {
                noScopes = true
                return@withLiveDaemonSessionLocked null
            }
            val caps = listOfNotNull(
                now.plusSeconds(config.mcpAccessTtlSeconds),
                loginExpiresAt,
                fresh.elevatedUntil.takeIf { scopes.any { it !in PMON_DEFAULT_SCOPES } },
            )
            val expiresAt = caps.min()
            val (token, id) = oauthStore.issueAccessOnly(c, fresh.principal, PMON_MCP_CLIENT_ID, config.mcpResource, scopes, expiresAt)
            val scope = canonicalScopes(scopes)
            authAudit.success(
                c,
                AuditActor(fresh.principal, clientAddr = clientAddr, channel = CHANNEL_PMON),
                ACTION_SESSION_MCP_TOKEN,
                auditEntity("Token", id.toString()),
                "pmon session minted MCP access token",
                detail = "scope=$scope",
            )
            PmonMcpTokenResponse(token, expiresAt.toString(), scope)
        }
        when {
            minted != null -> call.respond(minted)
            noScopes -> call.respond(HttpStatusCode.Forbidden, ApiError("auth.scopes_expired"))
            else -> call.respond(HttpStatusCode.Unauthorized, ApiError("auth.session_window_expired"))
        }
    }
}
