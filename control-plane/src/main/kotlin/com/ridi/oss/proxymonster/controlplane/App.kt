package com.ridi.oss.proxymonster.controlplane

import com.cedarpolicy.value.IpAddress
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext
import com.ridi.oss.proxymonster.controlplane.authz.cedarPolicyRoutes
import com.ridi.oss.proxymonster.controlplane.authz.contextTagLint
import com.ridi.oss.proxymonster.controlplane.management.DatasourceManagementService
import com.ridi.oss.proxymonster.controlplane.management.IdentityManagementService
import com.ridi.oss.proxymonster.controlplane.management.ManagementException
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.mcp.installMcp
import com.ridi.oss.proxymonster.controlplane.oauth.MCP_OAUTH_PENDING_COOKIE
import com.ridi.oss.proxymonster.controlplane.oauth.McpPendingAuthorization
import com.ridi.oss.proxymonster.controlplane.oauth.OAuthError
import com.ridi.oss.proxymonster.controlplane.oauth.installMcpOAuthProtocolGuard
import com.ridi.oss.proxymonster.controlplane.oauth.mcpOAuthRoutes
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.auth.session
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.contentLength
import io.ktor.server.request.receive
import io.ktor.server.request.receiveNullable
import io.ktor.server.request.path
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.clear
import io.ktor.server.sessions.get
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.set
import io.ktor.server.sessions.sessions
import io.ktor.server.sse.sse
import io.ktor.sse.ServerSentEvent
import java.io.IOException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.event.Level
import kotlin.time.Duration.Companion.seconds

/** How often the background sweep deletes expired result rows. */
private const val RESULT_PURGE_INTERVAL_MS = 15 * 60 * 1000L

/** An editor session idle longer than this is reaped (its proxy stream + backend connection freed).
 *  Swept on the same timer as RESULT_PURGE_INTERVAL_MS. */
private const val EDITOR_SESSION_MAX_IDLE_MS = 30 * 60 * 1000L

/** How often the task-event SSE stream re-validates its web session (a revoked/expired/displaced session
 *  must stop receiving pushes; `webSession()` caches per-call so the stream re-resolves the store directly). */
private const val SSE_SESSION_RECHECK_MS = 30_000L

/** Reconnect backoff advertised to an EventSource with no live session, so an expired-session tab does not
 *  hammer `/api/tasks/events` on its default ~3s retry (it cannot be told to stop after the 200 handshake). */
private const val SSE_UNAUTH_RETRY_MS = 60_000L

/**
 * One per-principal SSE stream of task terminal transitions (EXECUTED/FAILED/CANCELLED), so a
 * watching editor/approval tab updates immediately instead of on its next poll. Cookie-authenticated
 * (EventSource sends the session cookie); the web falls back to polling whenever this stream is absent or
 * drops, so a missed event only delays an update — it is never the source of truth.
 *
 * The stream stays bound to the poll's authorization: each event is filtered through the live `task.read`
 * gate (a Cedar forbid that 404s the poll also suppresses the push), and the web session is re-validated so
 * a revoked/expired/displaced session stops receiving pushes rather than streaming on its handshake identity.
 */
internal fun Route.taskEventsRoute(
    config: Config,
    taskCompletionHub: TaskCompletionHub,
    accessStore: AccessStore,
    authz: Authz,
    datasourceStore: DatasourceStore,
    principalSessionStore: PrincipalSessionStore,
    appJson: Json,
) {
    sse("/api/tasks/events") {
        val liveSession = if (config.authDebug) null else call.webSession()
        val principal = liveSession?.principal ?: if (config.authDebug) "debug-user" else null
        if (principal == null) {
            // No live session. EventSource cannot be told to STOP reconnecting after the 200 handshake, so
            // lengthen its reconnect backoff and end the stream (an expired-session tab then re-polls far less
            // aggressively; the app's 401ing polls redirect it to login). Poll is the truth.
            send(ServerSentEvent(retry = SSE_UNAUTH_RETRY_MS))
            return@sse
        }
        val sessionId = liveSession?.id
        val deviceId = call.deviceCookieId()
        val context = call.httpAuthzContext(config)
        val events = taskCompletionHub.subscribe(principal)
        try {
            while (true) {
                val keepOpen = select {
                    events.onReceiveCatching { result ->
                        val event = result.getOrNull() ?: return@onReceiveCatching false
                        // Bound the push to the SAME live `task.read` gate the poll/detail enforce, so a Cedar
                        // forbid (e.g. an untrusted zone) that 404s the poll also suppresses the push — the
                        // notification never reveals gated metadata. A denied/absent task is skipped.
                        if (taskReadableForPush(config, principal, event.taskId, context, accessStore, authz, datasourceStore)) {
                            send(ServerSentEvent(data = appJson.encodeToString(TaskEvent.serializer(), event), event = "task"))
                        }
                        sessionStillLive(config, sessionId, deviceId, principalSessionStore)
                    }
                    onTimeout(SSE_SESSION_RECHECK_MS) {
                        // A session revoked / expired / newest-wins-displaced mid-stream must stop receiving
                        // events; webSession() caches per-call, so re-resolve the store directly here.
                        //
                        // This tick also carries the keepalive, rather than Ktor's `heartbeat` helper. The
                        // helper writes from its OWN coroutine, so when the client is gone its write throws
                        // where no handler here can reach it — every ordinary disconnect surfaced as an
                        // unhandled exception and a 500. Writing on this loop's own coroutine puts that
                        // same throw inside the catch below, which is what turns a closed browser tab back
                        // into the non-event it is.
                        send(ServerSentEvent(comments = "keepalive"))
                        sessionStillLive(config, sessionId, deviceId, principalSessionStore)
                    }
                }
                if (!keepOpen) break
            }
        } catch (_: IOException) {
            // A browser closing the tab, navigating away, or reconnecting leaves this stream writing to a
            // channel that is already gone, and the write throws. That is the NORMAL end of an SSE stream,
            // not a server fault: unhandled, it logged a stack trace and a "500 Internal Server Error" for
            // every disconnect, which buries real failures in a log nobody can then read. Nothing is left
            // to send, so ending the coroutine quietly is the whole handling — the finally below still
            // releases the subscription.
        } finally {
            taskCompletionHub.unsubscribe(principal, events)
        }
    }
}

/** True while the SSE stream's web session is still live (authDebug has no session and is always live). */
internal fun sessionStillLive(config: Config, sessionId: Long?, deviceId: String?, store: PrincipalSessionStore): Boolean =
    config.authDebug || (sessionId != null && store.resolveWeb(sessionId, deviceId) != null)

/** Whether [principal] may still `task.read` [taskId] — the SAME live Cedar gate the poll/detail enforce,
 *  so the push cannot surface metadata the poll would 404. A missing task is not readable. */
internal fun taskReadableForPush(
    config: Config,
    principal: String,
    taskId: Long,
    context: AuthzContext,
    accessStore: AccessStore,
    authz: Authz,
    datasourceStore: DatasourceStore,
): Boolean {
    if (config.authDebug) return true
    val task = accessStore.getRequest(taskId) ?: return false
    val decision = authz.authorizeWithContext(
        principal,
        AuthzAction.TASK_READ,
        AuthzResource.ApprovalRequest(
            requester = task.principal, approver = task.decidedBy, executedBy = task.executedBy,
            datasourceName = task.datasourceName, roleName = task.roleName,
        ),
        context,
        task.datasourceName,
        task.datasourceId?.let(datasourceStore::get)?.tags.orEmpty(),
    )
    return decision !is AuthzDecision.Deny
}

@Serializable
internal data class MePermissions(
    val isAdmin: Boolean,
    val canReadAllAudit: Boolean,
    val canApprove: Boolean,
)

@Serializable
internal data class SessionStatus(
    val now: String,
    val idleExpiresAt: String,
    val absoluteExpiresAt: String,
    val principal: String,
    val sessionId: Long,
)

@Serializable
internal data class SessionStatusError(val reason: String)

@Serializable
internal data class LogoutRequest(val sessionId: Long? = null)

@Serializable
internal data class LogoutResponse(val ended: Boolean)

@Serializable
internal data class AuthConfigResponse(
    val oidcEnabled: Boolean,
    val authDebug: Boolean,
    val session: SessionUxConfig,
)

@Serializable
internal data class SessionUxConfig(
    val heartbeatMs: Long,
    val idleWarnLeadMs: Long,
    val absoluteWarnLeadMs: Long,
    val absoluteCapAmount: Long,
    val absoluteCapUnit: String,
)

internal data class NormalizedDuration(val amount: Long, val unit: String)

internal fun normalizeDuration(seconds: Long): NormalizedDuration = when {
    seconds % 3600 == 0L -> NormalizedDuration(seconds / 3600, "hours")
    seconds % 60 == 0L -> NormalizedDuration(seconds / 60, "minutes")
    else -> NormalizedDuration(seconds, "seconds")
}

private fun WebSessionRow.toSessionStatus() = SessionStatus(
    now = now.toString(),
    idleExpiresAt = idleExpiresAt.toString(),
    absoluteExpiresAt = absoluteExpiresAt.toString(),
    principal = principal,
    sessionId = id,
)

private suspend fun respondSessionUnauthorized(call: ApplicationCall, store: PrincipalSessionStore) {
    val sessionId = call.attributes.getOrNull(FAILED_WEB_SESSION)
    val endedReason = sessionId?.let(store::webEndedReason)
    val reason = when {
        sessionId == null -> "none"
        endedReason == ENDED_DISPLACED -> "displaced"
        endedReason == ENDED_DEVICE_BIND_MISMATCH -> "bind_mismatch"
        else -> "expired"
    }
    call.response.header(HttpHeaders.CacheControl, "no-store")
    call.respond(HttpStatusCode.Unauthorized, SessionStatusError(reason))
}

internal fun computeMePermissions(principal: String, authz: Authz, context: AuthzContext = AuthzContext()): MePermissions {
    // These are deliberately independent decisions: one permitted admin domain is enough to expose
    // the shared admin area, while audit collection access remains a separate capability.
    val canAdminDatasources = authz.authorize(
        principal,
        AuthzAction.ADMIN_DATASOURCES,
        AuthzResource.System,
        context,
    ) == AuthzDecision.Allow
    val canAdminPolicies = authz.authorize(
        principal,
        AuthzAction.ADMIN_POLICIES,
        AuthzResource.System,
        context,
    ) == AuthzDecision.Allow
    val canAdminIdentity = authz.authorize(
        principal,
        AuthzAction.ADMIN_IDENTITY,
        AuthzResource.System,
        context,
    ) == AuthzDecision.Allow
    val isAdmin = canAdminDatasources || canAdminPolicies || canAdminIdentity
    val canReadAllAudit = authz.authorize(
        principal,
        AuthzAction.AUDIT_READ,
        AuthzResource.AuditLog,
        context,
    ) == AuthzDecision.Allow

    return MePermissions(
        isAdmin = isAdmin,
        canReadAllAudit = canReadAllAudit,
        // `task.approve` is request-scoped, so there is no honest coarse System check yet.
        canApprove = isAdmin,
    )
}

internal fun Route.mePermissionsRoute(config: Config, authz: Authz) {
    get("/api/me/permissions") {
        if (!call.requireApi(config)) return@get
        val permissions = if (config.authDebug) {
            MePermissions(isAdmin = true, canReadAllAudit = true, canApprove = true)
        } else {
            val session = requireNotNull(call.userSession()) {
                "requireApi admitted a non-debug request without a UserSession"
            }
            computeMePermissions(session.principal, authz, call.httpAuthzContext(config))
        }

        // UI navigation and client-side guards are convenience only; every API authorizes independently.
        call.respond(permissions)
    }
}

/** The control-plane HTTP application: audit ingest/read + debug/OIDC auth surface. */
fun Application.module(config: Config, core: ControlPlaneCore) {
    val dataSource = core.dataSource
    // An unusable PM_TRUSTED_PROXIES entry fails closed — that hop is simply not trusted — which means a
    // typo presents as "forwarded headers stopped working" with nothing pointing at the cause. Say so at
    // startup instead. Not fatal: the remaining entries are still honored, and refusing to boot over one
    // malformed entry would be a worse failure than running with a narrower trust set.
    unusableTrustedProxyEntries(config.trustedProxies).takeIf { it.isNotEmpty() }?.let { bad ->
        environment.log.warn(
            "PM_TRUSTED_PROXIES: ignoring {} unusable entr{} (not an IP address or CIDR block): {}. " +
                "Forwarded headers from those hops are NOT honored.",
            bad.size, if (bad.size == 1) "y" else "ies", bad.joinToString(", "),
        )
    }
    // encodeDefaults so empty arrays / default fields are always present in responses —
    // the UI relies on e.g. effectiveRoles[]/rows[]/columns[] being arrays, not absent.
    // explicitNulls = false: the MCPA surface (`/mcp`, `/oauth/*`, `/.well-known/oauth-*`, co-hosted on
    // this SAME application) is consumed by the official MCP TypeScript SDK's strict Zod schemas, which
    // model every optional protocol field as `.optional()` (the key must be ABSENT), never `.nullable()`
    // (an explicit `null` value) — e.g. InitializeResult's capabilities.resources/prompts/logging/
    // completions/experimental, serverInfo.title/websiteUrl/icons, instructions, _meta. The MCP SDK's
    // OWN internal serializer already omits these; it's the SDK's `call.respond(...)` calls going through
    // THIS application's negotiated ContentNegotiation Json that reintroduced them (confirmed against a
    // real `claude mcp login` session — every login failed with a bare client-side "invalid_union" parse
    // error and zero server-side signal, 2026-07-15). A route-scoped override was tried first (only
    // relaxing this for the MCP/OAuth paths) but broke `AuthAndIngestRoutesDbTest`'s catch-all coverage —
    // a route registered via a SEPARATE `routing {}` call outside `module()` didn't inherit it — so this
    // applies application-wide instead. Safe for the REST API: every TS consumer already types nullable
    // fields `T | null` and reads them via `??`/`!= null`, which treats an absent key and an explicit
    // `null` identically; only the encoded byte-shape of an already-optional field changes, not any
    // contract already relied upon (`encodeDefaults` stays true, so arrays are still always present).
    val appJson = Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }
    // The shared enforcement graph (Layer 1 identity + Layer 2 Cedar authz + the stores the decision
    // path reads). Sourced from `core` — the SAME instances the gRPC decision surface uses, so a policy
    // edit here invalidates that engine's cache too (see ControlPlaneCore for why this must be shared).
    val store = core.auditStore
    val datasourceStore = core.datasourceStore
    val policyStore = core.policyStore
    val accessStore = core.accessStore
    // Fail any task/child left mid-execution by a previous process death (EXECUTING/RUNNING -> FAILED).
    // Also run in Main before the gRPC surface comes up; idempotent, so the double call is harmless and
    // this site keeps the reconcile on the real boot path that testApplication{module()} exercises.
    accessStore.reconcileOrphanedExecutions()
    val userGroupStore = core.userGroupStore
    val tokenStore = core.tokenStore
    val roleResolver = core.roleResolver
    // The Cedar policy store stays otherwise internal (consumers see `authz`), but the admin policy
    // routes mutate it — through THIS shared instance, so its version bump reaches the gRPC engine.
    val cedarPolicyStore = core.cedarPolicyStore
    val authz = core.authz

    // HTTP-only stores (not on the gRPC decision path).
    val queryHistoryStore = QueryHistoryStore(dataSource)
    val runExecService = RunExecService(core, config.queryTimeoutSeconds)
    // In-process push of task terminal transitions to the SSE stream, so a watching editor/approval tab
    // updates without waiting for its next poll. HTTP-only (the run coroutines + the SSE stream live here),
    // single-replica, and a pure accelerator over the poll (see TaskCompletionHub).
    val taskCompletionHub = TaskCompletionHub()
    val tableDetailService = TableDetailService(core)
    // AES-256-GCM at-rest crypto for PII-bearing rows we persist server-side: query results AND
    // encrypted refresh tokens for principal sessions. Null when PM_RESULT_KEY is unset — sensitive
    // values are omitted or refused rather than persisted as plaintext.
    val resultCrypto = config.resultKey?.let { ResultCrypto(it) }
    // Result storage is only available when PM_RESULT_KEY is set; otherwise APPROVER_EXEC execution
    // is refused fail-closed (no plaintext PII persisted).
    val queryResultStore = resultCrypto?.let { QueryResultStore(dataSource, it) }

    // OIDC (docs/auth-model.md): provider-agnostic via discovery, so any OIDC IdP works. `discovery`/
    // `validator` are null when `config.oidc` is unset — every consumer degrades gracefully (501),
    // never NPEs. Device-authorization reuses this SAME confidential client (no separate CLI client).
    val oidcHttp = oidcHttpClient()
    val discovery = config.oidc?.let { OidcDiscovery(oidcHttp, it.issuer) }
    val validator = config.oidc?.let { IdTokenValidator(discovery!!, it.issuer, it.clientId) }
    val deviceLoginStore = DeviceLoginStore(dataSource, resultCrypto)
    val principalSessionStore = PrincipalSessionStore(
        dataSource,
        resultCrypto,
        config.webSessionIdleSeconds,
        config.webSessionSlideSeconds,
        // Delete-on-session-end: when a principal's web session ends (logout, deprovision, device-bind
        // mismatch, newest-wins displacement), drop their saved editor results — the central end seam covers
        // every path in one place. The delete runs on the SAME connection as the end-write, so on the
        // deprovision path it joins that atomic teardown transaction and rolls back with it if the teardown aborts.
        onWebSessionEnded = { p, conn ->
            queryResultStore?.deleteEditorResultsForPrincipal(p, conn)
            runExecService.closeSessionsForPrincipal(p)
        },
    )
    val webSessionSerializer = jsonSessionSerializer<WebSessionRef>()
    val webSessionStorage = PrincipalSessionStorage(principalSessionStore, webSessionSerializer)
    attributes.put(PRINCIPAL_SESSION_STORE, principalSessionStore)

    // Background housekeeping on a timer, independent of traffic (both are also purged
    // opportunistically on reads/execute + poll). Canceled when the application stops. Expired
    // result rows enforce the short-retention posture (only when result storage is configured);
    // expired device-authorization attempts (RFC 8628) are dropped so `device_login` stays small.
    launch {
        while (true) {
            delay(RESULT_PURGE_INTERVAL_MS)
            runCatching { deviceLoginStore.purgeExpired() }
                .onFailure { environment.log.warn("device-login purge failed", it) }
            if (queryResultStore != null) {
                // Editor children are DELETED outright (no audit-retention obligation), unlike the workflow
                // children purgeExpired keeps. This MUST run first: purgeExpired NULLs expires_at on every
                // expired child (workflow AND editor), so an editor sweep ordered after it would never match
                // its expires_at <= now predicate and expired editor rows would linger payload-stripped.
                runCatching { queryResultStore.purgeExpiredEditorChildren() }
                    .onFailure { environment.log.warn("editor result purge failed", it) }
                runCatching { queryResultStore.purgeExpired() }
                    .onFailure { environment.log.warn("result purge failed", it) }
            }
            // Reap editor sessions idle past the cutoff — releases the held proxy stream + backend
            // connection + revokes the per-session token, so an abandoned editor tab doesn't pin resources.
            runCatching { runExecService.sweepIdleSessions(EDITOR_SESSION_MAX_IDLE_MS) }
                .onFailure { environment.log.warn("editor session idle sweep failed", it) }
            runCatching { core.connectionCatalog.sweepIdle(60L * 60 * 1000) }
                .onFailure { environment.log.warn("connection catalog idle sweep failed", it) }
        }
    }

    // Timer-driven IdP liveness is the sole revalidator for web and daemon sessions. A rejected
    // refresh token retires only its own session; transient failures preserve the cached state.
    launch {
        // Config guarantees a positive interval; `.seconds` converts without the overflow a raw
        // `* 1000` (Long millis) could hit for very large values.
        val recheckInterval = config.idpRecheckIntervalSeconds.seconds
        while (true) {
            delay(recheckInterval)
            runCatching {
                sweepSessionLiveness(
                    config, discovery, validator, oidcHttp, principalSessionStore, userGroupStore,
                    roleResolver, environment.log,
                )
            }.onFailure { environment.log.warn("session liveness sweep failed", it) }
        }
    }

    install(ContentNegotiation) {
        json(appJson)
    }
    install(CallLogging) {
        level = Level.INFO
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.application.environment.log.error("Unhandled exception", cause)
            if (call.request.path().startsWith("/oauth/") ||
                call.request.path() == "/.well-known/oauth-authorization-server"
            ) {
                call.respond(HttpStatusCode.InternalServerError, OAuthError("server_error"))
            } else {
                call.respondError(HttpStatusCode.InternalServerError, "common.fallback")
            }
        }
    }
    // NOTE: the Ktor SSE plugin is NOT installed here — the MCP SDK's `mcpStatelessStreamableHttp` mount
    // (see mcpOAuthRoutes) already installs it unconditionally, and Ktor's install throws on a duplicate.
    // The /api/tasks/events route below reuses that same application-level plugin. If the MCP mount is ever
    // removed, add `install(SSE)` back here.
    install(Sessions) {
        cookie<WebSessionRef>(SESSION_COOKIE, webSessionStorage) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.mcpIssuer.startsWith("https://")
            cookie.extensions["SameSite"] = "Lax"
            cookie.maxAgeInSeconds = config.webSessionAbsoluteSeconds
            serializer = webSessionSerializer
            transform(
                SessionTransportTransformerMessageAuthentication(
                    config.sessionSecret.toByteArray(),
                ),
            )
        }
        // Short-lived signed cookie holding the OAuth CSRF state across the OIDC redirect.
        cookie<OAuthStateSession>(OAUTH_STATE_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.mcpIssuer.startsWith("https://")
            cookie.extensions["SameSite"] = "Lax"
            cookie.maxAgeInSeconds = 300 // ~5 min — only needs to outlive the authorize round-trip
            serializer = jsonSessionSerializer()
            transform(
                SessionTransportTransformerMessageAuthentication(
                    config.sessionSecret.toByteArray(),
                ),
            )
        }
        // Short-lived signed cookie proving the browser viewed the /device page for a specific user_code —
        // the only channel that binds a device login to SSO, so a raw /auth/oidc/login link can't approve a
        // handle the user never confirmed (device-phishing defense).
        cookie<DeviceVerifySession>(DEVICE_VERIFY_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.mcpIssuer.startsWith("https://")
            cookie.extensions["SameSite"] = "Lax"
            cookie.maxAgeInSeconds = 600 // ~10 min — matches the device-login TTL
            serializer = jsonSessionSerializer()
            transform(
                SessionTransportTransformerMessageAuthentication(
                    config.sessionSecret.toByteArray(),
                ),
            )
        }
        // Short-lived signed cookie holding the OIDC nonce across the redirect (docs/auth-model.md
        // — id_token nonce validation defends against authorization-code injection).
        cookie<OAuthNonceSession>(OAUTH_NONCE_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.mcpIssuer.startsWith("https://")
            cookie.extensions["SameSite"] = "Lax"
            cookie.maxAgeInSeconds = 300 // ~5 min — only needs to outlive the authorize round-trip
            serializer = jsonSessionSerializer()
            transform(
                SessionTransportTransformerMessageAuthentication(
                    config.sessionSecret.toByteArray(),
                ),
            )
        }
        // Short-lived signed cookie holding the PKCE code_verifier across the redirect. Same
        // lifetime as the nonce above: it only has to outlive one authorize round-trip.
        cookie<OAuthVerifierSession>(OAUTH_VERIFIER_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.mcpIssuer.startsWith("https://")
            cookie.extensions["SameSite"] = "Lax"
            cookie.maxAgeInSeconds = 300 // ~5 min — only needs to outlive the authorize round-trip
            serializer = jsonSessionSerializer()
            transform(
                SessionTransportTransformerMessageAuthentication(
                    config.sessionSecret.toByteArray(),
                ),
            )
        }
        cookie<McpPendingAuthorization>(MCP_OAUTH_PENDING_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.mcpIssuer.startsWith("https://")
            cookie.maxAgeInSeconds = 600
            cookie.extensions["SameSite"] = "Lax"
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
        }
    }
    install(Authentication) {
        session<WebSessionRef>(WEB_SESSION_AUTH) {
            validate { webSession() }
            challenge { respondSessionUnauthorized(call, principalSessionStore) }
        }
    }

    installMcpOAuthProtocolGuard()

    // MCPA transport adapters share these service instances with the REST surface and the one live core.
    val datasourceManagement = DatasourceManagementService(datasourceStore, core.proxyEventsHub, tableDetailService)
    val policyManagement = PolicyManagementService(cedarPolicyStore, policyStore)
    val identityManagement = IdentityManagementService(
        dataSource, userGroupStore, policyStore, tokenStore, accessStore, principalSessionStore,
    )
    installMcp(config, core, datasourceManagement, policyManagement, identityManagement)

    routing {
        // Installed on the routing ROOT, not bare Application — Ktor's ContentNegotiation is a
        // RouteScopedPlugin, and it forbids combining an Application-level install with ANY route-level
        // install of the same plugin ("Installing RouteScopedPlugin to application and route is not
        // supported. Consider moving application level install to routing root" — its own error text).
        // Installing here instead is application-wide (this root Route covers every path) while still
        // permitting the nested overrides below.
        get("/health") {
            val diagnostics = buildList {
                if (!roleResolver.hasActiveAssignee("system:admin")) add("system:admin role has no active assignee")
                // Dangling-tag lint: warn on a context tag consumed with no producer (a grant that
                // can never apply — likely a typo) or produced with no consumer (a dead tag rule).
                addAll(contextTagLint(cedarPolicyStore.enabledSources()))
            }
            call.respond(
                kotlinx.serialization.json.JsonObject(
                    mapOf(
                        "status" to kotlinx.serialization.json.JsonPrimitive("ok"),
                        "diagnostics" to kotlinx.serialization.json.JsonArray(
                            diagnostics.map { kotlinx.serialization.json.JsonPrimitive(it) },
                        ),
                    ),
                ),
            )
        }

        // Auth capabilities and session UX timings are public so the login shell can initialize them.
        get("/auth/config") {
            val absoluteCap = normalizeDuration(config.webSessionAbsoluteSeconds)
            call.respond(
                AuthConfigResponse(
                    oidcEnabled = config.oidc != null,
                    authDebug = config.authDebug,
                    session = SessionUxConfig(
                        heartbeatMs = config.webSessionHeartbeatSeconds * 1000,
                        idleWarnLeadMs = config.webSessionIdleWarnLeadSeconds * 1000,
                        absoluteWarnLeadMs = config.webSessionAbsoluteWarnLeadSeconds * 1000,
                        absoluteCapAmount = absoluteCap.amount,
                        absoluteCapUnit = absoluteCap.unit,
                    ),
                ),
            )
        }

        // OIDC authorization-code routes (/auth/oidc/login, /auth/oidc/callback).
        oidcRoutes(
            config, discovery, validator, oidcHttp, userGroupStore, roleResolver, principalSessionStore,
            this@module.environment.log,
        )

        // OAuth 2.1/CIMD authorization-server routes share this process, origin, DB pool, OIDC login,
        // and signed user session with the control plane. There is no service-to-service auth hop.
        mcpOAuthRoutes(config, dataSource, principalSessionStore)

        // CLI/daemon login surface: /auth/device/start + /poll (pmon), the /device verification page + its
        // SSO/debug choices, and /auth/session/renew (docs/auth-model.md "CLI / daemon login").
        deviceSessionRoutes(
            config, deviceLoginStore, principalSessionStore,
            tokenStore, userGroupStore, this@module.environment.log,
        )

        // SCIM 2.0 provisioning (docs/auth-model.md "SCIM 2.0 provisioning") — bearer+TLS gated,
        // not a user session. principalSessionStore is passed so a SCIM deprovision durably closes the
        // principal's daemon session windows (renewal secrets), not just its wire tokens + grants.
        scimRoutes(config, userGroupStore, tokenStore, accessStore, principalSessionStore, this@module.environment.log)

        // Datasource + catalog + classification config API. Admin-gated: admin.datasources.
        // The events hub backs the admin "refresh now" push + the "which datasources have a proxy attached"
        // liveness view (docs/datasource-registration.md).
        datasourceRoutes(config, authz, roleResolver, datasourceStore, core.proxyEventsHub, tableDetailService, tokenStore, userGroupStore, datasourceManagement)

        // Roles, principal->role, mask functions, column policies. Admin-gated: admin.policies
        // (role-assignments are admin.identity — see Policies.kt).
        policyRoutes(config, authz, policyStore, policyManagement)

        // Local users + groups + group->role mapping (docs/authz-model.md). Admin-gated: admin.identity.
        // tokenStore/accessStore/principalSessionStore are threaded through so a local-admin rename or
        // active-flip can atomically revoke the affected principal's credentials,
        // mirroring the SCIM surface below.
        userGroupRoutes(
            config, authz, userGroupStore, tokenStore, accessStore, principalSessionStore, identityManagement,
        )

        // JIT access elevation: requests, approve/reject, grants, revoke (DESIGN.md).
        accessRoutes(config, accessStore, authz, datasourceStore, roleResolver)

        // Query-approval workflow: from-denied + proactive compose, approver decide, then async
        // execute-under-R with encrypted short-retention result storage.
        approvalRoutes(
            config, accessStore, store, datasourceStore, policyStore, userGroupStore, queryResultStore,
            roleResolver, authz, runExecService, this@module, core.systemClassification, taskCompletionHub,
        )

        // Enforcing SQL query endpoint (deny + result masking; effective roles come from RoleResolver).
        queryRoutes(config, datasourceStore, queryHistoryStore, runExecService)
        // Persistent editor sessions (one held proxy stream / backend connection per session)
        // whose submits run async as auto-approved EDITOR tasks with saved, task.assume-gated results.
        editorSessionRoutes(
            config, datasourceStore, accessStore, queryResultStore, policyStore, userGroupStore,
            roleResolver, authz, runExecService, this@module, core.systemClassification, taskCompletionHub,
        )

        taskEventsRoute(config, taskCompletionHub, accessStore, authz, datasourceStore, principalSessionStore, appJson)

        // Per-principal editor query history (auto-saved on each run; recalled in the editor).
        queryHistoryRoutes(config, queryHistoryStore)

        // Wire-auth: SESSION/PAT token issuance + revocation.
        tokenRoutes(config, tokenStore, userGroupStore, authz)

        // Cedar policy admin: put/enable/disable + validate-on-write. Admin-gated: admin.policies.
        cedarPolicyRoutes(config, authz, cedarPolicyStore, policyManagement)

        // Decision ingest from the proxy/data plane. Optionally token-gated.
        post("/api/ingest/decision") {
            val expected = config.secretToken
            if (expected != null) {
                val provided = call.request.headers["X-PM-Ingest-Token"]
                if (provided != expected) {
                    call.invalidToken("ingest")
                    return@post
                }
            }
            val rec = call.receive<AuditEvent>()
            store.insert(rec)
            call.respond(HttpStatusCode.Accepted, mapOf("status" to "accepted"))
        }

        // Live decision feed for the UI. Requires a session unless running in auth-debug mode.
        auditRoutes(config, store, authz)

        // Dev-only login shortcut; gated by PM_AUTH_DEBUG. OIDC (above) is the production path.
        post("/auth/debug") {
            if (!config.authDebug) {
                call.notFound("endpoint")
                return@post
            }
            val login = call.receive<DebugLogin>()
            // The claimed roles become the principal's DIRECT assignments, replacing whatever it had.
            // Authorization resolves roles from the database (RoleResolver.directRoles + grants + groups),
            // never from the session — so a role merely carried in the session would display in the UI while
            // every query denied on an empty role set. Persisting them is what makes "sign in as this
            // principal with these roles" true. Replace rather than add: the claim is the whole intended
            // set, so a second debug login cannot silently accumulate roles from the first.
            val roles = login.roles.map { it.trim() }.filter { it.isNotBlank() }.distinct()
            // Rejected outright when malformed rather than dropped to null: a silently-ignored address
            // would present as "the tag rule does not work", sending the reader after a policy bug that
            // isn't there.
            val debugRequesterIp = login.requesterIp?.trim()?.takeIf { it.isNotEmpty() }
            if (debugRequesterIp != null && !isStorableIpLiteral(debugRequesterIp, authz::evaluatesInCedar)) {
                call.respond(HttpStatusCode.BadRequest, ApiError("auth.invalid_requester_ip"))
                return@post
            }
            val deviceId = call.ensureDeviceCookie(config.mcpIssuer.startsWith("https://"))
            // Roles and session in ONE transaction under ONE per-principal lock (mintWeb re-takes the same
            // advisory lock, which is re-entrant). Committing separately would let a failed mint leave the roles
            // rewritten under a login that never succeeded, and would let two concurrent logins interleave —
            // roles {A} then roles {B} then mint {B} then mint {A} leaves the surviving session claiming {A}
            // while the database says {B}. The response must describe the state the session actually resolves.
            val sessionId = try {
                dataSource.inTx { c ->
                    policyManagement.replaceDirectRoles(login.principal, roles, c)
                    principalSessionStore.mintWeb(
                        login.principal,
                        null,
                        config.webSessionAbsoluteSeconds,
                        config.webSessionIdleSeconds,
                        deviceId,
                        c,
                        debugRequesterIp,
                    )
                }
            } catch (e: ManagementException) {
                call.respondManagementError(e)
                return@post
            }
            call.sessions.set(WebSessionRef(sessionId))
            call.respond(HttpStatusCode.OK, UserSession(login.principal, roles, debugRequesterIp))
        }

        mePermissionsRoute(config, authz)

        authenticate(WEB_SESSION_AUTH) {
            get("/auth/me") {
                call.response.header(HttpHeaders.CacheControl, "no-store")
                // Resolved per request, never carried in the session: a role gained or lost after
                // login (group change, expired JIT grant, deactivation) must be visible to the next
                // read, and the console shows this set while explaining a decision.
                val row = requireNotNull(call.principal<WebSessionRow>())
                // Reported only while the bypass that honors it is on, so the console never shows a
                // simulated address the decision path is in fact ignoring.
                val simulatedIp = row.debugRequesterIp.takeIf { config.authDebug }
                call.respond(UserSession(row.principal, roleResolver.resolve(row.principal).sorted(), simulatedIp))
            }

            get("/auth/session/status") {
                call.response.header(HttpHeaders.CacheControl, "no-store")
                val row = requireNotNull(call.principal<WebSessionRow>())
                call.respond(row.toSessionStatus())
            }

            post("/auth/session/heartbeat") {
                call.response.header(HttpHeaders.CacheControl, "no-store")
                val row = requireNotNull(call.principal<WebSessionRow>())
                val touched = principalSessionStore.touchWeb(row.id, call.deviceCookieId())
                if (touched == null) {
                    call.attributes.put(FAILED_WEB_SESSION, row.id)
                    respondSessionUnauthorized(call, principalSessionStore)
                    return@post
                }
                call.respond(touched.toSessionStatus())
            }
        }

        post("/auth/logout") {
            val request = if (call.request.contentLength() == 0L || call.request.headers[HttpHeaders.ContentType] == null) {
                null
            } else {
                call.receiveNullable<LogoutRequest>()
            }
            val currentRef = runCatching { call.sessions.get<WebSessionRef>() }.getOrNull()
            // A conditional automatic logout can end only the exact session observed by the client;
            // a re-login may already have replaced the tracker with a fresh row.
            if (request?.sessionId != null && currentRef != null && currentRef.sessionId != request.sessionId) {
                call.respond(HttpStatusCode.OK, LogoutResponse(ended = false))
                return@post
            }
            call.sessions.clear(SESSION_COOKIE)
            call.respond(HttpStatusCode.OK, LogoutResponse(ended = true))
        }
    }
}
