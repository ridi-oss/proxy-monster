package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.clampTtlSeconds
import java.net.URI

typealias OidcGroupMapping = com.ridi.oss.proxymonster.auth.OidcGroupMapping

/**
 * Generic OIDC settings (docs/auth-model.md) — provider-agnostic: endpoints are resolved from
 * discovery (`${issuer}/.well-known/openid-configuration`), not hardcoded per-provider paths.
 * Any OIDC provider works. Parsed only when all four required values are
 * present. Used by both the web authorization-code flow AND the CLI/daemon device-authorization
 * flow — device-auth reuses this SAME confidential client (no separate CLI client config).
 */
data class OidcConfig(
    val issuer: String,
    val clientId: String,
    val clientSecret: String,
    val redirectUri: String,
    val scopes: String,
    val groupMapping: OidcGroupMapping,
)

/**
 * Service configuration, read from the environment with local-dev defaults so the service
 * boots against the docker-compose Postgres without any env wiring.
 */
data class Config(
    val httpPort: Int,
    // The gRPC port the proxy connects to (docs/datasource-registration.md). Separate from httpPort:
    // the web UI keeps talking HTTP/JSON; only the proxy<->control-plane wire protocol is gRPC.
    // Defaulted so the many HTTP-route tests that build a Config by name need not name it.
    val grpcPort: Int = DEFAULT_GRPC_PORT,
    val dbUrl: String,
    val dbUser: String,
    val dbPassword: String,
    val authDebug: Boolean,
    // The one shared secret gating EVERY proxy↔control-plane surface: the gRPC transport (all RPCs) plus
    // the HTTP ingest routes. When set, calls must present it; when null the gate is OPEN (dev only, logged).
    val secretToken: String?,
    val sessionSecret: String,
    val oidc: OidcConfig?,
    // AES-256 key (32 bytes) for at-rest encryption of APPROVER_EXEC query results. Null when
    // PM_RESULT_KEY is unset → approver-exec execution is refused fail-closed (no plaintext PII at rest).
    val resultKey: ByteArray?,
    // SCIM 2.0 bearer token (docs/auth-model.md) — a standing secret, constant-time compared, TLS-only.
    // Null disables the SCIM endpoints fail-closed (no unauthenticated provisioning surface).
    val scimToken: String?,
    // The daemon/CLI session window (docs/auth-model.md "Session renewal") — within it, silent
    // wire-token renewal; after it, device-auth re-prompts.
    val sessionWindowSeconds: Long,
    val webSessionAbsoluteSeconds: Long = 2 * 3600,
    // Sliding inactivity window for web sessions.
    val webSessionIdleSeconds: Long = 15 * 60,
    // Minimum interval between web idle-deadline extensions; must be less than the idle window.
    val webSessionSlideSeconds: Long = 2 * 60,
    // Warning leads may exceed their session windows; the client clamps them instead of rejecting config.
    val webSessionIdleWarnLeadSeconds: Long = 60,
    val webSessionAbsoluteWarnLeadSeconds: Long = 5 * 60,
    val webSessionHeartbeatSeconds: Long = 90,
    // Timer-driven IdP identity/group revalidation interval for both web and daemon sessions
    // (docs/auth-model.md "Liveness").
    val idpRecheckIntervalSeconds: Long,
    // Explicit non-production marker required alongside PM_AUTH_DEBUG (see the guard below).
    val devMarker: Boolean,
    // Trusted forwarding edges (docs/authz-context.md): the SOCKET-PEER addresses (literal addresses or CIDR
    // blocks, matched against RequestConnectionPoint.remoteAddress) of edges the control-plane trusts
    // to assert forwarded headers about a request — e.g. a load balancer or reverse proxy terminating TLS
    // in front of the HTTP API. THREE headers are trusted from such a peer: `X-Forwarded-For` for
    // requester_ip (resolveHttpRequesterIp), `X-Forwarded-Proto` for the SCIM TLS gate (resolveScimTls),
    // and `X-Forwarded-Host` for the host the client addressed (resolveForwardedAuthority, which the
    // /mcp host check compares against PM_MCP_RESOURCE).
    // Empty (the default) means NO edge is trusted: every one of them is ignored, so requester_ip is the
    // raw socket peer, a plaintext request can never pass the SCIM TLS gate, and the /mcp check sees the
    // socket authority — the fail-closed posture, since an untrusted client can set any of them to anything.
    //
    // DEPLOYMENT REQUIREMENT for any address listed here: the edge must OVERWRITE the forwarded headers it
    // asserts, from its own view of the connection — never pass an inbound client-supplied value through.
    // An edge that forwards a client's `X-Forwarded-Proto: https` verbatim lets a PLAINTEXT request satisfy
    // the SCIM TLS gate and the standing SCIM bearer then travels in the clear. Every resolver reads the
    // RIGHTMOST value, which is the one a correctly-configured appending edge wrote, so an edge that
    // appends (rather than replaces) is also safe; one that relays the client's value unchanged is not.
    // Defaulted so the many Config-by-name test files need not name it.
    val trustedProxies: Set<String> = emptySet(),
    // Canonical MCP resource identifier. The co-hosted OAuth issuer is always this URI's origin; it is
    // never independently configured and never inferred from Host/X-Forwarded-* request data.
    val mcpResource: String = "http://127.0.0.1:8080/mcp",
    // Origin of the WEB console, used to build the browser URL `pmon login` prints (the `/device`
    // verification page is a web route, not a control-plane one). Blank means "same origin as the control
    // plane" ([mcpIssuer]) — correct for the normal single-edge deployment where one host fronts both. Set
    // PM_WEB_ORIGIN when the console is served from a different origin (e.g. a separate dev server port),
    // otherwise the printed URL would point at the control plane, which serves no such page.
    val webOrigin: String = "",
    val mcpAccessTtlSeconds: Long = 600,
    val mcpRefreshTtlSeconds: Long = 21_600,
    val mcpDebugAutoConsent: Boolean = true,
    val queryTimeoutSeconds: Long = 600,
) {
    init {
        require(webSessionSlideSeconds < webSessionIdleSeconds) {
            "PM_WEB_SESSION_SLIDE must be less than PM_WEB_SESSION_IDLE"
        }
        // The liveness sweep loops on delay(idpRecheckIntervalSeconds); a zero or negative value would
        // either busy-loop the sweep (exhausting single-use refresh tokens, hammering the IdP) or make
        // delay() throw and permanently kill the sole revalidator. Refuse to start instead.
        require(idpRecheckIntervalSeconds > 0) {
            "PM_IDP_RECHECK_INTERVAL must be a positive number of seconds"
        }
    }

    val mcpIssuer: String
        get() {
            val uri = URI(mcpResource)
            return URI(uri.scheme, null, uri.host, uri.port, null, null, null).toASCIIString().trimEnd('/')
        }

    /** Origin to build browser-facing web URLs on (the `/device` page): [webOrigin] when set, else same-origin. */
    val webBaseUrl: String
        get() = webOrigin.trim().trimEnd('/').ifBlank { mcpIssuer }

    fun webRedirectTarget(path: String): String =
        if (webOrigin.isBlank()) path else "$webBaseUrl$path"

    // The outer per-statement exchange budget the run paths wait on, in milliseconds. Overflow-safe:
    // queryTimeoutSeconds is bounded by MAX_QUERY_TIMEOUT_SECONDS. Kept a grace above the proxy watchdog
    // (see QUERY_EXCHANGE_GRACE_MS) so the watchdog cancels the statement gracefully before this fires.
    val queryExchangeTimeoutMs: Long
        get() = queryTimeoutSeconds * 1000 + QUERY_EXCHANGE_GRACE_MS

    companion object {
        // Dev-only signing secret; PM_SESSION_SECRET must be set in any real deployment.
        private const val DEV_SESSION_SECRET = "dev-insecure-session-secret-change-me"

        // Default gRPC port the control-plane listens on for the proxy (PM_GRPC_PORT overrides).
        const val DEFAULT_GRPC_PORT = 9090

        // Matches the proxy's duration-safe ceiling (goproxy/config/config.go): (MaxInt64ns - 30s)/1s =
        // 9_223_372_006 seconds (~292 years). Bounding the control-plane to the identical value keeps the
        // "one shared PM_QUERY_TIMEOUT" lockstep contract exact and every downstream millisecond
        // conversion (the exchange + run-stream caps) within Long range.
        const val MAX_QUERY_TIMEOUT_SECONDS = 9_223_372_006L

        // The control-plane's per-statement exchange budget sits this far above the configured query
        // timeout so the proxy's PM_QUERY_TIMEOUT watchdog — which starts later, at backend exec — fires
        // first and cancels the statement in-band, rather than the CP exchange pre-empting it.
        // Headroom the exchange budget adds over the proxy's own statement watchdog. It has to absorb
        // everything the proxy does around the guarded execution — the watchdog wraps only the backend
        // statement, while authorization and the catalog probes before it run outside that guard and have
        // been measured in the tens of seconds against a large remote catalog. Too small and the control
        // plane calls a timeout on a statement whose watchdog has not fired, blaming the query for time
        // spent before it started.
        const val QUERY_EXCHANGE_GRACE_MS = 150_000L

        fun fromEnv(env: (String) -> String? = System::getenv): Config {
            val oidc = run {
                val issuer = env("PM_OIDC_ISSUER")
                val clientId = env("PM_OIDC_CLIENT_ID")
                val clientSecret = env("PM_OIDC_CLIENT_SECRET")
                val redirectUri = env("PM_OIDC_REDIRECT_URI")
                if (issuer != null && clientId != null && clientSecret != null && redirectUri != null) {
                    OidcConfig(
                        issuer = issuer,
                        clientId = clientId,
                        clientSecret = clientSecret,
                        redirectUri = redirectUri,
                        // offline_access → a refresh token, needed for the daemon's silent renewal +
                        // refresh-grant IdP liveness check (docs/auth-model.md).
                        scopes = env("PM_OIDC_SCOPES") ?: "openid profile email groups offline_access",
                        groupMapping = OidcGroupMapping.parse(env("PM_OIDC_GROUP_MAP"), env("PM_OIDC_GROUP_PREFIX")),
                    )
                } else {
                    null
                }
            }
            val authDebug = env("PM_AUTH_DEBUG")?.toBooleanStrictOrNull() ?: true
            val sessionSecret = env("PM_SESSION_SECRET") ?: DEV_SESSION_SECRET
            val devMarker = env("PM_DEV")?.toBooleanStrictOrNull() ?: false
            val mcpResource = canonicalMcpResource(
                env("PM_MCP_RESOURCE") ?: "http://127.0.0.1:8080/mcp",
                requireHttps = !authDebug,
            )
            val mcpIssuer = mcpOrigin(mcpResource)
            // A set-but-garbage value fails fast rather than silently falling back to the default — a
            // misconfigured timeout must surface at boot, not be quietly ignored.
            val queryTimeoutSeconds = env("PM_QUERY_TIMEOUT")?.let {
                it.toLongOrNull() ?: throw IllegalArgumentException("PM_QUERY_TIMEOUT must be a positive integer number of seconds; got '$it'")
            } ?: 600
            require(queryTimeoutSeconds > 0) { "PM_QUERY_TIMEOUT must be greater than zero" }
            // Reject values the proxy would also reject, so a set-but-oversized timeout fails fast at boot
            // instead of silently overflowing the millisecond exchange/run-stream conversions to a negative
            // or tiny cap (and diverging from the proxy's identical bound).
            require(queryTimeoutSeconds <= MAX_QUERY_TIMEOUT_SECONDS) {
                "PM_QUERY_TIMEOUT must be at most $MAX_QUERY_TIMEOUT_SECONDS seconds; got '$queryTimeoutSeconds'"
            }

            // Fail-closed guard (docs/auth-model.md "Security invariants"): PM_AUTH_DEBUG is a full
            // authentication bypass (/auth/debug + the dev-resolved device flow set any principal) and
            // defaults ON for local dev. Heuristically detect a production-looking context — real OIDC
            // configured, or a real (non-default) session secret — and refuse to start with debug auth
            // on unless PM_DEV explicitly opts in. The heuristic can't be perfect, but it stops the
            // common "forgot to unset PM_AUTH_DEBUG in prod" mistake.
            require(!authDebug || devMarker || (oidc == null && sessionSecret == DEV_SESSION_SECRET)) {
                "PM_AUTH_DEBUG on in a production-looking context (PM_OIDC_* or PM_SESSION_SECRET set) " +
                    "without PM_DEV — refusing to start"
            }
            require(authDebug || (sessionSecret != DEV_SESSION_SECRET && sessionSecret.length >= 32)) {
                "PM_SESSION_SECRET must be a non-default secret of at least 32 characters when PM_AUTH_DEBUG is false"
            }
            require(authDebug || oidc != null) { "PM_OIDC_* must be configured when PM_AUTH_DEBUG is false" }
            if (!authDebug) {
                requireSecureOidcUri(requireNotNull(oidc).issuer, "PM_OIDC_ISSUER")
                require(oidc.redirectUri == "$mcpIssuer/auth/oidc/callback") {
                    "PM_OIDC_REDIRECT_URI must equal the co-hosted control-plane callback URI"
                }
            }

            return Config(
                httpPort = env("PM_HTTP_PORT")?.toIntOrNull() ?: 8080,
                grpcPort = env("PM_GRPC_PORT")?.toIntOrNull() ?: DEFAULT_GRPC_PORT,
                dbUrl = env("PM_DB_URL") ?: "jdbc:postgresql://localhost:5432/proxymonster",
                dbUser = env("PM_DB_USER") ?: "proxymonster",
                dbPassword = env("PM_DB_PASSWORD") ?: "proxymonster",
                authDebug = authDebug,
                secretToken = env("PM_SECRET_TOKEN"),
                sessionSecret = sessionSecret,
                oidc = oidc,
                resultKey = env("PM_RESULT_KEY")?.let { b64 ->
                    val bytes = java.util.Base64.getDecoder().decode(b64.trim())
                    require(bytes.size == 32) { "PM_RESULT_KEY must be a base64-encoded 32-byte (AES-256) key" }
                    bytes
                },
                scimToken = env("PM_SCIM_TOKEN"),
                sessionWindowSeconds = env("PM_SESSION_WINDOW")?.let(::parseDuration) ?: 2 * 3600,
                webSessionAbsoluteSeconds = env("PM_WEB_SESSION_ABSOLUTE")?.let(::parseDuration) ?: 2 * 3600,
                webSessionIdleSeconds = env("PM_WEB_SESSION_IDLE")?.let(::parseDuration) ?: 15 * 60,
                webSessionSlideSeconds = env("PM_WEB_SESSION_SLIDE")?.let(::parseDuration) ?: 2 * 60,
                webSessionIdleWarnLeadSeconds =
                    env("PM_WEB_SESSION_IDLE_WARN_LEAD")?.let(::parseDuration) ?: 60,
                webSessionAbsoluteWarnLeadSeconds =
                    env("PM_WEB_SESSION_ABSOLUTE_WARN_LEAD")?.let(::parseDuration) ?: 5 * 60,
                webSessionHeartbeatSeconds = env("PM_WEB_SESSION_HEARTBEAT")?.let(::parseDuration) ?: 90,
                idpRecheckIntervalSeconds = env("PM_IDP_RECHECK_INTERVAL")?.toLong() ?: 300,
                devMarker = devMarker,
                // `PM_TRUSTED_PROXIES = 10.0.0.1,10.0.0.2` — comma-separated socket-peer addresses (mirrors
                // OidcGroupMapping.parse's split/trim/filter-blank shape above). Unset/empty -> no trusted
                // edge -> neither X-Forwarded-For nor X-Forwarded-Proto is honored. A listed edge MUST
                // overwrite the headers it asserts rather than relay a client's (see the field doc).
                trustedProxies = env("PM_TRUSTED_PROXIES").orEmpty().split(',')
                    .map { it.trim() }.filter { it.isNotBlank() }.toSet(),
                mcpResource = mcpResource,
                webOrigin = env("PM_WEB_ORIGIN") ?: "",
                mcpAccessTtlSeconds = clampTtlSeconds(env("PM_OAUTH_ACCESS_TTL")?.toLongOrNull() ?: 600),
                mcpRefreshTtlSeconds = clampTtlSeconds(env("PM_OAUTH_REFRESH_TTL")?.toLongOrNull() ?: 21_600),
                mcpDebugAutoConsent = env("PM_OAUTH_DEBUG_AUTO_CONSENT")?.toBooleanStrictOrNull() ?: true,
                queryTimeoutSeconds = queryTimeoutSeconds,
            )
        }

        private fun canonicalMcpResource(raw: String, requireHttps: Boolean): String {
            val uri = URI(raw).normalize()
            require(
                uri.isAbsolute && uri.host != null && uri.userInfo == null && uri.fragment == null && uri.query == null &&
                    uri.path == "/mcp" && uri.scheme in setOf("http", "https") && (!requireHttps || uri.scheme == "https"),
            ) { "PM_MCP_RESOURCE must be a canonical ${if (requireHttps) "HTTPS " else ""}URI with exact /mcp path" }
            return URI(uri.scheme.lowercase(), null, uri.host.lowercase(), uri.port, "/mcp", null, null)
                .toASCIIString()
        }

        private fun mcpOrigin(resource: String): String {
            val uri = URI(resource)
            return URI(uri.scheme, null, uri.host, uri.port, null, null, null)
                .toASCIIString().trimEnd('/')
        }

        private fun requireSecureOidcUri(raw: String, name: String) {
            val uri = URI(raw)
            require(
                uri.scheme == "https" && uri.host != null && uri.userInfo == null &&
                    uri.query == null && uri.fragment == null,
            ) { "$name must be an HTTPS issuer URI" }
        }

    }
}

internal fun parseDuration(raw: String): Long = try {
    require(raw.isNotEmpty()) { "duration must not be empty" }
    if (raw.all(Char::isDigit)) {
        raw.toLong().also { require(it > 0) { "duration must be positive" } }
    } else {
        val segment = Regex("(\\d+)([hms])")
        var offset = 0
        var total = 0L
        for (match in segment.findAll(raw)) {
            require(match.range.first == offset) { "invalid duration: $raw" }
            val value = match.groupValues[1].toLong()
            val multiplier = when (match.groupValues[2]) {
                "h" -> 3600L
                "m" -> 60L
                else -> 1L
            }
            total = Math.addExact(total, Math.multiplyExact(value, multiplier))
            offset = match.range.last + 1
        }
        require(offset == raw.length && total > 0) { "invalid duration: $raw" }
        total
    }
} catch (e: ArithmeticException) {
    throw IllegalArgumentException("duration is too large: $raw", e)
}
