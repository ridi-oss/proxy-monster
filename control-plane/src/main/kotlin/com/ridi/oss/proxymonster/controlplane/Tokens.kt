package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_MINT
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_TOKEN_REVOKE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_WIRE
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.requireAuthz
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Connection
import java.util.Base64
import javax.sql.DataSource

// ---- Token kind ------------------------------------------------------------

/**
 * The kind of wire credential a token is. The enum name is the value stored in `proxy_token.kind` and
 * carried on the wire, so [name] round-trips to the DB/proto and [fromWire] parses back (null on an
 * unrecognized value, so callers fail closed rather than throw).
 */
enum class TokenKind {
    SESSION,        // daemon-held short-lived session (`pm login`)
    USER,           // generated PAT, pasted / injected by the user
    EDITOR,         // stateful editor session
    APPROVER_EXEC,  // approver running an approved query under role R
    ;

    companion object {
        fun fromWire(value: String): TokenKind? = entries.firstOrNull { it.name == value }
    }
}

// ---- DTOs — the wire contract for /api/wire-tokens + /api/tokens** -----------

/** A token row as listed to its owner — never includes the secret itself. */
@Serializable
data class WireTokenInfo(
    val id: Long,
    val kind: String,            // SESSION (daemon-held) | USER (generated to paste / inject)
    val principal: String,
    val name: String? = null,
    val createdAt: String,
    val expiresAt: String,       // always set — proxy-monster issues only expiring tokens
    val revokedAt: String? = null,
    val lastUsedAt: String? = null,
)

/** Returned exactly once at issuance — the only time the plaintext token is visible. */
@Serializable
data class IssuedToken(val token: String, val id: Long, val kind: String, val name: String? = null, val expiresAt: String)

/** Resolved identity for a presented wire token (the proxy's validate result). */
@Serializable
data class WireIdentity(val principal: String, val roles: List<String>, val kind: String)

@Serializable
data class MintSessionTokenInput(val ttlSeconds: Long? = null)

@Serializable
data class CreateTokenInput(val name: String? = null, val ttlSeconds: Long? = null)

// ---- TTL policy (pure; wire credentials are ALWAYS expiring — DESIGN.md) -----------------

/** Min/max lifetime for any issued token. No token is permanent; none lives past [TOKEN_MAX_TTL_SECONDS]. */
const val TOKEN_MIN_TTL_SECONDS = 60L
const val TOKEN_MAX_TTL_SECONDS = 24 * 3600L
const val SESSION_TTL_SECONDS = 12 * 3600L   // daemon session default (refreshed by the daemon)
const val DEFAULT_USER_TTL_SECONDS = 3600L   // generated "connect password" default: 1h

/** Clamp a requested TTL into the allowed window — the invariant that keeps tokens expiring + bounded. */
fun clampTtlSeconds(ttlSeconds: Long): Long = ttlSeconds.coerceIn(TOKEN_MIN_TTL_SECONDS, TOKEN_MAX_TTL_SECONDS)

// ---- Store ------------------------------------------------------------------

/**
 * SHA-256 hex digest of a wire/ephemeral token — the ONE hashing definition shared by [TokenStore] (the
 * `proxy_token.token_hash` column) and [RequesterIpRegistry] (RunExec.kt): the
 * CP-only decide-time carrier keys off this SAME hash so it never stores a raw token at rest in a second
 * map, and its key always matches the token row's own `token_hash`.
 */
internal fun tokenHash(token: String): String {
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(token.toByteArray()).joinToString("") { "%02x".format(it) }
}

class TokenStore(internal val dataSource: DataSource) {
    private val json = Json
    private val stringList = ListSerializer(String.serializer())
    private val rng = SecureRandom()

    val sessionTtlSeconds = SESSION_TTL_SECONDS
    val defaultUserTtlSeconds = DEFAULT_USER_TTL_SECONDS

    private fun hash(token: String): String = tokenHash(token)

    private fun randomToken(prefix: String): String {
        val raw = ByteArray(32).also { rng.nextBytes(it) }
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    /**
     * Issue an expiring token. [kind] is SESSION (daemon, prefix `pmt_`) or USER (generated,
     * prefix `pmk_`). [ttlSeconds] is clamped to [60, maxTtlSeconds]; there is no no-expiry option.
     */
    fun issue(kind: TokenKind, principal: String, roles: List<String>, name: String?, ttlSeconds: Long): IssuedToken =
        dataSource.connection.use { c -> issue(kind, principal, roles, name, ttlSeconds, c) }

    /**
     * Same as [issue], but INSERTs on the caller-supplied connection [c] instead of opening a new one —
     * so a caller composing a locked, multi-store transaction (the renew route's locked re-mint)
     * can mint the token as part of that SAME transaction/commit. `expires_at` comes back
     * from `RETURNING` on this SAME connection (never the plain no-connection [get], which would open a
     * second connection and could read a different/uncommitted view of the row).
     */
    fun issue(kind: TokenKind, principal: String, roles: List<String>, name: String?, ttlSeconds: Long, c: Connection): IssuedToken {
        val ttl = clampTtlSeconds(ttlSeconds)
        val prefix = if (kind == TokenKind.SESSION) "pmt_" else "pmk_"
        val token = randomToken(prefix)
        val (id, expiresAt) = c.prepareStatement(
            """INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at)
               VALUES (?, ?, ?, ?::jsonb, ?, now() + (?::bigint * interval '1 second'))
               RETURNING id, expires_at""",
        ).use { ps ->
            ps.setString(1, hash(token))
            ps.setString(2, kind.name)
            ps.setString(3, principal)
            ps.setString(4, json.encodeToString(stringList, roles))
            ps.setString(5, name)
            ps.setLong(6, ttl)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) to rs.getTimestamp(2).toInstant().toString() }
        }
        return IssuedToken(token, id, kind.name, name, expiresAt)
    }

    /**
     * Read-only token check for the per-query hot path (gRPC `Decide`, docs/datasource-registration.md):
     * same existence/revocation/expiry predicate as [validate] but WITHOUT the `last_used_at` write, so
     * many concurrent queries sharing one daemon/session token don't serialize on a single row's UPDATE
     * lock (or generate WAL per query). `last_used_at` is stamped once per session by [validate] at the
     * handshake, which is freshness enough for a "recently used" signal.
     */
    fun resolve(token: String): WireIdentity? = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT principal, roles, kind FROM proxy_token WHERE token_hash = ? AND kind IN ('SESSION', 'USER', 'EDITOR', 'APPROVER_EXEC') AND revoked_at IS NULL AND expires_at > now()",
        ).use { ps ->
            ps.setString(1, hash(token))
            ps.executeQuery().use { rs ->
                if (rs.next()) {
                    WireIdentity(
                        rs.getString("principal"),
                        json.decodeFromString(stringList, rs.getString("roles") ?: "[]"),
                        rs.getString("kind"),
                    )
                } else {
                    null
                }
            }
        }
    }

    /**
     * Validate a presented token: must exist, not be revoked, and not be expired. On success,
     * stamp `last_used_at` and return the principal + base roles. Null otherwise. Used for the session
     * handshake (per-query enforcement uses [resolve], which skips the write).
     */
    fun validate(token: String): WireIdentity? = dataSource.connection.use { c ->
        c.prepareStatement(
            // A transient editor/approver-exec token authorizes exactly ONE proxy-mediated query via the
            // per-query `resolve` path — it must NOT pass the wire-session handshake, so a leaked ephemeral
            // token can't open a native MySQL/PG session as that principal within its short TTL. Both
            // ephemeral kinds (editor and approver-exec) are excluded here.
            """UPDATE proxy_token SET last_used_at = now()
               WHERE token_hash = ? AND kind IN ('SESSION', 'USER') AND revoked_at IS NULL AND expires_at > now()
               RETURNING principal, roles, kind""",
        ).use { ps ->
            ps.setString(1, hash(token))
            ps.executeQuery().use { rs ->
                if (rs.next()) {
                    WireIdentity(
                        rs.getString("principal"),
                        json.decodeFromString(stringList, rs.getString("roles") ?: "[]"),
                        rs.getString("kind"),
                    )
                } else {
                    null
                }
            }
        }
    }

    /** List a principal's user-visible tokens, excluding transient editor-channel credentials. */
    fun list(principal: String): List<WireTokenInfo> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT id, kind, principal, name, created_at, expires_at, revoked_at, last_used_at
               FROM proxy_token WHERE principal = ? AND kind IN ('SESSION', 'USER') ORDER BY created_at DESC""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs ->
                val out = ArrayList<WireTokenInfo>()
                while (rs.next()) out += rs.toInfo()
                out
            }
        }
    }

    fun get(id: Long): WireTokenInfo? = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT id, kind, principal, name, created_at, expires_at, revoked_at, last_used_at
               FROM proxy_token WHERE id = ?""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toInfo() else null }
        }
    }

    /** Revoke a token by id, but only if it belongs to [principal] (ownership check). */
    fun revoke(id: Long, principal: String): Boolean = dataSource.connection.use { c -> revoke(id, principal, c) }

    fun revoke(id: Long, principal: String, c: Connection): Boolean =
        c.prepareStatement(
            "UPDATE proxy_token SET revoked_at = now() WHERE id = ? AND principal = ? AND revoked_at IS NULL",
        ).use { ps ->
            ps.setLong(1, id); ps.setString(2, principal)
            ps.executeUpdate() > 0
        }

    /**
     * Revoke every currently-active (non-revoked, non-expired) wire token for [principal] — the
     * deprovisioning backstop (docs/auth-model.md "Deprovisioning propagates two ways"): a SCIM
     * `active=false` push or a failed IdP liveness recheck kills live credentials mid-window,
     * without waiting for natural expiry. Returns the number of tokens revoked.
     */
    fun revokeAllForPrincipal(principal: String): Int = dataSource.connection.use { c -> revokeAllForPrincipal(principal, c) }

    /** Same as [revokeAllForPrincipal], composed onto a caller-supplied connection [c] (see [issue]'s overload doc). */
    fun revokeAllForPrincipal(principal: String, c: Connection): Int =
        c.prepareStatement(
            "UPDATE proxy_token SET revoked_at = now() WHERE principal = ? AND revoked_at IS NULL AND expires_at > now()",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeUpdate()
        }

    private fun java.sql.ResultSet.toInfo() = WireTokenInfo(
        id = getLong("id"),
        kind = getString("kind"),
        principal = getString("principal"),
        name = getString("name"),
        createdAt = getTimestamp("created_at").toInstant().toString(),
        expiresAt = getTimestamp("expires_at").toInstant().toString(),
        revokedAt = getTimestamp("revoked_at")?.toInstant()?.toString(),
        lastUsedAt = getTimestamp("last_used_at")?.toInstant()?.toString(),
    )
}

// ---- Routes -----------------------------------------------------------------

private fun principalOf(call: io.ktor.server.application.ApplicationCall) = call.userSession()?.principal ?: "debug-user"
private fun rolesOf(call: io.ktor.server.application.ApplicationCall) = call.userSession()?.roles ?: emptyList()

/** The audited actor of a token route: whoever made the request, resolved the same way the route's own
 *  authorization resolves it — never the token's owner, who may be someone else on the revoke path. */
private fun callerActor(call: io.ktor.server.application.ApplicationCall, config: Config) =
    AuditActor(principalOf(call), clientAddr = call.httpRequesterIp(config), channel = CHANNEL_WIRE)

fun Route.tokenRoutes(
    config: Config,
    store: TokenStore,
    userGroupStore: UserGroupStore,
    authz: Authz,
    authAudit: AuthAuditRecorder,
) {
    // Mint a short-lived SESSION token for the daemon (`pm login`) — held locally, refreshed.
    // Credential issuance is a Cedar decision (token.mint on Token{owner, kind}); the self seed permits a
    // principal to mint its own, a kind-scoped forbid can bar a role from long-lived PATs.
    post("/api/wire-tokens") {
        val principal = principalOf(call)
        if (!call.requireAuthz(config, authz, AuthzAction.TOKEN_MINT, AuthzResource.Token(principal, TokenKind.SESSION))) return@post
        val ttl = call.receive<MintSessionTokenInput>().ttlSeconds ?: store.sessionTtlSeconds
        val roles = rolesOf(call)
        // A deprovisioned principal must not mint fresh wire credentials, even mid-session — and the
        // check + the INSERT run on ONE transaction under the per-principal advisory lock,
        // so a concurrent SCIM/liveness teardown can't slip its revoke between them and leave a
        // token that survives the deprovision (resurrectable on a later reactivation).
        val minter = callerActor(call, config)
        val issued = store.dataSource.mintForActivePrincipalLocked(principal, userGroupStore) { c ->
            store.issue(TokenKind.SESSION, principal, roles, name = null, ttlSeconds = ttl, c).also { token ->
                authAudit.success(
                    c,
                    minter,
                    ACTION_TOKEN_MINT,
                    auditEntity("Token", token.id.toString()),
                    "Minted SESSION wire token",
                )
            }
        }
        if (issued == null) {
            call.respond(HttpStatusCode.Forbidden, ApiError("auth.principal_deprovisioned")); return@post
        }
        call.respond(issued)
    }

    // Managed user tokens (expiring): generate / list / revoke from the web UI or the `pm` CLI.
    get("/api/tokens") {
        // Defaults to the caller's own tokens (self seed); an identity admin may pass ?principal= to
        // list another principal's (token.list oversight seed). This returns METADATA only; a token's
        // secret is only ever exposed at mint (token.mint) and is never re-readable. kind is irrelevant here.
        val target = call.request.queryParameters["principal"] ?: principalOf(call)
        if (!call.requireAuthz(config, authz, AuthzAction.TOKEN_LIST, AuthzResource.Token(target, kind = null))) return@get
        call.respond(store.list(target))
    }
    post("/api/tokens") {
        val principal = principalOf(call)
        if (!call.requireAuthz(config, authz, AuthzAction.TOKEN_MINT, AuthzResource.Token(principal, TokenKind.USER))) return@post
        val input = call.receive<CreateTokenInput>()
        val ttl = input.ttlSeconds ?: store.defaultUserTtlSeconds
        val roles = rolesOf(call)
        // Same locked check-then-mint as /api/wire-tokens above — no fresh credentials
        // for a deactivated principal, and no revoke can race between the check and the INSERT.
        val minter = callerActor(call, config)
        val issued = store.dataSource.mintForActivePrincipalLocked(principal, userGroupStore) { c ->
            store.issue(TokenKind.USER, principal, roles, input.name?.ifBlank { null }, ttl, c).also { token ->
                authAudit.success(
                    c,
                    minter,
                    ACTION_TOKEN_MINT,
                    auditEntity("Token", token.id.toString()),
                    "Minted USER wire token",
                )
            }
        }
        if (issued == null) {
            call.respond(HttpStatusCode.Forbidden, ApiError("auth.principal_deprovisioned")); return@post
        }
        call.respond(HttpStatusCode.Created, issued)
    }
    delete("/api/tokens/{id}") {
        val id = call.parameters["id"]?.toLongOrNull()
            ?: return@delete call.badId()
        // Load the token so Cedar decides against its real owner/kind (replaces the WHERE
        // principal = ? ownership SQL). A missing token is a 404 before any authorization is revealed.
        val token = store.get(id)
            ?: return@delete call.notFound("token")
        if (!call.requireAuthz(config, authz, AuthzAction.TOKEN_REVOKE, AuthzResource.Token(token.principal, TokenKind.fromWire(token.kind)))) return@delete
        // The actor is the CALLER, not the token's owner: an oversight seed lets an identity admin revoke
        // someone else's token, and attributing that to the owner would name the victim as the actor.
        val revoker = callerActor(call, config)
        val revoked = store.dataSource.inTx { c ->
            store.revoke(id, token.principal, c).also { changed ->
                if (changed) {
                    authAudit.success(
                        c,
                        revoker,
                        ACTION_TOKEN_REVOKE,
                        auditEntity("Token", id.toString()),
                        "Revoked ${token.kind} wire token owned by ${token.principal}",
                    )
                }
            }
        }
        if (revoked) call.respond(HttpStatusCode.NoContent) else call.notFound("token")
    }
}
