package com.ridi.oss.proxymonster.controlplane

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.ClientRequestException
import io.ktor.client.request.forms.submitForm
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Types
import java.time.Instant
import java.util.Base64
import javax.sql.DataSource

// ---- Wire DTOs -------------------------------------------------------------------------------

@Serializable
data class RenewSessionResponse(val token: String, val expiresAt: String)

// ---- Renewal secret --------------------------------------------------------------------------

private val renewalTokenRng = SecureRandom()

/** A fresh high-entropy renewal bearer secret (`pmr_...`) — mint-once, returned only in the device-poll result. */
private fun newRenewalToken(): String {
    val raw = ByteArray(32).also { renewalTokenRng.nextBytes(it) }
    return "pmr_" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
}

/**
 * SHA-256 hex digest — the SAME idiom [TokenStore]'s private `hash()` uses for `proxy_token.
 * token_hash`, kept self-contained here rather than reaching into [TokenStore] (that's a different
 * part's file; this store persists its own hashed secret in its own column).
 */
private fun sha256Hex(s: String): String {
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(s.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}

// ---- Liveness status -------------------------------------------------------------------------

/** A principal session's last-known IdP-liveness verdict (docs/auth-model.md "Liveness"). */
const val LIVENESS_ACTIVE = "ACTIVE"
const val LIVENESS_INACTIVE = "INACTIVE"
const val ENDED_SIGNED_OUT = "SIGNED_OUT"
const val ENDED_DISPLACED = "DISPLACED"
const val ENDED_DEACTIVATED = "DEACTIVATED"
const val ENDED_GROUP_REVOKED = "GROUP_REVOKED"
const val ENDED_IDP_REJECTED = "IDP_REJECTED"
const val ENDED_DEVICE_BIND_MISMATCH = "DEVICE_BIND_MISMATCH"

// ---- Store -------------------------------------------------------------------------------------

data class DaemonSessionRow(
    val id: Long,
    val principal: String,
    val handle: String?,
    val refreshTokenEnc: ByteArray?,
    val ttlSeconds: Long,
    val sessionExpiresAt: Instant,
    val lastIdpCheckAt: Instant?,
    val livenessStatus: String,
    val createdAt: Instant,
)

data class WebSessionRow(
    val id: Long,
    val principal: String,
    val createdAt: Instant,
    val absoluteExpiresAt: Instant,
    val idleExpiresAt: Instant,
    val now: Instant,
    // A simulated source address chosen at debug login, or null for every ordinary login. Read ONLY
    // while the debug-authentication bypass is enabled; see [ApplicationCall.httpRequesterIp].
    val debugRequesterIp: String? = null,
)

data class LivenessCandidate(
    val id: Long,
    val kind: String,
    val principal: String,
    val refreshTokenEnc: ByteArray?,
    val lastIdpCheckAt: Instant?,
)

/**
 * Server-side session state for every kind of authenticated principal, discriminated by the `kind`
 * column: DAEMON rows back CLI/daemon logins, WEB rows back browser-console logins. Daemon lookups
 * and renewal remain scoped `kind = 'DAEMON'`; web lifecycle methods remain scoped `kind = 'WEB'`;
 * only the liveness candidate query intentionally covers both kinds.
 *
 * DAEMON (docs/auth-model.md "Session renewal" + "Liveness"): one row per completed device-auth
 * login; [DaemonSessionRow.sessionExpiresAt] is the hard cap on silent wire-token renewal — past it,
 * `pmon` must re-run device-auth. WEB: one row per console login with a sliding idle deadline plus
 * an immovable absolute cap. Plain resolution validates liveness and device binding without extending
 * idle; only [touchWeb] extends it, at most once per slide interval. A web row is live only while both
 * deadlines are in the future and it has not been explicitly ended ([endWeb]).
 *
 * A stored IdP refresh token (present only when the client granted `offline_access`) is encrypted
 * at rest via [crypto] — the SAME AES-256-GCM idiom [QueryResultStore] uses for APPROVER_EXEC results — and is
 * NEVER stored in plaintext; when [crypto] is null (`PM_RESULT_KEY` unset), the refresh token simply
 * isn't persisted (for daemons, silent renewal + the session window still work and the refresh-grant
 * IdP liveness recheck degrades to "can't verify, leave cached status alone").
 */
class PrincipalSessionStore(
    internal val dataSource: DataSource,
    private val crypto: ResultCrypto?,
    private val webSessionIdleSeconds: Long = 900,
    private val webSessionSlideSeconds: Long = 120,
    // Invoked with a principal AND the connection that performed the session-end write whenever
    // one of THEIR web sessions transitions to ended via the central end seam — the single hook that covers
    // logout, deprovision, group-revocation, device-bind mismatch, and newest-wins displacement. Wired in
    // App.kt to drop that principal's saved editor results (delete-on-end). It runs on the SAME connection as
    // the session-end write, so when that write is part of a larger transaction (deprovision's atomic teardown
    // via [endAllWebForPrincipal] on a caller-supplied connection) the cleanup commits or rolls back WITH it —
    // never a separate auto-commit delete that could survive a rolled-back teardown and orphan a live session's
    // tabs. Defaulted null so every existing construction (Main, tests) compiles and stays a no-op.
    private val onWebSessionEnded: ((String, Connection) -> Unit)? = null,
) {

    /** A freshly-minted session row plus its plaintext [renewalToken] — visible ONLY at creation time. */
    data class CreatedDaemonSession(val row: DaemonSessionRow, val renewalToken: String)

    fun create(principal: String, handle: String?, refreshToken: String?, windowSeconds: Long, ttlSeconds: Long): CreatedDaemonSession =
        dataSource.connection.use { c -> create(principal, handle, refreshToken, windowSeconds, ttlSeconds, c) }

    /**
     * Same as [create], on a caller-supplied connection [c] — so a device-login can re-check
     * deprovisioning + open the session window + issue the SESSION token as ONE locked transaction.
     * Reads the row back on [c] (the just-inserted, still-uncommitted row), never the
     * plain [getById] which would open a second connection with a different view.
     */
    fun create(principal: String, handle: String?, refreshToken: String?, windowSeconds: Long, ttlSeconds: Long, c: Connection): CreatedDaemonSession {
        val encrypted = refreshToken?.let { crypto?.encrypt(it.toByteArray(Charsets.UTF_8)) }
        val renewalToken = newRenewalToken()
        val id = c.prepareStatement(
            """INSERT INTO principal_session (principal, handle, refresh_token_enc, ttl_seconds, absolute_expires_at, liveness_status, renewal_token_hash, kind)
               VALUES (?, ?, ?, ?, now() + make_interval(secs => ?), ?, ?, 'DAEMON')
               RETURNING id""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.setString(2, handle)
            if (encrypted == null) ps.setNull(3, Types.BINARY) else ps.setBytes(3, encrypted)
            ps.setLong(4, ttlSeconds)
            ps.setDouble(5, windowSeconds.toDouble())
            ps.setString(6, LIVENESS_ACTIVE)
            ps.setString(7, sha256Hex(renewalToken))
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        return CreatedDaemonSession(queryOneOn(c, "$SELECT AND id = ?") { it.setLong(1, id) }!!, renewalToken)
    }

    /**
     * Mint a newest-wins web session. When [c] is supplied, the caller must already be inside a
     * transaction so the principal advisory lock remains held through commit.
     */
    fun mintWeb(
        principal: String,
        refreshToken: String?,
        absoluteSeconds: Long,
        idleSeconds: Long,
        deviceId: String,
        c: Connection? = null,
        // Set by the debug login, and carried over by the debug OAuth authorize when it remints the same
        // principal's session. Read back only under the debug bypass.
        debugRequesterIp: String? = null,
    ): Long {
        val encrypted = refreshToken?.let { crypto?.encrypt(it.toByteArray(Charsets.UTF_8)) }
        var displaced = 0
        val core: (Connection) -> Long = { connection ->
            connection.advisoryLockPrincipal(principal)
            // Stamp created_at and both deadlines from a single post-lock clock_timestamp(), NOT now():
            // Postgres freezes now()/transaction_timestamp() at the transaction's first statement, which
            // here is the advisory lock above — and that lock can block behind a concurrent login for the
            // full idle window. A now()-based idle_expires_at would then be minted already in the past and
            // 401 the very session it just created. clock_timestamp() reflects the real current instant;
            // one CTE reading shares it across all three columns so the new row is internally consistent.
            val id = connection.prepareStatement(
                """WITH t AS (SELECT clock_timestamp() AS ts)
                   INSERT INTO principal_session
                   (principal, refresh_token_enc, created_at, absolute_expires_at, idle_expires_at, liveness_status, device_id, kind, debug_requester_ip)
                   SELECT ?, ?, t.ts, t.ts + make_interval(secs => ?), t.ts + make_interval(secs => ?), ?, ?, 'WEB', ?
                   FROM t
                   RETURNING id""",
            ).use { ps ->
                ps.setString(1, principal)
                if (encrypted == null) ps.setNull(2, Types.BINARY) else ps.setBytes(2, encrypted)
                ps.setDouble(3, absoluteSeconds.toDouble())
                ps.setDouble(4, idleSeconds.toDouble())
                ps.setString(5, LIVENESS_ACTIVE)
                ps.setString(6, deviceId)
                ps.setString(7, debugRequesterIp)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
            displaced = connection.prepareStatement(
                """UPDATE principal_session
                   SET ended_at = clock_timestamp(), ended_reason = ?, liveness_status = ?
                   WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL AND id <> ?""",
            ).use { ps ->
                ps.setString(1, ENDED_DISPLACED)
                ps.setString(2, LIVENESS_INACTIVE)
                ps.setString(3, principal)
                ps.setLong(4, id)
                ps.executeUpdate()
            }
            // Newest-wins displaced a prior WEB session for this principal (a new device/login). Route it
            // through the same end seam logout/deprovision use so the old session's saved editor results are
            // dropped — the new session starts clean. Composed onto THIS connection (inside the mint tx) so a
            // rolled-back mint reverts the cleanup too, never displacing+deleting under a mint that aborts.
            if (displaced > 0) onWebSessionEnded?.invoke(principal, connection)
            id
        }
        return if (c == null) dataSource.inTx(core) else core(c)
    }

    fun resolveWeb(id: Long, deviceId: String?): WebSessionRow? = dataSource.connection.use { c ->
        resolveWeb(id, deviceId, c)
    }

    fun touchWeb(id: Long, deviceId: String?): WebSessionRow? = dataSource.connection.use { c ->
        c.prepareStatement(
            """UPDATE principal_session
               SET idle_expires_at = now() + make_interval(secs => ?), last_seen_at = now()
               WHERE id = ? AND kind = 'WEB' AND ended_at IS NULL
                 AND absolute_expires_at > clock_timestamp()
                 AND idle_expires_at > clock_timestamp()
                 AND device_id = ?
                 AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => ?))""",
        ).use { ps ->
            ps.setDouble(1, webSessionIdleSeconds.toDouble())
            ps.setLong(2, id)
            ps.setString(3, deviceId)
            ps.setDouble(4, webSessionSlideSeconds.toDouble())
            ps.executeUpdate()
        }
        resolveWeb(id, deviceId, c)
    }

    private fun resolveWeb(id: Long, deviceId: String?, c: Connection): WebSessionRow? {
        val resolved = c.prepareStatement(
            """SELECT id, principal, created_at, absolute_expires_at, idle_expires_at, device_id,
                      debug_requester_ip, clock_timestamp() AS db_now
               FROM principal_session
               WHERE id = ? AND kind = 'WEB' AND ended_at IS NULL
                 AND absolute_expires_at > clock_timestamp()
                 AND idle_expires_at > clock_timestamp()""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (!rs.next()) {
                    null
                } else {
                    rs.getString("device_id") to WebSessionRow(
                        id = rs.getLong("id"),
                        principal = rs.getString("principal"),
                        createdAt = rs.getTimestamp("created_at").toInstant(),
                        absoluteExpiresAt = rs.getTimestamp("absolute_expires_at").toInstant(),
                        idleExpiresAt = rs.getTimestamp("idle_expires_at").toInstant(),
                        now = rs.getTimestamp("db_now").toInstant(),
                        debugRequesterIp = rs.getString("debug_requester_ip"),
                    )
                }
            }
        } ?: return null
        return if (resolved.first == null || resolved.first != deviceId) {
            endWeb(id, ENDED_DEVICE_BIND_MISMATCH, c)
            null
        } else {
            resolved.second
        }
    }

    fun endWeb(id: Long, reason: String, c: Connection? = null): Boolean {
        // The cleanup callback runs on the SAME connection as the end-write (see [onWebSessionEnded]), so when
        // [c] is a caller's transaction the delete composes with it; when null it shares this auto-commit
        // connection. Invoked inside the .use block so the connection is still open.
        val useConnection: (Connection) -> Boolean = { connection ->
            val principal = connection.prepareStatement(
                """UPDATE principal_session
                   SET ended_at = now(), ended_reason = ?, liveness_status = ?
                   WHERE id = ? AND kind = 'WEB' AND ended_at IS NULL
                   RETURNING principal""",
            ).use { ps ->
                ps.setString(1, reason)
                ps.setString(2, LIVENESS_INACTIVE)
                ps.setLong(3, id)
                ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
            }
            if (principal != null) onWebSessionEnded?.invoke(principal, connection)
            principal != null
        }
        return if (c == null) dataSource.connection.use(useConnection) else useConnection(c)
    }

    fun webEndedReason(id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ? AND kind = 'WEB'").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString("ended_reason") else null }
        }
    }

    /**
     * The decrypted IdP refresh token of a live WEB session, if it has one. Used when that session approves a
     * pmon device login: the token is carried onto the device login so the daemon session minted from it keeps
     * its IdP-liveness revalidation. Null when the login granted no `offline_access` or no result key is set —
     * [WebSessionRow] deliberately doesn't carry the ciphertext, so this is the narrow read for that case.
     */
    fun webRefreshToken(id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement(
            "SELECT refresh_token_enc FROM principal_session WHERE id = ? AND kind = 'WEB' AND ended_at IS NULL",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) decryptRefresh(rs.getBytes("refresh_token_enc")) else null }
        }
    }

    /**
     * Whether WEB session [id] is still live RIGHT NOW — not ended and inside both deadlines. A request's
     * resolved identity is cached per call, so an action that grants a new credential off that identity
     * re-checks here immediately before committing: the liveness sweep may have ended the session (e.g. the
     * IdP answered `invalid_grant`) after it was resolved.
     */
    fun webSessionIsLive(id: Long): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT 1 FROM principal_session
               WHERE id = ? AND kind = 'WEB' AND ended_at IS NULL
                 AND absolute_expires_at > now() AND (idle_expires_at IS NULL OR idle_expires_at > now())""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { it.next() }
        }
    }

    fun linkWebSessionKey(rowId: Long, key: String) {
        dataSource.inTx { c ->
            c.prepareStatement(
                "UPDATE principal_session SET session_key = NULL WHERE session_key = ? AND kind = 'WEB' AND id <> ?",
            ).use { ps ->
                ps.setString(1, key)
                ps.setLong(2, rowId)
                ps.executeUpdate()
            }
            c.prepareStatement(
                "UPDATE principal_session SET session_key = ? WHERE id = ? AND kind = 'WEB'",
            ).use { ps ->
                ps.setString(1, key)
                ps.setLong(2, rowId)
                ps.executeUpdate()
            }
        }
    }

    fun webIdBySessionKey(key: String): Long? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM principal_session WHERE session_key = ? AND kind = 'WEB'").use { ps ->
            ps.setString(1, key)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getLong("id") else null }
        }
    }

    fun endWebBySessionKey(key: String, reason: String): Boolean = dataSource.connection.use { c ->
        val principal = c.prepareStatement(
            """UPDATE principal_session
               SET ended_at = now(), ended_reason = ?, liveness_status = ?
               WHERE session_key = ? AND kind = 'WEB' AND ended_at IS NULL
               RETURNING principal""",
        ).use { ps ->
            ps.setString(1, reason)
            ps.setString(2, LIVENESS_INACTIVE)
            ps.setString(3, key)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
        // Same-connection cleanup (see [onWebSessionEnded]); shares this auto-commit connection.
        if (principal != null) onWebSessionEnded?.invoke(principal, c)
        principal != null
    }

    fun getById(id: Long): DaemonSessionRow? = queryOne("$SELECT AND id = ?") { it.setLong(1, id) }

    /** The most recent session for [principal] (a principal may be logged in from more than one daemon). */
    fun getByPrincipal(principal: String): DaemonSessionRow? =
        queryOne("$SELECT AND principal = ? ORDER BY created_at DESC, id DESC LIMIT 1") { it.setString(1, principal) }

    fun getByHandle(handle: String): DaemonSessionRow? = queryOne("$SELECT AND handle = ?") { it.setString(1, handle) }

    /**
     * Resolve a session by the SHA-256 hash of its renewal bearer secret — the ONLY lookup
     * `POST /auth/session/renew` performs now (docs/auth-model.md "Session renewal"). Never look
     * this up by a caller-supplied principal/handle; that was the unauthenticated-renewal flaw.
     */
    fun getByRenewalTokenHash(hash: String): DaemonSessionRow? =
        queryOne("$SELECT AND renewal_token_hash = ?") { it.setString(1, hash) }

    /**
     * True iff [principal]'s most recent session is still inside its renewal window. False (fail-closed)
     * when there's none at all. The `absolute_expires_at > now()` comparison runs in the DATABASE clock
     * domain — the SAME clock that STAMPS `absolute_expires_at` on create/deactivate (`now()`) — so a
     * CP-vs-DB clock skew can't make a window that was just closed to `now()` momentarily read as
     * still-open (the mixed DB-timestamp-vs-JVM-`Instant.now()` compare this replaced could, under a
     * DB-ahead clock).
     */
    fun withinWindow(principal: String): Boolean = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT absolute_expires_at > now() AS within
               FROM principal_session
               WHERE principal = ? AND kind = 'DAEMON'
               ORDER BY created_at DESC, id DESC
               LIMIT 1""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getBoolean("within") else false }
        }
    }

    fun markCheck(id: Long, status: String) = dataSource.connection.use { c -> markCheck(id, status, c) }

    fun markCheck(id: Long, status: String, c: Connection) {
        c.prepareStatement(
            """UPDATE principal_session
               SET last_idp_check_at = now(),
                   liveness_status = CASE WHEN ended_at IS NULL THEN ? ELSE liveness_status END
               WHERE id = ?""",
        ).use { ps ->
            ps.setString(1, status)
            ps.setLong(2, id)
            ps.executeUpdate()
        }
    }

    /**
     * Close EVERY still-in-window session for [principal] NOW and mark them INACTIVE — the daemon
     * arm of [revokeActiveCredentials]. Deactivating by principal (not by a single row id) is what
     * closes the pull-deprovision hole completely: a principal may hold more than one daemon session
     * (multiple machines / re-logins), and a liveness sweep that finds ONE of them inactive must tear
     * down every sibling too, else the untouched siblings' renewal secrets keep minting fresh tokens.
     * Dropping `absolute_expires_at` to now() means a subsequent `/auth/session/renew` fails its window
     * check as well (not just the liveness-status check), and it stays failed across a later
     * reactivation — the deprovision is durable, not merely paused. Idempotent: only rows still inside
     * their window are touched, so a repeat call revokes nothing further. Returns the count closed.
     */
    fun deactivateAllForPrincipal(principal: String): Int = dataSource.connection.use { c -> deactivateAllForPrincipal(principal, c) }

    /** Same as [deactivateAllForPrincipal], composed onto a caller-supplied connection [c] (see Tokens.kt's [TokenStore.issue] overload doc). */
    fun deactivateAllForPrincipal(principal: String, c: Connection): Int =
        c.prepareStatement(
            """UPDATE principal_session SET liveness_status = ?, absolute_expires_at = now()
               WHERE principal = ? AND kind = 'DAEMON' AND absolute_expires_at > now()""",
        ).use { ps ->
            ps.setString(1, LIVENESS_INACTIVE)
            ps.setString(2, principal)
            ps.executeUpdate()
        }

    /** Close only the specified daemon session's still-open renewal window. */
    fun closeDaemonWindow(id: Long) = dataSource.connection.use { c ->
        c.prepareStatement(
            """UPDATE principal_session
               SET liveness_status = ?, absolute_expires_at = now()
               WHERE id = ? AND kind = 'DAEMON' AND absolute_expires_at > now()""",
        ).use { ps ->
            ps.setString(1, LIVENESS_INACTIVE)
            ps.setLong(2, id)
            ps.executeUpdate()
        }
    }

    /** End every active web session for [principal], on a fresh connection. Already-ended rows remain unchanged. */
    fun endAllWebForPrincipal(principal: String, reason: String): Int =
        dataSource.connection.use { c -> endAllWebForPrincipal(principal, reason, c) }

    /** End every active web session for [principal]. Already-ended rows remain unchanged. */
    fun endAllWebForPrincipal(principal: String, reason: String, c: Connection): Int {
        val ended = c.prepareStatement(
            """UPDATE principal_session
               SET ended_at = now(), ended_reason = ?, liveness_status = ?
               WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL""",
        ).use { ps ->
            ps.setString(1, reason)
            ps.setString(2, LIVENESS_INACTIVE)
            ps.setString(3, principal)
            ps.executeUpdate()
        }
        // Deprovision + group-revocation both bulk-end here; route through the same end seam as logout so the
        // principal's saved editor results are dropped. Composed onto the caller-supplied connection [c] so it
        // is part of deprovision's atomic teardown transaction — a later statement that aborts the teardown
        // rolls the result deletion back too, instead of a separate committed delete orphaning a session the
        // rollback keeps alive. Fired once when ≥1 session was ended (this overload is shared by both entry
        // points, so the callback lands on both).
        if (ended > 0) onWebSessionEnded?.invoke(principal, c)
        return ended
    }

    /** Live sessions whose liveness cache is older than [recheckIntervalSeconds], or was never checked. */
    fun staleSessions(recheckIntervalSeconds: Long): List<LivenessCandidate> = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT id, kind, principal, refresh_token_enc, last_idp_check_at
               FROM principal_session
               WHERE (last_idp_check_at IS NULL OR last_idp_check_at < now() - make_interval(secs => ?))
                 AND ((kind = 'DAEMON' AND absolute_expires_at > now())
                   OR (kind = 'WEB' AND ended_at IS NULL AND absolute_expires_at > now() AND idle_expires_at > now()))""",
        ).use { ps ->
            ps.setDouble(1, recheckIntervalSeconds.toDouble())
            ps.executeQuery().use { rs ->
                val out = ArrayList<LivenessCandidate>()
                while (rs.next()) {
                    out += LivenessCandidate(
                        id = rs.getLong("id"),
                        kind = rs.getString("kind"),
                        principal = rs.getString("principal"),
                        refreshTokenEnc = rs.getBytes("refresh_token_enc"),
                        lastIdpCheckAt = rs.getTimestamp("last_idp_check_at")?.toInstant(),
                    )
                }
                out
            }
        }
    }

    /** Persist a rotated refresh token returned by a refresh-grant liveness check. No-op when [crypto] is unset. */
    fun updateRefresh(id: Long, refreshToken: String) {
        val crypto = crypto ?: return
        val encrypted = crypto.encrypt(refreshToken.toByteArray(Charsets.UTF_8))
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET refresh_token_enc = ? WHERE id = ?").use { ps ->
                ps.setBytes(1, encrypted)
                ps.setLong(2, id)
                ps.executeUpdate()
            }
        }
    }

    /** Decrypt [row]'s stored refresh token, or null if there isn't one (no `offline_access`, or [crypto] unset). */
    fun decryptRefresh(row: DaemonSessionRow): String? = decryptRefresh(row.refreshTokenEnc)

    /** Decrypt an encrypted refresh token, or null when either the token or crypto is absent. */
    fun decryptRefresh(enc: ByteArray?): String? {
        val blob = enc ?: return null
        val crypto = crypto ?: return null
        return crypto.decrypt(blob).toString(Charsets.UTF_8)
    }

    /**
     * The locked core of `POST /auth/session/renew`: open a transaction, take the per-principal
     * advisory lock first, re-select [row] by id, and re-run every fail-closed check against that fresh
     * read. Authoritative deprovisioning takes the same lock, so it either commits before this re-read
     * or tears down the credential after this transaction commits. Returns null when any check fails
     * under the lock or the row no longer exists; otherwise returns the freshly-issued token.
     */
    fun renewLocked(
        row: DaemonSessionRow,
        isDeactivated: (String, Connection) -> Boolean,
        mint: (DaemonSessionRow, Connection) -> IssuedToken,
    ): IssuedToken? = dataSource.inTx { c ->
        c.advisoryLockPrincipal(row.principal) // may block for a while behind a concurrent teardown
        val fresh = queryOneOn(c, "$SELECT AND id = ?") { it.setLong(1, row.id) } ?: return@inTx null
        // The window check runs in the DATABASE clock domain (same fix as withinWindow) — comparing
        // fresh.sessionExpiresAt against the JVM's Instant.now() would let a CP-vs-DB clock skew
        // accept a renew for a window the DB itself already considers closed.
        if (!withinWindowOn(c, fresh.id) ||
            isDeactivated(fresh.principal, c) ||
            fresh.livenessStatus == LIVENESS_INACTIVE
        ) {
            return@inTx null
        }
        mint(fresh, c)
    }

    /**
     * [withinWindow], scoped to ONE row by id and read on the caller-supplied (locked) connection
     * [c] — what [renewLocked] needs. Uses `clock_timestamp()`, NOT `now()`:
     * Postgres's `now()` is frozen at the enclosing TRANSACTION's start, not the current instant —
     * [renewLocked] takes the advisory lock before this check and can block on it for a while, so
     * `now()` here could still reflect a moment BEFORE that wait, letting a window that has since
     * actually expired read as still open. `clock_timestamp()` always reflects the real current time.
     */
    private fun withinWindowOn(c: Connection, id: Long): Boolean =
        c.prepareStatement("SELECT absolute_expires_at > clock_timestamp() FROM principal_session WHERE id = ? AND kind = 'DAEMON'").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }
        }

    private fun queryOne(sql: String, bind: (PreparedStatement) -> Unit): DaemonSessionRow? =
        dataSource.connection.use { c -> queryOneOn(c, sql, bind) }

    private fun queryOneOn(c: Connection, sql: String, bind: (PreparedStatement) -> Unit): DaemonSessionRow? =
        c.prepareStatement(sql).use { ps ->
            bind(ps)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toRow() else null }
        }

    private fun ResultSet.toRow() = DaemonSessionRow(
        id = getLong("id"),
        principal = getString("principal"),
        handle = getString("handle"),
        refreshTokenEnc = getBytes("refresh_token_enc"),
        ttlSeconds = getLong("ttl_seconds"),
        sessionExpiresAt = getTimestamp("absolute_expires_at").toInstant(),
        lastIdpCheckAt = getTimestamp("last_idp_check_at")?.toInstant(),
        livenessStatus = getString("liveness_status"),
        createdAt = getTimestamp("created_at").toInstant(),
    )

    private companion object {
        const val SELECT =
            """SELECT id, principal, handle, refresh_token_enc, ttl_seconds, absolute_expires_at, last_idp_check_at, liveness_status, created_at
               FROM principal_session
               WHERE kind = 'DAEMON'"""
    }
}

// ---- Renewal route -----------------------------------------------------------------------------

/**
 * `POST /auth/session/renew` (docs/auth-model.md "Session renewal") — silently re-mint a wire
 * SESSION token *within* the session window; refuse (401) once the window has closed, the
 * principal has been deprovisioned, or liveness has gone INACTIVE, so the daemon falls back to a
 * fresh device-auth (re-prompt). The timer sweep is the sole IdP revalidator; renewal only reads the
 * cached result. Registered from [deviceSessionRoutes] (DeviceAuth.kt) so the two files compose into
 * one route group without either owning the other's table.
 *
 * Authenticates by the `Authorization: Bearer <renewalToken>` header ONLY — a high-entropy,
 * mint-once secret handed back in the `/auth/device/poll` result and hashed at rest, looked up by
 * hash. There is deliberately no request-body identity (no `handle`/`principal`): a bare knowledge
 * of someone's principal string must never be enough to mint them a fresh wire token.
 */
internal fun Route.sessionRenewRoutes(
    daemonSessionStore: PrincipalSessionStore,
    tokenStore: TokenStore,
    userGroupStore: UserGroupStore,
) {
    post("/auth/session/renew") {
        val authHeader = call.request.headers["Authorization"]
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            call.respond(HttpStatusCode.Unauthorized, ApiError("auth.missing_renewal_token"))
            return@post
        }
        val secret = authHeader.removePrefix("Bearer ").trim()
        val row = daemonSessionStore.getByRenewalTokenHash(sha256Hex(secret))
        if (row == null) {
            call.respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
            return@post
        }
        // Re-check and mint under the per-principal advisory lock, not against [row]'s pre-lock
        // snapshot. Every fail-closed decision is repeated on the locked connection before issuance.
        val issued = daemonSessionStore.renewLocked(
            row,
            isDeactivated = { principal, c -> userGroupStore.isDeactivated(principal, c) },
            mint = { fresh, c -> tokenStore.issue(TokenKind.SESSION, fresh.principal, emptyList(), name = null, ttlSeconds = fresh.ttlSeconds, c) },
        )
        if (issued == null) {
            call.respond(HttpStatusCode.Unauthorized, ApiError("auth.session_window_expired"))
            return@post
        }

        call.respond(RenewSessionResponse(issued.token, issued.expiresAt))
    }
}

// ---- IdP liveness sweep -------------------------------------------------------------------------

/**
 * The sole IdP revalidator: one timer-driven pass over every live web or daemon session whose cached
 * check is stale. Each session's own refresh token determines only that session's fate; transient
 * failures leave its state and check timestamp untouched. The IdP HTTP round-trip always completes
 * before any principal lock is taken; only the successful response's local DB phase is serialized.
 */
suspend fun sweepSessionLiveness(
    config: Config,
    discovery: OidcDiscovery?,
    validator: IdTokenValidator?,
    http: HttpClient,
    sessionStore: PrincipalSessionStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    log: Logger,
) {
    if (config.oidc == null || discovery == null) return
    for (row in sessionStore.staleSessions(config.idpRecheckIntervalSeconds)) {
        runCatching {
            revalidateSession(row, config, discovery, validator, http, sessionStore, userGroupStore, roleResolver, log)
        }.onFailure { log.warn("IdP liveness sweep failed for {} session {}", row.principal, row.id, it) }
    }
}

/**
 * Revalidate one session through its own refresh grant. A successful response is trusted only after
 * its id_token validates and resolves to the stored principal; then current IdP groups are synced and
 * the complete local role union is resolved. `invalid_grant` retires only the affected row.
 */
private suspend fun revalidateSession(
    row: LivenessCandidate,
    config: Config,
    discovery: OidcDiscovery,
    validator: IdTokenValidator?,
    http: HttpClient,
    sessionStore: PrincipalSessionStore,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    log: Logger,
) {
    val oidc = config.oidc ?: return
    val refreshToken = sessionStore.decryptRefresh(row.refreshTokenEnc)
    if (refreshToken == null) {
        log.debug("no refresh token to revalidate liveness for {} session {}", row.principal, row.id)
        return
    }
    val document = discovery.document()
    when (val outcome = refreshGrant(http, document.token_endpoint, oidc.clientId, oidc.clientSecret, refreshToken)) {
        is RefreshOutcome.Active -> {
            if (outcome.rotatedRefreshToken != null) {
                sessionStore.updateRefresh(row.id, outcome.rotatedRefreshToken)
            }
            val claims = outcome.idToken?.let { validator?.validate(it, expectedNonce = null) }
            if (claims == null) {
                log.warn("IdP liveness check returned no valid id_token for {} session {}", row.principal, row.id)
                return
            }
            val refreshedPrincipal = claims.email ?: claims.subject
            if (refreshedPrincipal != row.principal) {
                log.warn(
                    "IdP liveness identity mismatch for {} session {}: got {}",
                    row.principal,
                    row.id,
                    refreshedPrincipal,
                )
                return
            }
            userGroupStore.provisionFromOidc(row.principal, claims.email, claims.groups, oidc.groupMapping)
            if (roleResolver.resolve(row.principal).isEmpty()) {
                // Reconciliation is principal-global, so a zero-role verdict ends every live web
                // session for the principal regardless of which kind produced this candidate. Daemon
                // rows stay open; each daemon query re-resolves roles and fail-closes on its own.
                sessionStore.endAllWebForPrincipal(row.principal, ENDED_GROUP_REVOKED)
            }
            sessionStore.markCheck(row.id, LIVENESS_ACTIVE)
        }
        is RefreshOutcome.Inactive -> {
            log.warn("IdP rejected refresh token for {} session {} ({})", row.principal, row.id, outcome.reason)
            when (row.kind) {
                "WEB" -> sessionStore.endWeb(row.id, ENDED_IDP_REJECTED)
                "DAEMON" -> sessionStore.closeDaemonWindow(row.id)
                else -> log.warn("ignoring unknown principal session kind {} for row {}", row.kind, row.id)
            }
        }
        is RefreshOutcome.Transient ->
            log.warn("IdP liveness check transiently failed for {} session {}: {}", row.principal, row.id, outcome.reason)
    }
}

private sealed interface RefreshOutcome {
    data class Active(val rotatedRefreshToken: String?, val idToken: String?) : RefreshOutcome
    data class Inactive(val reason: String) : RefreshOutcome
    data class Transient(val reason: String) : RefreshOutcome
}

@Serializable
private data class RefreshTokenResponse(
    val access_token: String,
    val refresh_token: String? = null,
    val id_token: String? = null,
)

@Serializable
private data class RefreshErrorBody(val error: String? = null, val error_description: String? = null)

private suspend fun refreshGrant(
    http: HttpClient,
    tokenEndpoint: String,
    clientId: String,
    clientSecret: String,
    refreshToken: String,
): RefreshOutcome = try {
    val resp: RefreshTokenResponse = http.submitForm(
        url = tokenEndpoint,
        formParameters = Parameters.build {
            append("grant_type", "refresh_token")
            append("refresh_token", refreshToken)
            append("client_id", clientId)
            append("client_secret", clientSecret)
        },
    ).body()
    RefreshOutcome.Active(resp.refresh_token, resp.id_token)
} catch (e: ClientRequestException) {
    // Only `invalid_grant` is the IdP's definitive "this refresh token/account is no longer valid"
    // signal. The rest of the 4xx space — `invalid_client` (a rotated `client_secret`),
    // `unsupported_grant_type` (IdP-side config drift), etc. — is OUR-side/config trouble, not proof
    // the account is gone, and must NOT revoke a live session (a transient IdP/config error keeps
    // the last-known-good, docs/auth-model.md "Security invariants").
    val body = runCatching { e.response.body<RefreshErrorBody>() }.getOrNull()
    val error = body?.error ?: "http_${e.response.status.value}"
    if (error == "invalid_grant") RefreshOutcome.Inactive(error) else RefreshOutcome.Transient(error)
} catch (e: Exception) {
    RefreshOutcome.Transient(e.message ?: e::class.simpleName ?: "unknown error")
}
