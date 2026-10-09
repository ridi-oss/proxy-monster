package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_LOGOUT
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_SESSION_RENEW
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_PMON
import com.ridi.oss.proxymonster.auth.canonicalScopes
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Types
import java.time.Instant
import java.util.Base64
import javax.sql.DataSource

// ---- Liveness status -------------------------------------------------------------------------

/** A principal session's last-known IdP-liveness verdict (docs/auth-model.md "Liveness"). */
const val LIVENESS_ACTIVE = "ACTIVE"
const val LIVENESS_INACTIVE = "INACTIVE"
const val ENDED_SIGNED_OUT = "SIGNED_OUT"
const val ENDED_DISPLACED = "DISPLACED"
const val ENDED_DEACTIVATED = "DEACTIVATED"
const val ENDED_GROUP_REVOKED = "GROUP_REVOKED"
const val ENDED_DEVICE_BIND_MISMATCH = "DEVICE_BIND_MISMATCH"

// ---- Store -------------------------------------------------------------------------------------

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

/**
 * The Kotlin side of `principal_session`: WEB sessions the console still resolves here, and the daemon
 * teardowns deprovisioning and OAuth consent revocation run. cp-go mints and renews daemon sessions.
 * A WEB row is live only while both deadlines are in the future and it has not been ended ([endWeb]).
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

    fun endWeb(id: Long, reason: String, c: Connection? = null): Boolean = endWebOwner(id, reason, c) != null

    /**
     * [endWeb], returning the principal whose session this ended (null when nothing transitioned) — the owner
     * an audit record must name, which the caller may no longer be able to resolve: a row past its idle
     * deadline still ends here but no longer resolves as a session.
     */
    fun endWebOwner(id: Long, reason: String, c: Connection? = null): String? {
        // The cleanup callback runs on the SAME connection as the end-write (see [onWebSessionEnded]), so when
        // [c] is a caller's transaction the delete composes with it; when null it shares this auto-commit
        // connection. Invoked inside the .use block so the connection is still open.
        val useConnection: (Connection) -> String? = { connection ->
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
            principal
        }
        return if (c == null) dataSource.connection.use(useConnection) else useConnection(c)
    }

    fun webEndedReason(id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ? AND kind = 'WEB'").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString("ended_reason") else null }
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

    /** Ends daemon session [id] and revokes its tokens, or retires its wire tokens when [replaced]; null when already ended. */
    fun endDaemon(id: Long, c: Connection, replaced: Boolean = false): String? {
        val principal = c.prepareStatement(
            """UPDATE principal_session
               SET ended_at = now(), ended_reason = ?, liveness_status = ?, absolute_expires_at = LEAST(absolute_expires_at, now())
               WHERE id = ? AND kind = 'DAEMON' AND ended_at IS NULL
               RETURNING principal""",
        ).use { ps ->
            ps.setString(1, ENDED_SIGNED_OUT)
            ps.setString(2, LIVENESS_INACTIVE)
            ps.setLong(3, id)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        } ?: return null
        if (replaced) {
            c.prepareStatement(
                "UPDATE proxy_token SET retired_at = now() WHERE principal_session_id = ? AND kind = 'SESSION' AND revoked_at IS NULL AND retired_at IS NULL",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        val consents = c.prepareStatement(
            """UPDATE proxy_token SET revoked_at = now()
               WHERE principal_session_id = ? AND revoked_at IS NULL AND (kind <> 'SESSION' OR NOT ?)
               RETURNING consent_id""",
        ).use { ps ->
            ps.setLong(1, id)
            ps.setBoolean(2, replaced)
            ps.executeQuery().use { rs -> buildSet { while (rs.next()) rs.getObject(1, java.lang.Long::class.java)?.let { add(it.toLong()) } } }
        }
        for (consentId in consents) {
            c.prepareStatement(
                """UPDATE oauth_consent SET revoked_at = now(), updated_at = now()
                   WHERE id = ? AND revoked_at IS NULL
                     AND NOT EXISTS (SELECT 1 FROM proxy_token WHERE consent_id = ? AND revoked_at IS NULL AND expires_at > now())""",
            ).use { ps ->
                ps.setLong(1, consentId)
                ps.setLong(2, consentId)
                ps.executeUpdate()
            }
        }
        return principal
    }

    /** Ends every pmon login that minted an MCP token under consent [consentId], so pmon cannot mint it back. */
    fun endDaemonsByConsent(consentId: Long, principal: String) = dataSource.inTx { c ->
        c.advisoryLockPrincipal(principal)
        val ids = c.prepareStatement(
            "SELECT DISTINCT principal_session_id FROM proxy_token WHERE consent_id = ? AND principal_session_id IS NOT NULL",
        ).use { ps ->
            ps.setLong(1, consentId)
            ps.executeQuery().use { rs -> buildList { while (rs.next()) add(rs.getLong(1)) } }
        }
        ids.forEach { endDaemon(it, c) }
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
}
