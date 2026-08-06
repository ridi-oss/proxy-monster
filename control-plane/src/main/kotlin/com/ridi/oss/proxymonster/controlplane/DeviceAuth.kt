package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_DEVICE_APPROVE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_DEVICE_MINT
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_DEVICE
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.sessions.clear
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import java.security.SecureRandom
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource

// ---- Wire DTOs (SHARED CONTRACT REGISTRY — pmon + web consume these) ---------------------

@Serializable
data class DeviceStartInput(val ttlSeconds: Long? = null)

@Serializable
data class DeviceStartResponse(
    val verificationUri: String,
    val verificationUriComplete: String,
    val userCode: String,
    val handle: String,
    val interval: Int,
)

@Serializable
data class DevicePollInput(val handle: String)

/** The web /device page confirms the human-seen code before any auth (POST /auth/device/confirm). */
@Serializable
data class DeviceConfirmInput(val userCode: String)

@Serializable
data class DeviceConfirmAck(val ok: Boolean = true)

/** The 202 "still waiting on the user" shape. */
@Serializable
data class DevicePollPending(val status: String = "authorization_pending")

/**
 * The 200 "done" shape — a minted wire SESSION token + the session-window expiry +
 * [renewalToken], the high-entropy bearer secret `pmon` must present as
 * `Authorization: Bearer <renewalToken>` to `POST /auth/session/renew` (docs/auth-model.md
 * "Session renewal"). Returned EXACTLY ONCE, here — the control plane persists only its SHA-256
 * hash (see [PrincipalSessionStore.create]) and can never hand it back out again.
 */
@Serializable
data class DevicePollResult(
    val token: String,
    val expiresAt: String,
    val principal: String,
    val sessionExpiresAt: String,
    val renewalToken: String,
)

// ---- Store ---------------------------------------------------------------------------------

/** A single device-authorization attempt (RFC 8628), tracked server-side so `pmon` never sees the IdP's `device_code`. */
data class DeviceLoginRow(
    val id: Long,
    val handle: String,
    val userCode: String?, // the short human code shown on the CP verification page (RFC 8628 user_code)
    val deviceCode: String?,
    val intervalSec: Int,
    val ttlSeconds: Long,
    val status: String, // PENDING | APPROVED | CONSUMED (CONSUMED = the one-time mint already happened)
    val principal: String?,
    val refreshTokenEnc: ByteArray?, // IdP refresh token captured at SSO approval, encrypted (decryptRefresh)
    val createdAt: Instant,
    val expiresAt: Instant,
)

/**
 * Server-held device-authorization state (docs/auth-model.md "CLI / daemon login"). Mirrors
 * [TokenStore]'s plain-JDBC shape. The IdP's `device_code` lives ONLY here — under
 * `PM_AUTH_DEBUG` it's simply absent (the dev-bypass short-circuit pre-approves a synthetic row
 * without ever hitting the IdP); `pmon` only ever sees the opaque [DeviceLoginRow.handle].
 */
class DeviceLoginStore(internal val dataSource: DataSource, private val crypto: ResultCrypto? = null) {
    private val rng = SecureRandom()

    private companion object {
        // No ambiguous characters (0/O, 1/I/L) — a human reads this code off the CP verification page.
        const val USER_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

        /** Fold a human-typed code back to the stored form: uppercase, strip readability punctuation
         *  (RFC 8628 §6.1), then re-insert the single hyphen — so "wdjbmjht" / "WDJB-MJHT" both match. */
        fun normalizeUserCode(raw: String): String {
            val bare = raw.uppercase().filter { it in USER_CODE_ALPHABET }
            return if (bare.length == 8) "${bare.substring(0, 4)}-${bare.substring(4)}" else bare
        }
    }

    /** A fresh opaque handle — the only device-login identifier `pmon` ever sees. */
    fun newHandle(): String {
        val raw = ByteArray(24).also { rng.nextBytes(it) }
        return "dvc_" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    /**
     * A short human-typeable verification code (RFC 8628 user_code) shown on the CP `/device` page and
     * prefilled into its URL — from an unambiguous alphabet (no 0/O/1/I) formatted `XXXX-XXXX`. ~40 bits,
     * short-lived and single-use, so it is safe to show a human even though it is the page's approval key.
     */
    fun newUserCode(): String = buildString {
        repeat(8) { i ->
            if (i == 4) append('-')
            append(USER_CODE_ALPHABET[rng.nextInt(USER_CODE_ALPHABET.length)])
        }
    }

    fun create(handle: String, deviceCode: String?, intervalSec: Int, ttlSeconds: Long, expiresAt: Instant, userCode: String? = null): DeviceLoginRow {
        dataSource.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO device_login (handle, user_code, device_code, interval_sec, ttl_seconds, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
            ).use { ps ->
                ps.setString(1, handle)
                ps.setString(2, userCode)
                ps.setString(3, deviceCode)
                ps.setInt(4, intervalSec)
                ps.setLong(5, ttlSeconds)
                ps.setTimestamp(6, Timestamp.from(expiresAt))
                ps.executeUpdate()
            }
        }
        return get(handle)!!
    }

    fun get(handle: String): DeviceLoginRow? = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT id, handle, user_code, device_code, interval_sec, ttl_seconds, status, principal, refresh_token_enc, created_at, expires_at
               FROM device_login WHERE handle = ?""",
        ).use { ps ->
            ps.setString(1, handle)
            ps.executeQuery().use { rs -> if (rs.next()) rs.toRow() else null }
        }
    }

    /** Look up an in-flight login by its human [userCode], normalized (case/punctuation-insensitive) — the CP
     *  `/device` page approves via this. */
    fun getByUserCode(userCode: String): DeviceLoginRow? = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT id, handle, user_code, device_code, interval_sec, ttl_seconds, status, principal, refresh_token_enc, created_at, expires_at
               FROM device_login WHERE user_code = ?""",
        ).use { ps ->
            ps.setString(1, normalizeUserCode(userCode))
            ps.executeQuery().use { rs -> if (rs.next()) rs.toRow() else null }
        }
    }

    /**
     * Create a fresh PENDING login for `/auth/device/start`: a new opaque handle + a new human user_code.
     * Retries the user_code on the astronomically-rare unique-index collision (~40 bits, minutes-long TTL)
     * rather than surfacing a 500; the handle is 192-bit so it never collides. Returns the created row.
     */
    fun createPending(intervalSec: Int, ttlSeconds: Long, expiresAt: Instant): DeviceLoginRow {
        val handle = newHandle()
        var attempts = 0
        while (true) {
            try {
                return create(handle, deviceCode = null, intervalSec = intervalSec, ttlSeconds = ttlSeconds, expiresAt = expiresAt, userCode = newUserCode())
            } catch (e: java.sql.SQLException) {
                if (++attempts >= 5 || e.sqlState != "23505") throw e // 23505 = unique_violation → new code + retry
            }
        }
    }

    /**
     * Approve a still-pending, unexpired handle for [principal] (the /device SSO callback or the debug button).
     * A CAS on (PENDING, unexpired) — the return value is the truth. [refreshToken], present only on the SSO
     * path with offline_access, is stored encrypted so the minted daemon session keeps its IdP-liveness path.
     */
    fun markApproved(
        handle: String,
        principal: String,
        refreshToken: String? = null,
        c: Connection? = null,
    ): Boolean {
        val encrypted = refreshToken?.let { crypto?.encrypt(it.toByteArray(Charsets.UTF_8)) }
        val update: (Connection) -> Boolean = { connection ->
            connection.prepareStatement(
                """UPDATE device_login SET status = 'APPROVED', principal = ?, refresh_token_enc = ?
                   WHERE handle = ? AND status = 'PENDING' AND expires_at > now()""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setBytes(2, encrypted)
                ps.setString(3, handle)
                ps.executeUpdate() > 0
            }
        }
        return if (c == null) dataSource.connection.use(update) else update(c)
    }

    /** Decrypt the refresh token captured at SSO approval — null for a debug login, no offline_access, or no key. */
    fun decryptRefresh(row: DeviceLoginRow): String? =
        row.refreshTokenEnc?.let { enc -> crypto?.decrypt(enc)?.toString(Charsets.UTF_8) }

    /**
     * Atomically claim an APPROVED handle for a ONE-TIME session mint (APPROVED -> CONSUMED). Returns
     * true only for the single caller that wins the transition; false for any replay/race on an
     * already-consumed (or never-approved / expired) handle. The poll endpoint gates minting on this,
     * which is what makes a device handle yield EXACTLY one SESSION token + one `pmr_` renewal secret
     * — without it, re-polling an approved handle re-mints a fresh renewal secret on every call,
     * turning a short-lived login handle into an unbounded credential-minting handle.
     */
    fun consume(handle: String, c: Connection? = null): Boolean {
        val update: (Connection) -> Boolean = { connection ->
            connection.prepareStatement(
                "UPDATE device_login SET status = 'CONSUMED' WHERE handle = ? AND status = 'APPROVED' AND expires_at > now()",
            ).use { ps ->
                ps.setString(1, handle)
                ps.executeUpdate() > 0
            }
        }
        return if (c == null) dataSource.connection.use(update) else update(c)
    }

    /** Delete every expired row — device-auth attempts are short-lived; nothing to keep past expiry. */
    fun purgeExpired(): Int = dataSource.connection.use { c ->
        c.prepareStatement("DELETE FROM device_login WHERE expires_at <= now()").use { it.executeUpdate() }
    }

    private fun ResultSet.toRow() = DeviceLoginRow(
        id = getLong("id"),
        handle = getString("handle"),
        userCode = getString("user_code"),
        deviceCode = getString("device_code"),
        intervalSec = getInt("interval_sec"),
        ttlSeconds = getLong("ttl_seconds"),
        status = getString("status"),
        principal = getString("principal"),
        refreshTokenEnc = getBytes("refresh_token_enc"),
        createdAt = getTimestamp("created_at").toInstant(),
        expiresAt = getTimestamp("expires_at").toInstant(),
    )
}

private const val DEV_PRINCIPAL = "debug-user"
private const val DEVICE_POLL_INTERVAL_SEC = 2 // how often pmon polls /poll; the browser page approves out-of-band
private const val DEVICE_LOGIN_TTL_SEC = 600L // 10 min to complete the device-auth dance

// ---- Routes ----------------------------------------------------------------------------------

/**
 * The CLI/daemon login + renewal surface (docs/auth-model.md "CLI / daemon login"). The verification page
 * itself is the web app's `/device` (Next.js); the CP owns the API + the approval:
 *  - POST /auth/device/start   — pmon begins a login; the CP mints a PENDING handle + a short user_code and
 *    returns the verification page URL ({origin}/device?user_code=…). No IdP round-trip happens here.
 *  - POST /auth/device/confirm — the authenticated web /device page confirms the human-seen code and binds
 *    the verify cookie to that code and web session.
 *  - GET  /auth/device/authorize — the browser lands here after confirm and approves with that same live web
 *    session. A missing or replaced session returns to /device for authentication and confirmation again.
 *  - POST /auth/device/poll    — pmon polls by handle; 202 while PENDING, 200 + a one-time SESSION token once
 *    the page approved it.
 *  - /auth/session/renew (delegated to [sessionRenewRoutes]).
 * The IdP is reached ONLY by the browser SSO choice (the auth-code flow); the pmon↔CP device flow is
 * entirely CP-owned, so `pmon login` has one code path whether the user then chooses SSO or debug.
 */
fun Route.deviceSessionRoutes(
    config: Config,
    deviceLoginStore: DeviceLoginStore,
    daemonSessionStore: PrincipalSessionStore,
    tokenStore: TokenStore,
    userGroupStore: UserGroupStore,
    authAudit: AuthAuditRecorder,
    log: Logger,
) {
    // pmon begins a login: mint a PENDING handle (pmon polls it) + a short human user_code, and hand back the
    // CP's OWN verification page. The choice of SSO vs debug happens later, in the browser.
    post("/auth/device/start") {
        val input = runCatching { call.receive<DeviceStartInput>() }.getOrDefault(DeviceStartInput())
        val ttl = clampTtlSeconds(input.ttlSeconds ?: SESSION_TTL_SECONDS)
        val row = deviceLoginStore.createPending(DEVICE_POLL_INTERVAL_SEC, ttl, Instant.now().plusSeconds(DEVICE_LOGIN_TTL_SEC))
        val userCode = row.userCode!! // createPending always sets it
        // The verification page is a WEB route, so this must be the console's origin — same as the control
        // plane in the usual single-edge deployment, or PM_WEB_ORIGIN when the console is served elsewhere.
        val verifyUri = "${config.webBaseUrl}/device"
        call.respond(
            DeviceStartResponse(
                verificationUri = verifyUri,
                verificationUriComplete = "$verifyUri?user_code=${userCode.encodeURLParameter()}",
                userCode = userCode,
                handle = row.handle,
                interval = DEVICE_POLL_INTERVAL_SEC,
            ),
        )
    }

    // The web /device page POSTs here when the signed-in human confirms the code it shows. The verify cookie
    // binds THIS browser to the code, so an attacker's direct authorize link cannot approve.
    post("/auth/device/confirm") {
        val session = call.webSession()
        if (session == null) {
            call.unauthenticated()
            return@post
        }
        val userCode = runCatching { call.receive<DeviceConfirmInput>().userCode }.getOrNull()?.trim()
        val row = userCode?.let { deviceLoginStore.getByUserCode(it) }
        if (row?.userCode == null || row.expiresAt.isBefore(Instant.now()) || row.status != "PENDING") {
            call.respond(HttpStatusCode.BadRequest, ApiError("device.unknown_or_expired_login"))
            return@post
        }
        call.sessions.set(DeviceVerifySession(row.userCode, session.id))
        call.respond(HttpStatusCode.OK, DeviceConfirmAck())
    }

    // After confirm, the web page navigates the browser here. The same live session that confirmed the code
    // approves this pmon login. If it is gone, return to /device so authentication and confirmation repeat.
    get("/auth/device/authorize") {
        val userCode = call.request.queryParameters["user_code"]?.trim()
        fun backToDevice() = config.webRedirectTarget(
            "/device${if (userCode.isNullOrBlank()) "" else "?user_code=${userCode.encodeURLParameter()}"}",
        )
        val verified = call.sessions.get<DeviceVerifySession>()
        if (userCode.isNullOrBlank() || verified?.userCode != userCode) {
            call.respondRedirect(backToDevice())
            return@get
        }
        val row = deviceLoginStore.getByUserCode(userCode)
        if (row == null || row.expiresAt.isBefore(Instant.now()) || row.status != "PENDING") {
            call.sessions.clear(DEVICE_VERIFY_COOKIE)
            call.respondRedirect(backToDevice())
            return@get
        }
        val session = call.webSession()
        if (session == null || session.id != verified.webSessionId) {
            call.sessions.clear(DEVICE_VERIFY_COOKIE)
            call.respondRedirect(backToDevice())
            return@get
        }
        // Approve for the logged-in principal (SSO or debug — /login's PM_AUTH_DEBUG gate governs debug), and
        // carry that session's IdP refresh token onto the device login so the daemon session minted at poll
        // keeps its timer-driven IdP-liveness revalidation. Null when the login granted no offline_access (or
        // no result key), which simply leaves the daemon session without a liveness path.
        // webRefreshToken() is read from the STILL-LIVE row (`ended_at IS NULL`): a session the liveness sweep
        // rejected between resolve and here is already ended, so this returns null and the guard below refuses
        // to approve from it — a credential is never minted off an authentication that was just invalidated.
        val refreshToken = daemonSessionStore.webRefreshToken(session.id)
        if (!daemonSessionStore.webSessionIsLive(session.id)) {
            call.sessions.clear(DEVICE_VERIFY_COOKIE)
            call.respondRedirect(backToDevice())
            return@get
        }
        val approver = AuditActor(session.principal, clientAddr = call.httpRequesterIp(config), channel = CHANNEL_DEVICE)
        val approved = deviceLoginStore.dataSource.inTx { c ->
            deviceLoginStore.markApproved(row.handle, session.principal, refreshToken, c).also { changed ->
                if (changed) {
                    authAudit.success(
                        c,
                        approver,
                        ACTION_DEVICE_APPROVE,
                        // The row id, never [DeviceLoginRow.handle]: the handle is the bearer secret
                        // /auth/device/poll accepts on its own, and the audit trail is readable and exported.
                        auditEntity("DeviceLogin", row.id.toString()),
                        "Device login approved",
                    )
                }
            }
        }
        call.sessions.clear(DEVICE_VERIFY_COOKIE)
        call.respondRedirect(if (approved) config.webRedirectTarget("/device/success") else backToDevice())
    }

    // pmon polls by handle: 202 while the browser page has not approved yet, 200 + a one-time SESSION token
    // once it has (via SSO or debug). The approval already resolved the principal, so no IdP call happens here.
    post("/auth/device/poll") {
        val input = call.receive<DevicePollInput>()
        val row = deviceLoginStore.get(input.handle)
        if (row == null || row.expiresAt.isBefore(Instant.now())) {
            call.respond(HttpStatusCode.BadRequest, ApiError("device.unknown_or_expired_login"))
            return@post
        }
        val principal = row.principal
        if (row.status == "PENDING" || principal == null) {
            call.respond(HttpStatusCode.Accepted, DevicePollPending())
            return@post
        }
        // Carry the refresh token captured at SSO approval onto the daemon session (null for a debug login or
        // no offline_access/key), so its timer-driven IdP-liveness revalidation keeps working. The one-time
        // APPROVED -> CONSUMED claim happens INSIDE the mint transaction (respondWithMintedSession), so a
        // failed mint rolls the claim back and the poll can retry rather than stranding the handle CONSUMED.
        respondWithMintedSession(
            call, principal, row, refreshToken = deviceLoginStore.decryptRefresh(row), config, tokenStore,
            daemonSessionStore, deviceLoginStore, userGroupStore, authAudit,
        )
    }

    sessionRenewRoutes(config, daemonSessionStore, tokenStore, userGroupStore, authAudit)
}

/**
 * Open the session-window row + mint the wire SESSION token that completes a device-auth login —
 * re-checking deprovisioning, creating the session, and issuing the token as ONE transaction under
 * the per-principal advisory lock. The IdP may have completed device-auth just as a
 * SCIM `active=false` teardown swept, so a check-then-create outside the lock could persist a fresh
 * renewal secret + SESSION token AFTER the sweep already scanned — resurrectable on a later
 * reactivation. Refuses with 403 when the principal is deprovisioned.
 */
private suspend fun respondWithMintedSession(
    call: ApplicationCall,
    principal: String,
    row: DeviceLoginRow,
    refreshToken: String?,
    config: Config,
    tokenStore: TokenStore,
    daemonSessionStore: PrincipalSessionStore,
    deviceLoginStore: DeviceLoginStore,
    userGroupStore: UserGroupStore,
    authAudit: AuthAuditRecorder,
) {
    val poller = AuditActor(principal, clientAddr = call.httpRequesterIp(config), channel = CHANNEL_DEVICE)
    // consume + session + token + audit are ONE transaction under the per-principal lock. A replay finds the
    // handle already CONSUMED and never reaches the mint; a failed mint rolls the consume back so the poll can
    // retry. A deprovisioned principal is refused before the block runs, leaving the handle claimable again.
    var alreadyCompleted = false
    val result: DevicePollResult? = tokenStore.dataSource.mintForActivePrincipalLocked(principal, userGroupStore) { c ->
        if (!deviceLoginStore.consume(row.handle, c)) {
            alreadyCompleted = true
            return@mintForActivePrincipalLocked null
        }
        val created = daemonSessionStore.create(principal, row.handle, refreshToken, config.sessionWindowSeconds, row.ttlSeconds, c)
        val issued = tokenStore.issue(TokenKind.SESSION, principal, emptyList(), name = null, ttlSeconds = row.ttlSeconds, c)
        authAudit.success(
            c,
            poller,
            ACTION_DEVICE_MINT,
            auditEntity("Token", issued.id.toString()),
            "Device login minted SESSION token",
        )
        DevicePollResult(
            issued.token,
            issued.expiresAt,
            principal,
            created.row.sessionExpiresAt.toString(),
            created.renewalToken,
        )
    }
    when {
        alreadyCompleted -> call.respond(HttpStatusCode.BadRequest, ApiError("device.login_already_completed"))
        result == null -> call.respond(HttpStatusCode.Forbidden, ApiError("auth.principal_deprovisioned"))
        else -> call.respond(result)
    }
}
