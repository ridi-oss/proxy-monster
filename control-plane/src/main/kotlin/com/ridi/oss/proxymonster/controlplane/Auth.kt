package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.AuditSource
import io.ktor.http.Cookie
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.SessionSerializer
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.util.AttributeKey
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import java.security.MessageDigest
import java.util.UUID

/** The signed-cookie session name. */
const val SESSION_COOKIE = "pm_session"
const val DEVICE_COOKIE = "pm_did"
private const val DEVICE_COOKIE_MAX_AGE_SECONDS = 7_776_000

/**
 * The authenticated principal resolved from the server-side session row. Roles remain a
 * response-compatibility field; authorization resolves effective roles server-side.
 *
 * [requesterIp] is populated only for a session carrying a debug-login simulated address, so the console
 * can show which network its decisions are being authorized against — a masked column and a cleartext one
 * differ by nothing else on screen, and without this the reason is invisible.
 */
@kotlinx.serialization.Serializable
data class UserSession(
    val principal: String,
    val roles: List<String> = emptyList(),
    val requesterIp: String? = null,
)

@kotlinx.serialization.Serializable
data class WebSessionRef(val sessionId: Long)

const val WEB_SESSION_AUTH = "web-session"
val PRINCIPAL_SESSION_STORE = AttributeKey<PrincipalSessionStore>("principal-session-store")
val FAILED_WEB_SESSION = AttributeKey<Long>("failed-web-session")
private val RESOLVED_IDENTITY = AttributeKey<ResolvedIdentity>("resolved-session-identity")
private data class ResolvedIdentity(val row: WebSessionRow?)

/**
 * Body for the dev-only debug login (PM_AUTH_DEBUG) — the dev bypass alongside the OIDC login (Oidc.kt).
 *
 * [requesterIp] simulates the source address the session's decisions are authorized under, so a Cedar tag
 * rule keyed on a CIDR can be exercised from a development box where every request arrives from loopback.
 * Blank/absent leaves the observed peer authoritative. Honored only while the bypass is enabled.
 */
@kotlinx.serialization.Serializable
data class DebugLogin(
    val principal: String,
    val roles: List<String> = emptyList(),
    val requesterIp: String? = null,
)

/**
 * A [SessionSerializer] backed by kotlinx.serialization JSON. Ktor's bundled serializer
 * constructor shape has shifted across 3.x; delegating to kotlinx Json directly keeps this
 * stable and is what we already use on the wire.
 */
class JsonSessionSerializer<T : Any>(
    private val serializer: KSerializer<T>,
    private val json: Json = Json,
) : SessionSerializer<T> {
    override fun serialize(session: T): String = json.encodeToString(serializer, session)
    override fun deserialize(text: String): T = json.decodeFromString(serializer, text)
}

/** Build a typed JSON serializer for a Ktor session cookie. */
inline fun <reified T : Any> jsonSessionSerializer(): JsonSessionSerializer<T> =
    JsonSessionSerializer(serializer())

fun ApplicationCall.deviceCookieId(): String? = request.cookies[DEVICE_COOKIE]

fun ApplicationCall.ensureDeviceCookie(secure: Boolean): String {
    val value = deviceCookieId()?.takeIf { runCatching { UUID.fromString(it) }.isSuccess }
        ?: UUID.randomUUID().toString()
    response.cookies.append(
        Cookie(
            name = DEVICE_COOKIE,
            value = value,
            maxAge = DEVICE_COOKIE_MAX_AGE_SECONDS,
            path = "/",
            secure = secure,
            httpOnly = true,
            extensions = mapOf("SameSite" to "Lax"),
        ),
    )
    return value
}

/**
 * Authenticate the current server-side web session and enforce its liveness and device binding.
 * Request-time resolution never extends idle; only the explicit session heartbeat does.
 */
fun ApplicationCall.webSession(): WebSessionRow? {
    attributes.getOrNull(RESOLVED_IDENTITY)?.let { return it.row }
    val ref = runCatching { sessions.get<WebSessionRef>() }.getOrNull()
    val resolved = application.attributes.getOrNull(PRINCIPAL_SESSION_STORE)?.let { store ->
        ref?.let { store.resolveWeb(it.sessionId, deviceCookieId()) }
    }
    if (ref != null && resolved == null) attributes.put(FAILED_WEB_SESSION, ref.sessionId)
    attributes.put(RESOLVED_IDENTITY, ResolvedIdentity(resolved))
    return resolved
}

/** Resolve the current server-side web session, or null if unauthenticated. */
fun ApplicationCall.userSession(): UserSession? = webSession()?.let { UserSession(it.principal) }

/** Compare a presented secret against the expected one without leaking its prefix through timing —
 *  `==` on a standing secret is an oracle. Every standing-secret check goes through this: the ingest
 *  token, the SCIM bearer, the proxy's gRPC transport secret, and the consent CSRF token (an HMAC of
 *  the session secret, so it is standing per principal, not a per-request nonce). */
fun constantTimeEquals(presented: String?, expected: String): Boolean {
    if (presented == null) return false
    return MessageDigest.isEqual(presented.toByteArray(Charsets.UTF_8), expected.toByteArray(Charsets.UTF_8))
}

// Every mutation route gates on a session first (requireAdmin / requireAuthz both resolve one before they
// decide), so this names the principal the authorization decision ran against and the trail cannot disagree
// with the gate about who acted. Total rather than asserting that: an audit row is the last place to throw,
// and an unattributed row is a louder signal than a 500 that loses the row entirely.
fun ApplicationCall.auditActor(config: Config, channel: String = AuditSource.CONSOLE): AuditActor = AuditActor(
    principal = userSession()?.principal ?: AuthAuditRecorder.PRINCIPAL_UNATTRIBUTED,
    clientAddr = httpRequesterIp(config),
    channel = channel,
)
