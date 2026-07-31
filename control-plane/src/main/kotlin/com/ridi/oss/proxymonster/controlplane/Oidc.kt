package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.pkceS256
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.forms.submitForm
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.encodeURLParameter
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.sessions.clear
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import java.security.SecureRandom

/** Short-lived signed cookie carrying the CSRF `state` between /login and /callback. */
const val OAUTH_STATE_COOKIE = "pm_oauth_state"

/** The CSRF state stashed in [OAUTH_STATE_COOKIE] for the duration of the redirect dance. */
@Serializable
data class OAuthStateSession(val state: String, val returnTo: String? = null)

/**
 * Short-lived signed cookie proving the browser confirmed the pmon login code on the web `/device` page for
 * [userCode]. Set by `POST /auth/device/confirm`; `GET /auth/device/authorize` requires it, so an attacker's
 * direct authorize link (no `/device` confirm) cannot approve a code the user never confirmed.
 */
const val DEVICE_VERIFY_COOKIE = "pm_device_verify"

@Serializable
data class DeviceVerifySession(val userCode: String)

/** Short-lived signed cookie carrying the OIDC `nonce` between /login and /callback. */
const val OAUTH_NONCE_COOKIE = "pm_oauth_nonce"

/**
 * The `nonce` stashed in [OAUTH_NONCE_COOKIE] for the duration of the redirect dance. Bound into
 * the authorize request and echoed back inside the id_token; [IdTokenValidator] checks the two
 * match, which is what actually defends against authorization-code injection (docs/auth-model.md)
 * — `state` alone only proves the response came back to the browser that started the flow.
 */
@Serializable
data class OAuthNonceSession(val nonce: String)

/** Short-lived signed cookie carrying the PKCE `code_verifier` between /login and /callback. */
const val OAUTH_VERIFIER_COOKIE = "pm_oauth_verifier"

/**
 * The PKCE `code_verifier` stashed in [OAUTH_VERIFIER_COOKIE] for the duration of the redirect
 * dance. Only its S256 hash travels on the authorize request; the verifier itself is presented at
 * the token endpoint, so an attacker who intercepts the redirect still cannot redeem the code.
 *
 * For a confidential client the `nonce` above is already what defeats authorization-code
 * injection, so this is defense in depth rather than the primary control. It is sent only when
 * discovery advertises S256, because an IdP that rejects unknown authorize parameters would
 * otherwise break, and it is what satisfies providers configured to require PKCE (Okta's
 * "Require PKCE as additional verification" returns `invalid_request` without it).
 *
 * Like [OAUTH_STATE_COOKIE] and [OAUTH_NONCE_COOKIE], this must be registered by whoever installs
 * [oidcRoutes]; both handlers clear it unconditionally, so an unregistered name fails at login.
 */
@Serializable
data class OAuthVerifierSession(val verifier: String)

/** Token endpoint response — only the fields we consume; the rest are ignored. */
@Serializable
private data class TokenResponse(
    val id_token: String,
    val access_token: String? = null,
    val refresh_token: String? = null,
)

/** A 32-byte random, URL-safe-ish opaque token — used for both the CSRF `state` and the `nonce`. */
private fun randomOpaqueToken(): String {
    val bytes = ByteArray(24)
    SecureRandom().nextBytes(bytes)
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

/**
 * A PKCE `code_verifier`: 32 random bytes, base64url-encoded to 43 characters, which is the
 * minimum RFC 7636 permits and what [isValidPkceVerifier] enforces on the server side of this
 * same codebase. [randomOpaqueToken] is deliberately not reused — its 24 bytes encode to 32
 * characters and would be rejected as too short.
 */
private fun randomCodeVerifier(): String {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

/**
 * OIDC authorization-code routes (docs/auth-model.md) — provider-agnostic via discovery, so any
 * OIDC IdP works (nothing here is Okta-specific). Wired alongside the existing
 * debug-login surface in [Application.module]. All handlers degrade gracefully to 501 when OIDC
 * isn't configured (`config.oidc`/[discovery]/[validator] null) so the unconfigured deployment
 * never NPEs.
 *
 * Identity is established from the **id_token** (validated signature + issuer + audience +
 * expiry + nonce via [validator]), never from the userinfo endpoint or client-asserted claims —
 * userinfo is optional/absent on some providers and was never signed to begin with.
 */
fun Route.oidcRoutes(
    config: Config,
    discovery: OidcDiscovery?,
    validator: IdTokenValidator?,
    http: HttpClient,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    store: PrincipalSessionStore,
    log: Logger,
) {
    // Begin the auth-code flow: stash CSRF state + nonce, then 302 to the IdP's authorize endpoint.
    get("/auth/oidc/login") {
        val oidc = config.oidc
        if (oidc == null || discovery == null || validator == null) {
            call.respond(HttpStatusCode.NotImplemented, ApiError("common.oidc_not_configured"))
            return@get
        }
        val state = randomOpaqueToken()
        val nonce = randomOpaqueToken()
        // Only the co-hosted OAuth resume and popup re-auth landing routes are valid continuations.
        // Treat every other value as absent, so this can never become an open redirect.
        val returnTo = oidcReturnTarget(call.request.queryParameters["return_to"])
        call.sessions.set(OAUTH_STATE_COOKIE, OAuthStateSession(state, returnTo))
        call.sessions.set(OAUTH_NONCE_COOKIE, OAuthNonceSession(nonce))

        val document = discovery.document()
        // Negotiated, not assumed: only send a challenge to an IdP that advertises S256, so a
        // provider that rejects unknown authorize parameters keeps working unchanged.
        val verifier = if (document.supportsPkceS256()) randomCodeVerifier() else null
        if (verifier != null) {
            call.sessions.set(OAUTH_VERIFIER_COOKIE, OAuthVerifierSession(verifier))
        } else {
            call.sessions.clear(OAUTH_VERIFIER_COOKIE)
        }

        val authorizeUrl = buildString {
            append(document.authorization_endpoint)
            append("?client_id=").append(oidc.clientId.encodeURLParameter())
            append("&response_type=code")
            append("&scope=").append(oidc.scopes.encodeURLParameter())
            append("&redirect_uri=").append(oidc.redirectUri.encodeURLParameter())
            append("&state=").append(state.encodeURLParameter())
            append("&nonce=").append(nonce.encodeURLParameter())
            if (verifier != null) {
                append("&code_challenge=").append(pkceS256(verifier).encodeURLParameter())
                append("&code_challenge_method=S256")
            }
        }
        call.respondRedirect(authorizeUrl)
    }

    // The IdP redirects back here with ?code&state (or ?error). Validate, exchange, provision,
    // hydrate session.
    get("/auth/oidc/callback") {
        val oidc = config.oidc
        if (oidc == null || discovery == null || validator == null) {
            call.respond(HttpStatusCode.NotImplemented, ApiError("common.oidc_not_configured"))
            return@get
        }

        val params = call.request.queryParameters
        val code = params["code"]
        val state = params["state"]
        val stateSession = call.sessions.get<OAuthStateSession>()
        val expectedState = stateSession?.state
        val expectedNonce = call.sessions.get<OAuthNonceSession>()?.nonce
        val codeVerifier = call.sessions.get<OAuthVerifierSession>()?.verifier
        // One-time use: drop all three cookies regardless of the outcome below.
        call.sessions.clear(OAUTH_STATE_COOKIE)
        call.sessions.clear(OAUTH_NONCE_COOKIE)
        call.sessions.clear(OAUTH_VERIFIER_COOKIE)

        if (state == null || expectedState == null || state != expectedState) {
            log.warn("OIDC callback state validation failed")
            val target = if (stateSession?.returnTo == "/auth/reauth-complete") {
                oidcFailureTarget(stateSession, oauthError = "access_denied", consoleError = "state")
            } else {
                "/login?error=state"
            }
            call.respondRedirect(target)
            return@get
        }
        if (params["error"] != null) {
            log.warn("OIDC callback returned error: {}", params["error"])
            call.respondRedirect(oidcFailureTarget(stateSession, oauthError = "access_denied", consoleError = "oidc"))
            return@get
        }
        if (code == null) {
            log.warn("OIDC callback omitted both code and error")
            call.respondRedirect(oidcFailureTarget(stateSession, oauthError = "server_error", consoleError = "state"))
            return@get
        }
        if (expectedNonce == null) {
            log.warn("OIDC callback nonce state is absent")
            call.respondRedirect(oidcFailureTarget(stateSession, oauthError = "access_denied", consoleError = "nonce"))
            return@get
        }

        try {
            val document = discovery.document()
            val token: TokenResponse = http.submitForm(
                url = document.token_endpoint,
                formParameters = Parameters.build {
                    append("grant_type", "authorization_code")
                    append("code", code)
                    append("redirect_uri", oidc.redirectUri)
                    append("client_id", oidc.clientId)
                    append("client_secret", oidc.clientSecret)
                    // Present only when /login issued a challenge; sending it unconditionally
                    // would fail against an IdP that never saw one.
                    if (codeVerifier != null) append("code_verifier", codeVerifier)
                },
            ).body()

            // Signature + iss/aud/exp + nonce all verified inside validate(); null means any of
            // those failed (incl. a nonce mismatch — the one-time cookie above already guards
            // replay of the *state*, this guards injection of a *different* authorization result).
            val claims = validator.validate(token.id_token, expectedNonce = expectedNonce)
            if (claims == null) {
                log.warn("OIDC callback id_token validation failed")
                call.respondRedirect(oidcFailureTarget(stateSession, oauthError = "access_denied", consoleError = "nonce"))
                return@get
            }

            val principal = claims.email ?: claims.subject
            // JIT-provision + SYNC group membership to the IdP claim (docs/backlog.md):
            // membership is reconciled to the mapped claim set — added AND removed — so IdP group changes
            // (including admin, via system:admin) take effect on the next login. Deactivation stays SCIM's job.
            userGroupStore.provisionFromOidc(principal, claims.email, claims.groups, oidc.groupMapping)
            // Gate a principal with no effective roles to the no-access screen before minting a session.
            if (roleResolver.resolve(principal).isEmpty()) {
                log.warn("OIDC callback principal has no effective roles: {}", principal)
                call.respondRedirect(oidcFailureTarget(stateSession, oauthError = "access_denied", consoleError = "no_access"))
                return@get
            }

            val refreshToken = token.refresh_token?.takeIf {
                "offline_access" in oidc.scopes.split(Regex("\\s+")).filter(String::isNotBlank)
            }

            val deviceId = call.ensureDeviceCookie(config.mcpIssuer.startsWith("https://"))
            val sessionId = store.mintWeb(
                principal,
                refreshToken,
                config.webSessionAbsoluteSeconds,
                config.webSessionIdleSeconds,
                deviceId,
            )
            call.sessions.set(WebSessionRef(sessionId))
            call.respondRedirect(stateSession?.returnTo ?: "/")
        } catch (e: Exception) {
            log.error("OIDC token exchange failed", e)
            call.respondRedirect(oidcFailureTarget(stateSession, oauthError = "server_error", consoleError = "oidc"))
        }
    }
}

/**
 * Whether the IdP advertises S256 PKCE. Absent metadata means no: RFC 8414 makes the field
 * optional, and a provider that omits it may reject the extra authorize parameters outright.
 */
internal fun OidcDiscoveryDocument.supportsPkceS256(): Boolean =
    code_challenge_methods_supported?.any { it.equals("S256", ignoreCase = true) } == true

internal fun oidcReturnTarget(raw: String?): String? =
    raw?.takeIf {
        // Fixed co-hosted continuations, plus the pmon device-authorize landing (a fixed path with only a
        // constrained user_code query) — never an arbitrary value, so this can't become an open redirect.
        it == "/oauth/resume" || it == "/auth/reauth-complete" ||
            it.matches(Regex("/auth/device/authorize\\?user_code=[A-Za-z0-9-]{1,16}"))
    }

internal fun oidcFailureTarget(state: OAuthStateSession?, oauthError: String, consoleError: String): String {
    val returnTo = state?.returnTo
    return when {
        returnTo == "/oauth/resume" -> "/oauth/resume?error=${oauthError.encodeURLParameter()}"
        returnTo == "/auth/reauth-complete" ->
            "/login?error=${consoleError.encodeURLParameter()}&callbackUrl=%2Fauth%2Freauth-complete"
        // A device login that hit a recoverable failure (a cancelled consent, a transient token-endpoint
        // error) keeps its continuation, so retrying the sign-in still completes the pmon login instead of
        // silently becoming an ordinary console login and stranding the handle until it expires.
        returnTo != null -> "/login?error=${consoleError.encodeURLParameter()}&return_to=${returnTo.encodeURLParameter()}"
        else -> "/login?error=${consoleError.encodeURLParameter()}"
    }
}
