package com.ridi.oss.proxymonster.controlplane.oauth

import com.ridi.oss.proxymonster.auth.AuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.ConsumeAuthorizationCodeInput
import com.ridi.oss.proxymonster.auth.OAuthAuthorizationStore
import com.ridi.oss.proxymonster.auth.OAuthTokenPair
import com.ridi.oss.proxymonster.auth.RefreshTokenInput
import com.ridi.oss.proxymonster.auth.canonicalScopes
import com.ridi.oss.proxymonster.auth.isValidPkceChallenge
import com.ridi.oss.proxymonster.auth.randomSecret
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.WebSessionRef
import com.ridi.oss.proxymonster.controlplane.ensureDeviceCookie
import com.ridi.oss.proxymonster.controlplane.userSession
import com.ridi.oss.proxymonster.controlplane.webSession
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.path
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.sessions.clear
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.util.Locale
import java.util.ResourceBundle
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.sql.DataSource

val MCPA_SCOPES = setOf("mcp:read", "mcp:datasources:write", "mcp:policies:write", "mcp:identity:write")

internal const val MCP_OAUTH_PENDING_COOKIE = "pm_oauth_pending"

@Serializable
internal data class McpPendingAuthorization(
    val clientId: String,
    val redirectUri: String,
    val resource: String,
    val scope: String,
    val state: String,
    val codeChallenge: String,
    val principal: String? = null,
    val csrf: String = randomSecret("csrf_", 18),
)

@Serializable
internal data class OAuthError(val error: String, val error_description: String? = null)

@Serializable
private data class TokenResponse(
    val access_token: String,
    val token_type: String,
    val expires_in: Long,
    val refresh_token: String,
    val scope: String,
)

@Serializable
private data class AuthorizationServerMetadata(
    val issuer: String,
    val authorization_endpoint: String,
    val token_endpoint: String,
    val revocation_endpoint: String,
    val response_types_supported: List<String>,
    val grant_types_supported: List<String>,
    val code_challenge_methods_supported: List<String>,
    val token_endpoint_auth_methods_supported: List<String>,
    val scopes_supported: List<String>,
    val client_id_metadata_document_supported: Boolean,
)

@Serializable
private data class ConsentListResponse(
    val consents: List<com.ridi.oss.proxymonster.auth.OAuthConsent>,
    val csrfToken: String,
)

fun Application.installMcpOAuthProtocolGuard() {
    intercept(ApplicationCallPipeline.Plugins) {
        if (call.request.path().startsWith("/oauth/")) {
            call.response.header(HttpHeaders.CacheControl, "no-store")
            call.response.header(HttpHeaders.Pragma, "no-cache")
        }
    }
}

/** OAuth 2.1 authorization-server routes co-hosted in the control-plane process and session boundary. */
fun Route.mcpOAuthRoutes(
    config: Config,
    dataSource: DataSource,
    principalSessionStore: PrincipalSessionStore,
    cimdResolver: CimdResolver = HttpCimdResolver(productionChecks = !config.authDebug),
) {
    val store = OAuthAuthorizationStore(dataSource)
    get("/.well-known/oauth-authorization-server") {
        call.respond(
            AuthorizationServerMetadata(
                issuer = config.mcpIssuer,
                authorization_endpoint = "${config.mcpIssuer}/oauth/authorize",
                token_endpoint = "${config.mcpIssuer}/oauth/token",
                revocation_endpoint = "${config.mcpIssuer}/oauth/revoke",
                response_types_supported = listOf("code"),
                grant_types_supported = listOf("authorization_code", "refresh_token"),
                code_challenge_methods_supported = listOf("S256"),
                token_endpoint_auth_methods_supported = listOf("none"),
                scopes_supported = MCPA_SCOPES.sorted(),
                client_id_metadata_document_supported = true,
            ),
        )
    }

    get("/oauth/authorize") {
        val params = call.request.queryParameters
        val clientId = params["client_id"]
        val redirectUri = params["redirect_uri"]
        val scope = params["scope"]
        val state = params["state"]
        val resource = params["resource"]
        val challenge = params["code_challenge"]
        val requestedScopes = scope?.split(' ')?.filter(String::isNotBlank)?.toSet().orEmpty()
        val valid = params["response_type"] == "code" && !clientId.isNullOrBlank() && !redirectUri.isNullOrBlank() &&
            !state.isNullOrBlank() && resource == config.mcpResource && params["code_challenge_method"] == "S256" &&
            challenge != null && isValidPkceChallenge(challenge) && requestedScopes.isNotEmpty() &&
            requestedScopes.all { it in MCPA_SCOPES }
        if (!valid) {
            call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_request"))
            return@get
        }
        val metadata = runCatching { cimdResolver.resolve(clientId!!) }.getOrElse {
            call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_client")); return@get
        }
        runCatching { metadata.validateRequest(redirectUri!!, requestedScopes) }.getOrElse {
            call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_client")); return@get
        }
        val canonicalScope = canonicalScopes(requestedScopes)
        if (config.authDebug) {
            val principal = params["principal"]?.takeIf(String::isNotBlank)
                ?: call.userSession()?.principal
                ?: "debug-user"
            val pending = McpPendingAuthorization(clientId, redirectUri, resource, canonicalScope, state, challenge, principal)
            call.sessions.set(MCP_OAUTH_PENDING_COOKIE, pending)
            // Debug OAuth and the web console intentionally share the same authenticated session,
            // matching the production co-hosted flow without a second identity boundary.
            //
            // Sharing the session means REPLACING it: mintWeb is newest-wins, so this ends the console's
            // current session. Carry that session's simulated source address onto the new row, or an MCP
            // authorization in the same browser would silently drop it and every later console decision
            // would fall back to the observed peer — the console's authorization context changing as a
            // side effect of an unrelated login. Only when the principal is unchanged: an explicit
            // ?principal= switches identity, and one identity's simulated network must not follow another's.
            val inheritedRequesterIp = call.webSession()
                ?.takeIf { it.principal == principal }
                ?.debugRequesterIp
            val deviceId = call.ensureDeviceCookie(config.mcpIssuer.startsWith("https://"))
            call.sessions.set(
                WebSessionRef(
                    principalSessionStore.mintWeb(
                        principal,
                        null,
                        config.webSessionAbsoluteSeconds,
                        config.webSessionIdleSeconds,
                        deviceId,
                        debugRequesterIp = inheritedRequesterIp,
                    ),
                ),
            )
            if (config.mcpDebugAutoConsent || params["auto_consent"] == "true") {
                val consent = store.findActiveConsent(principal, clientId, resource, requestedScopes)
                    ?: store.rememberConsent(principal, clientId, resource, requestedScopes)
                issueAuthorizationCode(call, pending, consent.id, store, cimdResolver)
            } else {
                renderConsent(call, pending, metadata.client_name, metadata.client_id)
            }
            return@get
        }

        val pending = McpPendingAuthorization(
            clientId!!, redirectUri!!, resource!!, canonicalScope, state!!, challenge,
            principal = call.userSession()?.principal,
        )
        call.sessions.set(MCP_OAUTH_PENDING_COOKIE, pending)
        if (pending.principal == null) {
            // One origin and one signed session: use the existing control-plane OIDC login, then
            // return to /oauth/resume. No service call or service credential exists between them.
            call.respondRedirect("/auth/oidc/login?return_to=${"/oauth/resume".encodeURLParameter()}")
        } else {
            continueAuthorization(call, pending, store, cimdResolver)
        }
    }

    get("/oauth/resume") {
        val pending = call.sessions.get<McpPendingAuthorization>()
        val upstreamError = call.request.queryParameters["error"]
        if (upstreamError != null) {
            if (pending == null || upstreamError !in setOf("access_denied", "server_error")) {
                call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_request")); return@get
            }
            val scopes = pending.scope.split(' ').filter(String::isNotBlank).toSet()
            val validClient = runCatching {
                cimdResolver.resolve(pending.clientId).validateRequest(pending.redirectUri, scopes)
            }.isSuccess
            if (!validClient) {
                call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_client")); return@get
            }
            call.sessions.clear(MCP_OAUTH_PENDING_COOKIE)
            call.respondRedirect(
                oauthRedirect(pending.redirectUri, mapOf("error" to upstreamError, "state" to pending.state)),
            )
            return@get
        }
        val principal = call.userSession()?.principal
        if (pending == null || principal == null || (pending.principal != null && pending.principal != principal)) {
            call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_request")); return@get
        }
        val authenticated = pending.copy(principal = principal, csrf = randomSecret("csrf_", 18))
        call.sessions.set(MCP_OAUTH_PENDING_COOKIE, authenticated)
        continueAuthorization(call, authenticated, store, cimdResolver)
    }

    post("/oauth/consent") {
        val pending = call.sessions.get<McpPendingAuthorization>()
        val principal = pending?.principal
        val form = call.receiveParameters()
        if (pending == null || principal == null || call.userSession()?.principal != principal || form["csrf"] != pending.csrf) {
            call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_request")); return@post
        }
        if (form["decision"] != "approve") {
            call.sessions.clear(MCP_OAUTH_PENDING_COOKIE)
            call.respondRedirect(oauthRedirect(pending.redirectUri, mapOf("error" to "access_denied", "state" to pending.state)))
            return@post
        }
        val consent = store.rememberConsent(principal, pending.clientId, pending.resource, pending.scope.split(' '))
        issueAuthorizationCode(call, pending, consent.id, store, cimdResolver)
    }

    post("/oauth/token") {
        val form = call.receiveParameters()
        val pair: OAuthTokenPair? = when (form["grant_type"]) {
            "authorization_code" -> {
                val code = form["code"] ?: return@post call.oauthError("invalid_request")
                val clientId = form["client_id"] ?: return@post call.oauthError("invalid_request")
                val redirectUri = form["redirect_uri"] ?: return@post call.oauthError("invalid_request")
                val resource = form["resource"] ?: return@post call.oauthError("invalid_request")
                val verifier = form["code_verifier"] ?: return@post call.oauthError("invalid_request")
                if (resource != config.mcpResource) null else store.consumeAuthorizationCode(
                    ConsumeAuthorizationCodeInput(
                        code, clientId, redirectUri, resource, verifier,
                        config.mcpAccessTtlSeconds, config.mcpRefreshTtlSeconds,
                    ),
                )
            }
            "refresh_token" -> {
                val refresh = form["refresh_token"] ?: return@post call.oauthError("invalid_request")
                val clientId = form["client_id"] ?: return@post call.oauthError("invalid_request")
                val resource = form["resource"] ?: return@post call.oauthError("invalid_request")
                if (resource != config.mcpResource) null else store.rotateRefresh(
                    RefreshTokenInput(refresh, clientId, resource, config.mcpAccessTtlSeconds, config.mcpRefreshTtlSeconds),
                )
            }
            else -> return@post call.oauthError("unsupported_grant_type")
        }
        if (pair == null) return@post call.oauthError("invalid_grant")
        call.respond(pair.toResponse())
    }

    post("/oauth/revoke") {
        val token = call.receiveParameters()["token"]
        if (token != null) store.revoke(token)
        call.respond(HttpStatusCode.OK, emptyMap<String, String>())
    }

    get("/oauth/consents") {
        val user = call.userSession()
        if (user == null) return@get call.respond(HttpStatusCode.Unauthorized, OAuthError("login_required"))
        call.respond(ConsentListResponse(store.listConsents(user.principal), consentCsrf(config.sessionSecret, user.principal)))
    }

    delete("/oauth/consents/{id}") {
        val user = call.userSession()
        val id = call.parameters["id"]?.toLongOrNull()
        if (user == null) return@delete call.respond(HttpStatusCode.Unauthorized, OAuthError("login_required"))
        val expectedCsrf = consentCsrf(config.sessionSecret, user.principal)
        val suppliedCsrf = call.request.headers["X-PM-CSRF"]
        if (suppliedCsrf == null || !MessageDigest.isEqual(suppliedCsrf.toByteArray(), expectedCsrf.toByteArray())) {
            return@delete call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_request"))
        }
        if (id == null) return@delete call.respond(HttpStatusCode.BadRequest, OAuthError("invalid_request"))
        if (store.revokeConsent(id, user.principal)) call.respond(HttpStatusCode.NoContent)
        else call.respond(HttpStatusCode.NotFound, OAuthError("invalid_request"))
    }
}

private suspend fun continueAuthorization(
    call: ApplicationCall,
    pending: McpPendingAuthorization,
    store: OAuthAuthorizationStore,
    resolver: CimdResolver,
) {
    val principal = requireNotNull(pending.principal)
    val scopes = pending.scope.split(' ').filter(String::isNotBlank).toSet()
    val metadata = resolver.resolve(pending.clientId)
    metadata.validateRequest(pending.redirectUri, scopes)
    val consent = store.findActiveConsent(principal, pending.clientId, pending.resource, scopes)
    if (consent != null) issueAuthorizationCode(call, pending, consent.id, store, resolver)
    else renderConsent(call, pending, metadata.client_name, metadata.client_id)
}

private suspend fun issueAuthorizationCode(
    call: ApplicationCall,
    pending: McpPendingAuthorization,
    consentId: Long,
    store: OAuthAuthorizationStore,
    resolver: CimdResolver,
) {
    val scopes = pending.scope.split(' ').toSet()
    val metadata = resolver.resolve(pending.clientId)
    metadata.validateRequest(pending.redirectUri, scopes)
    val code = store.createAuthorizationCode(
        AuthorizationCodeInput(
            pending.clientId,
            requireNotNull(pending.principal),
            pending.redirectUri,
            pending.resource,
            scopes,
            pending.codeChallenge,
            consentId = consentId,
        ),
    )
    call.sessions.clear(MCP_OAUTH_PENDING_COOKIE)
    call.respondRedirect(oauthRedirect(pending.redirectUri, mapOf("code" to code, "state" to pending.state)))
}

private suspend fun renderConsent(
    call: ApplicationCall,
    pending: McpPendingAuthorization,
    clientName: String,
    clientId: String,
) {
    val bundle = localizedBundle(call)
    val scopes = pending.scope.split(' ').joinToString("<br>") { escapeHtml(it) }
    val redirect = validatedRedirectUri(pending.redirectUri)
    val redirectDisclosure = escapeHtml(pending.redirectUri)
    val loopbackWarning = if (isLoopbackRedirectHost(requireNotNull(redirect.host))) {
        "<p><strong>${escapeHtml(bundle.getString("consent.localhost_warning"))}</strong></p>"
    } else {
        ""
    }
    call.response.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
    call.response.header("X-Content-Type-Options", "nosniff")
    call.response.header("Referrer-Policy", "no-referrer")
    call.respondText(
        """<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(bundle.getString("consent.title"))}</title></head>
           <body><h1>${escapeHtml(bundle.getString("consent.title"))}</h1>
           <p>${escapeHtml(bundle.getString("consent.client"))}: ${escapeHtml(clientName)}</p>
           <p>${escapeHtml(bundle.getString("consent.client_id"))}: ${escapeHtml(clientId)}</p>
           <p>${escapeHtml(bundle.getString("consent.redirect"))}: $redirectDisclosure</p>
           $loopbackWarning
           <p>${escapeHtml(bundle.getString("consent.scopes"))}:<br>$scopes</p>
           <form method="post" action="/oauth/consent">
           <input type="hidden" name="csrf" value="${escapeHtml(pending.csrf)}">
           <button name="decision" value="approve">${escapeHtml(bundle.getString("consent.approve"))}</button>
           <button name="decision" value="deny">${escapeHtml(bundle.getString("consent.deny"))}</button>
           </form></body></html>""".trimIndent(),
        ContentType.Text.Html,
    )
}

private fun localizedBundle(call: ApplicationCall): ResourceBundle {
    val preferred = call.request.headers["Accept-Language"]?.lowercase().orEmpty()
    val locale = if (preferred.startsWith("ko")) Locale.KOREAN else Locale.ENGLISH
    return ResourceBundle.getBundle("authorization_messages", locale)
}

private fun escapeHtml(value: String): String = value.replace("&", "&amp;").replace("<", "&lt;")
    .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")

private fun oauthRedirect(uri: String, values: Map<String, String>): String = buildString {
    append(uri)
    append(if ('?' in uri) '&' else '?')
    append(values.entries.joinToString("&") { "${it.key.encodeURLParameter()}=${it.value.encodeURLParameter()}" })
}

private fun OAuthTokenPair.toResponse() = TokenResponse(accessToken, tokenType, expiresIn, refreshToken, scope)

private fun consentCsrf(sessionSecret: String, principal: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(sessionSecret.toByteArray(), "HmacSHA256"))
    return java.util.Base64.getUrlEncoder().withoutPadding()
        .encodeToString(mac.doFinal("mcp-oauth-consent\u0000$principal".toByteArray()))
}

private suspend fun ApplicationCall.oauthError(error: String) {
    respond(HttpStatusCode.BadRequest, OAuthError(error))
}
