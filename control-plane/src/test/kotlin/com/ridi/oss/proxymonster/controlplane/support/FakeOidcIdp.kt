package com.ridi.oss.proxymonster.controlplane.support

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.auth.OidcGroupMapping
import com.ridi.oss.proxymonster.controlplane.OidcConfig
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.time.Instant
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * A loopback IdP: the token endpoint signs an id_token for whichever identity [next] names, and answers a
 * refresh grant for a token [rejectRefresh] named with invalid_grant, every other one with the same identity.
 */
class FakeOidcIdp : AutoCloseable {
    data class Identity(val subject: String, val email: String?, val groups: List<String>?)

    private val key = RSAKeyGenerator(2048).keyID("fake-oidc-idp").generate()
    private val pending = AtomicReference<Pair<Identity, String>>()
    private val issued = ConcurrentHashMap<String, Identity>()
    private val rejected = ConcurrentHashMap.newKeySet<String>()
    private val refreshes = AtomicInteger()
    private val server: EmbeddedServer<*, *> = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
        routing {
            get("/.well-known/openid-configuration") {
                call.respondText(
                    """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token",""" +
                        """"jwks_uri":"$issuer/jwks","code_challenge_methods_supported":["S256"]}""",
                    ContentType.Application.Json,
                )
            }
            get("/jwks") { call.respondText(JWKSet(key.toPublicJWK()).toString(), ContentType.Application.Json) }
            post("/token") {
                val form = call.receiveParameters()
                if (form["grant_type"] == "refresh_token") {
                    val token = form["refresh_token"].orEmpty()
                    val identity = issued[token]
                    if (identity == null || token in rejected) {
                        call.respondText("""{"error":"invalid_grant"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                    } else {
                        call.respondText("""{"id_token":"${sign(identity, null)}"}""", ContentType.Application.Json)
                    }
                    return@post
                }
                val (identity, nonce) = pending.get()
                val refresh = "rt-${identity.subject}-${refreshes.incrementAndGet()}"
                issued[refresh] = identity
                call.respondText("""{"id_token":"${sign(identity, nonce)}","refresh_token":"$refresh"}""", ContentType.Application.Json)
            }
        }
    }.start(wait = false)
    private val port = runBlocking { server.engine.resolvedConnectors().first().port }

    val issuer get() = "http://127.0.0.1:$port"
    val clientId = "fake-oidc-client"
    private val clientSecret = "fake-oidc-secret"
    private val redirectUri = "http://control-plane.test/auth/oidc/callback"
    private val scopes = "openid email groups offline_access"

    /** The Kotlin control plane's OIDC settings for this IdP. */
    fun config(groupMap: Map<String, String> = emptyMap(), groupPrefix: String? = null) =
        OidcConfig(issuer, clientId, clientSecret, redirectUri, scopes, OidcGroupMapping(groupMap, groupPrefix))

    /** cp-go's OIDC settings for this IdP, the same ones [config] gives Kotlin. */
    fun env(groupMap: Map<String, String> = emptyMap(), groupPrefix: String? = null): Map<String, String> = buildMap {
        put("PM_OIDC_ISSUER", issuer)
        put("PM_OIDC_CLIENT_ID", clientId)
        put("PM_OIDC_CLIENT_SECRET", clientSecret)
        put("PM_OIDC_REDIRECT_URI", redirectUri)
        put("PM_OIDC_SCOPES", scopes)
        if (groupMap.isNotEmpty()) put("PM_OIDC_GROUP_MAP", groupMap.entries.joinToString(",") { "${it.key}=${it.value}" })
        groupPrefix?.let { put("PM_OIDC_GROUP_PREFIX", it) }
    }

    /** The identity the next authorization-code exchange signs for, bound to the login's [nonce]. */
    fun next(identity: Identity, nonce: String) = pending.set(identity to nonce)

    /** Refresh grants for [refreshToken] answer invalid_grant from now on. */
    fun rejectRefresh(refreshToken: String) {
        rejected += refreshToken
    }

    private fun sign(identity: Identity, nonce: String?): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(identity.subject)
            .audience(clientId)
            .issueTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .apply { nonce?.let { claim("nonce", it) } }
            .apply { identity.email?.let { claim("email", it) } }
            .apply { identity.groups?.let { claim("groups", it) } }
            .build()
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims).apply { sign(RSASSASigner(key)) }.serialize()
    }

    override fun close() {
        server.stop(0, 500)
    }
}
