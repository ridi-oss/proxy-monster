package com.ridi.oss.proxymonster.controlplane.support

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.parseQueryString
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.time.Instant
import java.util.Date
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** A loopback IdP whose token endpoint signs an id_token for whichever identity the next [login] names. */
class FakeOidcIdp : AutoCloseable {
    private data class Identity(val subject: String, val email: String?, val groups: List<String>?, val nonce: String)

    private val key = RSAKeyGenerator(2048).keyID("fake-oidc-idp").generate()
    private val next = AtomicReference<Identity>()
    private val server: EmbeddedServer<*, *> = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
        routing {
            get("/.well-known/openid-configuration") {
                call.respondText(
                    """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks"}""",
                    ContentType.Application.Json,
                )
            }
            get("/jwks") { call.respondText(JWKSet(key.toPublicJWK()).toString(), ContentType.Application.Json) }
            post("/token") { call.respondText("""{"id_token":"${sign(next.get())}"}""", ContentType.Application.Json) }
        }
    }.start(wait = false)
    private val port = runBlocking { server.engine.resolvedConnectors().first().port }

    val issuer get() = "http://127.0.0.1:$port"
    val clientId = "fake-oidc-client"

    /** cp-go's OIDC settings for this IdP, plus `PM_OIDC_GROUP_MAP`/`PM_OIDC_GROUP_PREFIX` when given. */
    fun env(groupMap: String? = null, groupPrefix: String? = null): Map<String, String> = buildMap {
        put("PM_OIDC_ISSUER", issuer)
        put("PM_OIDC_CLIENT_ID", clientId)
        put("PM_OIDC_CLIENT_SECRET", "fake-oidc-secret")
        put("PM_OIDC_REDIRECT_URI", "http://control-plane.test/auth/oidc/callback")
        put("PM_OIDC_SCOPES", "openid email groups")
        groupMap?.let { put("PM_OIDC_GROUP_MAP", it) }
        groupPrefix?.let { put("PM_OIDC_GROUP_PREFIX", it) }
    }

    /** A whole `/auth/oidc/login` + callback on [client] as [subject]; returns the callback's response. */
    suspend fun login(client: HttpClient, subject: String, email: String?, groups: List<String>?): HttpResponse {
        val start = client.get("/auth/oidc/login")
        assertEquals(HttpStatusCode.Found, start.status)
        val query = parseQueryString(assertNotNull(start.headers[HttpHeaders.Location]).substringAfter('?'))
        next.set(Identity(subject, email, groups, assertNotNull(query["nonce"])))
        val callback = client.get("/auth/oidc/callback?code=ok&state=${assertNotNull(query["state"])}")
        assertEquals(HttpStatusCode.Found, callback.status)
        return callback
    }

    private fun sign(identity: Identity): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(identity.subject)
            .audience(clientId)
            .issueTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .claim("nonce", identity.nonce)
            .apply { identity.email?.let { claim("email", it) } }
            .apply { identity.groups?.let { claim("groups", it) } }
            .build()
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims).apply { sign(RSASSASigner(key)) }.serialize()
    }

    override fun close() {
        server.stop(0, 500)
    }
}
