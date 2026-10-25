package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.net.ServerSocket
import java.util.Date

/** A loopback CI issuer serving a GitHub-shaped discovery document (issuer + jwks_uri only) and its JWKS. */
internal class CiOidcTestIssuer : AutoCloseable {
    val key: RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()
    private val port = ServerSocket(0).use { it.localPort }
    val url = "http://127.0.0.1:$port"
    val config = CiOidcIssuer("github", url, AUDIENCE)
    private val server: EmbeddedServer<*, *> = embeddedServer(Netty, port = port, host = "127.0.0.1") {
        routing {
            get("/.well-known/openid-configuration") {
                call.respondText("""{"issuer":"$url","jwks_uri":"$url/jwks"}""", ContentType.Application.Json)
            }
            get("/jwks") { call.respondText(JWKSet(key.toPublicJWK()).toString(), ContentType.Application.Json) }
        }
    }.start(wait = false)

    fun claims(
        iss: String = url,
        aud: String = AUDIENCE,
        sub: String? = "repo:acme/shop:ref:refs/heads/main",
        expOffsetSeconds: Long = 300,
        iatOffsetSeconds: Long = 0,
        nbfOffsetSeconds: Long? = null,
        repository: String? = "acme/shop",
        baseRef: String? = null,
    ): JWTClaimsSet {
        val now = System.currentTimeMillis()
        return JWTClaimsSet.Builder().issuer(iss).audience(aud)
            .expirationTime(Date(now + expOffsetSeconds * 1000))
            .issueTime(Date(now + iatOffsetSeconds * 1000))
            .apply {
                sub?.let { subject(it) }
                nbfOffsetSeconds?.let { notBeforeTime(Date(now + it * 1000)) }
                repository?.let { claim("repository", it) }
                claim("ref", "refs/heads/main")
                baseRef?.let { claim("base_ref", it) }
                claim("event_name", "push")
                claim("runner_environment", "github-hosted")
            }
            .build()
    }

    fun sign(claims: JWTClaimsSet = claims(), signingKey: RSAKey = key): String =
        SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.keyID).build(), claims)
            .apply { sign(RSASSASigner(signingKey)) }.serialize()

    /** A key the issuer never published, under the published kid. */
    fun impostorKey(): RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()

    override fun close() = server.stop(gracePeriodMillis = 0, timeoutMillis = 500)

    companion object {
        const val AUDIENCE = "https://pm.example.com"
        private const val KID = "ci-kid"
    }
}
