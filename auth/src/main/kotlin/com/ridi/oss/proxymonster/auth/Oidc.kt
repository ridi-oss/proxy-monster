package com.ridi.oss.proxymonster.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.get
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.net.URL

@Serializable
data class OidcDiscoveryDocument(
    val issuer: String,
    val authorization_endpoint: String,
    val token_endpoint: String,
    val userinfo_endpoint: String? = null,
    val jwks_uri: String,
    val device_authorization_endpoint: String? = null,
    val code_challenge_methods_supported: List<String>? = null,
)

class OidcDiscovery(private val http: HttpClient, private val issuer: String) {
    private val mutex = Mutex()
    @Volatile private var cached: OidcDiscoveryDocument? = null

    suspend fun document(): OidcDiscoveryDocument {
        cached?.let { return it }
        return mutex.withLock {
            cached?.let { return it }
            val document: OidcDiscoveryDocument = http.get(discoveryUrl()).body()
            require(document.issuer.trimEnd('/') == issuer.trimEnd('/')) { "OIDC discovery issuer mismatch" }
            cached = document
            document
        }
    }

    private fun discoveryUrl(): String = "${issuer.trimEnd('/')}/.well-known/openid-configuration"
}

data class ValidatedIdToken(
    val subject: String,
    val email: String?,
    val groups: List<String>,
    val nonce: String?,
)

class IdTokenValidator(
    private val discovery: OidcDiscovery,
    private val issuer: String,
    private val clientId: String,
) {
    private val log = LoggerFactory.getLogger(IdTokenValidator::class.java)

    suspend fun validate(idToken: String, expectedNonce: String?): ValidatedIdToken? {
        return try {
            val claims = withContext(Dispatchers.IO) {
                val jwkSource = RemoteJWKSet<SecurityContext>(URL(discovery.document().jwks_uri))
                val processor = DefaultJWTProcessor<SecurityContext>().apply {
                    jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)
                    jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
                        JWTClaimsSet.Builder().issuer(issuer).audience(clientId).build(),
                        setOf("exp"),
                    )
                }
                processor.process(idToken, null)
            }
            val subject = claims.subject ?: return null
            val actualNonce = claims.getClaim("nonce") as? String
            if (expectedNonce != null && actualNonce != expectedNonce) return null
            ValidatedIdToken(
                subject = subject,
                email = claims.getClaim("email") as? String,
                groups = (claims.getClaim("groups") as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
                nonce = actualNonce,
            )
        } catch (e: Exception) {
            log.warn("id_token validation failed", e)
            null
        }
    }
}

fun oidcHttpClient(): HttpClient = HttpClient(CIO) {
    expectSuccess = true
    install(ClientContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
}

data class OidcGroupMapping(val map: Map<String, String>, val prefix: String?) {
    fun resolve(idpGroups: List<String>): Set<String> = idpGroups.mapNotNullTo(LinkedHashSet()) { group ->
        map[group] ?: run {
            val raw = if (prefix != null && group.startsWith(prefix)) group.removePrefix(prefix) else group
            raw.ifBlank { null }?.takeUnless(::isReservedGroupName)
        }
    }

    companion object {
        const val RESERVED_GROUP_PREFIX = "system:"

        fun isReservedGroupName(name: String): Boolean = name.startsWith(RESERVED_GROUP_PREFIX, ignoreCase = true)

        fun parse(mapEnv: String?, prefixEnv: String?): OidcGroupMapping = OidcGroupMapping(
            map = mapEnv.orEmpty().split(',').mapNotNull { entry ->
                if ('=' !in entry) return@mapNotNull null
                val idp = entry.substringBefore('=').trim()
                val local = entry.substringAfter('=').trim()
                if (idp.isBlank() || local.isBlank()) null else idp to local
            }.toMap(),
            prefix = prefixEnv?.takeIf { it.isNotEmpty() },
        )
    }
}
