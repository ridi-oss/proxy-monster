package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.ACTION_WORKLOAD_EXCHANGE
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.CHANNEL_WORKLOAD
import com.ridi.oss.proxymonster.controlplane.AuthAuditRecorder.Companion.PRINCIPAL_UNATTRIBUTED
import com.ridi.oss.proxymonster.controlplane.authz.AuthzPrincipal
import com.ridi.oss.proxymonster.controlplane.authz.WORKLOAD_CLAIM_ATTRIBUTES
import com.ridi.oss.proxymonster.controlplane.management.AuditActor
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL
import java.text.ParseException
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

@Serializable
data class WorkloadTokenExchangeRequest(val token: String)

sealed class CiOidcException(message: String) : Exception(message) {
    class UntrustedIssuer(val iss: String?) : CiOidcException("untrusted issuer")
    class InvalidToken(reason: String) : CiOidcException(reason)
}

data class VerifiedCiToken(val issuer: CiOidcIssuer, val claims: JWTClaimsSet)

// CI issuers publish only `issuer` + `jwks_uri` (GitHub has no authorization/token endpoint), so the
// login flow's OidcDiscoveryDocument cannot parse their discovery document.
@Serializable
private data class CiOidcDiscoveryDocument(val issuer: String, @SerialName("jwks_uri") val jwksUri: String)

/** Verifies a CI OIDC JWT: RS256 signature against the issuer's JWKS, `iss`, `aud`, `exp`/`nbf`/`iat`, `sub`. */
class CiOidcTokenVerifier(
    issuers: List<CiOidcIssuer>,
    private val http: HttpClient = oidcHttpClient(),
    private val clockSkewSeconds: Int = 60,
) {
    private val byIssuer = issuers.associateBy { it.issuer }
    private val processors = ConcurrentHashMap<String, DefaultJWTProcessor<SecurityContext>>()

    suspend fun verify(jwt: String): VerifiedCiToken {
        val parsed = runCatching { SignedJWT.parse(jwt).also { it.jwtClaimsSet } }
            .getOrElse { throw CiOidcException.InvalidToken("malformed") }
        val iss = parsed.jwtClaimsSet.issuer
        val cfg = byIssuer[iss] ?: throw CiOidcException.UntrustedIssuer(iss)
        val processor = processorFor(cfg)
        val claims = try {
            withContext(Dispatchers.IO) { processor.process(parsed, null) }
        } catch (e: BadJOSEException) {
            throw CiOidcException.InvalidToken(e.message ?: "invalid")
        } catch (e: JOSEException) {
            throw CiOidcException.InvalidToken(e.message ?: "invalid")
        } catch (e: ParseException) {
            throw CiOidcException.InvalidToken(e.message ?: "invalid")
        }
        // DefaultJWTClaimsVerifier checks exp and nbf but not a future-dated iat.
        if (claims.issueTime.after(Date(System.currentTimeMillis() + clockSkewSeconds * 1000L))) {
            throw CiOidcException.InvalidToken("iat in the future")
        }
        return VerifiedCiToken(cfg, claims)
    }

    private suspend fun processorFor(cfg: CiOidcIssuer): DefaultJWTProcessor<SecurityContext> {
        processors[cfg.issuer]?.let { return it }
        val jwksUri = discoverJwksUri(cfg.issuer)
        return processors.computeIfAbsent(cfg.issuer) {
            DefaultJWTProcessor<SecurityContext>().apply {
                jwsKeySelector = JWSVerificationKeySelector(
                    JWSAlgorithm.RS256,
                    JWKSourceBuilder.create<SecurityContext>(URL(jwksUri)).build(),
                )
                jwtClaimsSetVerifier = DefaultJWTClaimsVerifier<SecurityContext>(
                    cfg.audience,
                    JWTClaimsSet.Builder().issuer(cfg.issuer).build(),
                    setOf("exp", "iat", "sub"),
                ).apply { maxClockSkew = clockSkewSeconds }
            }
        }
    }

    private suspend fun discoverJwksUri(issuer: String): String {
        val doc: CiOidcDiscoveryDocument = http.get("${issuer.trimEnd('/')}/.well-known/openid-configuration").body()
        require(doc.issuer.trimEnd('/') == issuer.trimEnd('/')) { "CI OIDC discovery issuer mismatch" }
        return doc.jwksUri
    }
}

const val WORKLOAD_TOKEN_TTL_SECONDS = 15 * 60L

/** Exchanges a verified CI OIDC JWT for a WORKLOAD bearer token carrying its allow-listed claims. */
class WorkloadTokenService(
    private val config: Config,
    private val tokenStore: TokenStore,
    private val authAudit: AuthAuditRecorder,
    private val verifier: CiOidcTokenVerifier = CiOidcTokenVerifier(config.ciOidcIssuers),
) {
    suspend fun exchange(jwt: String, requesterIp: String?): IssuedToken {
        if (config.ciOidcIssuers.isEmpty()) {
            throw TaskServiceException(HttpStatusCode.NotFound, ApiError("workload.not_configured"))
        }
        val unattributed = AuditActor(PRINCIPAL_UNATTRIBUTED, clientAddr = requesterIp, channel = CHANNEL_WORKLOAD)
        val verified = try {
            verifier.verify(jwt)
        } catch (e: CiOidcException.UntrustedIssuer) {
            authAudit.failureBestEffort(
                unattributed, ACTION_WORKLOAD_EXCHANGE, auditEntity("Workload", auditedValue(e.iss ?: "-")),
                "CI OIDC token from an untrusted issuer",
            )
            throw TaskServiceException(HttpStatusCode.Unauthorized, ApiError("workload.issuer_not_trusted"))
        } catch (e: CiOidcException.InvalidToken) {
            authAudit.failureBestEffort(
                unattributed, ACTION_WORKLOAD_EXCHANGE, auditEntity("Workload", issuerNameOf(jwt) ?: "-"),
                "CI OIDC token rejected", detail = auditedValue(e.message ?: "invalid"),
            )
            throw TaskServiceException(HttpStatusCode.Unauthorized, ApiError("common.invalid_token", mapOf("kind" to "ci_oidc")))
        }
        val name = verified.issuer.name
        val claims = WORKLOAD_CLAIM_ATTRIBUTES.mapNotNull { k -> (verified.claims.getClaim(k) as? String)?.let { k to it } }.toMap()
        return tokenStore.dataSource.inTx { c ->
            tokenStore.issueWorkload(name, claims, WORKLOAD_TOKEN_TTL_SECONDS, c).also {
                authAudit.success(
                    c,
                    AuditActor("workload:$name", clientAddr = requesterIp, channel = CHANNEL_WORKLOAD),
                    ACTION_WORKLOAD_EXCHANGE,
                    auditEntity("Workload", name),
                    "Exchanged a CI OIDC token for a workload token",
                    detail = auditedValue(claims.entries.joinToString(" ") { (k, v) -> "$k=$v" }),
                )
            }
        }
    }

    private fun issuerNameOf(jwt: String): String? {
        val iss = runCatching { SignedJWT.parse(jwt).jwtClaimsSet.issuer }.getOrNull() ?: return null
        return config.ciOidcIssuers.firstOrNull { it.issuer == iss }?.name
    }
}

/**
 * Authenticate a call by a WORKLOAD bearer token, or respond 401 and return null. A token whose issuer
 * is no longer configured is rejected, so removing an issuer revokes its outstanding tokens.
 */
suspend fun ApplicationCall.requireWorkload(config: Config, tokenStore: TokenStore): AuthzPrincipal.Workload? {
    val header = request.headers[HttpHeaders.Authorization]
    val token = header?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }?.substring(7)?.trim()?.ifBlank { null }
    val identity = token?.let { tokenStore.resolveWorkload(it) }
    val cfg = identity?.let { id -> config.ciOidcIssuers.firstOrNull { it.name == id.name } }
    if (identity == null || cfg == null) {
        respond(HttpStatusCode.Unauthorized, ApiError("common.unauthenticated"))
        return null
    }
    return AuthzPrincipal.Workload(identity.name, cfg.issuer, identity.claims)
}
