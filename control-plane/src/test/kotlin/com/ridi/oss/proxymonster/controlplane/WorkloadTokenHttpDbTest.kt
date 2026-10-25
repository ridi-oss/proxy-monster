package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/** `POST /api/workload/token` over HTTP: status, body, and the token and audit rows each exchange leaves. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WorkloadTokenHttpDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var issuer: CiOidcTestIssuer
    private lateinit var configured: CpGoStack
    private lateinit var unconfigured: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        issuer = CiOidcTestIssuer()
        val database = SharedPostgres.migratedDatabase("pm_workload_http")
        dataSource = SharedPostgres.hikari(database)
        val core = ControlPlaneCore(dataSource)
        fun config(issuers: List<CiOidcIssuer>) = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "workload-http-secret-of-32-chars-x", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true, ciOidcIssuers = issuers,
        )
        configured = CpGoStack(
            config(listOf(issuer.config)), core, database,
            extraEnv = mapOf("PM_CI_OIDC_ISSUERS" to "github=${issuer.url}", "PM_CI_OIDC_AUDIENCE" to CiOidcTestIssuer.AUDIENCE),
        )
        unconfigured = CpGoStack(config(emptyList()), core, database)
    }

    @AfterAll
    fun teardown() {
        if (::configured.isInitialized) configured.close()
        if (::unconfigured.isInitialized) unconfigured.close()
        if (::issuer.isInitialized) issuer.close()
    }

    /** One line per request, `label -> status body`, with tokens and timestamps masked. */
    private class Transcript {
        val lines = mutableListOf<String>()

        suspend fun exchange(
            label: String,
            client: HttpClient,
            body: String?,
            json: Boolean = true,
            vararg headers: Pair<String, String>,
        ) {
            val response = client.post("/api/workload/token") {
                headers.forEach { (k, v) -> header(k, v) }
                if (body != null) {
                    if (json) contentType(ContentType.Application.Json) else contentType(ContentType.Text.Plain)
                    setBody(body)
                }
            }
            lines += "$label -> ${response.status.value} ${response.bodyAsText()}".trimEnd()
                .replace(Regex("""pmw_[A-Za-z0-9_-]+"""), "{token}")
                .replace(Regex(""""expiresAt":"[^"]+""""), """"expiresAt":"{at}"""")
        }
    }

    private fun lastAuditId(): Long = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery("SELECT coalesce(max(id), 0) FROM audit_event").use { rs -> rs.next(); rs.getLong(1) } }
    }

    /** The auth audit rows after [afterId], as `action principal resource outcome channel client_addr | statement | detail`. */
    private fun auditSince(afterId: Long): String = rows(
        """SELECT action, principal, resource, outcome, channel, coalesce(client_addr, ''), statement, coalesce(detail, '')
           FROM audit_event WHERE kind = 'auth' AND id > $afterId ORDER BY id""",
    ) { (1..6).joinToString(" ") { i -> it[i] } + " | ${it[7]} | ${it[8]}" }

    /** The WORKLOAD token rows, as `id kind principal roles name claims ttl revoked`. */
    private fun workloadTokens(): String = rows(
        """SELECT id, kind, principal, roles::text, coalesce(name, '-'), claims::text,
                  extract(epoch FROM expires_at - created_at)::bigint, revoked_at IS NOT NULL
           FROM proxy_token WHERE kind = 'WORKLOAD' ORDER BY id""",
    ) { (1..8).joinToString(" ") { i -> it[i] } }

    private fun rows(sql: String, line: (List<String>) -> String): String = dataSource.connection.use { c ->
        c.createStatement().use { s ->
            s.executeQuery(sql).use { rs ->
                buildList {
                    while (rs.next()) add(line(listOf("") + (1..rs.metaData.columnCount).map { rs.getString(it) }).trimEnd())
                }
            }
        }
    }.joinToString("\n")

    private fun hs256(): String = SignedJWT(JWSHeader.Builder(JWSAlgorithm.HS256).keyID("ci-kid").build(), issuer.claims())
        .apply { sign(MACSigner(ByteArray(32) { 7 })) }.serialize()

    private fun signed(header: JWSHeader, claims: JWTClaimsSet = issuer.claims()): String =
        SignedJWT(header, claims).apply { sign(RSASSASigner(issuer.key)) }.serialize()

    private fun withoutIssuer(): String = issuer.sign(JWTClaimsSet.Builder(issuer.claims()).issuer(null).build())

    @Test
    fun `workload token exchange`() = runBlocking<Unit> {
        val t = Transcript()
        val c = configured.client()
        val before = lastAuditId()

        t.exchange("no body", c, null)
        t.exchange("not json", c, "{")
        t.exchange("text/plain", c, """{"token":"${issuer.sign()}"}""", json = false)
        t.exchange("token missing", c, """{}""")
        t.exchange("token null", c, """{"token":null}""")
        t.exchange("token a number", c, """{"token":5}""")
        t.exchange("token empty", c, """{"token":""}""")
        t.exchange("token blank", c, """{"token":"   "}""")
        t.exchange("malformed", c, """{"token":"not-a-jwt"}""")
        t.exchange("three garbage parts", c, """{"token":"a.b.c"}""")
        t.exchange("untrusted issuer", c, """{"token":"${issuer.sign(issuer.claims(iss = "https://ci.example.com"))}"}""")
        t.exchange("no issuer", c, """{"token":"${withoutIssuer()}"}""")
        t.exchange("forged signature", c, """{"token":"${issuer.sign(signingKey = issuer.impostorKey())}"}""")
        t.exchange("unknown kid", c, """{"token":"${issuer.sign(signingKey = RSAKeyGenerator(2048).keyID("other-kid").generate())}"}""")
        t.exchange("HS256", c, """{"token":"${hs256()}"}""")
        t.exchange("wrong audience", c, """{"token":"${issuer.sign(issuer.claims(aud = "https://other.example.com"))}"}""")
        t.exchange("expired", c, """{"token":"${issuer.sign(issuer.claims(expOffsetSeconds = -120, iatOffsetSeconds = -600))}"}""")
        t.exchange("expired within skew", c, """{"token":"${issuer.sign(issuer.claims(expOffsetSeconds = -30, iatOffsetSeconds = -600, repository = "acme/skew"))}"}""")
        t.exchange("not yet valid", c, """{"token":"${issuer.sign(issuer.claims(nbfOffsetSeconds = 300))}"}""")
        t.exchange("iat in the future", c, """{"token":"${issuer.sign(issuer.claims(iatOffsetSeconds = 300))}"}""")
        t.exchange("no sub", c, """{"token":"${issuer.sign(issuer.claims(sub = null))}"}""")
        t.exchange("no exp or iat", c, """{"token":"${issuer.sign(JWTClaimsSet.Builder(issuer.claims()).expirationTime(null).issueTime(null).build())}"}""")
        t.exchange("no aud", c, """{"token":"${issuer.sign(JWTClaimsSet.Builder(issuer.claims()).audience(null as String?).build())}"}""")
        t.exchange("wrong audience, no sub", c, """{"token":"${issuer.sign(issuer.claims(aud = "https://other.example.com", sub = null))}"}""")
        t.exchange("expired, wrong audience", c, """{"token":"${issuer.sign(issuer.claims(aud = "https://other.example.com", expOffsetSeconds = -120, iatOffsetSeconds = -600))}"}""")
        t.exchange("forged, expired", c, """{"token":"${issuer.sign(issuer.claims(expOffsetSeconds = -120, iatOffsetSeconds = -600), issuer.impostorKey())}"}""")
        t.exchange("typ at+jwt", c, """{"token":"${signed(JWSHeader.Builder(JWSAlgorithm.RS256).keyID("ci-kid").type(JOSEObjectType("at+jwt")).build())}"}""")
        t.exchange("valid, audience list", c, """{"token":"${issuer.sign(JWTClaimsSet.Builder(issuer.claims(repository = "acme/list")).audience(listOf("https://other.example.com", CiOidcTestIssuer.AUDIENCE)).build())}"}""")
        t.exchange("valid, no kid", c, """{"token":"${signed(JWSHeader.Builder(JWSAlgorithm.RS256).build(), issuer.claims(repository = "acme/nokid"))}"}""")
        t.exchange("valid, iat within skew", c, """{"token":"${issuer.sign(issuer.claims(iatOffsetSeconds = 30, repository = "acme/iat"))}"}""")
        t.exchange("valid", c, """{"token":"${issuer.sign()}","ignored":1}""")
        t.exchange("valid, pull request", c, """{"token":"${issuer.sign(issuer.claims(baseRef = "main", repository = null))}"}""")
        t.exchange("valid, forwarded-for ignored", c, """{"token":"${issuer.sign()}"}""", true, "X-Forwarded-For" to "203.0.113.9")
        val debug = configured.client()
        assertEquals(
            HttpStatusCode.OK,
            debug.post("/auth/debug") {
                contentType(ContentType.Application.Json)
                setBody("""{"principal":"ci-user@example.com","requesterIp":"198.51.100.7"}""")
            }.status,
        )
        t.exchange("valid, debug session", debug, """{"token":"${issuer.sign()}"}""")
        val audit = auditSince(before)

        val off = unconfigured.client()
        t.exchange("not configured", off, """{"token":"${issuer.sign()}"}""")
        t.exchange("not configured, blank", off, """{"token":""}""")

        assertEquals(EXPECTED.trimIndent(), t.lines.joinToString("\n"))
        assertEquals(EXPECTED_AUDIT.trimIndent(), audit)
        assertEquals(EXPECTED_TOKENS.trimIndent(), workloadTokens())
        verifyAuditChain(dataSource)
    }

    private companion object {
        const val EXPECTED = """
            no body -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            not json -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            text/plain -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            token missing -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            token null -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            token a number -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            token empty -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            token blank -> 400 {"code":"common.field_required","params":{"fields":"token"}}
            malformed -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            three garbage parts -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            untrusted issuer -> 401 {"code":"workload.issuer_not_trusted","params":{}}
            no issuer -> 401 {"code":"workload.issuer_not_trusted","params":{}}
            forged signature -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            unknown kid -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            HS256 -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            wrong audience -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            expired -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            expired within skew -> 200 {"token":"{token}","id":1,"kind":"WORKLOAD","expiresAt":"{at}"}
            not yet valid -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            iat in the future -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            no sub -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            no exp or iat -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            no aud -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            wrong audience, no sub -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            expired, wrong audience -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            forged, expired -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            typ at+jwt -> 401 {"code":"common.invalid_token","params":{"kind":"ci_oidc"}}
            valid, audience list -> 200 {"token":"{token}","id":2,"kind":"WORKLOAD","expiresAt":"{at}"}
            valid, no kid -> 200 {"token":"{token}","id":3,"kind":"WORKLOAD","expiresAt":"{at}"}
            valid, iat within skew -> 200 {"token":"{token}","id":4,"kind":"WORKLOAD","expiresAt":"{at}"}
            valid -> 200 {"token":"{token}","id":5,"kind":"WORKLOAD","expiresAt":"{at}"}
            valid, pull request -> 200 {"token":"{token}","id":6,"kind":"WORKLOAD","expiresAt":"{at}"}
            valid, forwarded-for ignored -> 200 {"token":"{token}","id":7,"kind":"WORKLOAD","expiresAt":"{at}"}
            valid, debug session -> 200 {"token":"{token}","id":8,"kind":"WORKLOAD","expiresAt":"{at}"}
            not configured -> 404 {"code":"workload.not_configured","params":{}}
            not configured, blank -> 400 {"code":"common.field_required","params":{"fields":"token"}}
        """
        const val EXPECTED_AUDIT = """
            auth.workload.exchange unknown Workload::"-" FAILURE workload 127.0.0.1 | CI OIDC token rejected | malformed
            auth.workload.exchange unknown Workload::"-" FAILURE workload 127.0.0.1 | CI OIDC token rejected | malformed
            auth.workload.exchange unknown Workload::"https://ci.example.com" FAILURE workload 127.0.0.1 | CI OIDC token from an untrusted issuer |
            auth.workload.exchange unknown Workload::"-" FAILURE workload 127.0.0.1 | CI OIDC token from an untrusted issuer |
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | Signed JWT rejected: Invalid signature
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | Signed JWT rejected: Another algorithm expected, or no matching key(s) found
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | Signed JWT rejected: Another algorithm expected, or no matching key(s) found
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT aud claim rejected
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | Expired JWT
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | repository=acme/skew ref=refs/heads/main event_name=push
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT before use time
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | iat in the future
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT missing required claims: [sub]
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT missing required claims: [exp, iat]
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT missing required aud claim
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT aud claim rejected
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JWT aud claim rejected
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | Signed JWT rejected: Invalid signature
            auth.workload.exchange unknown Workload::"github" FAILURE workload 127.0.0.1 | CI OIDC token rejected | JOSE header typ (type) at+jwt not allowed
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | repository=acme/list ref=refs/heads/main event_name=push
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | repository=acme/nokid ref=refs/heads/main event_name=push
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | repository=acme/iat ref=refs/heads/main event_name=push
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | repository=acme/shop ref=refs/heads/main event_name=push
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | ref=refs/heads/main base_ref=main event_name=push
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 127.0.0.1 | Exchanged a CI OIDC token for a workload token | repository=acme/shop ref=refs/heads/main event_name=push
            auth.workload.exchange workload:github Workload::"github" SUCCESS workload 198.51.100.7 | Exchanged a CI OIDC token for a workload token | repository=acme/shop ref=refs/heads/main event_name=push
        """
        const val EXPECTED_TOKENS = """
            1 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/skew"} 900 f
            2 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/list"} 900 f
            3 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/nokid"} 900 f
            4 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/iat"} 900 f
            5 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/shop"} 900 f
            6 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "base_ref": "main", "event_name": "push"} 900 f
            7 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/shop"} 900 f
            8 WORKLOAD workload:github [] - {"ref": "refs/heads/main", "event_name": "push", "repository": "acme/shop"} 900 f
        """
    }
}
