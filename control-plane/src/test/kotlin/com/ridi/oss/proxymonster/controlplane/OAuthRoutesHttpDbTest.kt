package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.sha256Hex
import com.ridi.oss.proxymonster.controlplane.management.McpCapabilityRegistry
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.verifyAuditChain
import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/**
 * The MCP OAuth routes that need no client metadata fetch, over HTTP: discovery, the requests refused before a
 * fetch, the token and revoke endpoints against codes written here, and the consent list and revoke.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OAuthRoutesHttpDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var cpGo: CpGoStack
    private lateinit var core: ControlPlaneCore

    private val user = "oauth-user@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_oauth_routes_http")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "oauth-routes-http-secret-of-32-chars", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
            mcpResource = RESOURCE, mcpAccessTtlSeconds = 600, mcpRefreshTtlSeconds = 3600,
        )
        val sessions = PrincipalSessionStore(dataSource, null)
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    /** One line per request, `METHOD path -> status body`, with tokens and timestamps masked. */
    private class Transcript(private val client: HttpClient) {
        val lines = mutableListOf<String>()

        suspend fun record(label: String, response: HttpResponse): String {
            val body = response.bodyAsText()
            val cache = response.headers[HttpHeaders.CacheControl]?.let { " [cache-control: $it]" }.orEmpty()
            lines += "$label -> ${response.status.value}$cache $body".trimEnd().replace(Regex("""pm[ar]_[A-Za-z0-9_-]+"""), "{token}")
                .replace(Regex(""""(createdAt|updatedAt)":"[^"]+""""), """"$1":"{at}"""")
            return body
        }

        suspend fun get(path: String, vararg header: Pair<String, String>) =
            record("GET $path", client.get(path) { header.forEach { (k, v) -> header(k, v) } })

        suspend fun form(path: String, vararg fields: Pair<String, String>) =
            record("POST $path ${fields.joinToString("&") { "${it.first}=${it.second.take(12)}" }}", client.submitForm(path, Parameters.build {
                fields.forEach { (k, v) -> append(k, v) }
            }))

        suspend fun delete(path: String, csrf: String) = record("DELETE $path", client.delete(path) { header("X-PM-CSRF", csrf) })
    }

    /** A live consent for [user] and an unused code under it, as /oauth/authorize leaves them. */
    private fun code(code: String): Long = dataSource.connection.use { c ->
        val consent = c.prepareStatement(
            """INSERT INTO oauth_consent (principal, client_id, resource, scope) VALUES (?, ?, ?, 'mcp:read')
               ON CONFLICT (principal, client_id, resource, scope) WHERE revoked_at IS NULL DO UPDATE SET updated_at = now()
               RETURNING id""",
        ).use { ps ->
            ps.setString(1, user); ps.setString(2, CLIENT_ID); ps.setString(3, RESOURCE)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        c.prepareStatement(
            """INSERT INTO oauth_authorization_code
               (code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge, expires_at, consent_id)
               VALUES (?, ?, ?, ?, ?, 'mcp:read', ?, now() + interval '5 minutes', ?)""",
        ).use { ps ->
            ps.setString(1, sha256Hex(code)); ps.setString(2, CLIENT_ID); ps.setString(3, user); ps.setString(4, REDIRECT_URI)
            ps.setString(5, RESOURCE); ps.setString(6, CHALLENGE); ps.setLong(7, consent)
            ps.executeUpdate()
        }
        consent
    }

    private fun lastAuditId(): Long = dataSource.connection.use { c ->
        c.createStatement().use { s -> s.executeQuery("SELECT coalesce(max(id), 0) FROM audit_event").use { rs -> rs.next(); rs.getLong(1) } }
    }

    /** The auth audit rows written after [afterId], as `action principal resource outcome channel | statement | detail`. */
    private fun auditSince(afterId: Long): String = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT action, principal, resource, outcome, channel, coalesce(client_addr, ''), statement, coalesce(detail, '')
               FROM audit_event WHERE kind = 'auth' AND id > ? ORDER BY id""",
        ).use { ps ->
            ps.setLong(1, afterId)
            ps.executeQuery().use { rs ->
                buildList {
                    while (rs.next()) {
                        add(((1..5).joinToString(" ") { rs.getString(it) } + " ${rs.getString(6)} | ${rs.getString(7)} | ${rs.getString(8)}").trimEnd())
                    }
                }
            }
        }
    }.joinToString("\n").replace(Regex("""Token::"\d+""""), """Token::"{id}"""")

    private fun tokenGrant(code: String, verifier: String = VERIFIER, resource: String = RESOURCE) = arrayOf(
        "grant_type" to "authorization_code", "code" to code, "client_id" to CLIENT_ID, "redirect_uri" to REDIRECT_URI,
        "resource" to resource, "code_verifier" to verifier,
    )

    @Test
    fun `oauth routes`() = runBlocking<Unit> {
        val anon = Transcript(cpGo.client())
        val signedIn = cpGo.client()
        assertEquals(HttpStatusCode.NoContent, signedIn.post("/test/session/$user").status)
        val t = Transcript(signedIn)
        val before = lastAuditId()

        val discovery = anon.get("/.well-known/oauth-authorization-server")
        val scopes = Regex(""""scopes_supported":\[([^]]*)]""").find(discovery)!!.groupValues[1].split(",").map { it.trim('"') }
        assertEquals(McpCapabilityRegistry.supportedScopes.toList(), scopes)
        anon.get("/oauth/authorize")
        val authorize = "/oauth/authorize?response_type=code&client_id=https%3A%2F%2F127.0.0.1%3A1%2Fclient.json" +
            "&redirect_uri=http%3A%2F%2F127.0.0.1%3A43110%2Fcallback&state=s&resource=" + RESOURCE.encodeURLParameter() +
            "&code_challenge=$CHALLENGE&principal=p"
        anon.get("$authorize&code_challenge_method=S256&scope=mcp%3Aread+mcp%3Aadmin")
        anon.get("$authorize&code_challenge_method=plain&scope=mcp%3Aread")
        anon.get("$authorize&code_challenge_method=S256&scope=mcp%3Aread")
        anon.get("/oauth/resume")
        anon.get("/oauth/resume?error=access_denied")
        anon.get("/oauth/pending")
        anon.form("/oauth/consent", "csrf" to "x", "decision" to "approve")

        anon.form("/oauth/token", "grant_type" to "password")
        anon.form("/oauth/token", "grant_type" to "authorization_code", "code" to "c", "client_id" to CLIENT_ID)
        anon.form("/oauth/token", "grant_type" to "refresh_token", "client_id" to CLIENT_ID)
        val consent = code("pmc_first")
        anon.form("/oauth/token", *tokenGrant("pmc_first", verifier = "w".repeat(43)))
        anon.form("/oauth/token", *tokenGrant("pmc_first", resource = "$RESOURCE/other"))
        val first = anon.form("/oauth/token", *tokenGrant("pmc_first"))
        anon.form("/oauth/token", *tokenGrant("pmc_first"))
        val firstAccess = Regex(""""access_token":"([^"]+)"""").find(first)!!.groupValues[1]
        assertEquals(user, core.mcpTokenStore.resolveAccess(firstAccess, RESOURCE)?.principal, "the MCP server accepts the issued token")
        val refresh = Regex(""""refresh_token":"([^"]+)"""").find(first)!!.groupValues[1]
        val rotated = anon.form("/oauth/token", "grant_type" to "refresh_token", "refresh_token" to refresh, "client_id" to CLIENT_ID, "resource" to RESOURCE)
        anon.form("/oauth/token", "grant_type" to "refresh_token", "refresh_token" to Regex(""""refresh_token":"([^"]+)"""").find(rotated)!!.groupValues[1],
            "client_id" to "https://other.example/c.json", "resource" to RESOURCE)
        anon.form("/oauth/token", "grant_type" to "refresh_token", "refresh_token" to refresh, "client_id" to CLIENT_ID, "resource" to RESOURCE)

        code("pmc_second")
        val second = anon.form("/oauth/token", *tokenGrant("pmc_second"))
        anon.form("/oauth/revoke", "token" to "pma_bogus")
        anon.form("/oauth/revoke")
        val access = Regex(""""access_token":"([^"]+)"""").find(second)!!.groupValues[1]
        anon.form("/oauth/revoke", "token" to access)
        anon.form("/oauth/revoke", "token" to access)
        anon.form("/oauth/revoke", "token" to Regex(""""refresh_token":"([^"]+)"""").find(second)!!.groupValues[1])

        anon.get("/oauth/consents")
        anon.delete("/oauth/consents/$consent", "x")
        val listed = t.get("/oauth/consents")
        val csrf = Regex(""""csrfToken":"([^"]+)"""").find(listed)!!.groupValues[1]
        t.delete("/oauth/consents/$consent", "wrong")
        t.delete("/oauth/consents/abc", csrf)
        t.delete("/oauth/consents/$consent", csrf)
        t.delete("/oauth/consents/$consent", csrf)
        t.get("/oauth/consents")

        assertEquals(EXPECTED.trimIndent(), (anon.lines + t.lines).joinToString("\n"))
        assertEquals(EXPECTED_AUDIT.trimIndent(), auditSince(before))
        verifyAuditChain(dataSource)
    }

    private fun String.encodeURLParameter() = java.net.URLEncoder.encode(this, Charsets.UTF_8)

    private companion object {
        const val RESOURCE = "http://control-plane.local/mcp"
        const val CLIENT_ID = "https://client.example/client.json"
        const val REDIRECT_URI = "http://127.0.0.1:43110/callback"
        val VERIFIER = "v".repeat(43)
        const val CHALLENGE = "7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM"

        const val EXPECTED = """
            GET /.well-known/oauth-authorization-server -> 200 {"issuer":"http://control-plane.local","authorization_endpoint":"http://control-plane.local/oauth/authorize","token_endpoint":"http://control-plane.local/oauth/token","revocation_endpoint":"http://control-plane.local/oauth/revoke","response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"scopes_supported":["mcp:approvals:write","mcp:datasources:write","mcp:identity:write","mcp:policies:write","mcp:query","mcp:read","mcp:tokens"],"client_id_metadata_document_supported":true}
            GET /oauth/authorize -> 400 [cache-control: no-store] {"error":"invalid_request"}
            GET /oauth/authorize?response_type=code&client_id=https%3A%2F%2F127.0.0.1%3A1%2Fclient.json&redirect_uri=http%3A%2F%2F127.0.0.1%3A43110%2Fcallback&state=s&resource=http%3A%2F%2Fcontrol-plane.local%2Fmcp&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&principal=p&code_challenge_method=S256&scope=mcp%3Aread+mcp%3Aadmin -> 400 [cache-control: no-store] {"error":"invalid_request"}
            GET /oauth/authorize?response_type=code&client_id=https%3A%2F%2F127.0.0.1%3A1%2Fclient.json&redirect_uri=http%3A%2F%2F127.0.0.1%3A43110%2Fcallback&state=s&resource=http%3A%2F%2Fcontrol-plane.local%2Fmcp&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&principal=p&code_challenge_method=plain&scope=mcp%3Aread -> 400 [cache-control: no-store] {"error":"invalid_request"}
            GET /oauth/authorize?response_type=code&client_id=https%3A%2F%2F127.0.0.1%3A1%2Fclient.json&redirect_uri=http%3A%2F%2F127.0.0.1%3A43110%2Fcallback&state=s&resource=http%3A%2F%2Fcontrol-plane.local%2Fmcp&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&principal=p&code_challenge_method=S256&scope=mcp%3Aread -> 400 [cache-control: no-store] {"error":"invalid_client"}
            GET /oauth/resume -> 400 [cache-control: no-store] {"error":"invalid_request"}
            GET /oauth/resume?error=access_denied -> 400 [cache-control: no-store] {"error":"invalid_request"}
            GET /oauth/pending -> 400 [cache-control: no-store] {"error":"invalid_request"}
            POST /oauth/consent csrf=x&decision=approve -> 400 [cache-control: no-store] {"error":"invalid_request"}
            POST /oauth/token grant_type=password -> 400 [cache-control: no-store] {"error":"unsupported_grant_type"}
            POST /oauth/token grant_type=authorizatio&code=c&client_id=https://clie -> 400 [cache-control: no-store] {"error":"invalid_request"}
            POST /oauth/token grant_type=refresh_toke&client_id=https://clie -> 400 [cache-control: no-store] {"error":"invalid_request"}
            POST /oauth/token grant_type=authorizatio&code=pmc_first&client_id=https://clie&redirect_uri=http://127.0&resource=http://contr&code_verifier=wwwwwwwwwwww -> 400 [cache-control: no-store] {"error":"invalid_grant"}
            POST /oauth/token grant_type=authorizatio&code=pmc_first&client_id=https://clie&redirect_uri=http://127.0&resource=http://contr&code_verifier=vvvvvvvvvvvv -> 400 [cache-control: no-store] {"error":"invalid_grant"}
            POST /oauth/token grant_type=authorizatio&code=pmc_first&client_id=https://clie&redirect_uri=http://127.0&resource=http://contr&code_verifier=vvvvvvvvvvvv -> 200 [cache-control: no-store] {"access_token":"{token}","token_type":"Bearer","expires_in":600,"refresh_token":"{token}","scope":"mcp:read"}
            POST /oauth/token grant_type=authorizatio&code=pmc_first&client_id=https://clie&redirect_uri=http://127.0&resource=http://contr&code_verifier=vvvvvvvvvvvv -> 400 [cache-control: no-store] {"error":"invalid_grant"}
            POST /oauth/token grant_type=refresh_toke&refresh_token={token}&client_id=https://clie&resource=http://contr -> 200 [cache-control: no-store] {"access_token":"{token}","token_type":"Bearer","expires_in":600,"refresh_token":"{token}","scope":"mcp:read"}
            POST /oauth/token grant_type=refresh_toke&refresh_token={token}&client_id=https://othe&resource=http://contr -> 400 [cache-control: no-store] {"error":"invalid_grant"}
            POST /oauth/token grant_type=refresh_toke&refresh_token={token}&client_id=https://clie&resource=http://contr -> 400 [cache-control: no-store] {"error":"invalid_grant"}
            POST /oauth/token grant_type=authorizatio&code=pmc_second&client_id=https://clie&redirect_uri=http://127.0&resource=http://contr&code_verifier=vvvvvvvvvvvv -> 200 [cache-control: no-store] {"access_token":"{token}","token_type":"Bearer","expires_in":600,"refresh_token":"{token}","scope":"mcp:read"}
            POST /oauth/revoke token={token} -> 200 [cache-control: no-store] {}
            POST /oauth/revoke  -> 200 [cache-control: no-store] {}
            POST /oauth/revoke token={token} -> 200 [cache-control: no-store] {}
            POST /oauth/revoke token={token} -> 200 [cache-control: no-store] {}
            POST /oauth/revoke token={token} -> 200 [cache-control: no-store] {}
            GET /oauth/consents -> 401 [cache-control: no-store] {"error":"login_required"}
            DELETE /oauth/consents/1 -> 401 [cache-control: no-store] {"error":"login_required"}
            GET /oauth/consents -> 200 [cache-control: no-store] {"consents":[{"id":1,"principal":"oauth-user@example.com","clientId":"https://client.example/client.json","resource":"http://control-plane.local/mcp","scope":"mcp:read","createdAt":"{at}","updatedAt":"{at}"}],"csrfToken":"Bw2KaxfujSfspm6-heK34aaSdY6utRYwAEEoNWd_6Pg"}
            DELETE /oauth/consents/1 -> 400 [cache-control: no-store] {"error":"invalid_request"}
            DELETE /oauth/consents/abc -> 400 [cache-control: no-store] {"error":"invalid_request"}
            DELETE /oauth/consents/1 -> 204 [cache-control: no-store]
            DELETE /oauth/consents/1 -> 404 [cache-control: no-store] {"error":"invalid_request"}
            GET /oauth/consents -> 200 [cache-control: no-store] {"consents":[],"csrfToken":"Bw2KaxfujSfspm6-heK34aaSdY6utRYwAEEoNWd_6Pg"}
        """
        const val EXPECTED_AUDIT = """
            auth.oauth.token unknown Client::"https://client.example/client.json" FAILURE oauth 127.0.0.1 | OAuth token grant denied | grant_type=authorization_code
            auth.oauth.token unknown Client::"https://client.example/client.json" FAILURE oauth 127.0.0.1 | OAuth token grant denied | grant_type=authorization_code
            auth.oauth.token unknown Client::"https://client.example/client.json" SUCCESS oauth 127.0.0.1 | OAuth token granted to client https://client.example/client.json | grant_type=authorization_code
            auth.oauth.token unknown Client::"https://client.example/client.json" FAILURE oauth 127.0.0.1 | OAuth token grant denied | grant_type=authorization_code
            auth.oauth.token unknown Client::"https://client.example/client.json" SUCCESS oauth 127.0.0.1 | OAuth token granted to client https://client.example/client.json | grant_type=refresh_token
            auth.oauth.token unknown Client::"https://other.example/c.json" FAILURE oauth 127.0.0.1 | OAuth token grant denied | grant_type=refresh_token
            auth.oauth.revoke unknown Token::"{id}" SUCCESS oauth 127.0.0.1 | OAuth refresh family revoked on replay | grant_type=refresh_token
            auth.oauth.token unknown Client::"https://client.example/client.json" FAILURE oauth 127.0.0.1 | OAuth token grant denied | grant_type=refresh_token
            auth.oauth.token unknown Client::"https://client.example/client.json" SUCCESS oauth 127.0.0.1 | OAuth token granted to client https://client.example/client.json | grant_type=authorization_code
            auth.oauth.revoke unknown Token::"{id}" SUCCESS oauth 127.0.0.1 | OAuth token revoked |
            auth.oauth.revoke unknown Token::"{id}" SUCCESS oauth 127.0.0.1 | OAuth token revoked |
            auth.oauth.revoke oauth-user@example.com Consent::"1" SUCCESS oauth 127.0.0.1 | OAuth consent revoked |
        """
    }
}
