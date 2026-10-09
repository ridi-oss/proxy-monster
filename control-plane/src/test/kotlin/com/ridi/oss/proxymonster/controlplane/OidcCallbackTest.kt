package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.isValidPkceChallenge
import com.ridi.oss.proxymonster.auth.isValidPkceVerifier
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.sun.net.httpserver.HttpServer
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.encodeURLParameter
import io.ktor.http.parseQueryString
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val TEST_SESSION_SECRET = "oidc-callback-test-secret-not-for-prod"

/** The IdP client every rejection row is attributed to — no principal exists before an id_token validates. */
private const val CLIENT_ID = "test-client"

/** The forwarded source address this suite's clients present, and the one every rejection row must carry. */
private const val CALLER_ADDR = "203.0.113.9"

/** Fails to parse, so validation rejects it without ever fetching `jwks_uri`. */
private const val UNPARSEABLE_ID_TOKEN = "not-a-real-jwt"

/**
 * `/auth/oidc/login` and `/auth/oidc/callback` behind cp-go: the CSRF `state` + `nonce` cookies'
 * one-time-use, callback errors, PKCE, and the allowlisted co-hosted OAuth continuation. The IdP is a
 * loopback HTTP double; every scenario fails validation/CSRF before JIT provisioning would run.
 *
 * A rejected callback records a `kind="auth"` FAILURE event, and asserting those rows is how each rejection
 * is told apart from a redirect that merely looks alike.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidcCallbackTest {
    private lateinit var dataSource: DataSource
    private lateinit var database: String
    private lateinit var core: ControlPlaneCore
    private lateinit var idp: HttpServer
    private val tokenForm = AtomicReference<Parameters?>()
    @Volatile private var tokenEndpointFails = false

    /** One cp-go per advertised PKCE variant: cp-go caches the discovery document for its lifetime. */
    private val stacks = mutableMapOf<String, CpGoStack>()

    /** The PKCE methods each issuer path advertises; null omits the field. */
    private val variants = mapOf("none" to null, "s256" to listOf("S256"), "plain" to listOf("plain"), "lower" to listOf("s256"))

    private val idpBase get() = "http://127.0.0.1:${idp.address.port}"

    private fun latestAuditId(): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT COALESCE(MAX(id), 0) FROM audit_event").use { ps ->
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    /**
     * Assert the callback appended exactly one `kind="auth"` row after [sinceId], reading as the full
     * contract requires. A rejection happens before any id_token is validated, so the row is attributed to
     * the IdP client.
     */
    private fun assertOneRejectionRecorded(sinceId: Long, detail: String) {
        val rows = dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT principal, action, resource, outcome, decision, channel, client_addr, detail
                   FROM audit_event WHERE kind='auth' AND id > ? ORDER BY id""",
            ).use { ps ->
                ps.setLong(1, sinceId)
                ps.executeQuery().use { rs -> buildList { while (rs.next()) add((1..8).map(rs::getString)) } }
            }
        }
        assertEquals(
            listOf(
                listOf(
                    AuthAuditRecorder.PRINCIPAL_UNATTRIBUTED,
                    "auth.oidc.login",
                    auditEntity("Client", CLIENT_ID),
                    "FAILURE",
                    "DENY",
                    "oidc",
                    CALLER_ADDR,
                    detail,
                ),
            ),
            rows,
        )
    }

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        database = SharedPostgres.freshDatabase("pm_oidc_callback")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        idp = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/") { ex ->
                val path = ex.requestURI.path
                val variant = path.removePrefix("/").substringBefore('/')
                val (status, body) = when {
                    path.endsWith("/.well-known/openid-configuration") && variant in variants -> {
                        val methods = variants[variant]?.joinToString(",", "[", "]") { "\"$it\"" }
                        200 to """{"issuer":"$idpBase/$variant","authorization_endpoint":"$idpBase/authorize",""" +
                            """"token_endpoint":"$idpBase/$variant/token","jwks_uri":"http://jwks.invalid/keys"""" +
                            (methods?.let { ""","code_challenge_methods_supported":$it""" } ?: "") + "}"
                    }
                    path.endsWith("/token") -> {
                        tokenForm.set(parseQueryString(ex.requestBody.readBytes().decodeToString()))
                        if (tokenEndpointFails) 502 to """{"error":"temporarily_unavailable"}"""
                        else 200 to """{"id_token":"$UNPARSEABLE_ID_TOKEN"}"""
                    }
                    else -> 404 to "{}"
                }
                val bytes = body.toByteArray()
                ex.responseHeaders.add("Content-Type", "application/json")
                ex.sendResponseHeaders(status, bytes.size.toLong())
                ex.responseBody.use { it.write(bytes) }
            }
            start()
        }
    }

    @AfterAll
    fun teardown() {
        stacks.values.forEach { it.close() }
        if (::idp.isInitialized) idp.stop(0)
    }

    @BeforeEach
    fun reset() {
        tokenForm.set(null)
        tokenEndpointFails = false
    }

    private fun config() = Config(
        httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
        sessionSecret = TEST_SESSION_SECRET, oidc = null, resultKey = null, scimToken = null,
        sessionWindowSeconds = 12 * 3600, idpRecheckIntervalSeconds = 600, devMarker = false,
    )

    private fun stack(variant: String?): CpGoStack = stacks.getOrPut(variant ?: "unconfigured") {
        val oidcEnv = variant?.let {
            mapOf(
                "PM_OIDC_ISSUER" to "$idpBase/$it",
                "PM_OIDC_CLIENT_ID" to CLIENT_ID,
                "PM_OIDC_CLIENT_SECRET" to "test-secret",
                "PM_OIDC_REDIRECT_URI" to "https://cp.example.test/auth/oidc/callback",
                "PM_OIDC_SCOPES" to "openid profile email groups offline_access",
            )
        }.orEmpty()
        CpGoStack(config(), core, database, extraEnv = oidcEnv + ("PM_TRUSTED_PROXIES" to "127.0.0.1"))
    }

    /** A cookie-jar client with redirects disabled, so the 3xx responses under test are inspectable directly. */
    private fun client(variant: String? = "none"): HttpClient = stack(variant).client().config {
        install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
    }

    private fun HttpClient.locationState(resp: io.ktor.client.statement.HttpResponse): String =
        parseQueryString(resp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!

    @Test
    fun `unconfigured oidc degrades both routes to 501`() = runBlocking<Unit> {
        val client = client(variant = null)

        assertEquals(HttpStatusCode.NotImplemented, client.get("/auth/oidc/login").status)
        assertEquals(HttpStatusCode.NotImplemented, client.get("/auth/oidc/callback").status)
    }

    @Test
    fun `provider error param redirects to error=oidc`() = runBlocking<Unit> {
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login"))
        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")
        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/login?error=oidc", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "idp_error=access_denied")
    }

    /** The IdP error is caller-chosen; it must be bounded before it reaches a hash-chained, exported row. */
    @Test
    fun `an oversized idp error is truncated before it reaches the trail`() = runBlocking<Unit> {
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login"))
        val before = latestAuditId()
        client.get("/auth/oidc/callback?error=${"a".repeat(5_000)}&state=$realState")

        assertOneRejectionRecorded(before, "idp_error=${"a".repeat(200)}")
    }

    @Test
    fun `a callback with neither code nor error is recorded`() = runBlocking<Unit> {
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login"))
        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?state=$realState")

        assertEquals("/login?error=state", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "missing_code")
    }

    @Test
    fun `a callback whose nonce cookie is gone is recorded`() = runBlocking<Unit> {
        val client = client()

        val loginResp = client.get("/auth/oidc/login")
        val realState = client.locationState(loginResp)
        // Replay the state cookie alone: a cookie-jar client would carry the nonce cookie too.
        val stateCookie = loginResp.headers.getAll(HttpHeaders.SetCookie)!!
            .single { it.startsWith("pm_oauth_state=") }.substringBefore(';')
        val jarless = HttpClient(CIO) {
            expectSuccess = false
            followRedirects = false
            install(DefaultRequest) {
                url(stack("none").baseUrl)
                header("X-Forwarded-For", CALLER_ADDR)
            }
        }
        val before = latestAuditId()
        val resp = jarless.get("/auth/oidc/callback?code=abc&state=$realState") {
            header(HttpHeaders.Cookie, stateCookie)
        }

        assertEquals("/login?error=nonce", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "missing_nonce")
    }

    @Test
    fun `a failed token exchange is recorded`() = runBlocking<Unit> {
        tokenEndpointFails = true
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login"))
        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?code=abc&state=$realState")

        assertEquals("/login?error=oidc", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "token_exchange_failed")
    }

    @Test
    fun `provider error preserves the popup reauth continuation`() = runBlocking<Unit> {
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login?return_to=%2Fauth%2Freauth-complete"))
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals(
            "/login?error=oidc&callbackUrl=%2Fauth%2Freauth-complete",
            resp.headers[HttpHeaders.Location],
        )
    }

    @Test
    fun `state failure preserves the popup reauth continuation`() = runBlocking<Unit> {
        val client = client()

        client.get("/auth/oidc/login?return_to=%2Fauth%2Freauth-complete")
        val resp = client.get("/auth/oidc/callback?code=abc&state=wrong-state")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals(
            "/login?error=state&callbackUrl=%2Fauth%2Freauth-complete",
            resp.headers[HttpHeaders.Location],
        )
    }

    @Test
    fun `provider error returns to the co-hosted OAuth resume route`() = runBlocking<Unit> {
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login?return_to=%2Foauth%2Fresume"))
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/oauth/resume?error=access_denied", resp.headers[HttpHeaders.Location])
    }

    @Test
    fun `OIDC continuation accepts only fixed auth and device routes`() = runBlocking<Unit> {
        assertEquals("/oauth/resume", oidcReturnTarget("/oauth/resume"))
        assertEquals("/auth/reauth-complete", oidcReturnTarget("/auth/reauth-complete"))
        assertEquals("/device", oidcReturnTarget("/device"))
        assertEquals("/device?user_code=ABCD-EFGH", oidcReturnTarget("/device?user_code=ABCD-EFGH"))
        assertNull(oidcReturnTarget("/auth/device/authorize?user_code=ABCD-EFGH"))
        assertNull(oidcReturnTarget("https://evil.example/device"))
        assertNull(oidcReturnTarget("//evil.example/device"))
        assertNull(oidcReturnTarget("/device/other"))
        assertNull(oidcReturnTarget("/device?foo=bar"))
        assertNull(oidcReturnTarget("/device?user_code=ABCD-EFGH&next=https://evil.example"))
        assertNull(oidcReturnTarget("/auth/device/authorize?user_code=ABCD-EFGH&extra=x"))
        assertNull(oidcReturnTarget("/other"))
        assertNull(oidcReturnTarget("/"))
    }

    /** The continuation a login kept for [returnTo], read off the redirect its failed callback answers. */
    private suspend fun oidcReturnTarget(returnTo: String): String? {
        val client = client()
        val state = client.locationState(client.get("/auth/oidc/login?return_to=${returnTo.encodeURLParameter()}"))
        val location = client.get("/auth/oidc/callback?error=access_denied&state=$state").headers[HttpHeaders.Location]!!
        if (location.startsWith("/oauth/resume?")) return "/oauth/resume"
        return parseQueryString(location.substringAfter('?')).let { it["callbackUrl"] ?: it["return_to"] }
    }

    @Test
    fun `state mismatch redirects to error=state, and the state cookie is one-time-use`() = runBlocking<Unit> {
        val client = client()

        val loginResp = client.get("/auth/oidc/login")
        assertEquals(HttpStatusCode.Found, loginResp.status)
        val realState = client.locationState(loginResp)

        val before = latestAuditId()
        val wrongResp = client.get("/auth/oidc/callback?code=abc&state=not-the-real-state")
        assertEquals(HttpStatusCode.Found, wrongResp.status)
        assertEquals("/login?error=state", wrongResp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "invalid_state")

        // The original, correct state now also fails: the cookie is gone, not just the string compared.
        val replayResp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals("/login?error=state", replayResp.headers[HttpHeaders.Location])
    }

    @Test
    fun `invalid id_token redirects to error=nonce, and the nonce cookie is one-time-use`() = runBlocking<Unit> {
        val client = client()

        val realState = client.locationState(client.get("/auth/oidc/login"))

        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/login?error=nonce", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "invalid_id_token")

        val replayResp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals("/login?error=state", replayResp.headers[HttpHeaders.Location])
    }

    @Test
    fun `a challenge is sent when the IdP advertises S256`() = runBlocking<Unit> {
        val query = client("s256").authorizeQuery()
        assertEquals("S256", query["code_challenge_method"])
        assertTrue(isValidPkceChallenge(query["code_challenge"]!!))
    }

    @Test
    fun `no challenge is sent when the IdP advertises no PKCE methods`() = runBlocking<Unit> {
        val query = client("none").authorizeQuery()
        assertNull(query["code_challenge"])
        assertNull(query["code_challenge_method"])
    }

    @Test
    fun `no challenge is sent when the IdP advertises only plain`() = runBlocking<Unit> {
        val query = client("plain").authorizeQuery()
        assertNull(query["code_challenge"])
        assertNull(query["code_challenge_method"])
    }

    @Test
    fun `S256 is matched case-insensitively`() = runBlocking<Unit> {
        assertEquals("S256", client("lower").authorizeQuery()["code_challenge_method"])
    }

    @Test
    fun `the challenge is the S256 hash of the verifier presented at the token endpoint`() = runBlocking<Unit> {
        val client = client("s256")

        val query = client.authorizeQuery()
        client.get("/auth/oidc/callback?code=abc&state=${query["state"]}")

        // What the IdP was shown must be the hash of what it is later told.
        val verifier = tokenForm.get()!!["code_verifier"]!!
        assertTrue(isValidPkceVerifier(verifier))
        assertEquals(query["code_challenge"], pkceS256(verifier))
    }

    @Test
    fun `no verifier is sent to a token endpoint that never issued a challenge`() = runBlocking<Unit> {
        val client = client("none")

        val query = client.authorizeQuery()
        client.get("/auth/oidc/callback?code=abc&state=${query["state"]}")

        // Absent, not blank: an empty code_verifier is itself a protocol error.
        assertNull(tokenForm.get()!!["code_verifier"])
    }

    @Test
    fun `the verifier cookie is one-time-use`() = runBlocking<Unit> {
        val client = client("s256")

        val query = client.authorizeQuery()
        client.get("/auth/oidc/callback?code=abc&state=${query["state"]}")
        assertNotNull(tokenForm.get()!!["code_verifier"])

        val second = client.authorizeQuery()
        assertTrue(second["code_challenge"] != query["code_challenge"])
    }

    /** The authorize parameters the login redirected to, lifted off the 302. */
    private suspend fun HttpClient.authorizeQuery(path: String = "/auth/oidc/login"): Parameters {
        val resp = get(path)
        assertEquals(HttpStatusCode.Found, resp.status)
        return parseQueryString(resp.headers[HttpHeaders.Location]!!.substringAfter('?'))
    }
}
