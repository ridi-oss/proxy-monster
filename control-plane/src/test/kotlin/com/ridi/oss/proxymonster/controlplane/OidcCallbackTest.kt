package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.auth.isValidPkceChallenge
import com.ridi.oss.proxymonster.auth.isValidPkceVerifier
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.parseQueryString
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.routing.get as serverGet
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.cookie
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.Logger
import org.slf4j.LoggerFactory
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

/**
 * Syntactically-invalid `id_token` — [IdTokenValidator.validate] fails to even parse it, so it
 * returns `null` **without ever fetching `jwks_uri`**. That's exactly what lets this suite exercise
 * the real [OidcDiscovery] + [IdTokenValidator] (not stand-ins) with zero real-network/signing
 * infrastructure: real JWKS/signature integration is verified manually against Okta
 * (docs/auth-model.md), not by this automated suite.
 */
private const val UNPARSEABLE_ID_TOKEN = "not-a-real-jwt"

/**
 * [oidcRoutes] exercised through a real Ktor test host: the CSRF `state` + `nonce` cookies'
 * one-time-use, callback errors, and the allowlisted co-hosted OAuth continuation. The IdP side
 * (discovery document + token endpoint) is a tiny double colocated in the same test application so
 * it's reachable via relative URLs through the in-process test client — no real sockets, and no real
 * signing keys needed since every scenario here fails validation/CSRF *before* JIT provisioning
 * would run.
 *
 * The store is nonetheless a real database: a rejected callback records a `kind="auth"` FAILURE event,
 * and asserting those rows is how each rejection is told apart from a redirect that merely looks alike.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidcCallbackTest {
    private val log = LoggerFactory.getLogger(OidcCallbackTest::class.java)
    private lateinit var dataSource: DataSource
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var roleResolver: RoleResolver

    /** The newest audit row's id, so an assertion can scope itself to what a single request appended —
     *  the whole class shares one database and several branches produce the same `detail`. */
    private fun latestAuditId(): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT COALESCE(MAX(id), 0) FROM audit_event").use { ps ->
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    /**
     * Assert the callback appended exactly one `kind="auth"` row after [sinceId], reading as the full
     * contract requires: a count alone would still pass with the action, channel, attribution, resource, or
     * requester address wrong, and those are what make the row usable.
     *
     * A rejection happens before any id_token is validated, so there is no principal to name and the row is
     * attributed to the IdP client instead. [OidcWebSessionDbTest] covers the one branch that DOES name a
     * principal (a login refused for having no effective roles).
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
                    AuthAuditRecorder.ACTION_OIDC_LOGIN,
                    auditEntity("Client", CLIENT_ID),
                    "FAILURE",
                    "DENY",
                    AuthAuditRecorder.CHANNEL_OIDC,
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
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_oidc_callback"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        userGroupStore = UserGroupStore(dataSource)
        roleResolver = RoleResolver(dataSource, userGroupStore, AccessStore(dataSource))
    }

    private fun testConfig(oidcConfigured: Boolean = true): Config = Config(
        httpPort = 0,
        dbUrl = "unused",
        dbUser = "unused",
        dbPassword = "unused",
        authDebug = false,
        secretToken = null,
        sessionSecret = TEST_SESSION_SECRET,
        oidc = if (oidcConfigured) {
            OidcConfig(
                issuer = "",
                clientId = CLIENT_ID,
                clientSecret = "test-secret",
                redirectUri = "https://cp.example.test/auth/oidc/callback",
                scopes = "openid profile email groups offline_access",
                groupMapping = OidcGroupMapping(emptyMap(), null),
            )
        } else {
            null
        },
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 12 * 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = false,
        // The Ktor test host's socket peer, trusted as an edge so the client's X-Forwarded-For resolves to
        // [CALLER_ADDR] — the requester address every rejection row is asserted to carry.
        trustedProxies = setOf("localhost"),
    )

    /**
     * Wires the real [oidcRoutes] plus a fake-IdP double (discovery + token endpoint, both relative
     * paths served by this SAME test app) and returns a cookie-jar-aware client with redirects
     * disabled, so the 3xx responses under test are inspectable directly instead of being silently
     * followed.
     */
    private fun ApplicationTestBuilder.wireOidc(
        config: Config,
        pkceMethods: List<String>? = null,
        tokenForm: AtomicReference<Parameters>? = null,
        tokenEndpointFails: Boolean = false,
    ): HttpClient {
        // The client oidcRoutes/OidcDiscovery use for their OWN outbound calls (discovery fetch +
        // token exchange) — bound to this test app's in-process engine, so "/.well-known/..." and
        // "/token" below resolve without a real socket.
        val internalHttp = createClient {
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        val discovery = config.oidc?.let { OidcDiscovery(internalHttp, it.issuer) }
        val validator = discovery?.let { IdTokenValidator(it, config.oidc!!.issuer, config.oidc!!.clientId) }

        // A top-level `Application.()` extension (below) rather than inlined here: nested directly in
        // this `ApplicationTestBuilder` extension function, plain `install(...)` calls are ambiguous
        // between `Application.install` and `TestApplicationBuilder.install` (both are implicit
        // receivers in scope) — pulling the app setup out to its own receiver scope, matching how
        // Application.module itself is structured, resolves it unambiguously.
        application {
            installOidcTestApp(
                config, discovery, validator, internalHttp, dataSource, userGroupStore, roleResolver, log,
                pkceMethods, tokenForm, tokenEndpointFails,
            )
        }

        return createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
            install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
        }
    }

    @Test
    fun `OIDC continuation accepts only the co-hosted resume and reauth routes`() {
        assertEquals("/oauth/resume", oidcReturnTarget("/oauth/resume"))
        assertEquals("/auth/reauth-complete", oidcReturnTarget("/auth/reauth-complete"))
        assertNull(oidcReturnTarget("https://evil.example/callback"))
        assertNull(oidcReturnTarget("//evil.example/callback"))
        assertNull(oidcReturnTarget("/other"))
        assertNull(oidcReturnTarget("/"))
    }

    @Test
    fun `unconfigured oidc degrades both routes to 501`() = testApplication {
        val client = wireOidc(testConfig(oidcConfigured = false))

        assertEquals(HttpStatusCode.NotImplemented, client.get("/auth/oidc/login").status)
        assertEquals(HttpStatusCode.NotImplemented, client.get("/auth/oidc/callback").status)
    }

    @Test
    fun `provider error param redirects to error=oidc`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")
        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/login?error=oidc", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "idp_error=access_denied")
    }

    /**
     * The IdP error is a caller-chosen query parameter — `/auth/oidc/login` is open, so a self-minted state
     * reaches this branch with any value. It must be bounded before it reaches a hash-chained, SIEM-exported
     * row, or an unauthenticated caller decides how much of the trail each attempt consumes.
     */
    @Test
    fun `an oversized idp error is truncated before it reaches the trail`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val before = latestAuditId()
        client.get("/auth/oidc/callback?error=${"a".repeat(5_000)}&state=$realState")

        assertOneRejectionRecorded(before, "idp_error=${"a".repeat(200)}")
    }

    @Test
    fun `a callback with neither code nor error is recorded`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?state=$realState")

        assertEquals("/login?error=state", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "missing_code")
    }

    @Test
    fun `a callback whose nonce cookie is gone is recorded`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        // Replay the state cookie alone, without the nonce one: state then validates and the absent nonce is
        // what rejects the callback, which is the branch under test. A cookie-jar client would carry both.
        val stateCookie = loginResp.headers.getAll(HttpHeaders.SetCookie)!!
            .single { it.startsWith("$OAUTH_STATE_COOKIE=") }.substringBefore(';')
        val jarless = createClient {
            expectSuccess = false
            followRedirects = false
            install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
        }
        val before = latestAuditId()
        val resp = jarless.get("/auth/oidc/callback?code=abc&state=$realState") {
            header(HttpHeaders.Cookie, stateCookie)
        }

        assertEquals("/login?error=nonce", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "missing_nonce")
    }

    @Test
    fun `a failed token exchange is recorded`() = testApplication {
        val client = wireOidc(testConfig(), tokenEndpointFails = true)

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?code=abc&state=$realState")

        assertEquals("/login?error=oidc", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "token_exchange_failed")
    }

    @Test
    fun `provider error preserves the popup reauth continuation`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login?return_to=%2Fauth%2Freauth-complete")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals(
            "/login?error=oidc&callbackUrl=%2Fauth%2Freauth-complete",
            resp.headers[HttpHeaders.Location],
        )
    }

    @Test
    fun `state failure preserves the popup reauth continuation`() = testApplication {
        val client = wireOidc(testConfig())

        client.get("/auth/oidc/login?return_to=%2Fauth%2Freauth-complete")
        val resp = client.get("/auth/oidc/callback?code=abc&state=wrong-state")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals(
            "/login?error=state&callbackUrl=%2Fauth%2Freauth-complete",
            resp.headers[HttpHeaders.Location],
        )
    }

    @Test
    fun `provider error returns to the co-hosted OAuth resume route`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login?return_to=%2Foauth%2Fresume")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/oauth/resume?error=access_denied", resp.headers[HttpHeaders.Location])
    }

    @Test
    fun `state mismatch redirects to error=state, and the state cookie is one-time-use`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        assertEquals(HttpStatusCode.Found, loginResp.status)
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!

        // Wrong state -> rejected; per the clear-regardless idiom, the cookie is burned either way.
        val before = latestAuditId()
        val wrongResp = client.get("/auth/oidc/callback?code=abc&state=not-the-real-state")
        assertEquals(HttpStatusCode.Found, wrongResp.status)
        assertEquals("/login?error=state", wrongResp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "invalid_state")

        // Replaying with the ORIGINAL, correct state now also fails — proves one-time-use (the
        // cookie is gone), not just that the string comparison rejects a bad value.
        val replayResp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals("/login?error=state", replayResp.headers[HttpHeaders.Location])
    }

    @Test
    fun `invalid id_token redirects to error=nonce, and the nonce cookie is one-time-use`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!

        val before = latestAuditId()
        val resp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/login?error=nonce", resp.headers[HttpHeaders.Location])
        assertOneRejectionRecorded(before, "invalid_id_token")

        // The state (and nonce) cookies were cleared on this first attempt regardless of outcome —
        // a replay of the same, originally-valid state now hits the (now-empty) state guard.
        val replayResp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals("/login?error=state", replayResp.headers[HttpHeaders.Location])
    }

    @Test
    fun `a challenge is sent when the IdP advertises S256`() = testApplication {
        val client = wireOidc(testConfig(), pkceMethods = listOf("S256"))

        val query = client.authorizeQuery()
        assertEquals("S256", query["code_challenge_method"])
        assertTrue(isValidPkceChallenge(query["code_challenge"]!!))
    }

    @Test
    fun `no challenge is sent when the IdP advertises no PKCE methods`() = testApplication {
        val client = wireOidc(testConfig())

        val query = client.authorizeQuery()
        assertNull(query["code_challenge"])
        assertNull(query["code_challenge_method"])
    }

    @Test
    fun `no challenge is sent when the IdP advertises only plain`() = testApplication {
        val client = wireOidc(testConfig(), pkceMethods = listOf("plain"))

        val query = client.authorizeQuery()
        assertNull(query["code_challenge"])
        assertNull(query["code_challenge_method"])
    }

    @Test
    fun `S256 is matched case-insensitively`() = testApplication {
        val client = wireOidc(testConfig(), pkceMethods = listOf("s256"))

        assertEquals("S256", client.authorizeQuery()["code_challenge_method"])
    }

    @Test
    fun `the challenge is the S256 hash of the verifier presented at the token endpoint`() = testApplication {
        val tokenForm = AtomicReference<Parameters>()
        val client = wireOidc(testConfig(), pkceMethods = listOf("S256"), tokenForm = tokenForm)

        val query = client.authorizeQuery()
        client.get("/auth/oidc/callback?code=abc&state=${query["state"]}")

        // The RFC 7636 binding itself: what the IdP was shown must be the hash of what it is later
        // told, or the whole exchange proves nothing.
        val verifier = tokenForm.get()["code_verifier"]!!
        assertTrue(isValidPkceVerifier(verifier))
        assertEquals(query["code_challenge"], pkceS256(verifier))
    }

    @Test
    fun `no verifier is sent to a token endpoint that never issued a challenge`() = testApplication {
        val tokenForm = AtomicReference<Parameters>()
        val client = wireOidc(testConfig(), tokenForm = tokenForm)

        val query = client.authorizeQuery()
        client.get("/auth/oidc/callback?code=abc&state=${query["state"]}")

        // Absent, not blank: an empty code_verifier is itself a protocol error.
        assertNull(tokenForm.get()["code_verifier"])
    }

    @Test
    fun `the verifier cookie is one-time-use`() = testApplication {
        val tokenForm = AtomicReference<Parameters>()
        val client = wireOidc(testConfig(), pkceMethods = listOf("S256"), tokenForm = tokenForm)

        val query = client.authorizeQuery()
        client.get("/auth/oidc/callback?code=abc&state=${query["state"]}")
        assertNotNull(tokenForm.get()["code_verifier"])

        // A second login mints its own verifier rather than reusing the first one, which is what
        // keeps an abandoned login from leaking a verifier into an unrelated exchange.
        val second = client.authorizeQuery()
        assertTrue(second["code_challenge"] != query["code_challenge"])
    }

    /** The authorize parameters `oidcRoutes` redirected to, lifted off the 302. */
    private suspend fun HttpClient.authorizeQuery(path: String = "/auth/oidc/login"): Parameters {
        val resp = get(path)
        assertEquals(HttpStatusCode.Found, resp.status)
        return parseQueryString(resp.headers[HttpHeaders.Location]!!.substringAfter('?'))
    }
}

/**
 * Sessions/content-negotiation + the fake IdP double (discovery + token) + the real [oidcRoutes]
 * under test, all in one [Application] extension so `install(...)` inside it resolves unambiguously
 * (see the comment at its call site in [OidcCallbackTest.wireOidc]).
 */
private fun Application.installOidcTestApp(
    config: Config,
    discovery: OidcDiscovery?,
    validator: IdTokenValidator?,
    http: HttpClient,
    dataSource: DataSource,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    log: Logger,
    pkceMethods: List<String>? = null,
    tokenForm: AtomicReference<Parameters>? = null,
    tokenEndpointFails: Boolean = false,
) {
    install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    install(Sessions) {
        cookie<OAuthStateSession>(OAUTH_STATE_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
        cookie<OAuthNonceSession>(OAUTH_NONCE_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
        cookie<DeviceVerifySession>(DEVICE_VERIFY_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
        // oidcRoutes clears this on every login and every callback, so it must be registered even
        // for an IdP that advertises no PKCE — an unregistered session name throws.
        cookie<OAuthVerifierSession>(OAUTH_VERIFIER_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
    }
    routing {
        // Fake IdP double: a discovery document + token endpoint, just enough for oidcRoutes' own
        // round-trips. jwks_uri is deliberately unreachable — never hit (see UNPARSEABLE_ID_TOKEN).
        serverGet("/.well-known/openid-configuration") {
            call.respond(
                OidcDiscoveryDocument(
                    issuer = config.oidc?.issuer ?: "",
                    authorization_endpoint = "/authorize",
                    token_endpoint = "/token",
                    jwks_uri = "http://jwks.invalid/keys",
                    code_challenge_methods_supported = pkceMethods,
                ),
            )
        }
        post("/token") {
            tokenForm?.set(call.receiveParameters())
            if (tokenEndpointFails) call.respond(HttpStatusCode.BadGateway, mapOf("error" to "temporarily_unavailable"))
            else call.respond(mapOf("id_token" to UNPARSEABLE_ID_TOKEN))
        }
        oidcRoutes(
            config, discovery, validator, http, userGroupStore, roleResolver, PrincipalSessionStore(dataSource, null),
            AuthAuditRecorder(AuditStore(dataSource)), log,
        )
    }
}
