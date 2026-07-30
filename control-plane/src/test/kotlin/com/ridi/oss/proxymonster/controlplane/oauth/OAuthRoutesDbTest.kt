package com.ridi.oss.proxymonster.controlplane.oauth

import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.PRINCIPAL_SESSION_STORE
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.SESSION_COOKIE
import com.ridi.oss.proxymonster.controlplane.WebSessionRef
import com.ridi.oss.proxymonster.controlplane.ensureDeviceCookie
import com.ridi.oss.proxymonster.controlplane.jsonSessionSerializer
import com.ridi.oss.proxymonster.controlplane.module
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.post as serverPost
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OAuthRoutesDbTest {
    private lateinit var dataSource: DataSource

    @BeforeAll
    fun setUp() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_oauth_routes"))
        Flyway.configure().dataSource(dataSource).load().migrate()
    }

    @Test
    fun `debug authorization code PKCE refresh and discovery work end to end`() = testApplication {
        application { oauthTestModule(config(), dataSource, resolver()) }
        val client = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }

        val discovery = client.get("/.well-known/oauth-authorization-server")
        assertEquals(HttpStatusCode.OK, discovery.status)
        val metadata = discovery.body<JsonObject>()
        assertEquals(ORIGIN, metadata.getValue("issuer").jsonPrimitive.content)
        assertTrue(metadata.getValue("client_id_metadata_document_supported").jsonPrimitive.content.toBoolean())
        assertTrue("registration_endpoint" !in metadata)

        val authorization = client.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:read mcp:policies:write")
            parameter("state", "state-1")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
            parameter("principal", "mcp-debug@example.com")
        }
        assertEquals(HttpStatusCode.Found, authorization.status)
        assertEquals("no-store", authorization.headers[HttpHeaders.CacheControl])
        val redirect = Url(assertNotNull(authorization.headers[HttpHeaders.Location]))
        assertEquals("state-1", redirect.parameters["state"])
        val code = assertNotNull(redirect.parameters["code"])

        val token = client.submitForm(
            "/oauth/token",
            Parameters.build {
                append("grant_type", "authorization_code")
                append("code", code)
                append("client_id", CLIENT_ID)
                append("redirect_uri", REDIRECT_URI)
                append("resource", RESOURCE)
                append("code_verifier", VERIFIER)
            },
        )
        assertEquals(HttpStatusCode.OK, token.status)
        val first = token.body<JsonObject>()
        assertEquals("Bearer", first.getValue("token_type").jsonPrimitive.content)
        val refresh = first.getValue("refresh_token").jsonPrimitive.content

        val rotated = client.submitForm(
            "/oauth/token",
            Parameters.build {
                append("grant_type", "refresh_token")
                append("refresh_token", refresh)
                append("client_id", CLIENT_ID)
                append("resource", RESOURCE)
            },
        )
        assertEquals(HttpStatusCode.OK, rotated.status)
        assertNotEquals(refresh, rotated.body<JsonObject>().getValue("refresh_token").jsonPrimitive.content)

        val replay = client.submitForm(
            "/oauth/token",
            Parameters.build {
                append("grant_type", "refresh_token")
                append("refresh_token", refresh)
                append("client_id", CLIENT_ID)
                append("resource", RESOURCE)
            },
        )
        assertEquals(HttpStatusCode.BadRequest, replay.status)
        assertEquals("invalid_grant", replay.body<JsonObject>().getValue("error").jsonPrimitive.content)

        // OAuth debug login and the control-plane console now share one authenticated session.
        assertEquals(HttpStatusCode.OK, client.get("/oauth/consents").status)
    }

    @Test
    fun `control-plane application mounts both OAuth AS and MCP resource discovery on one origin`() = testApplication {
        application { module(config(), ControlPlaneCore(dataSource)) }
        val jsonClient = createClient {
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        val oauthMetadata = jsonClient.get("/.well-known/oauth-authorization-server").body<JsonObject>()
        val resourceMetadata = jsonClient.get("/.well-known/oauth-protected-resource/mcp").body<JsonObject>()

        assertEquals(ORIGIN, oauthMetadata.getValue("issuer").jsonPrimitive.content)
        assertEquals(
            ORIGIN,
            resourceMetadata.getValue("authorization_servers").jsonArray.single().jsonPrimitive.content,
        )
    }

    @Test
    fun `CIMD validation accepts omitted scope but rejects unsafe client identifiers`() {
        metadata().validateRequest(REDIRECT_URI, setOf("mcp:read"))
        metadata().copy(redirect_uris = listOf("https://client.example/callback"))
            .validateRequest("https://client.example/callback", setOf("mcp:read"))
        metadata().copy(redirect_uris = listOf("http://[::1]:43110/callback"))
            .validateRequest("http://[::1]:43110/callback", setOf("mcp:read"))
        assertFailsWith<IllegalArgumentException> {
            metadata().copy(redirect_uris = listOf("http://remote.example/callback"))
                .validateRequest("http://remote.example/callback", setOf("mcp:read"))
        }
        assertFailsWith<IllegalArgumentException> {
            metadata().copy(redirect_uris = listOf("https://client.example/callback#fragment"))
                .validateRequest("https://client.example/callback#fragment", setOf("mcp:read"))
        }

        runBlocking {
            assertFailsWith<IllegalArgumentException> {
                HttpCimdResolver(productionChecks = true).resolve("https://127.0.0.1/client.json")
            }
            assertFailsWith<IllegalArgumentException> {
                HttpCimdResolver(productionChecks = true).resolve("https://user@example.com/client.json")
            }
            assertFailsWith<IllegalArgumentException> {
                HttpCimdResolver(productionChecks = true).resolve("https://example.com/a/../client.json")
            }
        }
    }

    @Test
    fun `CIMD validation matches a portless loopback redirect_uri against any request port, RFC 8252 section 7`() {
        // Regression for the real Claude Code client metadata document, which declares
        // http://localhost/callback and http://127.0.0.1/callback with NO port — a native/CLI client
        // binds an ephemeral port each launch, so `claude mcp login` always requests one, e.g.
        // http://localhost:54213/callback. Exact-string redirect_uri matching rejected every real
        // login unconditionally before this fix.
        val claudeCode = metadata().copy(redirect_uris = listOf("http://localhost/callback", "http://127.0.0.1/callback"))
        claudeCode.validateRequest("http://localhost:54213/callback", setOf("mcp:read"))
        claudeCode.validateRequest("http://127.0.0.1:1/callback", setOf("mcp:read"))
        claudeCode.validateRequest("http://localhost/callback", setOf("mcp:read")) // still matches with no port too

        // Still fail-closed: a different host, a different path, or a non-loopback/HTTPS request must
        // NOT be relaxed just because a loopback URI happens to be declared elsewhere in the list.
        assertFailsWith<IllegalArgumentException> {
            claudeCode.validateRequest("http://evil.example:54213/callback", setOf("mcp:read"))
        }
        assertFailsWith<IllegalArgumentException> {
            claudeCode.validateRequest("http://localhost:54213/other", setOf("mcp:read"))
        }
        assertFailsWith<IllegalArgumentException> {
            claudeCode.validateRequest("https://localhost:54213/callback", setOf("mcp:read"))
        }
        // A declared FIXED-port loopback URI is unaffected — still exact-match only, no relaxation
        // beyond what RFC 8252 asks for (a portless declaration).
        assertFailsWith<IllegalArgumentException> {
            metadata().validateRequest("http://127.0.0.1:9999/callback", setOf("mcp:read"))
        }
    }

    @Test
    fun `consent discloses redirect destination and warns for loopback clients`() = testApplication {
        application { oauthTestModule(config().copy(mcpDebugAutoConsent = false), dataSource, resolver()) }
        val response = client.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:read")
            parameter("state", "state-consent")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
            parameter("principal", "mcp-debug@example.com")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertContains(body, REDIRECT_URI)
        assertContains(body, "Verify that you started the local client")
    }

    @Test
    fun `production OAuth reuses the existing control-plane user session without another auth boundary`() = testApplication {
        val production = config().copy(authDebug = false, mcpDebugAutoConsent = false)
        application { oauthTestModule(production, dataSource, resolver()) }
        val client = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/login/mcp-user@example.com").status)

        val response = client.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:read")
            parameter("state", "state-shared-session")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        assertContains(response.bodyAsText(), "Test MCP Client")

        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT'
                   WHERE principal = ? AND kind = 'WEB'""",
            ).use { ps ->
                ps.setString(1, "mcp-user@example.com")
                ps.executeUpdate()
            }
        }
        val ended = client.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:read")
            parameter("state", "state-ended-session")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
        }
        assertEquals(HttpStatusCode.Found, ended.status)
        assertContains(assertNotNull(ended.headers[HttpHeaders.Location]), "/auth/oidc/login")
    }

    @Test
    fun `production OAuth without a session enters the existing control-plane OIDC login`() = testApplication {
        val production = config().copy(authDebug = false)
        application { oauthTestModule(production, dataSource, resolver()) }
        val browser = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
        }
        val response = browser.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:read")
            parameter("state", "state-shared-oidc")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
        }

        assertEquals(HttpStatusCode.Found, response.status)
        assertEquals("/auth/oidc/login?return_to=%2Foauth%2Fresume", response.headers[HttpHeaders.Location])

        val canceled = browser.get("/oauth/resume?error=access_denied")
        assertEquals(HttpStatusCode.Found, canceled.status)
        val redirect = Url(assertNotNull(canceled.headers[HttpHeaders.Location]))
        assertEquals(REDIRECT_URI, "${redirect.protocol.name}://${redirect.host}:${redirect.port}${redirect.encodedPath}")
        assertEquals("access_denied", redirect.parameters["error"])
        assertEquals("state-shared-oidc", redirect.parameters["state"])

        // The signed pending request is one-time-use even on the cancellation path.
        assertEquals(HttpStatusCode.BadRequest, browser.get("/oauth/resume?error=access_denied").status)
    }

    @Test
    fun `production OAuth resumes through the shared session and issues a code after consent`() = testApplication {
        val production = config().copy(authDebug = false, mcpDebugAutoConsent = false)
        application { oauthTestModule(production, dataSource, resolver()) }
        val browser = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
        }

        val authorization = browser.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:identity:write")
            parameter("state", "state-resumed")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
        }
        assertEquals(HttpStatusCode.Found, authorization.status)
        assertEquals("/auth/oidc/login?return_to=%2Foauth%2Fresume", authorization.headers[HttpHeaders.Location])

        // This test helper establishes exactly the shared UserSession that a successful OIDC callback sets.
        assertEquals(HttpStatusCode.NoContent, browser.post("/test/login/resume-user@example.com").status)
        val consent = browser.get("/oauth/resume")
        assertEquals(HttpStatusCode.OK, consent.status)
        val csrf = Regex("""name="csrf" value="([^"]+)"""")
            .find(consent.bodyAsText())?.groupValues?.get(1)
        assertNotNull(csrf)

        val approved = browser.submitForm(
            "/oauth/consent",
            Parameters.build {
                append("csrf", csrf)
                append("decision", "approve")
            },
        )
        assertEquals(HttpStatusCode.Found, approved.status)
        val redirect = Url(assertNotNull(approved.headers[HttpHeaders.Location]))
        assertNotNull(redirect.parameters["code"])
        assertEquals("state-resumed", redirect.parameters["state"])
    }

    @Test
    fun `production configuration rejects the public dev session secret and insecure origins`() {
        val base = mutableMapOf(
            "PM_AUTH_DEBUG" to "false",
            "PM_MCP_RESOURCE" to "https://proxy.example/mcp",
            "PM_OIDC_ISSUER" to "https://idp.example/oauth2/default",
            "PM_OIDC_CLIENT_ID" to "client",
            "PM_OIDC_CLIENT_SECRET" to "secret",
            "PM_OIDC_REDIRECT_URI" to "https://proxy.example/auth/oidc/callback",
        )
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(base::get) }
        base["PM_SESSION_SECRET"] = "x".repeat(32)
        assertEquals("https://proxy.example", Config.fromEnv(base::get).mcpIssuer)
        base["PM_MCP_RESOURCE"] = "http://proxy.example/mcp"
        assertContains(
            assertFailsWith<IllegalArgumentException> { Config.fromEnv(base::get) }.message.orEmpty(),
            "HTTPS",
        )
    }

    /**
     * The debug `/oauth/authorize` shares the console's authenticated session, and sharing means REPLACING
     * it — `mintWeb` is newest-wins. So the simulated source address the console is deciding under has to
     * survive that remint, or an MCP authorization in the same browser silently changes the console's
     * authorization context: tag rules stop firing, and nothing on screen says why.
     *
     * Pinned here rather than in DebugRequesterIpDbTest because the bug lives in THIS route. Both branches
     * are asserted — the carry-over, and the deliberate drop when `?principal=` names someone else, since
     * one identity's simulated network must never follow another's.
     */
    @Test
    fun `debug authorize carries the simulated source address across its session remint`() = testApplication {
        application { oauthTestModule(config(), dataSource, resolver()) }
        val client = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }

        suspend fun authorizeAs(principal: String): HttpStatusCode = client.get("/oauth/authorize") {
            parameter("response_type", "code")
            parameter("client_id", CLIENT_ID)
            parameter("redirect_uri", REDIRECT_URI)
            parameter("scope", "mcp:read")
            parameter("state", "state-ip")
            parameter("resource", RESOURCE)
            parameter("code_challenge", CHALLENGE)
            parameter("code_challenge_method", "S256")
            parameter("principal", principal)
        }.status

        // The console session: signed in, deciding as if from the trusted network.
        val owner = "ip-owner@example.com"
        client.post("/test/login/$owner") { parameter("requesterIp", "100.100.1.10") }
        assertEquals("100.100.1.10", liveDebugIp(owner))

        // Same principal: the remint must carry the address over.
        assertEquals(HttpStatusCode.Found, authorizeAs(owner))
        assertEquals(
            "100.100.1.10", liveDebugIp(owner),
            "an MCP authorization must not silently drop the console's simulated address",
        )

        // A DIFFERENT principal: the new session must start with no simulated address at all.
        val other = "ip-other@example.com"
        assertEquals(HttpStatusCode.Found, authorizeAs(other))
        assertNull(
            liveDebugIp(other),
            "one principal's simulated network must not follow another's identity",
        )
    }

    /** The simulated address on [principal]'s single LIVE web session — the row a decision would resolve. */
    private fun liveDebugIp(principal: String): String? = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT debug_requester_ip FROM principal_session
               WHERE principal = ? AND kind = 'WEB' AND ended_at IS NULL
               ORDER BY id DESC LIMIT 1""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs ->
                assertTrue(rs.next(), "no live web session for $principal")
                rs.getString(1)
            }
        }
    }

    private fun resolver(): CimdResolver = CimdResolver { clientId ->
        require(clientId == CLIENT_ID)
        metadata()
    }

    private fun metadata() = CimdClientMetadata(
        client_id = CLIENT_ID,
        client_name = "Test MCP Client",
        redirect_uris = listOf(REDIRECT_URI),
        scope = "",
    )

    private fun config() = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = true,
        secretToken = null,
        sessionSecret = "control-plane-oauth-test-secret-32-bytes",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3_600,
        idpRecheckIntervalSeconds = 600,
        devMarker = false,
        mcpResource = RESOURCE,
        mcpAccessTtlSeconds = 600,
        mcpRefreshTtlSeconds = 3_600,
    )

    private companion object {
        const val ORIGIN = "http://control-plane.local"
        const val RESOURCE = "$ORIGIN/mcp"
        const val CLIENT_ID = "https://client.example/client.json"
        const val REDIRECT_URI = "http://127.0.0.1:43110/callback"
        val VERIFIER = "v".repeat(43)
        val CHALLENGE = pkceS256(VERIFIER)
    }
}

private fun Application.oauthTestModule(config: Config, dataSource: DataSource, resolver: CimdResolver) {
    val principalSessionStore = PrincipalSessionStore(dataSource, null)
    attributes.put(PRINCIPAL_SESSION_STORE, principalSessionStore)
    install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
    install(Sessions) {
        webSessionCookie(principalSessionStore, config.sessionSecret)
        cookie<McpPendingAuthorization>(MCP_OAUTH_PENDING_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.maxAgeInSeconds = 600
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
        }
    }
    installMcpOAuthProtocolGuard()
    routing {
        serverPost("/test/login/{principal}") {
            val principal = requireNotNull(call.parameters["principal"])
            val deviceId = call.ensureDeviceCookie(secure = false)
            call.sessions.set(WebSessionRef(principalSessionStore.mintWeb(
                    principal,
                    null,
                    config.webSessionAbsoluteSeconds,
                    config.webSessionIdleSeconds,
                    deviceId,
                    // Optional so existing callers are unchanged; set by the inheritance test, which needs a
                    // session that already carries a simulated address before OAuth remints it.
                    debugRequesterIp = call.request.queryParameters["requesterIp"],
                )))
            call.respond(HttpStatusCode.NoContent)
        }
        mcpOAuthRoutes(config, dataSource, principalSessionStore, resolver)
    }
}
