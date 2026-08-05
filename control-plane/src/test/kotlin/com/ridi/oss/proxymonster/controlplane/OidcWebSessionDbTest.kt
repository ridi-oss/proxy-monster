package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.auth.pkceS256
import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.http.parseQueryString
import java.time.Instant
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.net.ServerSocket
import java.util.Date
import java.util.concurrent.atomic.AtomicReference
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The forwarded source address the callback client presents, and the one the login's audit row must carry. */
private const val CALLER_ADDR = "203.0.113.11"

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidcWebSessionDbTest {
    private lateinit var key: RSAKey
    private lateinit var server: EmbeddedServer<*, *>
    private val nonce = AtomicReference<String>()
    private val tokenCodeVerifier = AtomicReference<String>()
    private val callbackPrincipal = AtomicReference("oidc-web@example.com")
    private var port = 0
    private val issuer get() = "http://127.0.0.1:$port"

    @BeforeAll
    fun startIdp() {
        key = RSAKeyGenerator(2048).keyID("oidc-web-session").generate()
        port = ServerSocket(0).use { it.localPort }
        server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            routing {
                get("/.well-known/openid-configuration") {
                    call.respondText(
                        """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks","code_challenge_methods_supported":["S256"]}""",
                        ContentType.Application.Json,
                    )
                }
                get("/jwks") {
                    call.respondText(JWKSet(key.toPublicJWK()).toString(), ContentType.Application.Json)
                }
                post("/token") {
                    tokenCodeVerifier.set(call.receiveParameters()["code_verifier"])
                    call.respondText(
                        Json.encodeToString(
                            kotlinx.serialization.json.JsonObject.serializer(),
                            kotlinx.serialization.json.buildJsonObject {
                                put("id_token", kotlinx.serialization.json.JsonPrimitive(sign(requireNotNull(nonce.get()))))
                                put("refresh_token", kotlinx.serialization.json.JsonPrimitive("web-refresh-secret"))
                            },
                        ),
                        ContentType.Application.Json,
                    )
                }
            }
        }.start(wait = false)
    }

    @AfterAll
    fun stopIdp() {
        server.stop(0, 500)
    }

    @Test
    fun `oidc callback mints web row and stores refresh only when encrypted offline access is available`() {
        verifyCallback(scopes = "openid email offline_access", resultKey = ByteArray(32) { it.toByte() }, expectRefresh = true)
        verifyCallback(scopes = "openid email offline_access", resultKey = null, expectRefresh = false)
        verifyCallback(scopes = "openid email", resultKey = ByteArray(32) { it.toByte() }, expectRefresh = false)
    }

    @Test
    fun `oidc callback denies a principal with zero effective roles without minting a session`() {
        verifyCallback(
            scopes = "openid email offline_access",
            resultKey = ByteArray(32) { it.toByte() },
            expectRefresh = false,
            principal = "oidc-no-access@example.com",
            seedRole = false,
            expectSession = false,
        )
    }

    @Test
    fun `a session mint failure after id_token validation is audited and leaves no session`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_oidc_web"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val principal = "oidc-mint-fail@example.com"
        callbackPrincipal.set(principal)
        val policyStore = PolicyStore(dataSource)
        val role = policyStore.createRole(RoleInput("oidc-mint-fail-role"))
        policyStore.createAssignment(RoleAssignmentInput(principal, role.id))

        // Fail the session mint AFTER the id_token validates: a BEFORE INSERT trigger on principal_session
        // rolls the mint transaction back, exercising the callback's own mint-failure catch. The standalone
        // failure row it writes is not on that rolled-back transaction, so it survives.
        dataSource.connection.use { c ->
            c.createStatement().use {
                it.execute(
                    """CREATE OR REPLACE FUNCTION pm_test_reject_session_insert() RETURNS trigger AS ${'$'}body${'$'}
                       BEGIN RAISE EXCEPTION 'forced session mint failure'; END
                       ${'$'}body${'$'} LANGUAGE plpgsql""",
                )
                it.execute(
                    """CREATE TRIGGER pm_test_reject_session_insert BEFORE INSERT ON principal_session
                       FOR EACH ROW EXECUTE FUNCTION pm_test_reject_session_insert()""",
                )
            }
        }

        application { installOidcWebApp(config("openid email", resultKey = ByteArray(32) { it.toByte() }), dataSource) }
        val client = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
            install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
        }

        val login = client.get("/auth/oidc/login")
        val query = parseQueryString(assertNotNull(login.headers[HttpHeaders.Location]).substringAfter('?'))
        nonce.set(assertNotNull(query["nonce"]))
        val callback = client.get("/auth/oidc/callback?code=ok&state=${assertNotNull(query["state"])}")

        assertEquals(HttpStatusCode.Found, callback.status)
        assertEquals("/login?error=oidc", callback.headers[HttpHeaders.Location])
        assertTrue(
            callback.headers.getAll(HttpHeaders.SetCookie).orEmpty().none { it.startsWith("$SESSION_COOKIE=") },
            "a rolled-back mint must set no console session cookie",
        )

        dataSource.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM principal_session WHERE principal = ?").use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    assertEquals(0, rs.getInt(1), "the rolled-back mint leaves no session row")
                }
            }
            c.prepareStatement(
                """SELECT outcome, decision, channel, detail, client_addr, resource FROM audit_event
                   WHERE kind='auth' AND principal=? AND action=?""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.setString(2, AuthAuditRecorder.ACTION_OIDC_LOGIN)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next(), "the mint failure must be audited")
                    assertEquals("FAILURE", rs.getString("outcome"))
                    assertEquals("DENY", rs.getString("decision"))
                    assertEquals(AuthAuditRecorder.CHANNEL_OIDC, rs.getString("channel"))
                    assertEquals("session_mint_failed", rs.getString("detail"))
                    assertEquals(CALLER_ADDR, rs.getString("client_addr"))
                    assertEquals(auditEntity("User", principal), rs.getString("resource"))
                    assertTrue(!rs.next(), "exactly one FAILURE row for the mint failure")
                }
            }
        }
    }

    @Test
    fun `oidc callback returns a successful popup reauth to its landing route`() {
        verifyCallback(
            scopes = "openid email offline_access",
            resultKey = ByteArray(32) { it.toByte() },
            expectRefresh = true,
            principal = "oidc-reauth@example.com",
            returnTo = "/auth/reauth-complete",
        )
    }

    @Test
    fun `a device login with no session logs in via SSO and comes back to approve the handle`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_oidc_web"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val principal = "oidc-device@example.com"
        callbackPrincipal.set(principal)
        val policyStore = PolicyStore(dataSource)
        val role = policyStore.createRole(RoleInput("oidc-device-role"))
        policyStore.createAssignment(RoleAssignmentInput(principal, role.id))

        // A pmon login already in flight: a PENDING device_login row keyed by a user_code (as /auth/device/start makes).
        val deviceStore = DeviceLoginStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        val started = deviceStore.createPending(intervalSec = 2, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        val userCode = started.userCode!!

        application { installOidcWebApp(config("openid email offline_access", resultKey = ByteArray(32) { it.toByte() }), dataSource) }
        val client = createClient { expectSuccess = false; followRedirects = false; install(HttpCookies) }

        // 1) The web /device page confirms the code the human read off their terminal.
        client.post("/auth/device/confirm") {
            contentType(ContentType.Application.Json)
            setBody("""{"userCode":"$userCode"}""")
        }
        // 2) The page sends the browser to authorize; with no console session it routes through /login.
        val authorize = client.get("/auth/device/authorize?user_code=$userCode")
        val loginTarget = assertNotNull(authorize.headers[HttpHeaders.Location])
        assertTrue(loginTarget.startsWith("/login?return_to="), "no session → /login first, got $loginTarget")
        val returnTo = parseQueryString(loginTarget.substringAfter('?'))["return_to"]!!

        // 3) /login's SSO button carries that return_to into the auth-code flow.
        val login = client.get("/auth/oidc/login?return_to=${returnTo.encodeURLParameter()}")
        val query = parseQueryString(assertNotNull(login.headers[HttpHeaders.Location]).substringAfter('?'))
        nonce.set(assertNotNull(query["nonce"]))
        val callback = client.get("/auth/oidc/callback?code=ok&state=${assertNotNull(query["state"])}")

        // PKCE survives the full signed-id_token path, not just the redirect shape: this IdP double
        // advertises S256, so the challenge on /authorize must be the hash of what /token received.
        assertEquals(query["code_challenge"], pkceS256(assertNotNull(tokenCodeVerifier.get())))
        assertEquals(HttpStatusCode.Found, callback.status)
        assertEquals(returnTo, callback.headers[HttpHeaders.Location], "SSO returns to the device authorize URL")
        assertTrue(
            callback.headers.getAll(HttpHeaders.SetCookie).orEmpty().any { it.startsWith("$SESSION_COOKIE=") },
            "the login itself mints the console session that authorize then reuses",
        )

        // 4) Back on authorize — now a session exists, so the handle is approved for that principal.
        val approve = client.get(returnTo)
        assertEquals(HttpStatusCode.Found, approve.status)
        assertEquals("/device/success", approve.headers[HttpHeaders.Location])

        val approved = deviceStore.get(started.handle)!!
        assertEquals("APPROVED", approved.status)
        assertEquals(principal, approved.principal, "approved for the SSO principal, never a debug default")
        // The approving session's IdP refresh token must ride onto the device login, or the daemon session
        // minted at poll has nothing for its timer-driven IdP-liveness revalidation to run.
        assertEquals(
            "web-refresh-secret",
            deviceStore.decryptRefresh(approved),
            "the IdP refresh token is carried onto the device login for daemon IdP-liveness",
        )
    }

    @Test
    fun `a direct authorize link with no device-page confirm approves no handle`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_oidc_web"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val principal = "oidc-phish@example.com"
        callbackPrincipal.set(principal)
        val policyStore = PolicyStore(dataSource)
        val role = policyStore.createRole(RoleInput("oidc-phish-role"))
        policyStore.createAssignment(RoleAssignmentInput(principal, role.id))

        val deviceStore = DeviceLoginStore(dataSource)
        val started = deviceStore.createPending(intervalSec = 2, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))

        application { installOidcWebApp(config("openid email", resultKey = ByteArray(32) { it.toByte() }), dataSource) }
        val client = createClient { expectSuccess = false; followRedirects = false; install(HttpCookies) }

        // The phishing shape: the victim is handed an authorize link for the ATTACKER's code and logs in
        // normally — but never confirmed that code on /device, so there is no verify cookie in this browser.
        val login = client.get("/auth/oidc/login")
        val query = parseQueryString(assertNotNull(login.headers[HttpHeaders.Location]).substringAfter('?'))
        nonce.set(assertNotNull(query["nonce"]))
        assertEquals(HttpStatusCode.Found, client.get("/auth/oidc/callback?code=ok&state=${assertNotNull(query["state"])}").status)

        val authorize = client.get("/auth/device/authorize?user_code=${started.userCode!!.encodeURLParameter()}")
        assertEquals(HttpStatusCode.Found, authorize.status)
        assertTrue(
            authorize.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "an unconfirmed authorize bounces to the device page, got ${authorize.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", deviceStore.get(started.handle)!!.status, "the attacker's handle is NOT approved by a victim's login")
    }

    private fun verifyCallback(
        scopes: String,
        resultKey: ByteArray?,
        expectRefresh: Boolean,
        principal: String = "oidc-web@example.com",
        seedRole: Boolean = true,
        expectSession: Boolean = true,
        returnTo: String? = null,
    ) = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_oidc_web"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        callbackPrincipal.set(principal)
        if (seedRole) {
            val policyStore = PolicyStore(dataSource)
            val role = policyStore.createRole(RoleInput("oidc-web-role"))
            policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        }
        val config = config(scopes, resultKey)
        application { installOidcWebApp(config, dataSource) }
        val client = createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
            install(DefaultRequest) { header("X-Forwarded-For", CALLER_ADDR) }
        }

        val login = client.get(
            if (returnTo == null) "/auth/oidc/login" else "/auth/oidc/login?return_to=${returnTo.encodeURLParameter()}",
        )
        val location = assertNotNull(login.headers[HttpHeaders.Location])
        val query = parseQueryString(location.substringAfter('?'))
        val state = assertNotNull(query["state"])
        nonce.set(assertNotNull(query["nonce"]))
        val callback = client.get("/auth/oidc/callback?code=ok&state=$state")
        assertEquals(HttpStatusCode.Found, callback.status)
        val setCookies = assertNotNull(callback.headers.getAll(HttpHeaders.SetCookie))
        if (!expectSession) {
            assertEquals("/login?error=no_access", callback.headers[HttpHeaders.Location])
            assertTrue(setCookies.none { it.startsWith("$SESSION_COOKIE=") })
            dataSource.connection.use { c ->
                c.prepareStatement("SELECT count(*) FROM principal_session WHERE principal = ?").use { ps ->
                    ps.setString(1, principal)
                    ps.executeQuery().use { rs ->
                        assertTrue(rs.next())
                        assertEquals(0, rs.getInt(1))
                    }
                }
                c.prepareStatement(
                    """SELECT outcome, decision, channel, detail, client_addr FROM audit_event
                       WHERE kind='auth' AND principal=? AND action=?""",
                ).use { ps ->
                    ps.setString(1, principal)
                    ps.setString(2, AuthAuditRecorder.ACTION_OIDC_LOGIN)
                    ps.executeQuery().use { rs ->
                        assertTrue(rs.next(), "a login refused for having no roles must be audited")
                        assertEquals("FAILURE", rs.getString("outcome"))
                        assertEquals("DENY", rs.getString("decision"))
                        assertEquals(AuthAuditRecorder.CHANNEL_OIDC, rs.getString("channel"))
                        assertEquals("no_effective_roles", rs.getString("detail"))
                        assertEquals(CALLER_ADDR, rs.getString("client_addr"))
                    }
                }
            }
            return@testApplication
        }
        assertEquals(returnTo ?: "/", callback.headers[HttpHeaders.Location])
        assertContains(setCookies.joinToString(), "Max-Age=7200")
        assertTrue(setCookies.any { it.startsWith("$SESSION_COOKIE=") })
        val deviceCookie = setCookies.first { it.startsWith("$DEVICE_COOKIE=") }
        assertContains(deviceCookie, "Max-Age=7776000")
        assertContains(deviceCookie, "Path=/")
        assertContains(deviceCookie, "HttpOnly")
        assertContains(deviceCookie, "SameSite=Lax")
        val deviceId = deviceCookie.substringAfter('=').substringBefore(';')

        dataSource.connection.use { c ->
            c.prepareStatement(
                """SELECT kind, refresh_token_enc, idle_expires_at, absolute_expires_at, created_at, device_id, session_key, id
                   FROM principal_session WHERE principal = ?""",
            ).use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next())
                    // The audit row names the session this login actually minted, not merely that some
                    // login happened: a row pointing at a different session would go unnoticed otherwise.
                    val sessionId = rs.getLong("id")
                    c.prepareStatement(
                        """SELECT outcome, decision, channel, resource, client_addr FROM audit_event
                           WHERE kind='auth' AND principal=? AND action=?""",
                    ).use { auditPs ->
                        auditPs.setString(1, principal)
                        auditPs.setString(2, AuthAuditRecorder.ACTION_OIDC_LOGIN)
                        auditPs.executeQuery().use { auditRs ->
                            assertTrue(auditRs.next(), "a login that minted a session must be audited")
                            assertEquals("SUCCESS", auditRs.getString("outcome"))
                            assertEquals("ALLOW", auditRs.getString("decision"))
                            assertEquals(AuthAuditRecorder.CHANNEL_OIDC, auditRs.getString("channel"))
                            assertEquals(auditEntity("Session", sessionId.toString()), auditRs.getString("resource"))
                            assertEquals(CALLER_ADDR, auditRs.getString("client_addr"))
                        }
                    }
                    assertEquals("WEB", rs.getString("kind"))
                    assertEquals(deviceId, rs.getString("device_id"))
                    assertNotNull(rs.getString("session_key"))
                    if (expectRefresh) assertNotNull(rs.getBytes("refresh_token_enc")) else assertNull(rs.getBytes("refresh_token_enc"))
                    val createdAt = rs.getTimestamp("created_at").toInstant()
                    val idleExpiresAt = assertNotNull(rs.getTimestamp("idle_expires_at")).toInstant()
                    assertTrue(rs.getTimestamp("absolute_expires_at").toInstant().isAfter(idleExpiresAt))
                    assertEquals(config.webSessionIdleSeconds, java.time.Duration.between(createdAt, idleExpiresAt).seconds)
                }
            }
        }
    }

    private fun Application.installOidcWebApp(config: Config, dataSource: DataSource) {
        val http = oidcHttpClient()
        val oidc = requireNotNull(config.oidc)
        val discovery = OidcDiscovery(http, oidc.issuer)
        val validator = IdTokenValidator(discovery, oidc.issuer, oidc.clientId)
        val store = PrincipalSessionStore(
            dataSource,
            config.resultKey?.let(::ResultCrypto),
            config.webSessionIdleSeconds,
            config.webSessionSlideSeconds,
        )
        val userGroupStore = UserGroupStore(dataSource)
        val roleResolver = RoleResolver(dataSource, userGroupStore, AccessStore(dataSource))
        val deviceLoginStore = DeviceLoginStore(dataSource, config.resultKey?.let(::ResultCrypto))
        attributes.put(PRINCIPAL_SESSION_STORE, store)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(Sessions) {
            webSessionCookie(store, config.sessionSecret) {
                cookie.maxAgeInSeconds = config.webSessionAbsoluteSeconds
            }
            cookie<OAuthStateSession>(OAUTH_STATE_COOKIE) {
                serializer = jsonSessionSerializer()
                transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
            }
            cookie<OAuthNonceSession>(OAUTH_NONCE_COOKIE) {
                serializer = jsonSessionSerializer()
                transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
            }
            cookie<DeviceVerifySession>(DEVICE_VERIFY_COOKIE) {
                serializer = jsonSessionSerializer()
                transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
            }
            // oidcRoutes clears this on every login and every callback, so it must be registered
            // even when the IdP advertises no PKCE — an unregistered session name throws.
            cookie<OAuthVerifierSession>(OAUTH_VERIFIER_COOKIE) {
                serializer = jsonSessionSerializer()
                transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
            }
        }
        routing {
            val authAudit = AuthAuditRecorder(AuditStore(dataSource))
            oidcRoutes(config, discovery, validator, http, userGroupStore, roleResolver, store, authAudit, environment.log)
            deviceSessionRoutes(
                config, deviceLoginStore, store, TokenStore(dataSource), userGroupStore, authAudit, environment.log,
            )
        }
    }

    private fun config(scopes: String, resultKey: ByteArray?) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = false,
        secretToken = null,
        sessionSecret = "oidc-web-session-test-secret-32-bytes",
        oidc = OidcConfig(
            issuer = issuer,
            clientId = "oidc-web-client",
            clientSecret = "secret",
            redirectUri = "http://control-plane.test/auth/oidc/callback",
            scopes = scopes,
            groupMapping = OidcGroupMapping(emptyMap(), null),
        ),
        resultKey = resultKey,
        scimToken = null,
        sessionWindowSeconds = 7200,
        webSessionAbsoluteSeconds = 7200,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
        // The Ktor test host's socket peer, trusted as an edge so the client's X-Forwarded-For resolves to
        // [CALLER_ADDR] — the requester address the login's audit row is asserted to carry.
        trustedProxies = setOf("localhost"),
    )

    private fun sign(expectedNonce: String): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("oidc-user")
            .audience("oidc-web-client")
            .expirationTime(Date(System.currentTimeMillis() + 300_000))
            .claim("nonce", expectedNonce)
            .claim("email", callbackPrincipal.get())
            .build()
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims).also {
            it.sign(RSASSASigner(key))
        }.serialize()
    }
}
