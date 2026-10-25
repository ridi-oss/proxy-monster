package com.ridi.oss.proxymonster.controlplane

import org.junit.jupiter.api.AfterEach
import io.ktor.client.plugins.defaultRequest
import com.zaxxer.hikari.HikariDataSource
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.DeviceStartResponse
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.runBlocking
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.ridi.oss.proxymonster.controlplane.support.pkceS256
import com.ridi.oss.proxymonster.controlplane.authz.UserAttribute
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
    private val callbackManager = AtomicReference<String?>(null)
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
    fun `oidc callback stores a declared claim on the user`() {
        callbackManager.set("lead@example.com")
        try {
            verifyCallback(
                scopes = "openid email",
                resultKey = null,
                expectRefresh = false,
                expectAttributes = """{"manager": "lead@example.com"}""",
            )
        } finally {
            callbackManager.set(null)
        }
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
        val dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_oidc_web"))
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

        val stack = stack(config("openid email", resultKey = ByteArray(32) { it.toByte() }), dataSource)
        val client = stack.client().config { defaultRequest { header("X-Forwarded-For", CALLER_ADDR) } }

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
    fun `a device login authenticates via SSO before confirming and approving the handle`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_oidc_web"))
        val principal = "oidc-device@example.com"
        callbackPrincipal.set(principal)
        val policyStore = PolicyStore(dataSource)
        val role = policyStore.createRole(RoleInput("oidc-device-role"))
        policyStore.createAssignment(RoleAssignmentInput(principal, role.id))

        val stack = stack(
            config("openid email offline_access", resultKey = ByteArray(32) { it.toByte() })
                .copy(webOrigin = "https://console.example"),
            dataSource,
        )
        val client = stack.client()
        // A pmon login already in flight, started by the daemon.
        val started = startDeviceLogin(stack)
        val userCode = started.userCode

        // The unauthenticated /device page sends this exact continuation through the login page.
        val returnTo = "/device?user_code=${userCode.encodeURLParameter()}"
        val login = client.get("/auth/oidc/login?return_to=${returnTo.encodeURLParameter()}")
        val query = parseQueryString(assertNotNull(login.headers[HttpHeaders.Location]).substringAfter('?'))
        nonce.set(assertNotNull(query["nonce"]))
        val callback = client.get("/auth/oidc/callback?code=ok&state=${assertNotNull(query["state"])}")

        // PKCE survives the full signed-id_token path, not just the redirect shape: this IdP double
        // advertises S256, so the challenge on /authorize must be the hash of what /token received.
        assertEquals(query["code_challenge"], pkceS256(assertNotNull(tokenCodeVerifier.get())))
        assertEquals(HttpStatusCode.Found, callback.status)
        assertEquals(
            "https://console.example$returnTo",
            callback.headers[HttpHeaders.Location],
            "SSO returns to the web console's device confirmation page",
        )
        assertTrue(
            callback.headers.getAll(HttpHeaders.SetCookie).orEmpty().any { it.startsWith("$SESSION_COOKIE=") },
            "the login itself mints the console session that device confirmation then reuses",
        )

        val confirm = client.post("/auth/device/confirm") {
            contentType(ContentType.Application.Json)
            setBody("""{"userCode":"$userCode"}""")
        }
        assertEquals(HttpStatusCode.OK, confirm.status)

        val approve = client.get("/auth/device/authorize?user_code=${userCode.encodeURLParameter()}")
        assertEquals(HttpStatusCode.Found, approve.status)
        assertEquals("https://console.example/device/success", approve.headers[HttpHeaders.Location])

        val approved = deviceRow(dataSource, started.handle)
        assertEquals("APPROVED", approved.status)
        assertEquals(principal, approved.principal, "approved for the SSO principal, never a debug default")
        // The approving session's IdP refresh token must ride onto the device login, or the daemon session
        // minted at poll has nothing for its timer-driven IdP-liveness revalidation to run.
        assertEquals(
            "web-refresh-secret",
            approved.refreshEnc?.let { String(ResultCrypto(ByteArray(32) { it.toByte() }).decrypt(it)) },
            "the IdP refresh token is carried onto the device login for daemon IdP-liveness",
        )
    }

    @Test
    fun `a direct authorize link with no device-page confirm approves no handle`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_oidc_web"))
        val principal = "oidc-phish@example.com"
        callbackPrincipal.set(principal)
        val policyStore = PolicyStore(dataSource)
        val role = policyStore.createRole(RoleInput("oidc-phish-role"))
        policyStore.createAssignment(RoleAssignmentInput(principal, role.id))

        val stack = stack(config("openid email", resultKey = ByteArray(32) { it.toByte() }), dataSource)
        val client = stack.client()
        val started = startDeviceLogin(stack)

        // The phishing shape: the victim is handed an authorize link for the ATTACKER's code and logs in
        // normally — but never confirmed that code on /device, so there is no verify cookie in this browser.
        val login = client.get("/auth/oidc/login")
        val query = parseQueryString(assertNotNull(login.headers[HttpHeaders.Location]).substringAfter('?'))
        nonce.set(assertNotNull(query["nonce"]))
        assertEquals(HttpStatusCode.Found, client.get("/auth/oidc/callback?code=ok&state=${assertNotNull(query["state"])}").status)

        val authorize = client.get("/auth/device/authorize?user_code=${started.userCode.encodeURLParameter()}")
        assertEquals(HttpStatusCode.Found, authorize.status)
        assertTrue(
            authorize.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "an unconfirmed authorize bounces to the device page, got ${authorize.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", deviceRow(dataSource, started.handle).status, "the attacker's handle is NOT approved by a victim's login")
    }

    private fun startDeviceLogin(stack: CpGoStack): DeviceStartResponse = runBlocking {
        val start = stack.client().post("/auth/device/start") { contentType(ContentType.Application.Json); setBody("{}") }
        assertEquals(HttpStatusCode.OK, start.status)
        MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(start.bodyAsText())
    }

    private class DeviceRow(val status: String, val principal: String?, val refreshEnc: ByteArray?)

    private fun deviceRow(dataSource: DataSource, handle: String): DeviceRow = dataSource.connection.use { c ->
        c.prepareStatement("SELECT status, principal, refresh_token_enc FROM device_login WHERE handle = ?").use { ps ->
            ps.setString(1, handle)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); DeviceRow(rs.getString(1), rs.getString(2), rs.getBytes(3)) }
        }
    }

    private fun verifyCallback(
        scopes: String,
        resultKey: ByteArray?,
        expectRefresh: Boolean,
        principal: String = "oidc-web@example.com",
        seedRole: Boolean = true,
        expectSession: Boolean = true,
        returnTo: String? = null,
        expectAttributes: String = "{}",
    ) = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_oidc_web"))
        callbackPrincipal.set(principal)
        if (seedRole) {
            val policyStore = PolicyStore(dataSource)
            val role = policyStore.createRole(RoleInput("oidc-web-role"))
            policyStore.createAssignment(RoleAssignmentInput(principal, role.id))
        }
        val config = config(scopes, resultKey)
        val stack = stack(config, dataSource)
        val client = stack.client().config { defaultRequest { header("X-Forwarded-For", CALLER_ADDR) } }

        val login = client.get(
            if (returnTo == null) "/auth/oidc/login" else "/auth/oidc/login?return_to=${returnTo.encodeURLParameter()}",
        )
        val location = assertNotNull(login.headers[HttpHeaders.Location])
        val query = parseQueryString(location.substringAfter('?'))
        val state = assertNotNull(query["state"])
        nonce.set(assertNotNull(query["nonce"]))
        val callback = client.get("/auth/oidc/callback?code=ok&state=$state")
        assertEquals(HttpStatusCode.Found, callback.status)
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT attributes::text FROM app_user WHERE principal = ?").use { ps ->
                ps.setString(1, principal)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); assertEquals(expectAttributes, rs.getString(1)) }
            }
        }
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

    private val stacks = mutableListOf<CpGoStack>()

    @AfterEach
    fun closeStacks() {
        stacks.forEach { it.close() }
        stacks.clear()
    }

    /** The control plane behind cp-go on [dataSource], with cp-go given the same OIDC settings as [config]. */
    private fun stack(config: Config, dataSource: DataSource): CpGoStack {
        val oidc = requireNotNull(config.oidc)
        val env = mapOf(
            "PM_OIDC_ISSUER" to oidc.issuer,
            "PM_OIDC_CLIENT_ID" to oidc.clientId,
            "PM_OIDC_CLIENT_SECRET" to oidc.clientSecret,
            "PM_OIDC_REDIRECT_URI" to oidc.redirectUri,
            "PM_OIDC_SCOPES" to oidc.scopes,
            "PM_OIDC_USER_ATTRIBUTES" to oidc.userAttributes.joinToString(",") { "${it.name}:${it.type.cedar}" },
            "PM_TRUSTED_PROXIES" to "127.0.0.1",
        )
        val database = (dataSource as HikariDataSource).jdbcUrl.substringAfterLast('/')
        return CpGoStack(config, ControlPlaneCore(dataSource), database, extraEnv = env).also(stacks::add)
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
            userAttributes = UserAttribute.parseList("manager:User"),
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
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + 300_000))
            .claim("nonce", expectedNonce)
            .claim("email", callbackPrincipal.get())
            .apply { callbackManager.get()?.let { claim("manager", it) } }
            .build()
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims).also {
            it.sign(RSASSASigner(key))
        }.serialize()
    }
}
