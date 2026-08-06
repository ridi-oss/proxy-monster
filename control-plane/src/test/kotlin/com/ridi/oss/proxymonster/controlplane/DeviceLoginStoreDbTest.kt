package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed store round-trips for [DeviceLoginStore] (docs/auth-model.md "CLI / daemon login")
 * + a route-level proof that `PM_AUTH_DEBUG` mints a wire token end-to-end through
 * `/auth/device/start` + `/auth/device/poll` **without ever configuring an IdP** — `discovery`/
 * `validator` are both null and nothing here makes an outbound HTTP call.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceLoginStoreDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: DeviceLoginStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_device_login"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = DeviceLoginStore(ds)
    }

    @Test
    fun `create then get round-trips a pending row`() {
        val handle = store.newHandle()
        val row = store.create(handle, deviceCode = "dc-1", intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        assertEquals(handle, row.handle)
        assertEquals("dc-1", row.deviceCode)
        assertEquals("PENDING", row.status)
        assertNull(row.principal)

        val fetched = store.get(handle)!!
        assertEquals(row.id, fetched.id)
        assertEquals(5, fetched.intervalSec)
        assertEquals(3600L, fetched.ttlSeconds)
    }

    @Test
    fun `unknown handle is absent`() {
        assertNull(store.get("no-such-handle"))
    }

    @Test
    fun `a login is retrievable by its user_code and a fresh one is well-formed`() {
        val handle = store.newHandle()
        val userCode = store.newUserCode()
        assertTrue(userCode.matches(Regex("[A-Z0-9]{4}-[A-Z0-9]{4}")), "user_code is XXXX-XXXX from the unambiguous alphabet, got $userCode")
        store.create(handle, deviceCode = null, intervalSec = 2, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600), userCode = userCode)

        val byCode = store.getByUserCode(userCode)!!
        assertEquals(handle, byCode.handle, "the page looks the handle up by the human user_code")
        assertEquals(userCode, byCode.userCode)
        assertNull(store.getByUserCode("NOPE-NOPE"), "an unknown user_code is absent")
    }

    @Test
    fun `markApproved sets status and principal, only once`() {
        val handle = store.newHandle()
        store.create(handle, deviceCode = "dc-2", intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        assertTrue(store.markApproved(handle, "alice@example.com"))
        val row = store.get(handle)!!
        assertEquals("APPROVED", row.status)
        assertEquals("alice@example.com", row.principal)

        // Re-approving an already-approved row is a no-op (it's no longer PENDING) — a second IdP
        // exchange for the same handle must not silently switch the winning principal.
        assertFalse(store.markApproved(handle, "mallory@example.com"))
        assertEquals("alice@example.com", store.get(handle)!!.principal)
    }

    @Test
    fun `markApproved refuses an expired handle`() {
        val handle = store.newHandle()
        store.create(handle, deviceCode = "dc-3", intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().minusSeconds(1))
        assertFalse(store.markApproved(handle, "alice@example.com"))
        assertEquals("PENDING", store.get(handle)!!.status)
    }

    @Test
    fun `purgeExpired removes only expired rows`() {
        val live = store.newHandle()
        val dead = store.newHandle()
        store.create(live, deviceCode = null, intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        store.create(dead, deviceCode = null, intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().minusSeconds(1))
        assertTrue(store.purgeExpired() >= 1)
        assertNull(store.get(dead))
        assertNotNull(store.get(live))
    }

    /** The daemon session store the device routes minted into — so a test can inspect what was minted. */
    private lateinit var lastPrincipalSessionStore: PrincipalSessionStore
    private lateinit var lastTokenStore: TokenStore

    /**
     * Stand up the device-login API surface (the verification PAGE itself is the web app's /device; the CP
     * owns start/confirm/authorize/poll). The web-session cookie is installed too, so a test can drive the
     * "already logged in → approve with that session" path. Redirects are NOT auto-followed so a test can
     * assert where authorize sends the browser.
     */
    private fun ApplicationTestBuilder.installDeviceRoutes(): io.ktor.client.HttpClient {
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "test-secret-at-least-32-chars-long!!", oidc = null, resultKey = ByteArray(32) { it.toByte() },
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        lastTokenStore = TokenStore(ds)
        val userGroupStore = UserGroupStore(ds)
        lastPrincipalSessionStore = PrincipalSessionStore(ds, ResultCrypto(config.resultKey!!))
        val log = LoggerFactory.getLogger("DeviceLoginStoreDbTest")

        // webSession() resolves the cookie through this application attribute — without it every request
        // reads as unauthenticated and the authorize route would always bounce to /login.
        application { attributes.put(PRINCIPAL_SESSION_STORE, lastPrincipalSessionStore) }
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        // Mirrors module()'s fallback so a poll whose atomic mint audit throws answers 500, as in the running
        // server, rather than surfacing as a transport failure.
        install(StatusPages) { exception<Throwable> { call, _ -> call.respond(HttpStatusCode.InternalServerError) } }
        install(Sessions) {
            webSessionCookie(lastPrincipalSessionStore, config.sessionSecret) {
                cookie.maxAgeInSeconds = config.webSessionAbsoluteSeconds
            }
            cookie<DeviceVerifySession>(DEVICE_VERIFY_COOKIE) {
                serializer = jsonSessionSerializer()
                transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
            }
        }
        routing {
            deviceSessionRoutes(
                config, store, lastPrincipalSessionStore, lastTokenStore, userGroupStore,
                AuthAuditRecorder(AuditStore(ds)), log,
            )
            // Stands in for the web console's own login: mints a web session so the "already logged in" path
            // can be exercised without dragging the whole OIDC flow into this test.
            get("/test/login-as/{principal}") {
                // Bind the session to this browser's device cookie exactly as the real OIDC callback does —
                // resolveWeb refuses a session whose stored device_id doesn't match the request's cookie.
                val deviceId = call.ensureDeviceCookie(secure = false)
                val sessionId = lastPrincipalSessionStore.mintWeb(
                    call.parameters["principal"]!!, null, config.webSessionAbsoluteSeconds, config.webSessionIdleSeconds, deviceId,
                )
                call.sessions.set(WebSessionRef(sessionId))
                call.respond(HttpStatusCode.OK, "ok")
            }
            get("/test/end-session") {
                lastPrincipalSessionStore.endWeb(call.webSession()!!.id, ENDED_SIGNED_OUT)
                call.respond(HttpStatusCode.OK, "ok")
            }
        }
        return createClient {
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
            install(HttpCookies)
            followRedirects = false
        }
    }

    private suspend fun io.ktor.client.HttpClient.startLogin(): DeviceStartResponse {
        val start = post("/auth/device/start") { contentType(ContentType.Application.Json); setBody("{}") }
        assertEquals(HttpStatusCode.OK, start.status)
        return start.body<DeviceStartResponse>().also {
            assertTrue(it.handle.isNotBlank())
            assertTrue(it.userCode.isNotBlank())
            assertTrue(it.verificationUriComplete.endsWith("/device?user_code=${it.userCode}"), "start points at the web /device page")
        }
    }

    /** What the web /device page POSTs when the human confirms the code it shows. */
    private suspend fun io.ktor.client.HttpClient.confirm(userCode: String) =
        post("/auth/device/confirm") { contentType(ContentType.Application.Json); setBody("""{"userCode":"$userCode"}""") }

    /** Where the web page sends the browser after a successful confirm. */
    private suspend fun io.ktor.client.HttpClient.authorize(userCode: String) = get("/auth/device/authorize?user_code=$userCode")

    private suspend fun io.ktor.client.HttpClient.poll(handle: String) =
        post("/auth/device/poll") { contentType(ContentType.Application.Json); setBody("""{"handle":"$handle"}""") }

    /** `kind="auth"` rows matching [where], whose `?` placeholders [args] fill in order. */
    private fun auditCount(where: String, vararg args: String): Int = ds.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM audit_event WHERE kind='auth' AND ($where)").use { ps ->
            args.forEachIndexed { i, value -> ps.setString(i + 1, value) }
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun daemonSessionCount(handle: String): Int = ds.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM principal_session WHERE handle = ? AND kind = 'DAEMON'").use { ps ->
            ps.setString(1, handle)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    /** Make every `kind="auth"` insert for [action] fail, so the poll's mint transaction must roll back with it. */
    private fun rejectAction(action: String) {
        execute(
            """CREATE OR REPLACE FUNCTION pm_test_reject_auth_audit() RETURNS trigger AS ${'$'}body${'$'}
               BEGIN RAISE EXCEPTION 'forced auth audit failure'; END
               ${'$'}body${'$'} LANGUAGE plpgsql""",
        )
        execute(
            """CREATE TRIGGER pm_test_reject_auth_audit BEFORE INSERT ON audit_event
               FOR EACH ROW WHEN (NEW.kind = 'auth' AND NEW.action = '$action')
               EXECUTE FUNCTION pm_test_reject_auth_audit()""",
        )
    }

    private fun dropRejectTrigger() {
        execute("DROP TRIGGER IF EXISTS pm_test_reject_auth_audit ON audit_event")
        execute("DROP FUNCTION IF EXISTS pm_test_reject_auth_audit()")
    }

    private fun execute(sql: String) = ds.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    /**
     * The APPROVED -> CONSUMED claim now runs INSIDE the mint transaction, so a failed mint rolls it back and
     * the poll can retry — instead of stranding the handle CONSUMED with no token and no audit (finding 3). A
     * reject-trigger on the device-mint audit forces the mint to fail after consume would have run.
     */
    @Test
    fun `a failed device mint rolls the consume back so the poll can retry`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/retry@example.com")
        client.confirm(started.userCode)
        client.authorize(started.userCode)

        rejectAction(AuthAuditRecorder.ACTION_DEVICE_MINT)
        try {
            assertEquals(HttpStatusCode.InternalServerError, client.poll(started.handle).status)
            assertEquals(
                "APPROVED", store.get(started.handle)!!.status,
                "a failed mint must roll the consume back, leaving the handle replayable",
            )
            assertEquals(0, daemonSessionCount(started.handle), "a rolled-back mint must leave no session")
            assertEquals(
                0, auditCount("action=? AND principal=?", AuthAuditRecorder.ACTION_DEVICE_MINT, "retry@example.com"),
                "a rolled-back mint must leave no device-mint audit row",
            )
        } finally {
            dropRejectTrigger()
        }

        // The retry succeeds — proving the handle was never stranded CONSUMED.
        val poll = client.poll(started.handle)
        assertEquals(HttpStatusCode.OK, poll.status)
        assertEquals("retry@example.com", poll.body<DevicePollResult>().principal)
    }

    @Test
    fun `the verification URL points at the web console origin, not the control plane`() {
        // /device is a WEB route, so the URL pmon prints must be the console's origin. Blank PM_WEB_ORIGIN
        // means "same origin" (the usual single-edge deployment); set, it wins — otherwise a split-origin
        // deployment would send the browser to the control plane, which serves no such page.
        val sameOrigin = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "s".repeat(32), oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
            mcpResource = "https://console.example/mcp",
        )
        assertEquals("https://console.example", sameOrigin.webBaseUrl)
        assertEquals("/device", sameOrigin.webRedirectTarget("/device"))
        val splitOrigin = sameOrigin.copy(webOrigin = "http://127.0.0.1:41300/")
        assertEquals("http://127.0.0.1:41300", splitOrigin.webBaseUrl)
        assertEquals("http://127.0.0.1:41300/device", splitOrigin.webRedirectTarget("/device"))
    }

    @Test
    fun `confirm requires a live web session`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()

        assertEquals(HttpStatusCode.Unauthorized, client.confirm(started.userCode).status)
        assertEquals("PENDING", store.get(started.handle)!!.status)
    }

    @Test
    fun `an authenticated confirm accepts a pending code and rejects an unknown one`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")

        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        assertEquals(HttpStatusCode.BadRequest, client.confirm("NOPE-NOPE").status, "an unknown code must not be confirmable")
    }

    @Test
    fun `authorize without a prior confirm approves nothing and bounces back to the device page`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com") // logged in, but never confirmed the code on /device

        // The device-phishing gate: a direct authorize link (no /device confirm in THIS browser) can't approve.
        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertTrue(
            res.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "an unconfirmed authorize must bounce to the device page, got ${res.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", store.get(started.handle)!!.status, "no approval without a confirm")
    }

    @Test
    fun `a confirm for one code cannot authorize a different code`() = testApplication {
        val client = installDeviceRoutes()
        val mine = client.startLogin()
        val other = client.startLogin() // e.g. an attacker's own pending login
        client.get("/test/login-as/alice@example.com")

        // Confirming MY code must not become a blanket approval capability: the verify cookie is bound to that
        // exact code, so authorizing a different one is refused even though this browser is confirmed + signed in.
        assertEquals(HttpStatusCode.OK, client.confirm(mine.userCode).status)
        val res = client.authorize(other.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertTrue(
            res.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "authorizing a code this browser did not confirm must bounce, got ${res.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", store.get(other.handle)!!.status, "the other login must NOT be approved")
        // …and my own code still authorizes normally.
        assertEquals("/device/success", client.authorize(mine.userCode).headers[HttpHeaders.Location])
    }

    @Test
    fun `session loss after confirm returns to the device page and approves nothing`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        client.get("/test/end-session")

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device?user_code=${started.userCode}", res.headers[HttpHeaders.Location])
        assertEquals("PENDING", store.get(started.handle)!!.status)

        client.get("/test/login-as/alice@example.com")
        assertEquals(
            "/device?user_code=${started.userCode}",
            client.authorize(started.userCode).headers[HttpHeaders.Location],
            "a new session must confirm the code again",
        )
    }

    @Test
    fun `a replacement session cannot inherit an earlier confirmation`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        client.get("/test/login-as/bob@example.com")

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device?user_code=${started.userCode}", res.headers[HttpHeaders.Location])
        assertEquals("PENDING", store.get(started.handle)!!.status)
    }

    @Test
    fun `an existing console session approves the login without re-authenticating`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device/success", res.headers[HttpHeaders.Location], "an existing session approves straight through")

        val row = store.get(started.handle)!!
        assertEquals("APPROVED", row.status)
        assertEquals("alice@example.com", row.principal, "approved as the logged-in principal, never a debug default")
        assertEquals(
            1,
            auditCount(
                "action=? AND principal=? AND resource=?",
                AuthAuditRecorder.ACTION_DEVICE_APPROVE, "alice@example.com", auditEntity("DeviceLogin", row.id.toString()),
            ),
        )
        // The handle is the bearer secret /auth/device/poll accepts on its own, and the audit trail is
        // readable by every auditor and exported to the SIEM. It must appear in NO column of NO event.
        assertEquals(
            0,
            auditCount(
                "resource LIKE ? OR statement LIKE ? OR detail LIKE ? OR principal = ?",
                "%${started.handle}%", "%${started.handle}%", "%${started.handle}%", started.handle,
            ),
            "the device-login handle is a credential and must never reach the audit trail",
        )
    }

    @Test
    fun `a login mints a wire token end-to-end via start, confirm, authorize, then poll`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()

        // Until the browser approves, pmon's poll is pending — start never auto-approves.
        assertEquals(HttpStatusCode.Accepted, client.poll(started.handle).status, "poll is pending until the browser approves")

        client.get("/test/login-as/alice@example.com")
        client.confirm(started.userCode)
        assertEquals(HttpStatusCode.Found, client.authorize(started.userCode).status)

        val poll = client.poll(started.handle)
        assertEquals(HttpStatusCode.OK, poll.status)
        val result: DevicePollResult = poll.body()
        assertEquals("alice@example.com", result.principal)
        assertTrue(result.token.isNotBlank())
        assertNotNull(lastTokenStore.validate(result.token))
        assertTrue(result.renewalToken.startsWith("pmr_"), "renewalToken must be the mint-once bearer renewal secret")
        assertEquals(
            1,
            auditCount(
                "action=? AND principal=? AND resource=?",
                AuthAuditRecorder.ACTION_DEVICE_MINT, "alice@example.com",
                auditEntity("Token", lastTokenStore.list("alice@example.com").first().id.toString()),
            ),
        )
        assertEquals(
            0,
            auditCount("statement LIKE ? OR detail LIKE ? OR resource LIKE ?", "%${result.token}%", "%${result.renewalToken}%", "%pmr_%"),
            "a minted token and its renewal secret must never reach the audit trail",
        )
    }

    @Test
    fun `a device handle mints exactly once — a replayed poll is refused and mints no second session`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        client.confirm(started.userCode)
        client.authorize(started.userCode)

        // First poll completes the login and mints the one session + renewal secret.
        assertEquals(HttpStatusCode.OK, client.poll(started.handle).status)

        // A second poll on the SAME (now-consumed) handle must be refused, not mint again — otherwise
        // the short-lived login handle becomes an unbounded renewal-secret-minting handle.
        assertEquals(HttpStatusCode.BadRequest, client.poll(started.handle).status, "a replayed poll on a consumed handle must be refused")

        // Exactly one daemon session (one renewal secret) exists for this handle.
        val count = ds.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM principal_session WHERE handle = ? AND kind = 'DAEMON'").use { ps ->
                ps.setString(1, started.handle)
                ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
            }
        }
        assertEquals(1, count, "a replayed poll must not mint a second session/renewal secret")
        assertEquals(
            1,
            auditCount(
                "action=? AND principal=? AND resource=?",
                AuthAuditRecorder.ACTION_DEVICE_MINT, "alice@example.com",
                auditEntity("Token", lastTokenStore.list("alice@example.com").first().id.toString()),
            ),
            "a replayed poll must not emit a second device mint event",
        )
    }
}
