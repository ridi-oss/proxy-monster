package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.DevicePollResult
import com.ridi.oss.proxymonster.controlplane.support.DeviceStartResponse
import com.ridi.oss.proxymonster.controlplane.support.MCP_TEST_JSON
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * [DeviceLoginStore.purgeExpired], plus the device-login routes cp-go serves: `PM_AUTH_DEBUG` mints a wire
 * token end-to-end through `/auth/device/start` + `/auth/device/poll` without ever configuring an IdP.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceLoginStoreDbTest {
    @Test
    fun `purgeExpired removes only expired rows`() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_device_login"))
        Flyway.configure().dataSource(ds).load().migrate()
        ds.connection.use { c ->
            c.createStatement().use { st ->
                st.execute(
                    """INSERT INTO device_login (handle, ttl_seconds, expires_at) VALUES
                       ('live', 3600, now() + interval '10 minutes'), ('dead', 3600, now() - interval '1 second')""",
                )
            }
        }

        assertTrue(DeviceLoginStore(ds).purgeExpired() >= 1)

        val left = ds.connection.use { c ->
            c.createStatement().use { st ->
                st.executeQuery("SELECT handle FROM device_login").use { rs -> buildSet { while (rs.next()) add(rs.getString(1)) } }
            }
        }
        assertEquals(setOf("live"), left)
    }

    private lateinit var dataSource: DataSource
    private lateinit var tokenStore: TokenStore
    private lateinit var crypto: ResultCrypto
    private lateinit var stack: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_device_login_routes")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        tokenStore = TokenStore(dataSource)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "test-secret-at-least-32-chars-long!!", oidc = null, resultKey = ByteArray(32) { it.toByte() },
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        crypto = ResultCrypto(config.resultKey!!)
        val sessions = PrincipalSessionStore(dataSource, crypto)
        stack = CpGoStack(config, ControlPlaneCore(dataSource), database) {
            routing {
                get("/test/login-as/{principal}") {
                    val deviceId = call.ensureDeviceCookie(secure = false)
                    val sessionId = sessions.mintWeb(
                        call.parameters["principal"]!!, call.request.queryParameters["refresh"], config.webSessionAbsoluteSeconds, config.webSessionIdleSeconds, deviceId,
                    )
                    call.sessions.set(WebSessionRef(sessionId))
                    call.respond(HttpStatusCode.OK, "ok")
                }
                get("/test/end-session") {
                    sessions.endWeb(call.webSession()!!.id, ENDED_SIGNED_OUT)
                    call.respond(HttpStatusCode.OK, "ok")
                }
            }
        }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    private suspend fun HttpClient.startLogin(): DeviceStartResponse {
        val start = post("/auth/device/start") { contentType(ContentType.Application.Json); setBody("{}") }
        assertEquals(HttpStatusCode.OK, start.status)
        return MCP_TEST_JSON.decodeFromString<DeviceStartResponse>(start.bodyAsText()).also {
            assertTrue(it.handle.isNotBlank())
            assertTrue(it.userCode.isNotBlank())
            assertTrue(it.verificationUriComplete.endsWith("/device?user_code=${it.userCode}"), "start points at the web /device page")
        }
    }

    /** What the web /device page POSTs when the human confirms the code it shows. */
    private suspend fun HttpClient.confirm(userCode: String) =
        post("/auth/device/confirm") { contentType(ContentType.Application.Json); setBody("""{"userCode":"$userCode"}""") }

    /** Where the web page sends the browser after a successful confirm. */
    private suspend fun HttpClient.authorize(userCode: String) = get("/auth/device/authorize?user_code=$userCode")

    private suspend fun HttpClient.poll(handle: String) =
        post("/auth/device/poll") { contentType(ContentType.Application.Json); setBody("""{"handle":"$handle"}""") }

    private suspend fun HttpResponse.pollResult(): DevicePollResult = MCP_TEST_JSON.decodeFromString(bodyAsText())

    private data class LoginRow(val id: Long, val status: String, val principal: String?)

    private fun loginRow(handle: String): LoginRow = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id, status, principal FROM device_login WHERE handle = ?").use { ps ->
            ps.setString(1, handle)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); LoginRow(rs.getLong(1), rs.getString(2), rs.getString(3)) }
        }
    }

    /** `kind="auth"` rows matching [where], whose `?` placeholders [args] fill in order. */
    private fun auditCount(where: String, vararg args: String): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM audit_event WHERE kind='auth' AND ($where)").use { ps ->
            args.forEachIndexed { i, value -> ps.setString(i + 1, value) }
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    private fun daemonSessionCount(handle: String): Int = dataSource.connection.use { c ->
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

    private fun execute(sql: String) = dataSource.connection.use { c -> c.createStatement().use { it.execute(sql) } }

    @Test
    fun `a failed device mint rolls the consume back so the poll can retry`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/retry@example.com")
        client.confirm(started.userCode)
        client.authorize(started.userCode)

        rejectAction(AuthAuditRecorder.ACTION_DEVICE_MINT)
        try {
            assertEquals(HttpStatusCode.InternalServerError, client.poll(started.handle).status)
            assertEquals(
                "APPROVED", loginRow(started.handle).status,
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

        val poll = client.poll(started.handle)
        assertEquals(HttpStatusCode.OK, poll.status)
        assertEquals("retry@example.com", poll.pollResult().principal)
    }

    @Test
    fun `confirm requires a live web session`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()

        assertEquals(HttpStatusCode.Unauthorized, client.confirm(started.userCode).status)
        assertEquals("PENDING", loginRow(started.handle).status)
    }

    @Test
    fun `an authenticated confirm accepts a pending code and rejects an unknown one`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")

        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        assertEquals(HttpStatusCode.BadRequest, client.confirm("NOPE-NOPE").status, "an unknown code must not be confirmable")
    }

    @Test
    fun `authorize without a prior confirm approves nothing and bounces back to the device page`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertTrue(
            res.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "an unconfirmed authorize must bounce to the device page, got ${res.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", loginRow(started.handle).status, "no approval without a confirm")
    }

    @Test
    fun `a confirm for one code cannot authorize a different code`() = runBlocking<Unit> {
        val client = stack.client()
        val mine = client.startLogin()
        val other = client.startLogin()
        client.get("/test/login-as/alice@example.com")

        assertEquals(HttpStatusCode.OK, client.confirm(mine.userCode).status)
        val res = client.authorize(other.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertTrue(
            res.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "authorizing a code this browser did not confirm must bounce, got ${res.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", loginRow(other.handle).status, "the other login must NOT be approved")
        assertEquals("/device/success", client.authorize(mine.userCode).headers[HttpHeaders.Location])
    }

    @Test
    fun `session loss after confirm returns to the device page and approves nothing`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        client.get("/test/end-session")

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device?user_code=${started.userCode}", res.headers[HttpHeaders.Location])
        assertEquals("PENDING", loginRow(started.handle).status)

        client.get("/test/login-as/alice@example.com")
        assertEquals(
            "/device?user_code=${started.userCode}",
            client.authorize(started.userCode).headers[HttpHeaders.Location],
            "a new session must confirm the code again",
        )
    }

    @Test
    fun `a replacement session cannot inherit an earlier confirmation`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        client.get("/test/login-as/bob@example.com")

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device?user_code=${started.userCode}", res.headers[HttpHeaders.Location])
        assertEquals("PENDING", loginRow(started.handle).status)
    }

    @Test
    fun `an existing console session approves the login without re-authenticating`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device/success", res.headers[HttpHeaders.Location], "an existing session approves straight through")

        val row = loginRow(started.handle)
        assertEquals("APPROVED", row.status)
        assertEquals("alice@example.com", row.principal, "approved as the logged-in principal, never a debug default")
        assertEquals(
            1,
            auditCount(
                "action=? AND principal=? AND resource=?",
                AuthAuditRecorder.ACTION_DEVICE_APPROVE, "alice@example.com", auditEntity("DeviceLogin", row.id.toString()),
            ),
        )
        // The handle alone is accepted by /auth/device/poll, and the audit trail is exported to the SIEM.
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
    fun `the approving web session's IdP refresh token is carried onto the device login`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/carol@example.com?refresh=web-refresh-secret")
        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        assertEquals("/device/success", client.authorize(started.userCode).headers[HttpHeaders.Location])

        val enc = dataSource.connection.use { c ->
            c.prepareStatement("SELECT refresh_token_enc FROM device_login WHERE handle = ?").use { ps ->
                ps.setString(1, started.handle)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getBytes(1) }
            }
        }
        assertEquals("web-refresh-secret", String(crypto.decrypt(enc)))
    }

    @Test
    fun `a login mints a wire token end-to-end via start, confirm, authorize, then poll`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()

        assertEquals(HttpStatusCode.Accepted, client.poll(started.handle).status, "poll is pending until the browser approves")

        client.get("/test/login-as/alice@example.com")
        client.confirm(started.userCode)
        assertEquals(HttpStatusCode.Found, client.authorize(started.userCode).status)

        val poll = client.poll(started.handle)
        assertEquals(HttpStatusCode.OK, poll.status)
        val result = poll.pollResult()
        assertEquals("alice@example.com", result.principal)
        assertTrue(result.token.isNotBlank())
        assertNotNull(tokenStore.validate(result.token))
        assertTrue(result.renewalToken.startsWith("pmr_"), "renewalToken must be the mint-once bearer renewal secret")
        assertEquals(
            1,
            auditCount(
                "action=? AND principal=? AND resource=?",
                AuthAuditRecorder.ACTION_DEVICE_MINT, "alice@example.com",
                auditEntity("Token", tokenStore.list("alice@example.com").first().id.toString()),
            ),
        )
        assertEquals(
            0,
            auditCount("statement LIKE ? OR detail LIKE ? OR resource LIKE ?", "%${result.token}%", "%${result.renewalToken}%", "%pmr_%"),
            "a minted token and its renewal secret must never reach the audit trail",
        )
    }

    @Test
    fun `a device handle mints exactly once — a replayed poll is refused and mints no second session`() = runBlocking<Unit> {
        val client = stack.client()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com")
        client.confirm(started.userCode)
        client.authorize(started.userCode)

        assertEquals(HttpStatusCode.OK, client.poll(started.handle).status)

        assertEquals(HttpStatusCode.BadRequest, client.poll(started.handle).status, "a replayed poll on a consumed handle must be refused")

        assertEquals(1, daemonSessionCount(started.handle), "a replayed poll must not mint a second session/renewal secret")
        assertEquals(
            1,
            auditCount(
                "action=? AND principal=? AND resource=?",
                AuthAuditRecorder.ACTION_DEVICE_MINT, "alice@example.com",
                auditEntity("Token", tokenStore.list("alice@example.com").first().id.toString()),
            ),
            "a replayed poll must not emit a second device mint event",
        )
    }
}
