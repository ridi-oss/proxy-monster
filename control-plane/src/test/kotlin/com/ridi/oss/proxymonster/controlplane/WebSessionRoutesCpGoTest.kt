package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.defaultRequest
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The web-session routes cp-go serves: `/auth/config`, `/auth/debug`, `/auth/me`, logout, status and heartbeat. */
class WebSessionRoutesCpGoTest {
    @Serializable
    private data class DebugLogin(val principal: String, val roles: List<String> = emptyList())

    @Serializable
    private data class SessionStatus(
        val now: String,
        val idleExpiresAt: String,
        val absoluteExpiresAt: String,
        val principal: String,
        val sessionId: Long,
    )

    @Serializable
    private data class SessionStatusError(val reason: String)

    @Serializable
    private data class LogoutRequest(val sessionId: Long? = null)

    @Serializable
    private data class LogoutResponse(val ended: Boolean)

    @Serializable
    private data class AuthConfigResponse(val oidcEnabled: Boolean, val authDebug: Boolean, val session: SessionUxConfig)

    @Serializable
    private data class SessionUxConfig(
        val heartbeatMs: Long,
        val idleWarnLeadMs: Long,
        val absoluteWarnLeadMs: Long,
        val absoluteCapAmount: Long,
        val absoluteCapUnit: String,
    )

    private class Fixture(val dataSource: DataSource, val core: ControlPlaneCore, val stack: CpGoStack) {
        /** A client with no cookie jar, for replaying a captured cookie by hand. */
        fun bareClient(): HttpClient = HttpClient(CIO) {
            expectSuccess = false
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
            defaultRequest { url(stack.baseUrl) }
        }
    }

    /** A fresh database and cp-go; [env] reaches both the Kotlin [Config] and cp-go as the raw setting. */
    private fun withStack(
        prefix: String,
        env: Map<String, String> = emptyMap(),
        protectedPath: String? = null,
        block: suspend Fixture.() -> Unit,
    ) {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase(prefix)
        val dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        val core = ControlPlaneCore(dataSource)
        val config = Config.fromEnv { env[it] }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        CpGoStack(config, core, database, extraEnv = env) {
            if (protectedPath != null) {
                routing {
                    get(protectedPath) {
                        call.requireApi() ?: return@get
                        call.respond(HttpStatusCode.OK)
                    }
                }
            }
        }.use { runBlocking { Fixture(dataSource, core, it).block() } }
    }

    private suspend fun HttpClient.debugLogin(principal: String, roles: List<String> = emptyList()): HttpResponse =
        post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin(principal, roles))
        }

    private suspend fun assertReason(response: HttpResponse, reason: String) {
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("no-store", response.headers[HttpHeaders.CacheControl])
        assertEquals(SessionStatusError(reason), response.body())
    }

    private fun webSessionCount(dataSource: DataSource, principal: String): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM principal_session WHERE principal = ? AND kind = 'WEB'").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getInt(1) }
        }
    }

    private fun webSessionId(dataSource: DataSource, principal: String): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB' ORDER BY id DESC LIMIT 1").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
        }
    }

    private fun endedReason(dataSource: DataSource, id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getString(1) }
        }
    }

    private fun sessionDeadline(dataSource: DataSource, id: Long, column: String): Instant = dataSource.connection.use { c ->
        c.prepareStatement("SELECT $column FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getTimestamp(1).toInstant() }
        }
    }

    private fun idleExpiresAt(dataSource: DataSource, id: Long): Instant = sessionDeadline(dataSource, id, "idle_expires_at")

    private fun databaseNow(dataSource: DataSource): Instant = dataSource.connection.use { c ->
        c.prepareStatement("SELECT clock_timestamp()").use { ps ->
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getTimestamp(1).toInstant() }
        }
    }

    private fun update(dataSource: DataSource, sql: String, id: Long) {
        dataSource.connection.use { c ->
            c.prepareStatement(sql).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
    }

    private fun HttpResponse.sessionCookie(): String =
        assertNotNull(headers.getAll(HttpHeaders.SetCookie)).first { it.startsWith("$SESSION_COOKIE=") }.substringBefore(';')

    @Test
    fun `auth config exposes default session UX timings`() = withStack("pm_auth_config_defaults") {
        val response = stack.client().get("/auth/config")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            AuthConfigResponse(
                oidcEnabled = false,
                authDebug = true,
                session = SessionUxConfig(
                    heartbeatMs = 90_000,
                    idleWarnLeadMs = 60_000,
                    absoluteWarnLeadMs = 300_000,
                    absoluteCapAmount = 2,
                    absoluteCapUnit = "hours",
                ),
            ),
            response.body(),
        )
    }

    @Test
    fun `auth config normalizes a mixed-unit absolute cap to minutes`() =
        withStack("pm_auth_config_minutes", env = mapOf("PM_WEB_SESSION_ABSOLUTE" to "1h30m")) {
            val response = stack.client().get("/auth/config").body<AuthConfigResponse>()
            assertEquals(90L, response.session.absoluteCapAmount)
            assertEquals("minutes", response.session.absoluteCapUnit)
        }

    @Test
    fun `debug login resolves through the database and logout ends the row`() =
        withStack("pm_web_routes", env = mapOf("PM_WEB_SESSION_ABSOLUTE" to "90s")) {
            val client = stack.client()

            // A claimed role must exist: `system:auditor` is seeded by the migrations.
            val login = client.debugLogin("web@example.com", listOf("system:auditor"))
            assertEquals(HttpStatusCode.OK, login.status)
            val setCookies = assertNotNull(login.headers.getAll(HttpHeaders.SetCookie))
            val sessionCookie = setCookies.first { it.startsWith("$SESSION_COOKIE=") }
            val deviceCookie = setCookies.first { it.startsWith("$DEVICE_COOKIE=") }
            assertContains(sessionCookie, "Max-Age=90;")
            assertContains(deviceCookie, "Max-Age=7776000")
            assertContains(deviceCookie, "Path=/")
            assertContains(deviceCookie, "HttpOnly")
            assertContains(deviceCookie, "SameSite=Lax")
            assertEquals(UserSession("web@example.com", listOf("system:auditor")), login.body())
            // /auth/me re-resolves rather than echoing the session.
            assertEquals(UserSession("web@example.com", listOf("system:auditor")), client.get("/auth/me").body())

            // The claim became a direct assignment, so authorization (which reads the database) sees it.
            assertEquals(listOf("system:auditor"), core.roleResolver.directRoles("web@example.com"))

            // An unknown name fails the whole login, naming the rejected role.
            val sessionsBefore = webSessionCount(dataSource, "web@example.com")
            val bogus = client.debugLogin("web@example.com", listOf("system:auditor", "no-such-role"))
            assertEquals(HttpStatusCode.NotFound, bogus.status)
            assertContains(bogus.bodyAsText(), "no-such-role")
            // Rejected atomically: neither the assignment nor the session table changes.
            assertEquals(listOf("system:auditor"), core.roleResolver.directRoles("web@example.com"))
            assertEquals(sessionsBefore, webSessionCount(dataSource, "web@example.com"))

            // REPLACE, not add.
            client.debugLogin("web@example.com", listOf("system:development-viewer"))
            assertEquals(listOf("system:development-viewer"), core.roleResolver.directRoles("web@example.com"))

            // An EMPTY claim is a deliberate wipe of the direct set, not a no-op.
            client.debugLogin("web@example.com", emptyList())
            assertEquals(emptyList(), core.roleResolver.directRoles("web@example.com"))

            client.debugLogin("web@example.com", listOf("system:auditor"))

            val id = dataSource.connection.use { c ->
                c.prepareStatement("SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB'").use { ps ->
                    ps.setString(1, "web@example.com")
                    ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
                }
            }
            val signedCookie = sessionCookie.substringBefore(';')
            val logout = client.post("/auth/logout")
            assertEquals(HttpStatusCode.OK, logout.status)
            assertEquals(LogoutResponse(ended = true), logout.body())
            assertContains(assertNotNull(logout.headers.getAll(HttpHeaders.SetCookie)?.joinToString()), "Max-Age=0")
            dataSource.connection.use { c ->
                c.prepareStatement("SELECT ended_at, ended_reason FROM principal_session WHERE id = ?").use { ps ->
                    ps.setLong(1, id)
                    ps.executeQuery().use { rs ->
                        assertTrue(rs.next())
                        assertNotNull(rs.getTimestamp("ended_at"))
                        assertEquals(ENDED_SIGNED_OUT, rs.getString("ended_reason"))
                    }
                }
                c.prepareStatement(
                    """SELECT outcome, decision, channel FROM audit_event
                       WHERE kind='auth' AND principal=? AND action=? AND resource=?""",
                ).use { ps ->
                    ps.setString(1, "web@example.com")
                    ps.setString(2, AuthAuditRecorder.ACTION_LOGOUT)
                    ps.setString(3, auditEntity("Session", id.toString()))
                    ps.executeQuery().use { rs ->
                        assertTrue(rs.next())
                        assertEquals("SUCCESS", rs.getString("outcome"))
                        assertEquals("ALLOW", rs.getString("decision"))
                        assertEquals("session", rs.getString("channel"))
                    }
                }
            }
            assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status)
            val replay = bareClient().get("/auth/me") { header(HttpHeaders.Cookie, signedCookie) }
            assertEquals(HttpStatusCode.Unauthorized, replay.status)
        }

    @Test
    fun `conditional logout ends only the session id observed by the client`() = withStack("pm_web_conditional_logout") {
        val client = stack.client()

        client.debugLogin("empty-body@example.com")
        val emptyBodyLogout = client.post("/auth/logout") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        }
        assertEquals(HttpStatusCode.OK, emptyBodyLogout.status)
        assertEquals(LogoutResponse(ended = true), emptyBodyLogout.body())

        client.debugLogin("conditional@example.com")
        val staleId = webSessionId(dataSource, "conditional@example.com")

        client.debugLogin("conditional@example.com")
        val currentId = webSessionId(dataSource, "conditional@example.com")
        assertTrue(currentId != staleId)

        val staleLogout = client.post("/auth/logout") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(LogoutRequest(staleId))
        }
        assertEquals(HttpStatusCode.OK, staleLogout.status)
        assertEquals(LogoutResponse(ended = false), staleLogout.body())
        assertNull(staleLogout.headers[HttpHeaders.SetCookie], "a stale conditional logout must not clear the cookie")
        assertEquals(
            0,
            dataSource.connection.use { c ->
                c.prepareStatement("SELECT count(*) FROM audit_event WHERE kind='auth' AND action=? AND resource=?").use { ps ->
                    ps.setString(1, AuthAuditRecorder.ACTION_LOGOUT)
                    ps.setString(2, auditEntity("Session", currentId.toString()))
                    ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
                }
            },
        )
        val stillCurrent = client.get("/auth/session/status")
        assertEquals(HttpStatusCode.OK, stillCurrent.status)
        assertEquals(currentId, stillCurrent.body<SessionStatus>().sessionId)

        val matchingLogout = client.post("/auth/logout") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(LogoutRequest(currentId))
        }
        assertEquals(HttpStatusCode.OK, matchingLogout.status)
        assertEquals(LogoutResponse(ended = true), matchingLogout.body())
        assertContains(assertNotNull(matchingLogout.headers.getAll(HttpHeaders.SetCookie)?.joinToString()), "Max-Age=0")
        assertReason(client.get("/auth/session/status"), "none")
    }

    /** An idle-expired row is still open, so logout ends it and the end must be audited. */
    @Test
    fun `logging out of an idle-expired session still records the termination`() = withStack("pm_web_idle_logout") {
        val client = stack.client()

        client.debugLogin("idle-logout@example.com")
        val id = webSessionId(dataSource, "idle-logout@example.com")
        update(dataSource, "UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?", id)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status, "the row must no longer resolve")

        assertEquals(HttpStatusCode.OK, client.post("/auth/logout").status)
        assertEquals(ENDED_SIGNED_OUT, endedReason(dataSource, id))
        dataSource.connection.use { c ->
            c.prepareStatement(
                "SELECT principal, outcome FROM audit_event WHERE kind='auth' AND action=? AND resource=?",
            ).use { ps ->
                ps.setString(1, AuthAuditRecorder.ACTION_LOGOUT)
                ps.setString(2, auditEntity("Session", id.toString()))
                ps.executeQuery().use { rs ->
                    assertTrue(rs.next(), "a logout that ended a session must be audited even when it no longer resolves")
                    assertEquals("idle-logout@example.com", rs.getString("principal"))
                    assertEquals("SUCCESS", rs.getString("outcome"))
                }
            }
        }
    }

    @Test
    fun `expired and ended web rows fail closed`() = withStack("pm_web_fail_closed", protectedPath = "/test/protected") {
        val client = stack.client()
        client.debugLogin("missing@example.com")
        dataSource.connection.use { c ->
            c.prepareStatement("DELETE FROM principal_session WHERE principal = ?").use { ps ->
                ps.setString(1, "missing@example.com")
                ps.executeUpdate()
            }
        }
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status)

        client.debugLogin("expired@example.com")
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE principal = ?").use { ps ->
                ps.setString(1, "expired@example.com")
                ps.executeUpdate()
            }
        }
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
        assertNull(PrincipalSessionStore(dataSource, null).resolveWeb(-1, null))
    }

    @Test
    fun `session observation and ordinary authenticated routes never slide idle while heartbeat does`() =
        withStack("pm_web_status", protectedPath = "/api/test/protected") {
            val client = stack.client()
            val freshClient = bareClient()

            assertReason(freshClient.get("/auth/session/status"), "none")
            assertReason(freshClient.get("/auth/me"), "none")
            assertReason(freshClient.post("/auth/session/heartbeat"), "none")

            client.debugLogin("status@example.com")
            val id = webSessionId(dataSource, "status@example.com")
            update(
                dataSource,
                """UPDATE principal_session
                   SET last_seen_at = now() - interval '3 minutes', idle_expires_at = idle_expires_at - interval '3 minutes'
                   WHERE id = ?""",
                id,
            )
            val beforeObserve = idleExpiresAt(dataSource, id)
            val dbBefore = databaseNow(dataSource)

            val statusResponse = client.get("/auth/session/status")
            val dbAfter = databaseNow(dataSource)
            assertEquals(HttpStatusCode.OK, statusResponse.status)
            assertEquals("no-store", statusResponse.headers[HttpHeaders.CacheControl])
            val status = statusResponse.body<SessionStatus>()
            assertEquals("status@example.com", status.principal)
            assertEquals(id, status.sessionId)
            assertEquals(beforeObserve, Instant.parse(status.idleExpiresAt))
            assertEquals(beforeObserve, idleExpiresAt(dataSource, id), "status observation must not extend idle")
            assertEquals(sessionDeadline(dataSource, id, "absolute_expires_at"), Instant.parse(status.absoluteExpiresAt))
            val serverNow = Instant.parse(status.now)
            assertTrue(!serverNow.isBefore(dbBefore.minusSeconds(2)), "status now must use the database clock")
            assertTrue(!serverNow.isAfter(dbAfter.plusSeconds(2)), "status now must use the database clock")

            val okMe = client.get("/auth/me")
            assertEquals(HttpStatusCode.OK, okMe.status)
            assertEquals("no-store", okMe.headers[HttpHeaders.CacheControl])
            assertEquals(beforeObserve, idleExpiresAt(dataSource, id), "/auth/me must not extend idle")

            val okApi = client.get("/api/test/protected")
            assertEquals(HttpStatusCode.OK, okApi.status)
            assertEquals(beforeObserve, idleExpiresAt(dataSource, id), "ordinary /api traffic must not extend idle")

            val heartbeat = client.post("/auth/session/heartbeat")
            assertEquals(HttpStatusCode.OK, heartbeat.status)
            assertEquals("no-store", heartbeat.headers[HttpHeaders.CacheControl])
            val heartbeatStatus = heartbeat.body<SessionStatus>()
            val afterHeartbeat = idleExpiresAt(dataSource, id)
            assertTrue(afterHeartbeat.isAfter(beforeObserve), "heartbeat must extend an eligible idle deadline")
            assertEquals(afterHeartbeat, Instant.parse(heartbeatStatus.idleExpiresAt))
            assertEquals(id, heartbeatStatus.sessionId)

            val throttled = client.post("/auth/session/heartbeat")
            assertEquals(HttpStatusCode.OK, throttled.status)
            assertEquals(afterHeartbeat, Instant.parse(throttled.body<SessionStatus>().idleExpiresAt))
            assertEquals(afterHeartbeat, idleExpiresAt(dataSource, id), "heartbeat must throttle within the slide interval")

            update(dataSource, "UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?", id)
            assertReason(client.get("/auth/session/status"), "expired")
            assertReason(client.get("/auth/me"), "expired")
            assertReason(client.post("/auth/session/heartbeat"), "expired")
        }

    @Test
    fun `session status and me surface displacement and bind mismatch reasons`() = withStack("pm_web_status_reasons") {
        val firstClient = stack.client()
        val secondClient = stack.client()

        val firstLogin = firstClient.debugLogin("reason-status@example.com")
        assertEquals(HttpStatusCode.OK, firstLogin.status)
        val capturedSession = firstLogin.sessionCookie()

        val secondLogin = secondClient.debugLogin("reason-status@example.com")
        assertEquals(HttpStatusCode.OK, secondLogin.status)

        assertReason(firstClient.get("/auth/session/status"), "displaced")
        assertReason(firstClient.get("/auth/me"), "displaced")
        assertReason(firstClient.post("/auth/session/heartbeat"), "displaced")

        assertReason(
            bareClient().get("/auth/session/status") { header(HttpHeaders.Cookie, capturedSession) },
            "displaced",
        )

        val boundSession = secondClient.debugLogin("bind-status@example.com").sessionCookie()
        val boundId = webSessionId(dataSource, "bind-status@example.com")
        val wrongDevice = "${DEVICE_COOKIE}=00000000-0000-0000-0000-000000000000"
        val bindReplay = bareClient()
        assertReason(
            bindReplay.get("/auth/session/status") { header(HttpHeaders.Cookie, "$boundSession; $wrongDevice") },
            "bind_mismatch",
        )
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, endedReason(dataSource, boundId))
        assertReason(
            bindReplay.get("/auth/me") { header(HttpHeaders.Cookie, "$boundSession; $wrongDevice") },
            "bind_mismatch",
        )

        // /auth/me as the first mismatching request must itself resolve, end the row, then map the reason.
        val meFirstSession = secondClient.debugLogin("bind-me-first@example.com").sessionCookie()
        val meFirstId = webSessionId(dataSource, "bind-me-first@example.com")
        assertReason(
            bindReplay.get("/auth/me") { header(HttpHeaders.Cookie, "$meFirstSession; $wrongDevice") },
            "bind_mismatch",
        )
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, endedReason(dataSource, meFirstId))

        // An absent pm_did fails closed exactly like a wrong one, never a wildcard match.
        val absentSession = secondClient.debugLogin("bind-absent@example.com").sessionCookie()
        val absentId = webSessionId(dataSource, "bind-absent@example.com")
        assertReason(
            bindReplay.get("/auth/session/status") { header(HttpHeaders.Cookie, absentSession) },
            "bind_mismatch",
        )
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, endedReason(dataSource, absentId))
    }
}
