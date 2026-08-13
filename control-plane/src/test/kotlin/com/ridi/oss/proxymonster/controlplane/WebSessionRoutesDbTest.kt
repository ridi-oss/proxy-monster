package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.management.auditEntity
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.routing.get as serverGet
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.testing.testApplication
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

class WebSessionRoutesDbTest {
    private fun io.ktor.server.testing.ApplicationTestBuilder.sessionClient(): HttpClient = createClient {
        expectSuccess = false
        install(HttpCookies)
        install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    }

    private suspend fun assertReason(response: HttpResponse, reason: String) {
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("no-store", response.headers[HttpHeaders.CacheControl])
        assertEquals(SessionStatusError(reason), response.body())
    }

    /** WEB session rows for [principal] — lets a test assert that a failed login minted nothing. */
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

    private fun idleExpiresAt(dataSource: DataSource, id: Long): Instant = sessionDeadline(dataSource, id, "idle_expires_at")

    private fun absoluteExpiresAt(dataSource: DataSource, id: Long): Instant =
        sessionDeadline(dataSource, id, "absolute_expires_at")

    private fun sessionDeadline(dataSource: DataSource, id: Long, column: String): Instant = dataSource.connection.use { c ->
        c.prepareStatement("SELECT $column FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getTimestamp(1).toInstant() }
        }
    }

    private fun databaseNow(dataSource: DataSource): Instant = dataSource.connection.use { c ->
        c.prepareStatement("SELECT clock_timestamp()").use { ps ->
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getTimestamp(1).toInstant() }
        }
    }

    private fun backdateIdle(dataSource: DataSource, id: Long) {
        dataSource.connection.use { c ->
            c.prepareStatement(
                """UPDATE principal_session
                   SET last_seen_at = now() - interval '3 minutes',
                       idle_expires_at = idle_expires_at - interval '3 minutes'
                   WHERE id = ?""",
            ).use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
    }

    @Test
    fun `auth config exposes default session UX timings`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_auth_config_defaults"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        application { module(config, ControlPlaneCore(dataSource)) }

        val response = sessionClient().get("/auth/config")
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
    fun `auth config normalizes a mixed-unit absolute cap to minutes`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_auth_config_minutes"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { name ->
            if (name == "PM_WEB_SESSION_ABSOLUTE") "1h30m" else null
        }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        application { module(config, ControlPlaneCore(dataSource)) }

        val response = sessionClient().get("/auth/config").body<AuthConfigResponse>()
        assertEquals(90L, response.session.absoluteCapAmount)
        assertEquals("minutes", response.session.absoluteCapUnit)
    }

    @Test
    fun `debug login resolves through the database and logout ends the row`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_routes"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { name ->
            if (name == "PM_WEB_SESSION_ABSOLUTE") "90s" else null
        }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val core = ControlPlaneCore(dataSource)
        application {
            module(config, core)
            routing {
                serverGet("/test/protected") {
                    call.requireApi() ?: return@serverGet
                    call.respond(HttpStatusCode.OK)
                }
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }

        // A claimed role must EXIST: the debug login persists the claim as real `principal_role` rows, so a
        // name with no `app_role` behind it is rejected rather than accepted and quietly ignored. `system:auditor`
        // is seeded by the migrations, so it resolves in this freshly-migrated database.
        val login = client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("web@example.com", listOf("system:auditor")))
        }
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
        // /auth/me re-resolves rather than echoing the session: the console reads this to show who it
        // thinks you are, so reporting an empty set for a principal that holds roles misdescribes
        // every later denial.
        assertEquals(UserSession("web@example.com", listOf("system:auditor")), client.get("/auth/me").body())

        // The claim is not cosmetic: it became a direct assignment, so authorization (which reads the database,
        // never the session) actually sees it. Without this the route could echo any role back and still resolve
        // to none — the bug this behavior replaced.
        assertEquals(listOf("system:auditor"), core.roleResolver.directRoles("web@example.com"))

        // And an unknown name fails the whole login rather than being dropped, naming which role was rejected —
        // a silently-ignored claim is what let a "logged in with roles" session resolve to zero.
        val sessionsBefore = webSessionCount(dataSource, "web@example.com")
        val bogus = client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("web@example.com", listOf("system:auditor", "no-such-role")))
        }
        assertEquals(HttpStatusCode.NotFound, bogus.status)
        assertContains(bogus.bodyAsText(), "no-such-role")
        // Rejected atomically: the pre-existing assignment survives a failed claim.
        assertEquals(listOf("system:auditor"), core.roleResolver.directRoles("web@example.com"))
        // …and so does the session table. Roles and mint share one transaction, so a login that fails on any
        // part leaves NEITHER behind — no session authorized by roles that were never committed, and no role
        // rewrite standing under a login that did not succeed.
        assertEquals(sessionsBefore, webSessionCount(dataSource, "web@example.com"))

        // REPLACE, not add — the assertions above would all pass an implementation that only ever inserts, so
        // claim a DIFFERENT single role and require the first one to be gone. Accumulating across logins would
        // leave a principal holding roles no claim asked for.
        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("web@example.com", listOf("system:development-viewer")))
        }
        assertEquals(listOf("system:development-viewer"), core.roleResolver.directRoles("web@example.com"))

        // An EMPTY claim is a deliberate wipe of the direct set, not a no-op: it is how you drop back to
        // whatever groups and JIT grants alone confer.
        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("web@example.com", emptyList()))
        }
        assertEquals(emptyList(), core.roleResolver.directRoles("web@example.com"))

        // Restore the role the rest of this test's session assertions run under.
        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("web@example.com", listOf("system:auditor")))
        }

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
                    assertEquals(AuthAuditRecorder.CHANNEL_SESSION, rs.getString("channel"))
                }
            }
        }
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status)
        val replay = createClient { expectSuccess = false }.get("/auth/me") {
            header(HttpHeaders.Cookie, signedCookie)
        }
        assertEquals(HttpStatusCode.Unauthorized, replay.status)
    }

    @Test
    fun `conditional logout ends only the session id observed by the client`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_conditional_logout"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        application { module(config, ControlPlaneCore(dataSource)) }
        val client = sessionClient()

        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("empty-body@example.com"))
        }
        val emptyBodyLogout = client.post("/auth/logout") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        }
        assertEquals(HttpStatusCode.OK, emptyBodyLogout.status)
        assertEquals(LogoutResponse(ended = true), emptyBodyLogout.body())

        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("conditional@example.com"))
        }
        val staleId = webSessionId(dataSource, "conditional@example.com")

        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("conditional@example.com"))
        }
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

    /**
     * A logout that terminates a session must appear in the trail even when that session no longer resolves.
     * An idle-expired row is still open (`ended_at IS NULL`), so logout ends it for real — keying the audit
     * record off the resolved identity instead of the session reference would silently drop this one.
     */
    @Test
    fun `logging out of an idle-expired session still records the termination`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_idle_logout"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        application { module(config, ControlPlaneCore(dataSource)) }
        val client = sessionClient()

        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("idle-logout@example.com"))
        }
        val id = webSessionId(dataSource, "idle-logout@example.com")
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status, "the row must no longer resolve")

        assertEquals(HttpStatusCode.OK, client.post("/auth/logout").status)
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); assertEquals(ENDED_SIGNED_OUT, rs.getString(1)) }
            }
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
    fun `expired and ended web rows fail closed`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_fail_closed"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv().copy(dbUrl = "", dbUser = "", dbPassword = "")
        application {
            module(config, ControlPlaneCore(dataSource))
            routing {
                serverGet("/test/protected") {
                    call.requireApi() ?: return@serverGet
                    call.respond(HttpStatusCode.OK)
                }
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("missing@example.com"))
        }
        dataSource.connection.use { c ->
            c.prepareStatement("DELETE FROM principal_session WHERE principal = ?").use { ps ->
                ps.setString(1, "missing@example.com")
                ps.executeUpdate()
            }
        }
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status)

        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("expired@example.com"))
        }
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
    fun `session observation and ordinary authenticated routes never slide idle while heartbeat does`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_status"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        application {
            module(config, ControlPlaneCore(dataSource))
            routing {
                serverGet("/api/test/protected") {
                    call.requireApi() ?: return@serverGet
                    call.respond(HttpStatusCode.OK)
                }
            }
        }
        val client = sessionClient()
        val freshClient = createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }

        assertReason(freshClient.get("/auth/session/status"), "none")
        assertReason(freshClient.get("/auth/me"), "none")
        assertReason(freshClient.post("/auth/session/heartbeat"), "none")

        client.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("status@example.com"))
        }
        val id = webSessionId(dataSource, "status@example.com")
        backdateIdle(dataSource, id)
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
        assertEquals(absoluteExpiresAt(dataSource, id), Instant.parse(status.absoluteExpiresAt))
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

        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?").use { ps ->
                ps.setLong(1, id)
                ps.executeUpdate()
            }
        }
        assertReason(client.get("/auth/session/status"), "expired")
        assertReason(client.get("/auth/me"), "expired")
        assertReason(client.post("/auth/session/heartbeat"), "expired")
    }

    @Test
    fun `session status and me surface displacement and bind mismatch reasons`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_status_reasons"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        application { module(config, ControlPlaneCore(dataSource)) }
        val firstClient = sessionClient()
        val secondClient = sessionClient()

        val firstLogin = firstClient.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("reason-status@example.com"))
        }
        assertEquals(HttpStatusCode.OK, firstLogin.status)
        val capturedSession = assertNotNull(firstLogin.headers.getAll(HttpHeaders.SetCookie))
            .first { it.startsWith("$SESSION_COOKIE=") }
            .substringBefore(';')

        val secondLogin = secondClient.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("reason-status@example.com"))
        }
        assertEquals(HttpStatusCode.OK, secondLogin.status)

        assertReason(firstClient.get("/auth/session/status"), "displaced")
        assertReason(firstClient.get("/auth/me"), "displaced")
        assertReason(firstClient.post("/auth/session/heartbeat"), "displaced")

        val replayClient = createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertReason(
            replayClient.get("/auth/session/status") { header(HttpHeaders.Cookie, capturedSession) },
            "displaced",
        )

        val boundLogin = secondClient.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("bind-status@example.com"))
        }
        val boundSession = assertNotNull(boundLogin.headers.getAll(HttpHeaders.SetCookie))
            .first { it.startsWith("$SESSION_COOKIE=") }
            .substringBefore(';')
        val boundId = dataSource.connection.use { c ->
            c.prepareStatement("SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB'").use { ps ->
                ps.setString(1, "bind-status@example.com")
                ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
            }
        }
        val wrongDevice = "${DEVICE_COOKIE}=00000000-0000-0000-0000-000000000000"
        val bindReplay = createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertReason(
            bindReplay.get("/auth/session/status") {
                header(HttpHeaders.Cookie, "$boundSession; $wrongDevice")
            },
            "bind_mismatch",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, boundId)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); assertEquals(ENDED_DEVICE_BIND_MISMATCH, rs.getString(1)) }
            }
        }
        assertReason(
            bindReplay.get("/auth/me") {
                header(HttpHeaders.Cookie, "$boundSession; $wrongDevice")
            },
            "bind_mismatch",
        )

        // /auth/me as the FIRST mismatching request on a fresh session (no prior status call that already
        // ended the row): /auth/me must itself resolve-then-map — the resolve ends the row
        // DEVICE_BIND_MISMATCH and its own ended-reason lookup surfaces bind_mismatch. This guards against
        // regressing to reading the reason before resolving a still-active mismatch.
        val meFirstLogin = secondClient.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("bind-me-first@example.com"))
        }
        val meFirstSession = assertNotNull(meFirstLogin.headers.getAll(HttpHeaders.SetCookie))
            .first { it.startsWith("$SESSION_COOKIE=") }
            .substringBefore(';')
        val meFirstId = dataSource.connection.use { c ->
            c.prepareStatement("SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB'").use { ps ->
                ps.setString(1, "bind-me-first@example.com")
                ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
            }
        }
        assertReason(
            bindReplay.get("/auth/me") { header(HttpHeaders.Cookie, "$meFirstSession; $wrongDevice") },
            "bind_mismatch",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, meFirstId)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); assertEquals(ENDED_DEVICE_BIND_MISMATCH, rs.getString(1)) }
            }
        }

        // An ABSENT pm_did — a stolen pm_session replayed with no device cookie at all — must fail closed
        // to bind_mismatch exactly like a wrong one, never resolve as a wildcard match.
        val absentLogin = secondClient.post("/auth/debug") {
            headers.append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(DebugLogin("bind-absent@example.com"))
        }
        val absentSession = assertNotNull(absentLogin.headers.getAll(HttpHeaders.SetCookie))
            .first { it.startsWith("$SESSION_COOKIE=") }
            .substringBefore(';')
        val absentId = dataSource.connection.use { c ->
            c.prepareStatement("SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB'").use { ps ->
                ps.setString(1, "bind-absent@example.com")
                ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
            }
        }
        assertReason(
            bindReplay.get("/auth/session/status") { header(HttpHeaders.Cookie, absentSession) },
            "bind_mismatch",
        )
        dataSource.connection.use { c ->
            c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ?").use { ps ->
                ps.setLong(1, absentId)
                ps.executeQuery().use { rs -> assertTrue(rs.next()); assertEquals(ENDED_DEVICE_BIND_MISMATCH, rs.getString(1)) }
            }
        }
    }

    @Test
    fun `a pre-cutover principal-roles cookie fails closed to unauthenticated`() = testApplication {
        requireDockerOrSkip()
        val dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_web_legacy_cookie"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        val config = Config.fromEnv().copy(dbUrl = "", dbUser = "", dbPassword = "")
        application {
            module(config, ControlPlaneCore(dataSource))
            routing {
                // Reproduce a pre-cutover {principal, roles} session cookie: HMAC-valid under the same
                // key, but a value that is not a known storage tracker id.
                serverGet("/test/forge-legacy") {
                    val legacy = Json.encodeToString(UserSession.serializer(), UserSession("legacy@example.com"))
                    val signed = SessionTransportTransformerMessageAuthentication(
                        config.sessionSecret.toByteArray(),
                    ).transformWrite(legacy)
                    call.response.cookies.append(Cookie(SESSION_COOKIE, signed, path = "/"))
                    call.respond(HttpStatusCode.NoContent)
                }
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        client.get("/test/forge-legacy")
        // A valid HMAC over a wrong-shape payload must be treated as unauthenticated, never a 500.
        assertEquals(HttpStatusCode.Unauthorized, client.get("/auth/me").status)
    }
}
