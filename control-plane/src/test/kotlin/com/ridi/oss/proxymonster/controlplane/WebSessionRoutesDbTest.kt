package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.routing.get as serverGet
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.testing.ApplicationTestBuilder
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

/**
 * The web session cookie as `Application.module()` installs it: a minted row resolves through
 * [PrincipalSessionStorage] and [webSession], and every way a row stops being live fails closed.
 */
class WebSessionRoutesDbTest {
    private fun ApplicationTestBuilder.client(): HttpClient = createClient {
        expectSuccess = false
        install(HttpCookies)
        install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    }

    private fun ApplicationTestBuilder.bareClient(): HttpClient = createClient { expectSuccess = false }

    private fun migratedDatabase(prefix: String): DataSource {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase(prefix))
        Flyway.configure().dataSource(ds).load().migrate()
        return ds
    }

    /** Boots the full module plus a login route and a session-gated probe; returns the module's store. */
    private fun ApplicationTestBuilder.boot(config: Config, dataSource: DataSource): () -> PrincipalSessionStore {
        var store: PrincipalSessionStore? = null
        application {
            module(config, ControlPlaneCore(dataSource))
            val sessions = attributes[PRINCIPAL_SESSION_STORE]
            store = sessions
            routing {
                testLoginRoute(sessions, config)
                serverGet("/test/protected") {
                    call.requireApi() ?: return@serverGet
                    call.respond(HttpStatusCode.OK)
                }
            }
        }
        return { requireNotNull(store) }
    }

    private suspend fun HttpClient.login(principal: String): HttpResponse =
        post("/test/session/$principal").also { assertEquals(HttpStatusCode.NoContent, it.status) }

    private fun HttpResponse.cookie(name: String): String =
        assertNotNull(headers.getAll(HttpHeaders.SetCookie)).first { it.startsWith("$name=") }

    private fun webSessionId(dataSource: DataSource, principal: String): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT id FROM principal_session WHERE principal = ? AND kind = 'WEB' ORDER BY id DESC LIMIT 1").use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getLong(1) }
        }
    }

    private fun deviceId(dataSource: DataSource, id: Long): String = dataSource.connection.use { c ->
        c.prepareStatement("SELECT device_id FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getString(1) }
        }
    }

    private fun endedReason(dataSource: DataSource, id: Long): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT ended_reason FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> assertTrue(rs.next()); rs.getString(1) }
        }
    }

    private fun idleExpiresAt(dataSource: DataSource, id: Long): Instant = dataSource.connection.use { c ->
        c.prepareStatement("SELECT idle_expires_at FROM principal_session WHERE id = ?").use { ps ->
            ps.setLong(1, id)
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

    @Test
    fun `a minted session resolves through its cookie until the row is ended`() = testApplication {
        requireDockerOrSkip()
        val dataSource = migratedDatabase("pm_web_routes")
        val config = Config.fromEnv { name ->
            if (name == "PM_WEB_SESSION_ABSOLUTE") "90s" else null
        }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val store = boot(config, dataSource)
        val client = client()

        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
        val login = client.login("web@example.com")
        assertContains(login.cookie(SESSION_COOKIE), "Max-Age=90;")
        val deviceCookie = login.cookie(DEVICE_COOKIE)
        assertContains(deviceCookie, "Max-Age=7776000")
        assertContains(deviceCookie, "Path=/")
        assertContains(deviceCookie, "HttpOnly")
        assertContains(deviceCookie, "SameSite=Lax")
        assertEquals(HttpStatusCode.OK, client.get("/test/protected").status)

        val id = webSessionId(dataSource, "web@example.com")
        val signedCookie = login.cookie(SESSION_COOKIE).substringBefore(';')
        assertEquals("web@example.com", store().endWebOwner(id, ENDED_SIGNED_OUT))
        assertEquals(ENDED_SIGNED_OUT, endedReason(dataSource, id))
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
        val replay = bareClient().get("/test/protected") { header(HttpHeaders.Cookie, signedCookie) }
        assertEquals(HttpStatusCode.Unauthorized, replay.status)
    }

    @Test
    fun `expired and deleted web rows fail closed`() = testApplication {
        requireDockerOrSkip()
        val dataSource = migratedDatabase("pm_web_fail_closed")
        val config = Config.fromEnv().copy(dbUrl = "", dbUser = "", dbPassword = "")
        val store = boot(config, dataSource)
        val client = client()

        client.login("missing@example.com")
        update(dataSource, "DELETE FROM principal_session WHERE id = ?", webSessionId(dataSource, "missing@example.com"))
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)

        client.login("expired@example.com")
        update(
            dataSource,
            "UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = ?",
            webSessionId(dataSource, "expired@example.com"),
        )
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
        assertNull(store().resolveWeb(-1, null))

        // An idle-expired row no longer resolves but is still open, so ending it still records the end.
        client.login("idle@example.com")
        val idle = webSessionId(dataSource, "idle@example.com")
        update(dataSource, "UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?", idle)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
        assertEquals("idle@example.com", store().endWebOwner(idle, ENDED_SIGNED_OUT))
        assertEquals(ENDED_SIGNED_OUT, endedReason(dataSource, idle))
    }

    @Test
    fun `authenticated requests never slide idle while touchWeb does`() = testApplication {
        requireDockerOrSkip()
        val dataSource = migratedDatabase("pm_web_status")
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val store = boot(config, dataSource)
        val client = client()

        client.login("status@example.com")
        val id = webSessionId(dataSource, "status@example.com")
        val device = deviceId(dataSource, id)
        update(
            dataSource,
            """UPDATE principal_session
               SET last_seen_at = now() - interval '3 minutes', idle_expires_at = idle_expires_at - interval '3 minutes'
               WHERE id = ?""",
            id,
        )
        val beforeObserve = idleExpiresAt(dataSource, id)

        assertEquals(HttpStatusCode.OK, client.get("/test/protected").status)
        assertEquals(beforeObserve, idleExpiresAt(dataSource, id), "an authenticated request must not extend idle")

        val touched = assertNotNull(store().touchWeb(id, device))
        val afterTouch = idleExpiresAt(dataSource, id)
        assertTrue(afterTouch.isAfter(beforeObserve), "touchWeb must extend an eligible idle deadline")
        assertEquals(afterTouch, touched.idleExpiresAt)
        assertEquals(afterTouch, assertNotNull(store().touchWeb(id, device)).idleExpiresAt)
        assertEquals(afterTouch, idleExpiresAt(dataSource, id), "touchWeb must throttle within the slide interval")

        update(dataSource, "UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = ?", id)
        assertNull(store().touchWeb(id, device))
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
    }

    @Test
    fun `displacement and a device-bind mismatch end the row and fail closed`() = testApplication {
        requireDockerOrSkip()
        val dataSource = migratedDatabase("pm_web_status_reasons")
        val config = Config.fromEnv { null }.copy(dbUrl = "", dbUser = "", dbPassword = "")
        val store = boot(config, dataSource)
        val firstClient = client()
        val secondClient = client()

        val captured = firstClient.login("reason@example.com").cookie(SESSION_COOKIE).substringBefore(';')
        val first = webSessionId(dataSource, "reason@example.com")
        secondClient.login("reason@example.com")
        assertEquals(HttpStatusCode.Unauthorized, firstClient.get("/test/protected").status)
        assertEquals(HttpStatusCode.OK, secondClient.get("/test/protected").status)
        assertEquals(ENDED_DISPLACED, store().webEndedReason(first))
        assertEquals(
            HttpStatusCode.Unauthorized,
            bareClient().get("/test/protected") { header(HttpHeaders.Cookie, captured) }.status,
        )

        val wrongDevice = "$DEVICE_COOKIE=00000000-0000-0000-0000-000000000000"
        val bound = secondClient.login("bind@example.com").cookie(SESSION_COOKIE).substringBefore(';')
        val boundId = webSessionId(dataSource, "bind@example.com")
        assertEquals(
            HttpStatusCode.Unauthorized,
            bareClient().get("/test/protected") { header(HttpHeaders.Cookie, "$bound; $wrongDevice") }.status,
        )
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, store().webEndedReason(boundId))

        // A replayed session cookie with no device cookie at all is a mismatch, never a wildcard match.
        val absent = secondClient.login("bind-absent@example.com").cookie(SESSION_COOKIE).substringBefore(';')
        val absentId = webSessionId(dataSource, "bind-absent@example.com")
        assertEquals(
            HttpStatusCode.Unauthorized,
            bareClient().get("/test/protected") { header(HttpHeaders.Cookie, absent) }.status,
        )
        assertEquals(ENDED_DEVICE_BIND_MISMATCH, store().webEndedReason(absentId))
    }

    @Test
    fun `a pre-cutover principal-roles cookie fails closed to unauthenticated`() = testApplication {
        requireDockerOrSkip()
        val dataSource = migratedDatabase("pm_web_legacy_cookie")
        val config = Config.fromEnv().copy(dbUrl = "", dbUser = "", dbPassword = "")
        boot(config, dataSource)
        application {
            routing {
                // HMAC-valid under the same key, but a value that is not a known storage tracker id.
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
        val client = client()
        client.get("/test/forge-legacy")
        assertEquals(HttpStatusCode.Unauthorized, client.get("/test/protected").status)
    }
}
