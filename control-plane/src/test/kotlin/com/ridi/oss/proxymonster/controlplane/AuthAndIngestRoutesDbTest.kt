package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * These three routes (`/auth/me`, `/auth/debug`, `/api/ingest/decision`) live inline in
 * `Application.module()`, not in a dedicated `Route.xRoutes()` extension, so they can only be exercised
 * by booting the full module (mirrors ReadinessDiagnosticDbTest.kt). Pins the migration of App.kt's
 * vestigial `ErrorResponse("...")` envelopes onto `ApiError(code, params)`.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthAndIngestRoutesDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `auth me without a session is unauthenticated`() = testApplication {
        application { module(config(), ControlPlaneCore(migratedDatabase("pm_auth_ingest_me"))) }
        val client = wireClient()

        val response = client.get("/auth/me")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("no-store", response.headers[HttpHeaders.CacheControl])
        assertEquals(SessionStatusError("none"), response.body())
    }

    @Test
    fun `auth debug is a 404 endpoint when PM_AUTH_DEBUG is off`() = testApplication {
        application { module(config(authDebug = false), ControlPlaneCore(migratedDatabase("pm_auth_ingest_debug"))) }
        val client = wireClient()

        val response = client.post("/auth/debug") {
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"alice","roles":[]}""")
        }

        assertEquals(HttpStatusCode.NotFound, response.status)
        val error = response.body<ApiError>()
        assertEquals("common.not_found", error.code)
        assertEquals("endpoint", error.params["resource"])
    }

    @Test
    fun `ingest with a wrong token is an invalid ingest token`() = testApplication {
        application { module(config(), ControlPlaneCore(migratedDatabase("pm_auth_ingest_wrong_token"))) }
        val client = wireClient()

        val response = client.post("/api/ingest/decision") {
            header("X-PM-Ingest-Token", "wrong")
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"alice","datasource":"ds","statement":"select 1","decision":"ALLOW"}""")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        val error = response.body<ApiError>()
        assertEquals("common.invalid_token", error.code)
        assertEquals("ingest", error.params["kind"])
    }

    @Test
    fun `an unhandled exception is caught by the StatusPages fallback without leaking the cause`() = testApplication {
        application {
            module(config(), ControlPlaneCore(migratedDatabase("pm_status_pages_fallback")))
            // A test-only route registered AFTER module() installed StatusPages, so the SAME application-level
            // exception<Throwable> handler catches its throw — the only way to exercise the catch-all
            // (App.kt:185-189) end to end. A regression that re-serialized `cause.message` (e.g. a DB error
            // carrying connection details) would leak SENTINEL here while every other test stayed green.
            routing {
                get("/__boom") { throw RuntimeException(SENTINEL) }
            }
        }
        val client = wireClient()

        val response = client.get("/__boom")

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        val body = response.bodyAsText()
        assertFalse(body.contains(SENTINEL), "the catch-all must NOT serialize cause.message — an internal exception must never reach the client")
        val error = Json.decodeFromString<ApiError>(body)
        assertEquals("common.fallback", error.code)
        assertEquals(emptyMap(), error.params)
    }

    @Test
    fun `ingest with the correct token and a minimal record is accepted`() = testApplication {
        val dataSource = migratedDatabase("pm_auth_ingest_good_token")
        application { module(config(), ControlPlaneCore(dataSource)) }
        val client = wireClient()

        val before = Instant.now()
        val response = client.post("/api/ingest/decision") {
            header("X-PM-Ingest-Token", INGEST_TOKEN)
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"alice","datasource":"ds","statement":"select 1","decision":"ALLOW"}""")
        }
        val after = Instant.now()

        assertEquals(HttpStatusCode.Accepted, response.status)
        dataSource.connection.use { connection ->
            connection.prepareStatement(
                "SELECT ts, kind, prev_hash, row_hash FROM audit_event WHERE principal = 'alice'",
            ).use { statement ->
                statement.executeQuery().use { result ->
                    assertEquals(true, result.next())
                    val stored = result.getTimestamp("ts").toInstant()
                    assertEquals("decision", result.getString("kind"))
                    assertEquals(32, result.getBytes("prev_hash").size)
                    assertEquals(32, result.getBytes("row_hash").size)
                    assertEquals(true, !stored.isBefore(before) && !stored.isAfter(after))
                }
            }
        }
    }

    private fun io.ktor.server.testing.ApplicationTestBuilder.wireClient() = createClient {
        expectSuccess = false
        install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    }

    private fun migratedDatabase(prefix: String): DataSource {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase(prefix))
        Flyway.configure().dataSource(ds).load().migrate()
        return ds
    }

    private fun config(authDebug: Boolean = false) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = authDebug,
        secretToken = INGEST_TOKEN,
        sessionSecret = "auth-ingest-route-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
    )

    private companion object {
        const val INGEST_TOKEN = "test-ingest-token"

        // A distinctive marker only ever present in a thrown exception's message — asserted ABSENT from the
        // 500 body, so a catch-all that leaked cause.message would be caught.
        const val SENTINEL = "sentinel-secret-9f83c2-do-not-leak"
    }
}
