package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** `/auth/me`, `/auth/debug` and wire-token datasource discovery as cp-go serves them, with `PM_AUTH_DEBUG` off. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthAndIngestRoutesCpGoTest {
    @Serializable
    private data class SessionStatusError(val reason: String)

    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var stack: CpGoStack

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_auth_ingest_cpgo")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = "test-ingest-token",
            sessionSecret = "auth-ingest-route-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        stack = CpGoStack(config, core, database)
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    @Test
    fun `auth me without a session is unauthenticated`() = runBlocking<Unit> {
        val response = stack.client().get("/auth/me")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("no-store", response.headers[HttpHeaders.CacheControl])
        assertEquals(SessionStatusError("none"), response.body())
    }

    @Test
    fun `auth debug is a 404 endpoint when PM_AUTH_DEBUG is off`() = runBlocking<Unit> {
        val response = stack.client().post("/auth/debug") {
            contentType(ContentType.Application.Json)
            setBody("""{"principal":"alice","roles":[]}""")
        }

        assertEquals(HttpStatusCode.NotFound, response.status)
        val error = response.body<ApiError>()
        assertEquals("common.not_found", error.code)
        assertEquals("endpoint", error.params["resource"])
    }

    @Test
    fun `datasource discovery accepts a wire-token Bearer and rejects missing or bad auth`() = runBlocking<Unit> {
        val client = stack.client()

        core.datasourceStore.create(
            DatasourceInput(name = "ds-bearer", engine = "mysql", host = "h", port = 3306, dbName = "app"),
        )
        val token = core.tokenStore.issue(TokenKind.USER, "alice@example.com", emptyList(), name = null, ttlSeconds = 3600).token

        val ok = client.get("/api/datasources") { header(HttpHeaders.Authorization, "Bearer $token") }
        assertEquals(HttpStatusCode.OK, ok.status)
        assertTrue(ok.bodyAsText().contains("ds-bearer"), "expected the datasource in the discovery response")

        // With authDebug off, no auth and a garbage Bearer are both unauthorized.
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/datasources").status)
        val badBearer = client.get("/api/datasources") { header(HttpHeaders.Authorization, "Bearer pmk_not-a-real-token") }
        assertEquals(HttpStatusCode.Unauthorized, badBearer.status)

        // Only SESSION/USER are pmon-client kinds; EDITOR tokens are wire-only.
        val editorToken = core.tokenStore.issue(TokenKind.EDITOR, "editor@example.com", emptyList(), name = null, ttlSeconds = 3600).token
        assertEquals(
            HttpStatusCode.Unauthorized,
            client.get("/api/datasources") { header(HttpHeaders.Authorization, "Bearer $editorToken") }.status,
            "EDITOR-kind tokens must not authenticate the Bearer discovery path",
        )

        // A deactivated principal's still-valid token must fail closed (matches the gRPC decide path).
        dataSource.connection.use { c ->
            c.prepareStatement("INSERT INTO app_user (principal, active) VALUES ('deact@example.com', false)").use { it.executeUpdate() }
        }
        val deactToken = core.tokenStore.issue(TokenKind.USER, "deact@example.com", emptyList(), name = null, ttlSeconds = 3600).token
        assertEquals(
            HttpStatusCode.Unauthorized,
            client.get("/api/datasources") { header(HttpHeaders.Authorization, "Bearer $deactToken") }.status,
            "a deactivated principal's token must not enumerate datasources",
        )
    }
}
