package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.call.body
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * `POST /api/wire-tokens` and `POST /api/tokens` refuse to mint for a deactivated principal, through cp-go.
 * Deleting either route's deactivation check makes exactly one of these fail.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenRoutesDeactivationTest {
    private lateinit var stack: CpGoStack

    // Both routes mint for the session holder, so the caller is the deactivated principal itself.
    private val caller = "dev@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_tokroutes")
        val ds = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(ds).load().migrate()
        val core = ControlPlaneCore(ds)
        val sessions = PrincipalSessionStore(ds, null)
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        core.userGroupStore.createUser(AppUserInput(principal = caller), core.tokenStore, core.accessStore, sessions)
        core.userGroupStore.setUserActive(caller, false)
        stack = CpGoStack(config, core, database) { routing { testLoginRoute(sessions, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    @Test
    fun `POST api-wire-tokens for a deactivated principal is refused before minting`() = runBlocking<Unit> {
        val client = stack.client()
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$caller").status)

        val resp = client.post("/api/wire-tokens") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("auth.principal_deprovisioned", resp.body<ApiError>().code)
    }

    @Test
    fun `POST api-tokens for a deactivated principal is refused before minting`() = runBlocking<Unit> {
        val client = stack.client()
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$caller").status)

        val resp = client.post("/api/tokens") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("auth.principal_deprovisioned", resp.body<ApiError>().code)
    }
}
