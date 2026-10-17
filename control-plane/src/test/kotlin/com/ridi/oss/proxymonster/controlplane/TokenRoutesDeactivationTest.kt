package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.Serializable
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals

/**
 * Route-level coverage of [Route.tokenRoutes]'s deactivation backstop:
 * `POST /api/wire-tokens` and `POST /api/tokens` refuse to mint for a deactivated principal
 * (Tokens.kt:204, :223) — the same deprovisioning invariant [RenewalWindowTest]/[DeprovisionDbTest]
 * cover for session renewal and credential revocation, exercised here through the HTTP routes
 * themselves so the branches (not just the store methods underneath them) stay covered. Each
 * assertion is written so that deleting the corresponding `isDeactivated` check in Tokens.kt makes
 * exactly that test fail. (The equivalent deactivation-recheck coverage for a presented token on the
 * gRPC decide path lives in GrpcDecideHandlerDbTest.)
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenRoutesDeactivationTest {
    private lateinit var ds: DataSource
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var cpGo: CpGoStack
    private lateinit var config: Config
    private lateinit var sessionStore: PrincipalSessionStore

    // The deprovisioned caller every mint test below runs as. Both routes mint for the SESSION-holder, so
    // the caller has to be the deactivated principal itself for the backstop to be what refuses.
    private val caller = "dev@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_tokroutes")
        ds = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(ds).load().migrate()
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        sessionStore = PrincipalSessionStore(ds, null)
        userGroupStore = UserGroupStore(ds)
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        userGroupStore.createUser(AppUserInput(principal = caller), tokenStore, accessStore, daemonSessionStore)
        userGroupStore.setUserActive(caller, false)
        cpGo = CpGoStack(config, ControlPlaneCore(ds), database) { routing { testLoginRoute(sessionStore, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    @Suppress("UnusedReceiverParameter")
    private fun ApplicationTestBuilder.installTokenRoutes(): HttpClient = cpGo.client()

    @Test
    fun `POST api-wire-tokens for a deactivated principal is refused before minting`() = testApplication {
        val client = installTokenRoutes()
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$caller").status)

        val resp = client.post("/api/wire-tokens") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("auth.principal_deprovisioned", resp.body<ApiError>().code)
    }

    @Test
    fun `POST api-tokens for a deactivated principal is refused before minting`() = testApplication {
        val client = installTokenRoutes()
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$caller").status)

        val resp = client.post("/api/tokens") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("auth.principal_deprovisioned", resp.body<ApiError>().code)
    }
}
