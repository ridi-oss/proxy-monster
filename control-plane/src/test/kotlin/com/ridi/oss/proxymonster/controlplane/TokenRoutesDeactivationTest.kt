package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.cookie
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
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
    private lateinit var authz: Authz
    private lateinit var config: Config

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_tokroutes"))
        Flyway.configure().dataSource(ds).load().migrate()
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        userGroupStore = UserGroupStore(ds)
        // authDebug=true below bypasses authz in requireAuthz, so this instance is only needed to satisfy
        // the route signature; back it with the real migrated policy store all the same.
        val policyStore = CedarPolicyStore(ds)
        authz = Authz(CedarEngine(policyStore), policyStore, RoleSource { emptySet() })
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        // principalOf(call) falls back to this literal under authDebug when no session cookie is
        // sent (Tokens.kt:194) — no test here installs one. Deactivate it once, up front, so every
        // mint-route test below sees a deprovisioned caller.
        userGroupStore.createUser(AppUserInput(principal = "debug-user"), tokenStore, accessStore, daemonSessionStore)
        userGroupStore.setUserActive("debug-user", false)
    }

    private fun ApplicationTestBuilder.installTokenRoutes() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            tokenRoutes(config, tokenStore, userGroupStore, authz, AuthAuditRecorder(AuditStore(ds)))
        }
    }

    @Test
    fun `POST api-wire-tokens for a deactivated principal is refused before minting`() = testApplication {
        installTokenRoutes()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }

        val resp = client.post("/api/wire-tokens") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("auth.principal_deprovisioned", resp.body<ApiError>().code)
    }

    @Test
    fun `POST api-tokens for a deactivated principal is refused before minting`() = testApplication {
        installTokenRoutes()
        val client = createClient { install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) } }

        val resp = client.post("/api/tokens") {
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("auth.principal_deprovisioned", resp.body<ApiError>().code)
    }
}
