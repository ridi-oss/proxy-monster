package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `GET /api/access-requests` and `GET /api/access-grants` forward-filter every row through `task.read`, so
 * one principal never sees another's. Both are covered together because they are the same shape twice: a
 * listing that decides per row, where anything short-circuiting the filter returns the whole table.
 *
 * The shipped seeds decide this: `workflow.self-request` grants `task.read` on a Request whose requester is
 * the caller, `workflow.self-grant` on an AccessGrant it owns. Neither test grants anything beyond those, so
 * a filter that stops running shows up immediately as a stranger's row in the response.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AccessListingForwardFilterDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var config: Config
    private var roleId: Long = 0

    private val owner = "owner@example.com"
    private val stranger = "stranger@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_access_forward_filter"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)

        val sessionStore = PrincipalSessionStore(dataSource, null)
        for (p in listOf(owner, stranger)) {
            core.userGroupStore.createUser(AppUserInput(principal = p), core.tokenStore, core.accessStore, sessionStore)
        }
        roleId = core.policyStore.createRole(RoleInput("forward-filter-role")).id

        // One ROLE request owned by `owner`, approved so it also produces an access_grant row for `owner`.
        val request = core.accessStore.createRequest(owner, AccessRequestInput(roleId = roleId, requestedDurationSec = 3600))
        core.accessStore.approve(request.id, 3600, owner)

        // authDebug=TRUE throughout: the flag is the thing under test, so a listing keyed on it fails here.
        // Asserting a security property under the safe configuration asserts almost nothing.
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "access-forward-filter-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
    }

    private fun ApplicationTestBuilder.wire(): HttpClient {
        application { installRoutes() }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private fun Application.installRoutes() {
        val sessionStore = PrincipalSessionStore(dataSource, null)
        attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
        routing {
            testLoginRoute(sessionStore, config)
            accessRoutes(
                config, core.accessStore, core.authz, core.datasourceStore, core.roleResolver,
                ManagementAuditRecorder(AuditStore(dataSource)),
            )
        }
    }

    @Test
    fun `the requests listing shows a principal its own rows and never another's`() = testApplication {
        val client = wire()

        client.post("/test/session/$owner")
        assertTrue(
            client.get("/api/access-requests").bodyAsText().contains(owner),
            "the owner must see the request it opened",
        )

        client.post("/test/session/$stranger")
        val response = client.get("/api/access-requests")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            emptyList(), response.body<List<AccessRequest>>(),
            "a stranger holding no task.read grant must see an empty list, not merely a redacted one",
        )
    }

    @Test
    fun `the grants listing shows a principal its own rows and never another's`() = testApplication {
        val client = wire()

        client.post("/test/session/$owner")
        assertTrue(
            client.get("/api/access-grants").bodyAsText().contains(owner),
            "the owner must see the grant it holds",
        )

        client.post("/test/session/$stranger")
        val response = client.get("/api/access-grants")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            emptyList(), response.body<List<AccessGrant>>(),
            "a stranger must see an empty list, not merely one with the owner's row redacted",
        )
    }

    /**
     * `?principal=` selects whose rows to LOOK for; it never widens what may be returned. Asking for another
     * principal's grants by name yields nothing, because each row still has to clear `task.read`.
     */
    @Test
    fun `a principal query parameter does not widen the grants listing`() = testApplication {
        val client = wire()
        client.post("/test/session/$stranger")

        val response = client.get("/api/access-grants?principal=$owner")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            emptyList(), response.body<List<AccessGrant>>(),
            "naming another principal must not bypass the per-row filter",
        )
    }

    /** `PM_AUTH_DEBUG` enables a login, so a caller that has not used one is refused with no row attached. */
    @Test
    fun `both listings reject a caller with no session even under auth debug`() = testApplication {
        val client = wire()
        val requests = client.get("/api/access-requests")
        assertEquals(HttpStatusCode.Unauthorized, requests.status)
        assertFalse(requests.bodyAsText().contains(owner), "a rejected read must carry no row: ${requests.bodyAsText()}")

        val grants = client.get("/api/access-grants")
        assertEquals(HttpStatusCode.Unauthorized, grants.status)
        assertFalse(grants.bodyAsText().contains(owner), "a rejected read must carry no row: ${grants.bodyAsText()}")

        // Naming a principal is not a way in either.
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/access-grants?principal=$owner").status)
    }
}
