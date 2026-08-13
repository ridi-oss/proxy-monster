package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
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
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuditReadRoutesDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var auditStore: AuditStore
    private lateinit var roleResolver: RoleResolver
    private lateinit var aliceIds: Set<Long>
    private lateinit var bobIds: Set<Long>
    private var e3Id: Long = -1

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_audit_read_routes"))
        Flyway.configure().dataSource(dataSource).load().migrate()

        auditStore = AuditStore(dataSource)
        val policyStore = PolicyStore(dataSource)
        val userGroupStore = UserGroupStore(dataSource)
        val accessStore = AccessStore(dataSource)
        roleResolver = RoleResolver(dataSource, userGroupStore, accessStore)

        // The whole audit log is granted to `system:admin` by default; there is no separate `auditor` role. Assign the
        // audit reader to the shipped system:admin role.
        val adminRole = policyStore.getRoleByName("system:admin")!!
        policyStore.createAssignment(RoleAssignmentInput(principal = AUDITOR, roleId = adminRole.id))

        aliceIds = setOf(
            insertNormal(ALICE, "select alice_one"),
            insertNormal(ALICE, "select alice_two"),
        )
        bobIds = setOf(
            insertNormal(BOB, "select bob_one"),
            insertNormal(BOB, "select bob_two"),
        )
        e3Id = auditStore.insert(
            AuditEvent(
                principal = ALICE,
                datasource = "acme",
                statement = "approval #1 result-viewed-by-requester",
                decision = Decision.ALLOW,
                kind = "approval_lifecycle",
            ),
        )
    }

    @Test
    fun `an unauthenticated list is rejected without authorization`() = testApplication {
        val app = wireAuditApp(authDebug = false)
        app.roleSource.reset()

        val response = app.client.get("/api/audit")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("common.unauthenticated", response.body<ApiError>().code)
        assertEquals(0, app.roleSource.lookupCount)
    }

    @Test
    fun `ordinary principal sees only own rows and denied detail is indistinguishable from missing`() = testApplication {
        val app = wireAuditApp(authDebug = false)
        app.client.login(ALICE)

        app.roleSource.reset()
        val listResponse = app.client.get("/api/audit?limit=500")
        assertEquals(HttpStatusCode.OK, listResponse.status)
        val records: List<AuditEvent> = listResponse.body()
        assertEquals(aliceIds + e3Id, records.mapNotNull { it.id }.toSet())
        assertTrue(records.all { it.principal == ALICE })
        assertEquals(1, app.roleSource.lookupCount, "the list must make one collection authorization")

        app.roleSource.reset()
        val ownResponse = app.client.get("/api/audit/${aliceIds.first()}")
        assertEquals(HttpStatusCode.OK, ownResponse.status)
        assertEquals(ALICE, ownResponse.body<AuditEvent>().principal)
        assertEquals(1, app.roleSource.lookupCount)

        app.roleSource.reset()
        val deniedResponse = app.client.get("/api/audit/${bobIds.first()}")
        assertEquals(HttpStatusCode.NotFound, deniedResponse.status)
        val deniedBody = deniedResponse.bodyAsText()
        val deniedError = Json.decodeFromString<ApiError>(deniedBody)
        assertEquals("common.not_found", deniedError.code)
        assertEquals(mapOf("resource" to "audit record"), deniedError.params)
        assertEquals(1, app.roleSource.lookupCount)

        app.roleSource.reset()
        val missingResponse = app.client.get("/api/audit/${Long.MAX_VALUE}")
        assertEquals(deniedResponse.status, missingResponse.status)
        assertEquals(deniedBody, missingResponse.bodyAsText())
        assertEquals(0, app.roleSource.lookupCount, "a missing row must not reach Cedar")
    }

    @Test
    fun `non-numeric audit id is a bad id, not a lookup`() = testApplication {
        val app = wireAuditApp(authDebug = false)
        app.client.login(ALICE)

        val response = app.client.get("/api/audit/not-a-number")

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("common.bad_id", response.body<ApiError>().code)
    }

    @Test
    fun `old decisions route is removed`() = testApplication {
        val app = wireAuditApp(authDebug = true)
        assertEquals(HttpStatusCode.NotFound, app.client.get("/api/decisions").status)
    }

    @Test
    fun `auditor sees every row and can read details`() = testApplication {
        val app = wireAuditApp(authDebug = false)
        app.client.login(AUDITOR)

        app.roleSource.reset()
        val listResponse = app.client.get("/api/audit?limit=500")
        assertEquals(HttpStatusCode.OK, listResponse.status)
        val records: List<AuditEvent> = listResponse.body()
        assertEquals(normalIds + e3Id, records.mapNotNull { it.id }.toSet())
        assertEquals(setOf(ALICE, BOB), records.map { it.principal }.toSet())
        assertEquals("approval_lifecycle", records.single { it.id == e3Id }.kind)
        assertEquals(1, app.roleSource.lookupCount, "row count must not affect collection authorization")

        for (id in normalIds + e3Id) {
            app.roleSource.reset()
            val detailResponse = app.client.get("/api/audit/$id")
            assertEquals(HttpStatusCode.OK, detailResponse.status)
            assertEquals(id, detailResponse.body<AuditEvent>().id)
            assertEquals(1, app.roleSource.lookupCount)
        }
    }

    /**
     * `PM_AUTH_DEBUG` authenticates nobody: with no session the read is 401 before any decision, and a dev
     * session is decided exactly like an SSO one. This principal holds no audit.read grant on the
     * collection, so it falls back to its own rows (none) rather than being handed every principal's trail.
     */
    @Test
    fun `under auth debug a sessionless read is rejected and a signed-in read still authorizes`() = testApplication {
        val app = wireAuditApp(authDebug = true)

        app.roleSource.reset()
        assertEquals(HttpStatusCode.Unauthorized, app.client.get("/api/audit?limit=500").status)
        assertEquals(0, app.roleSource.lookupCount, "an unauthenticated read must not reach Cedar")

        app.client.login(GRANTLESS)
        app.roleSource.reset()
        val listResponse = app.client.get("/api/audit?limit=500")
        assertEquals(HttpStatusCode.OK, listResponse.status)
        assertEquals(emptyList(), listResponse.body<List<AuditEvent>>().mapNotNull { it.id })
        assertTrue(app.roleSource.lookupCount > 0, "the decision must run: authDebug authenticates, never authorizes")

        // Another principal's record is not readable without a grant — 404, the same non-oracle the
        // collection fallback implies.
        val detailResponse = app.client.get("/api/audit/${bobIds.first()}")
        assertEquals(HttpStatusCode.NotFound, detailResponse.status)
    }

    @Test
    fun `requester_ip from a trusted edge gates the audit-collection read`() = testApplication {
        // A role whose ONLY audit.read grant is ip-gated — so the /api/audit collection authorization is
        // observably sensitive to requester_ip. Pins the httpAuthzContext argument at the audit route: drop it
        // and the in-range caller would no longer read the whole collection.
        val edgeAuditor = "edge-auditor"
        val policyStore = PolicyStore(dataSource)
        val role = policyStore.createRole(RoleInput(name = "ip-auditor", description = "ip-gated audit route test"))
        policyStore.createAssignment(RoleAssignmentInput(principal = edgeAuditor, roleId = role.id))
        CedarPolicyStore(dataSource).create(
            CedarPolicyInput(
                name = "ip-gated-audit-read",
                cedarSrc = """permit(principal in Role::"ip-auditor", action == Action::"audit.read", resource)
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )

        val app = wireAuditApp(authDebug = false, trustedProxies = setOf("localhost"))
        app.client.login(edgeAuditor)

        // In-range requester_ip via the trusted edge -> audit.read on AuditLog Allows -> the whole collection.
        val inRange = app.client.get("/api/audit?limit=500") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(HttpStatusCode.OK, inRange.status)
        assertEquals(normalIds + e3Id, inRange.body<List<AuditEvent>>().mapNotNull { it.id }.toSet())

        // Out of range -> Deny -> falls back to own rows only (this principal authored none).
        val outOfRange = app.client.get("/api/audit?limit=500") { header("X-Forwarded-For", "198.51.100.10") }
        assertEquals(HttpStatusCode.OK, outOfRange.status)
        assertTrue(
            outOfRange.body<List<AuditEvent>>().isEmpty(),
            "no trusted-range requester_ip -> no collection read -> only the caller's own (zero) rows",
        )
    }

    private val normalIds: Set<Long>
        get() = aliceIds + bobIds

    private fun insertNormal(principal: String, statement: String): Long = auditStore.insert(
        AuditEvent(
            principal = principal,
            datasource = "acme",
            statement = statement,
            decision = Decision.ALLOW,
        ),
    )

    private fun config(authDebug: Boolean, trustedProxies: Set<String> = emptySet()) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = authDebug,
        secretToken = null,
        sessionSecret = "audit-route-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
        trustedProxies = trustedProxies,
    )

    private fun ApplicationTestBuilder.wireAuditApp(authDebug: Boolean, trustedProxies: Set<String> = emptySet()): AuditTestApp {
        val config = config(authDebug, trustedProxies)
        val roleSource = CountingRoleSource(roleResolver)
        val cedarPolicyStore = CedarPolicyStore(dataSource)
        val authz = Authz(CedarEngine(cedarPolicyStore), cedarPolicyStore, roleSource)
        application { installAuditTestApp(config, authz) }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        return AuditTestApp(client, roleSource)
    }

    private fun Application.installAuditTestApp(config: Config, authz: Authz) {
        val sessionStore = PrincipalSessionStore(dataSource, null)
        attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) {
            webSessionCookie(sessionStore, config.sessionSecret)
        }
        routing {
            testLoginRoute(sessionStore, config)
            auditRoutes(config, auditStore, authz)
        }
    }

    private suspend fun HttpClient.login(principal: String) {
        assertEquals(HttpStatusCode.NoContent, post("/test/session/$principal").status)
    }

    private data class AuditTestApp(
        val client: HttpClient,
        val roleSource: CountingRoleSource,
    )

    private class CountingRoleSource(private val delegate: RoleResolver) : RoleSource {
        private val lookups = AtomicInteger()

        val lookupCount: Int
            get() = lookups.get()

        fun reset() {
            lookups.set(0)
        }

        override fun rolesOf(principal: String): Set<String> {
            lookups.incrementAndGet()
            return delegate.resolve(principal)
        }
    }

    private companion object {
        const val ALICE = "alice"
        const val BOB = "bob"
        const val AUDITOR = "auditor-user"

        // A principal with no roles and no audited rows of its own, so a read that fell back to own-rows
        // returns an observably EMPTY list rather than one that merely looks filtered.
        const val GRANTLESS = "grantless"
    }
}
