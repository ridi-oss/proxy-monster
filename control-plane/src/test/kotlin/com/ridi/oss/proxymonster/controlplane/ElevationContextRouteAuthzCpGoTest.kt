package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The requester-IP context wiring of the approve routes and the datasource list behind cp-go
 * (support/CpGoStack.kt): a `workflow.approve` permit gated only on a tag derived from a trusted edge's
 * in-range `X-Forwarded-For`.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ElevationContextRouteAuthzCpGoTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var datasource: Datasource
    private lateinit var stack: CpGoStack
    private var targetRoleId: Long = 0

    private val approver = "approver@example.com"
    private val requester = "requester@example.com"

    private val trustedNetworkTagRule = """permit(
        principal, action == Action::"context.tag::trusted-network", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };"""

    private val tagGatedApprovePermit = """permit(
        principal in Role::"reviewer", action in [Action::"task.approve", Action::"task.run"], resource
    ) when { context has tags && context.tags.contains("trusted-network") };"""

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.freshDatabase("pm_elev_route_cpgo")
        dataSource = SharedPostgres.hikari(database)
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)

        datasource = core.datasourceStore.create(
            DatasourceInput(name = "elev-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        val reviewerRole = core.policyStore.createRole(RoleInput("reviewer"))
        core.policyStore.createAssignment(RoleAssignmentInput(approver, reviewerRole.id))
        core.userGroupStore.createUser(
            AppUserInput(principal = approver), core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null),
        )
        targetRoleId = core.policyStore.createRole(RoleInput("target-role")).id

        core.cedarPolicyStore.create(CedarPolicyInput(name = "elev-trusted-network-tag", cedarSrc = trustedNetworkTagRule), updatedBy = null)
        core.cedarPolicyStore.create(CedarPolicyInput(name = "elev-tag-gated-approve", cedarSrc = tagGatedApprovePermit), updatedBy = null)

        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "elev-route-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        stack = CpGoStack(config, core, database, extraEnv = mapOf("PM_TRUSTED_PROXIES" to "127.0.0.1")) {
            routing { testLoginRoute(PrincipalSessionStore(dataSource, null), config) }
        }
    }

    @AfterAll
    fun teardown() {
        if (::stack.isInitialized) stack.close()
    }

    private suspend fun signedIn(principal: String): HttpClient = stack.client().also {
        assertEquals(HttpStatusCode.NoContent, it.post("/test/session/$principal").status)
    }

    private fun seedRoleRequest(): Long = core.accessStore.createRequest(
        requester,
        AccessRequestInput(roleId = targetRoleId, datasourceId = datasource.id, reason = "need the role"),
    ).id

    private fun seedQueryRequest(): Long = core.accessStore.createQueryRequest(
        principal = requester, datasourceId = datasource.id, statements = listOf("select 1"), denyReason = "denied",
        sourceDecisionId = null, reason = "need it", title = null,
        evaluatedDecision = "DENY", roleId = targetRoleId,
    ).id

    @Test
    fun `ROLE access-request approve fires the tag-gated permit only through a trusted edge (Access-kt wiring)`() = runBlocking<Unit> {
        val client = signedIn(approver)

        val forbidden = seedRoleRequest()
        val denied = client.post("/api/access-requests/$forbidden/approve")
        assertEquals(
            HttpStatusCode.Forbidden, denied.status,
            "no requester_ip -> no trusted-network tag -> TASK_APPROVE denied (would still pass if the route dropped the requester IP)",
        )

        val approved = seedRoleRequest()
        val ok = client.post("/api/access-requests/$approved/approve") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(
            HttpStatusCode.OK, ok.status,
            "trusted-edge requester_ip -> derived tag -> approve succeeds; FAILS if the route drops the requester IP or the datasource tag-scoping",
        )
    }

    @Test
    fun `approve routes write a kind=admin audit event through the wiring`() = runBlocking<Unit> {
        val client = signedIn(approver)

        val roleReq = seedRoleRequest()
        assertEquals(
            HttpStatusCode.OK,
            client.post("/api/access-requests/$roleReq/approve") { header("X-Forwarded-For", "100.100.5.5") }.status,
        )
        assertEquals(1, adminAuditCount("approve access request #$roleReq:%"), "ROLE approve route must audit")

        val queryReq = seedQueryRequest()
        assertEquals(
            HttpStatusCode.OK,
            client.post("/api/approvals/$queryReq/approve") {
                header("X-Forwarded-For", "100.100.5.5")
                contentType(ContentType.Application.Json)
                setBody("""{"revision":1}""")
            }.status,
        )
        assertEquals(1, adminAuditCount("approve query request #$queryReq%"), "QUERY approve route must audit")
    }

    @Test
    fun `datasource list is filtered by connect only when connectable is requested`() = runBlocking<Unit> {
        val client = signedIn(requester)

        val full = client.get("/api/datasources")
        assertEquals(HttpStatusCode.OK, full.status)
        assertTrue(full.bodyAsText().contains(datasource.name), "the default list is unfiltered (compose needs it)")

        val filtered = client.get("/api/datasources?connectable=true")
        assertEquals(HttpStatusCode.OK, filtered.status)
        assertFalse(filtered.bodyAsText().contains(datasource.name), "no datasource.connect -> excluded from ?connectable=true")

        val connect = core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "elev-requester-connect-list",
                cedarSrc = """permit(principal == User::"$requester", action == Action::"datasource.connect", resource == Datasource::"${datasource.name}");""",
            ),
            updatedBy = null,
        )
        try {
            val allowed = client.get("/api/datasources?connectable=true")
            assertTrue(allowed.bodyAsText().contains(datasource.name), "with datasource.connect -> included in ?connectable=true")
        } finally {
            core.cedarPolicyStore.setEnabled(connect.id, false, "test-cleanup")
        }
    }

    private fun adminAuditCount(statementLike: String): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM audit_event WHERE kind='admin' AND statement LIKE ?").use { ps ->
            ps.setString(1, statementLike)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }
}
