package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.header
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * ROUTE-level coverage of the non-query context wiring that [ElevationContextTagTest]
 * (which drives the [com.ridi.oss.proxymonster.controlplane.authz.authorizeWithContext] helper directly)
 * cannot pin: whether the PRODUCTION routes actually thread `call.httpAuthzContext(config)` + the request's
 * datasource into that helper. Deleting the wiring at Access.kt (the ROLE access-request TASK_APPROVE
 * sites) or Approvals.kt (the query-approval `mayDecide` call) leaves the helper test
 * green — so this test drives the REAL routes through [testApplication] end to end.
 *
 * The gate is a `workflow.approve` permit conditioned ONLY on a requester-IP-derived datasource `context.tag`
 * (the ElevationContextTagTest `trustedNetworkTagRule` + `tagGatedApprovePermit` shape). A request that
 * arrives through a TRUSTED edge (socket peer in `trustedProxies` + an in-range `X-Forwarded-For`) resolves
 * `requester_ip` → derives the tag → the permit fires → APPROVE. The SAME request without the trusted XFF
 * (requester_ip absent → tag not derived) FORBIDS. Dropping `httpAuthzContext` (requester_ip never reaches
 * Cedar) OR the datasource tag-scoping (no datasource in scope → no tag derivation) turns the trusted case
 * FORBIDDEN, failing this test — the teeth [ElevationContextTagTest] lacks.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ElevationContextRouteAuthzDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var runExecService: RunExecService
    // Real (non-null) result storage — required so the /execute positive control (test b below) can
    // distinguish "the R-scoped authority gate passed" (503 no_proxy_attached) from "result storage isn't
    // configured" (503 result_storage_not_configured); Approvals.kt:611 gates on it AFTER the authority
    // check at :603, so a real store keeps that positive control unambiguous.
    private lateinit var resultStore: QueryResultStore
    private lateinit var datasource: Datasource
    private lateinit var config: Config
    private var targetRoleId: Long = 0

    private val approver = "approver@example.com"
    private val requester = "requester@example.com"

    // requester_ip in the example range 100.100.0.0/16 (inside the CGNAT block 100.64.0.0/10) earns the "trusted-network" tag (principal-agnostic).
    private val trustedNetworkTagRule = """permit(
        principal, action == Action::"context.tag::trusted-network", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };"""

    // A TASK_APPROVE permit gated ONLY on the derived tag — the consuming end of the two-pass. The
    // approver holds Role::"reviewer"; without the derived tag (no requester_ip / no datasource) it cannot fire.
    private val tagGatedApprovePermit = """permit(
        principal in Role::"reviewer", action == Action::"task.approve", resource
    ) when { context has tags && context.tags.contains("trusted-network") };"""

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_elev_route"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        runExecService = RunExecService(core) // required by approvalRoutes; /execute reaches it (test b below)
        resultStore = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))

        datasource = core.datasourceStore.create(
            DatasourceInput(name = "elev-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        // The approver earns Role::"reviewer" server-side (a direct assignment RoleResolver resolves) and is an
        // ACTIVE app_user, so the tag-gated workflow.approve policy on that role decides the elevation.
        val reviewerRole = core.policyStore.createRole(RoleInput("reviewer"))
        core.policyStore.createAssignment(RoleAssignmentInput(approver, reviewerRole.id))
        core.userGroupStore.createUser(
            AppUserInput(principal = approver), core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null),
        )
        // The elevation role R every request targets — a distinct role, so the approve-authority check is a real
        // R-scoped Cedar decision against that role, not a trivial no-elevation case.
        targetRoleId = core.policyStore.createRole(RoleInput("target-role")).id

        core.cedarPolicyStore.create(CedarPolicyInput(name = "elev-trusted-network-tag", cedarSrc = trustedNetworkTagRule), updatedBy = null)
        core.cedarPolicyStore.create(CedarPolicyInput(name = "elev-tag-gated-approve", cedarSrc = tagGatedApprovePermit), updatedBy = null)

        // authDebug=false so the Cedar approve-authority check actually runs; "localhost" (the testApplication
        // socket peer) is the sole trusted edge, so ONLY an XFF appended behind it is honored as requester_ip.
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "elev-route-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
            trustedProxies = setOf("localhost"),
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
        install(Sessions) {
            webSessionCookie(sessionStore, config.sessionSecret)
        }
        routing {
            post("/test/session/{principal}") {
                val deviceId = call.ensureDeviceCookie(secure = false)
                call.sessions.set(
                    WebSessionRef(
                        sessionStore.mintWeb(
                            requireNotNull(call.parameters["principal"]),
                            null,
                            config.webSessionAbsoluteSeconds,
                            config.webSessionIdleSeconds,
                            deviceId,
                        ),
                    ),
                )
                call.respond(HttpStatusCode.NoContent)
            }
            accessRoutes(config, core.accessStore, core.authz, core.datasourceStore, core.roleResolver, ManagementAuditRecorder(core.auditStore))
            datasourceRoutes(config, core.authz, core.roleResolver, core.datasourceStore, core.proxyEventsHub, TableDetailService(core), core.tokenStore, core.userGroupStore)
            approvalRoutes(
                config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore,
                core.userGroupStore, resultStore, core.roleResolver,
                core.authz, runExecService,
            )
        }
    }

    /** A PENDING ROLE access-request elevating [requester] to `target-role` on the tag-gated datasource. */
    private fun seedRoleRequest(): Long = core.accessStore.createRequest(
        requester,
        AccessRequestInput(roleId = targetRoleId, datasourceId = datasource.id, reason = "need the role"),
    ).id

    /** A PENDING QUERY approval request elevating [requester] to `target-role` on the tag-gated datasource. */
    private fun seedQueryRequest(): Long = core.accessStore.createQueryRequest(
        principal = requester, datasourceId = datasource.id, statements = listOf("select 1"), denyReason = "denied",
        sourceDecisionId = null, reason = "need it", title = null,
        evaluatedDecision = "DENY", roleId = targetRoleId,
    ).id

    /** A QUERY request elevating [requester] to `target-role`, already APPROVED for APPROVER_EXEC —
     *  modeling the defense-in-depth scenario: a request legitimately approved earlier, now
     *  reaching /execute where the SAME R-scoped authority must be re-checked. */
    private fun seedApprovedQueryRequest(): Long {
        val id = seedQueryRequest()
        // decided_by = the approver who also executes, so /execute's approver=executor gate passes (the
        // executor here is [approver]); the tag-gated mayDecide authority remains the property under test.
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status='APPROVED', decided_by=? WHERE id=?").use { ps ->
                ps.setString(1, approver)
                ps.setLong(2, id)
                ps.executeUpdate()
            }
        }
        return id
    }

    @Test
    fun `ROLE access-request approve fires the tag-gated permit only through a trusted edge (Access-kt wiring)`() = testApplication {
        val client = wire()
        client.post("/test/session/$approver")

        // No trusted XFF -> requester_ip absent -> tag not derived -> the tag-gated approve permit cannot fire.
        val forbidden = seedRoleRequest()
        val denied = client.post("/api/access-requests/$forbidden/approve")
        assertEquals(
            HttpStatusCode.Forbidden, denied.status,
            "no requester_ip -> no trusted-network tag -> TASK_APPROVE denied (would still pass if the route dropped httpAuthzContext)",
        )

        // A trusted edge's in-range XFF -> requester_ip 100.100.5.5 -> trusted-network tag -> the permit fires.
        val approved = seedRoleRequest()
        val ok = client.post("/api/access-requests/$approved/approve") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(
            HttpStatusCode.OK, ok.status,
            "trusted-edge requester_ip -> derived tag -> approve succeeds; FAILS if the route drops httpAuthzContext or the datasource tag-scoping",
        )
    }

    @Test
    fun `query-approval approve fires the tag-gated permit only through a trusted edge (Approvals-kt wiring)`() = testApplication {
        val client = wire()
        client.post("/test/session/$approver")

        // No trusted XFF -> requester_ip absent -> tag not derived -> mayDecide denies.
        val forbidden = seedQueryRequest()
        val denied = client.post("/api/approvals/$forbidden/approve") {
            contentType(ContentType.Application.Json)
            setBody("""{"mode":"APPROVER_EXEC"}""")
        }
        assertEquals(
            HttpStatusCode.Forbidden, denied.status,
            "no requester_ip -> no trusted-network tag -> elevation approve denied (would still pass if the route dropped httpAuthzContext)",
        )

        // A trusted edge's in-range XFF -> requester_ip 100.100.5.5 -> trusted-network tag -> approve succeeds.
        val approved = seedQueryRequest()
        val ok = client.post("/api/approvals/$approved/approve") {
            header("X-Forwarded-For", "100.100.5.5")
            contentType(ContentType.Application.Json)
            setBody("""{"mode":"APPROVER_EXEC"}""")
        }
        assertEquals(
            HttpStatusCode.OK, ok.status,
            "trusted-edge requester_ip -> derived tag -> approve succeeds; FAILS if the route drops httpAuthzContext or the datasource tag-scoping",
        )
    }

    @Test
    fun `approve routes write a kind=admin audit event through the wiring`() = testApplication {
        val client = wire()
        client.post("/test/session/$approver")

        // ROLE approve through the real route writes one kind="admin" event; count is scoped to this
        // request's id so the per-class DB's other approvals don't pollute it. Drop call.auditActor/recorder
        // from the route and this count is 0.
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
                setBody("""{"mode":"APPROVER_EXEC"}""")
            }.status,
        )
        assertEquals(1, adminAuditCount("approve query request #$queryReq%"), "QUERY approve route must audit")
    }

    private fun adminAuditCount(statementLike: String): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM audit_event WHERE kind='admin' AND statement LIKE ?").use { ps ->
            ps.setString(1, statementLike)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    @Test
    fun `query-approval approve mutates only authorization state and never runs the query`() = testApplication {
        val client = wire()
        client.post("/test/session/$approver")

        val id = seedQueryRequest()
        // Task creation already made exactly one statement child, not yet run (status NULL).
        assertEquals(1, childCount(id))
        assertNull(childColumn(id, "status"))

        // Approve is authorized through a trusted edge (approver in reviewer + the derived trusted-network tag).
        // No proxy is attached to runExecService; a pure approve must not need one.
        val ok = client.post("/api/approvals/$id/approve") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(HttpStatusCode.OK, ok.status, "trusted-edge approve succeeds")

        // Authorization state advanced: APPROVED + who/when.
        val req = core.accessStore.getRequest(id)!!
        assertEquals("APPROVED", req.status)
        assertEquals(approver, req.decidedBy)
        assertNotNull(req.decidedAt)
        assertNotNull(req.approvedAt)

        // But approve ran nothing: no new child, the statement child is still not-run (status NULL), and no
        // verdict/mask/payload was stored on it. (executed_at is not asserted — V9 defaults it to now() at
        // child creation, so status IS NULL, not executed_at, is the not-run signal.)
        assertEquals(1, childCount(id))
        assertNull(childColumn(id, "status"))
        assertNull(childColumn(id, "ciphertext"))
        assertNull(childColumn(id, "row_count"))
        assertNull(childColumn(id, "columns"))
    }

    private fun childCount(taskId: Long): Int = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }

    /** The latest child's column as a nullable String (null when the column is SQL NULL). */
    private fun childColumn(taskId: Long, column: String): String? = dataSource.connection.use { c ->
        c.prepareStatement("SELECT $column FROM query_result WHERE task_id = ? ORDER BY id DESC LIMIT 1").use { ps ->
            ps.setLong(1, taskId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }

    // ---- Defense-in-depth: /execute re-checks the SAME R-scoped authority ----
    //
    // A request already APPROVED for APPROVER_EXEC (modeling one legitimately approved earlier) must still
    // clear the tag-gated workflow.approve authority for role R when the approver RUNS it — a group member
    // reaching an already-approved request is not automatically authorized to execute an arbitrary elevation.

    @Test
    fun `query-approval execute is forbidden without the trusted edge, even for an already-approved request`() = testApplication {
        val client = wire()
        client.post("/test/session/$approver")

        // No trusted XFF -> requester_ip absent -> tag not derived -> mayDecide denies.
        // This gate fires BEFORE runExecService is ever reached (Approvals.kt:603-610), so no proxy needs
        // to be attached here — a 503 (service-unavailable) instead of 403 would mean the gate leaked.
        val id = seedApprovedQueryRequest()
        val denied = client.post("/api/approvals/$id/execute")
        assertEquals(
            HttpStatusCode.Forbidden, denied.status,
            "no requester_ip -> no trusted-network tag -> execute-under-R authority denied (defense in depth)",
        )
        assertEquals("approval.not_approver", denied.body<ApiError>().code)
    }

    @Test
    fun `query-approval execute clears the R-scoped authority gate through a trusted edge (then fails on no attached proxy)`() = testApplication {
        val client = wire()
        client.post("/test/session/$approver")

        // A trusted edge's in-range XFF -> requester_ip 100.100.5.5 -> trusted-network tag -> the authority
        // gate at :603-610 passes, and the route proceeds to runExecService — which, with no proxy
        // attached in this fixture, fails 503/query.no_proxy_attached (Approvals.kt:646-647). That specific
        // status+code (NOT 403, NOT result_storage_not_configured) is the minimal honest proof the R-scoped
        // authority check passed, without standing up a second fake proxy in this file.
        val id = seedApprovedQueryRequest()
        val ok = client.post("/api/approvals/$id/execute") {
            header("X-Forwarded-For", "100.100.5.5")
        }
        assertEquals(
            HttpStatusCode.Accepted, ok.status,
            "trusted-edge requester_ip -> derived tag -> execute-under-R authority passes and submits asynchronously",
        )
        kotlinx.coroutines.withTimeout(5_000) {
            while (core.accessStore.getRequest(id)?.status != "FAILED") kotlinx.coroutines.delay(20)
        }
    }

    @Test
    fun `catalog browse is gated by datasource-connect`() = testApplication {
        val client = wire()
        client.post("/test/session/$requester")

        // Deny-by-default: the requester holds no datasource.connect on the datasource -> browse is forbidden.
        val denied = client.get("/api/datasources/${datasource.id}/catalog")
        assertEquals(HttpStatusCode.Forbidden, denied.status, "no datasource.connect -> catalog browse forbidden")

        // Granting datasource.connect opens the browse (an empty catalog is a fine 200 -- the point is the gate).
        val connect = core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "elev-requester-connect",
                cedarSrc = """permit(principal == User::"$requester", action == Action::"datasource.connect", resource == Datasource::"${datasource.name}");""",
            ),
            updatedBy = null,
        )
        try {
            val allowed = client.get("/api/datasources/${datasource.id}/catalog")
            assertEquals(HttpStatusCode.OK, allowed.status, "with datasource.connect -> catalog browse allowed")
        } finally {
            core.cedarPolicyStore.setEnabled(connect.id, false, "test-cleanup")
        }
    }

    @Test
    fun `ROLE request creation against a datasource is gated by workflow-request`() = testApplication {
        val client = wire()
        client.post("/test/session/$requester")
        val body = """{"roleId": $targetRoleId, "datasourceId": ${datasource.id}, "reason": "need it"}"""

        // The shipped -16 workflow.request-default permits everyone -> creating against the datasource succeeds.
        val created = client.post("/api/access-requests") {
            contentType(ContentType.Application.Json)
            setBody(body)
        }
        assertEquals(HttpStatusCode.Created, created.status, "default workflow.request permit -> create allowed")

        // A per-datasource forbid on workflow.request denies opening a request against that datasource.
        val forbid = core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "elev-no-request",
                cedarSrc = """forbid(principal, action == Action::"task.request", resource == Datasource::"${datasource.name}");""",
            ),
            updatedBy = null,
        )
        try {
            val denied = client.post("/api/access-requests") {
                contentType(ContentType.Application.Json)
                setBody(body)
            }
            assertEquals(HttpStatusCode.Forbidden, denied.status, "per-datasource workflow.request forbid -> create denied")
        } finally {
            core.cedarPolicyStore.setEnabled(forbid.id, false, "test-cleanup")
        }
    }

    @Test
    fun `datasource list is filtered by connect only when connectable is requested`() = testApplication {
        val client = wire()
        client.post("/test/session/$requester")

        // Default (no param): the full list, so JIT-request compose can show datasources the caller cannot
        // yet connect to -- elev-ds is present even without a connect grant.
        val full = client.get("/api/datasources")
        assertEquals(HttpStatusCode.OK, full.status)
        assertTrue(full.bodyAsText().contains(datasource.name), "the default list is unfiltered (compose needs it)")

        // ?connectable=true with no datasource.connect grant -> elev-ds is filtered out (the query picker).
        val filtered = client.get("/api/datasources?connectable=true")
        assertEquals(HttpStatusCode.OK, filtered.status)
        assertFalse(filtered.bodyAsText().contains(datasource.name), "no datasource.connect -> excluded from ?connectable=true")

        // Granting datasource.connect brings it into the connectable list.
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
}
