package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
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
import kotlin.test.assertTrue

/**
 * The /api/approvals human-approval surface must expose WORKFLOW-origin QUERY tasks only. EDITOR and WIRE
 * tasks share the access_request table but are internal lifecycle records (an editor tab's saved result; a
 * native-wire statement's per-statement authorization) with null SQL and no approver — they must never be
 * listed, fetched, decided, executed, or viewed as approvals. A native-wire statement now creates one WIRE
 * task per Decide, so without the creator_kind guard every statement the principal ran would pollute their
 * approvals feed and expose a nonsensical (null-SQL) approve/execute action surface.
 *
 * The caller is granted task.approve/read/assume outright, so the creator_kind guard is the SOLE gate under
 * test: if it were absent, these routes would happily serve the WIRE/EDITOR rows here.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalSurfaceCreatorKindDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var runExecService: RunExecService
    private lateinit var resultStore: QueryResultStore
    private lateinit var datasource: Datasource
    private lateinit var config: Config

    private lateinit var sessionStore: PrincipalSessionStore

    private val principal = "dev@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_approval_surface"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        runExecService = RunExecService(core)
        resultStore = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        sessionStore = PrincipalSessionStore(dataSource, null)
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "surface-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        // Blanket task authority for the caller, so every 404 below is the creator_kind guard's and never a
        // missing grant. task.assume covers the /result case, which is gated separately from the rest.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "approval-surface-test-task-authority",
                cedarSrc = """permit(
                    principal == User::"$principal",
                    action in [
                        Action::"task.approve", Action::"task.read", Action::"task.cancel", Action::"task.assume"
                    ],
                    resource
                );""",
            ),
            updatedBy = null,
        )
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "surface-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
    }

    private suspend fun ApplicationTestBuilder.wire(): HttpClient {
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
            routing {
                testLoginRoute(sessionStore, config)
                approvalRoutes(
                    config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore,
                    core.userGroupStore, resultStore, core.roleResolver, core.authz, runExecService,
                )
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return client
    }

    private fun seedWorkflowRequest(): Long = core.accessStore.createQueryRequest(
        principal = principal, datasourceId = datasource.id, statements = listOf("select id from users"),
        denyReason = "policy denies", sourceDecisionId = null, reason = "need it", title = "t",
        evaluatedDecision = "DENY",
    ).id

    private fun seedWireTask(): Long {
        val decisionId = core.auditStore.insert(
            AuditEvent(principal = principal, datasource = datasource.name, statement = "select id from users", decision = Decision.ALLOW),
        )
        return dataSource.inTx { c ->
            core.accessStore.createWireTask(c, principal, datasource.id, listOf("analyst"), decisionId)
        }
    }

    private fun seedEditorTask(): Long = core.accessStore.createEditorTask(
        principal, datasource.id, listOf("select id from users"), listOf("analyst"), principal,
    ).id

    @Test
    fun `list surfaces only WORKFLOW tasks - WIRE and EDITOR never appear`() = testApplication {
        val client = wire()
        val workflowId = seedWorkflowRequest()
        val wireId = seedWireTask()
        val editorId = seedEditorTask()

        val listed = client.get("/api/approvals").body<List<AccessRequest>>().map { it.id }
        assertTrue(workflowId in listed, "the WORKFLOW approval request must appear on the feed")
        assertTrue(wireId !in listed, "a native-wire lifecycle task must never appear on the approvals feed")
        assertTrue(editorId !in listed, "an editor lifecycle task must never appear on the approvals feed")
        assertEquals(setOf(workflowId), listed.toSet(), "the feed carries WORKFLOW rows and nothing else")
    }

    @Test
    fun `a WIRE task is not fetchable, decidable, executable, or viewable as an approval`() = testApplication {
        val client = wire()
        assertUnreachableAsApproval(client, seedWireTask())
    }

    @Test
    fun `an EDITOR task is not fetchable, decidable, executable, or viewable as an approval`() = testApplication {
        val client = wire()
        assertUnreachableAsApproval(client, seedEditorTask())
    }

    /** Every id-addressed approval route must 404 a non-WORKFLOW task even though the Cedar gate passes. */
    private suspend fun assertUnreachableAsApproval(client: HttpClient, id: Long) {
        assertEquals(HttpStatusCode.NotFound, client.get("/api/approvals/$id").status, "detail")
        assertEquals(HttpStatusCode.NotFound, client.post("/api/approvals/$id/approve").status, "approve")
        val reject = client.post("/api/approvals/$id/reject") {
            contentType(ContentType.Application.Json)
            setBody("""{"reason":"x"}""")
        }
        assertEquals(HttpStatusCode.NotFound, reject.status, "reject")
        assertEquals(HttpStatusCode.NotFound, client.post("/api/approvals/$id/execute").status, "execute")
        assertEquals(HttpStatusCode.NotFound, client.get("/api/approvals/$id/result").status, "result")
    }
}
