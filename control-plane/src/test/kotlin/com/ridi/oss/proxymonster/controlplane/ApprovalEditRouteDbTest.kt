package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalEditRouteDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var cpGo: CpGoStack
    private lateinit var config: Config
    private var roleId = 0L

    private val requester = "edit-requester@example.com"
    private val approver = "edit-approver@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        sessionStore = PrincipalSessionStore(fx.dataSource, null)
        roleId = fx.policyStore.createRole(RoleInput("edit-runner")).id
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "edit-route-approver",
                cedarSrc = """permit(principal == User::"$approver", action in [Action::"task.approve", Action::"task.read"], resource);""",
            ),
            updatedBy = null,
        )
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "edit-route-test-secret-of-32-characters", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, ControlPlaneCore(fx.dataSource), fx.metaDatabase) { routing { testLoginRoute(sessionStore, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun ApplicationTestBuilder.wire(): HttpClient = cpGo.client()

    private suspend fun HttpClient.signIn(principal: String) =
        assertEquals(HttpStatusCode.NoContent, post("/test/session/$principal").status)

    private suspend fun HttpClient.create(sql: String): AccessRequest {
        signIn(requester)
        val response = post("/api/approvals") {
            contentType(ContentType.Application.Json)
            setBody(CreateQueryRequestInput(datasourceId = fx.datasource.id, sql = sql, title = "t", reason = "r", roleId = roleId))
        }
        assertEquals(HttpStatusCode.Created, response.status)
        return response.body<CreateQueryRequestResponse>().request
    }

    private suspend fun HttpClient.edit(id: Long, input: EditQueryRequestInput): HttpResponse = post("/api/approvals/$id/edit") {
        contentType(ContentType.Application.Json)
        setBody(input)
    }

    private suspend fun HttpClient.approve(id: Long, revision: Int): HttpResponse = post("/api/approvals/$id/approve") {
        contentType(ContentType.Application.Json)
        setBody(ApproveQueryRequestInput(revision))
    }

    @Test
    fun `an edit replaces the SQL and returns an approved request to pending under the next revision`() = testApplication {
        val client = wire()
        val created = client.create("select id from users")
        client.signIn(approver)
        assertEquals("APPROVED", client.approve(created.id, revision = 1).body<AccessRequest>().status)

        client.signIn(requester)
        assertTrue(client.get("/api/approvals/${created.id}").body<QueryRequestDetail>().canEdit)
        val edited = client.edit(created.id, EditQueryRequestInput("select id from users where id = 1; select 1", reason = "new reason"))
        assertEquals(HttpStatusCode.OK, edited.status)
        val request = edited.body<AccessRequest>()
        assertEquals("PENDING", request.status)
        assertEquals(2, request.revision)
        assertEquals(null, request.decidedBy)
        assertEquals(2, request.statementCount)
        assertEquals("new reason", request.reason)
        assertEquals("t", request.title)
    }

    @Test
    fun `an edit that keeps the SQL's hash keeps the revision and the approval`() = testApplication {
        val client = wire()
        val created = client.create("select id from users where id = 1")
        client.signIn(approver)
        assertEquals("APPROVED", client.approve(created.id, revision = 1).body<AccessRequest>().status)

        client.signIn(requester)
        val edited = client.edit(created.id, EditQueryRequestInput("SELECT id\nFROM users -- same query\nWHERE id = 1", reason = "clearer"))
        assertEquals(HttpStatusCode.OK, edited.status)
        val request = edited.body<AccessRequest>()
        assertEquals("APPROVED" to 1, request.status to request.revision)
        assertEquals("clearer", request.reason)
        assertEquals("select id from users where id = 1", request.sql, "the approved text is what runs")
    }

    @Test
    fun `an approval of an earlier revision is refused`() = testApplication {
        val client = wire()
        val created = client.create("select id from users")
        assertEquals(HttpStatusCode.OK, client.edit(created.id, EditQueryRequestInput("select id from users where id = 2")).status)

        client.signIn(approver)
        val refused = client.approve(created.id, 1)
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertEquals("approval.request_changed", refused.body<ApiError>().code)
        val missing = client.post("/api/approvals/${created.id}/approve")
        assertEquals(HttpStatusCode.BadRequest to "common.field_required", missing.status to missing.body<ApiError>().code, "a revision is required")
        assertEquals("APPROVED", client.approve(created.id, 2).body<AccessRequest>().status)
    }

    @Test
    fun `only the requester edits, and only before it runs or is rejected`() = testApplication {
        val client = wire()
        val created = client.create("select id from users")

        client.signIn(approver)
        assertFalse(client.get("/api/approvals/${created.id}").body<QueryRequestDetail>().canEdit)
        val forbidden = client.edit(created.id, EditQueryRequestInput("select 1"))
        assertEquals(HttpStatusCode.Forbidden, forbidden.status)
        assertEquals("approval.edit_forbidden", forbidden.body<ApiError>().code)

        val rejected = client.post("/api/approvals/${created.id}/reject") {
            contentType(ContentType.Application.Json)
            setBody(RejectInput("no"))
        }
        assertEquals(HttpStatusCode.OK, rejected.status)
        client.signIn(requester)
        val closed = client.edit(created.id, EditQueryRequestInput("select 1"))
        assertEquals(HttpStatusCode.Conflict, closed.status)
        assertEquals("approval.not_editable", closed.body<ApiError>().code)
    }
}
