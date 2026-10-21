package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.CpGoStack
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** `/api/approvals/involved` lists from the participant table, and hides another person's flagged SQL. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalInvolvedListDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var datasource: Datasource
    private lateinit var config: Config
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var cpGo: CpGoStack

    private val requester = "req@example.com"
    private val approver = "appr@example.com"
    private val notified = "notified@example.com"
    private val outsider = "out@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val database = SharedPostgres.migratedDatabase("pm_approval_involved")
        dataSource = SharedPostgres.hikari(database)
        core = ControlPlaneCore(dataSource)
        sessionStore = PrincipalSessionStore(dataSource, null)
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "involved-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "involved-test-approver",
                cedarSrc = """permit(principal == User::"$approver", action == Action::"task.approve", resource);""",
            ),
            updatedBy = null,
        )
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "involved-test-secret-of-32-characters", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        cpGo = CpGoStack(config, core, database) { routing { testLoginRoute(sessionStore, config) } }
    }

    @AfterAll
    fun teardown() {
        if (::cpGo.isInitialized) cpGo.close()
    }

    private fun ApplicationTestBuilder.wire() = Unit

    private suspend fun ApplicationTestBuilder.clientAs(principal: String): HttpClient {
        val client = cpGo.client()
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return client
    }

    private fun seed(protectedLiteral: Boolean?): Long = core.accessStore.createQueryRequest(
        principal = requester, datasourceId = datasource.id, statements = listOf("select id from users where email = 'a@b.c'"),
        denyReason = "policy denies", sourceDecisionId = null, reason = "need it", title = "t",
        evaluatedDecision = "DENY", carriesProtectedLiteral = protectedLiteral,
    ).id

    private suspend fun HttpClient.involved(): Map<Long, AccessRequest> =
        get("/api/requests/involved").body<List<AccessRequest>>().associateBy { it.id }

    @Test
    fun `decider, notified approver and requester list the request, an outsider does not`() = testApplication {
        wire()
        val flagged = seed(protectedLiteral = true)
        val cleared = seed(protectedLiteral = false)
        dataSource.connection.use { c ->
            RequestParticipants.add(c, flagged, listOf(notified, requester), ParticipantKind.APPROVER)
        }
        val approverClient = clientAs(approver)
        assertEquals(HttpStatusCode.OK, approverClient.post("/api/approvals/$flagged/approve") {
            contentType(ContentType.Application.Json)
            setBody("""{"revision":1}""")
        }.status)

        val asApprover = approverClient.involved()
        assertEquals(setOf(flagged), asApprover.keys)
        assertNull(asApprover.getValue(flagged).sql, "another person's flagged statement stays hidden")

        assertEquals(setOf(flagged), clientAs(notified).involved().keys)

        val asRequester = clientAs(requester).involved()
        assertEquals(setOf(flagged, cleared), asRequester.keys)
        assertEquals("select id from users where email = 'a@b.c'", asRequester.getValue(flagged).sql)

        assertEquals(emptySet(), clientAs(outsider).involved().keys)

        val requesterRows = dataSource.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM request_participant WHERE principal = ?").use { ps ->
                ps.setString(1, requester)
                ps.executeQuery().use { it.next(); it.getInt(1) }
            }
        }
        assertEquals(0, requesterRows, "the requester is never stored as a participant")
    }
}
