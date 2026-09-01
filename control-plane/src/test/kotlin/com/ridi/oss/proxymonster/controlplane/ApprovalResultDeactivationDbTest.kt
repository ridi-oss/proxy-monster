package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * Route-level coverage of the explicit deprovisioned-viewer gate, isolated on a no-R (empty execute-as)
 * request. That gate runs BEFORE the live result re-decision, so it is the ONLY thing that flips an active
 * viewer's outcome: an active viewer passes the gate and reaches the re-decision, which itself fails closed on
 * an empty {R} (no raw-snapshot side-channel) and returns 403 `result_view_denied`; a deactivated viewer is
 * turned away at the gate first with 404, no result-existence oracle. The 403-vs-404 difference IS the gate's
 * effect. The viewer is also the task requester, so the shipped task.assume party policy admits it; removing
 * the deactivation gate would turn the deactivated case's 404 into the same 403 and fail the second test.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalResultDeactivationDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var resultStore: QueryResultStore
    private lateinit var runExecService: RunExecService
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var config: Config
    private val viewer = "dev@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        // runExecService is only reached by /execute, never by the /result path under test — but
        // approvalRoutes requires it. A core over the same DB is sufficient (it is never invoked here).
        runExecService = RunExecService(ControlPlaneCore(fx.dataSource))
        sessionStore = PrincipalSessionStore(fx.dataSource, null)
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "test-secret", oidc = null, resultKey = null,
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        fx.userGroupStore.createUser(
            AppUserInput(principal = viewer), fx.tokenStore, fx.accessStore, fx.daemonSessionStore,
        )
    }

    private suspend fun ApplicationTestBuilder.installApprovalRoutes(): HttpClient {
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
            routing {
                testLoginRoute(sessionStore, config)
                approvalRoutes(
                    config, fx.accessStore, fx.auditStore, fx.datasourceStore, fx.policyStore,
                    fx.userGroupStore, resultStore, fx.roleResolver, fx.authz, runExecService,
                )
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$viewer").status)
        return client
    }

    /** A QUERY task + stored result whose requester may assume R through the shipped party policy. */
    private fun storedResultId(): Long {
        val reqId = fx.dataSource.connection.use { c ->
            c.prepareStatement(
                "INSERT INTO access_request (principal, kind, datasource_id, role_id, creator_kind) VALUES (?, 'QUERY', ?, NULL, 'WORKFLOW') RETURNING id",
            ).use { ps ->
                ps.setString(1, viewer)
                ps.setLong(2, fx.datasource.id)
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
        }
        fx.dataSource.connection.use { c -> c.prepareStatement("INSERT INTO query_result (task_id, sql, sql_hash) VALUES (?, 'select 1', 'fixture')").use { ps -> ps.setLong(1, reqId); ps.executeUpdate() } }
        resultStore.startNextRun(reqId, viewer)!!
        resultStore.completeRun(reqId, DecryptedResult(listOf("id"), listOf(listOf("1"))), 3600)!!
        return reqId
    }

    @Test
    fun `an active viewer passes the deactivation gate and reaches the live re-decision — positive control`() = testApplication {
        val client = installApprovalRoutes()
        fx.userGroupStore.setUserActive(viewer, true)
        val id = storedResultId()
        val resp = client.get("/api/approvals/$id/result")
        // The gate is passed; the empty-{R} re-decision then denies fail-closed (never the stored snapshot).
        assertEquals(HttpStatusCode.Forbidden, resp.status, "an active viewer must reach the live re-decision")
        assertEquals("approval.result_view_denied", resp.body<ApiError>().code, "empty-R must fail closed, not return stored bytes")
    }

    @Test
    fun `a deactivated viewer is gated out before any result decision — NotFound, no existence oracle`() = testApplication {
        val client = installApprovalRoutes()
        val id = storedResultId()
        fx.userGroupStore.setUserActive(viewer, false)
        val resp = client.get("/api/approvals/$id/result")
        assertEquals(
            HttpStatusCode.NotFound, resp.status,
            "a deactivated viewer must be gated out of /result before the re-decision (deleting the isDeactivated gate turns this into the 403 above)",
        )
    }
}
