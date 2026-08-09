package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runReady
import com.ridi.oss.proxymonster.grpc.runServing
import com.ridi.oss.proxymonster.grpc.runValue
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
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
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Route/DB regression coverage for `POST /api/approvals/{id}/execute`'s DENY-under-R fail-closed
 * floor (Approvals.kt:589-670): a request elevated to role R, already APPROVED for APPROVER_EXEC, whose
 * execute-under-R decision comes back DENY must (1) never leak columns/rows in the HTTP response
 * ([ExecuteApprovalResponse.result] stays null) and (2) never write a `query_result` row — the early
 * return at :642-644 must precede [QueryResultStore.save] at :657, not race it. Runs a REAL fake proxy over
 * gRPC (the SAME [ControlPlaneCore] wired into both [RunExecService] and [ControlPlaneGrpcService], so
 * the fake proxy's Events/runExec streams land on the same `proxyEventsHub` — mirrors
 * `GrpcRunExecDbTest`) so the DENY plays back over the real execute-under-R wire path, not a mock.
 *
 * Runs under `authDebug=true` (the executor principal is the literal `debug-user`): `mayDecide`
 * short-circuits true under authDebug, isolating the DENY branch from the R-scoped authority gate — that
 * gate gets its own coverage in [ElevationContextRouteAuthzDbTest].
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalExecuteRouteDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var runExecService: RunExecService
    private lateinit var resultStore: QueryResultStore
    private lateinit var datasource: Datasource
    private lateinit var config: Config
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: ManagedChannel

    private val executor = "debug-user" // the authDebug fallback principal (no session cookie is sent)
    private val requester = "requester@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_exec_route"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        runExecService = RunExecService(core)
        resultStore = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))

        datasource = core.datasourceStore.create(
            DatasourceInput(name = "exec-route-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )

        // debug-user (the authDebug fallback executor) is registered as an app_user; authDebug bypasses the
        // approve-authority gate, isolating the execute-under-R branch under test.
        core.userGroupStore.createUser(
            AppUserInput(principal = executor), core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null),
        )

        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "exec-route-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )

        // The gRPC server + stub is the fake proxy's transport — the SAME core as runExecService above,
        // so the fake proxy dialed through this stub attaches to the exact proxyEventsHub run() dials
        // (GrpcRunExecDbTest.kt:72-97's shape).
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun teardown() {
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private suspend fun awaitUntil(what: String, predicate: () -> Boolean) {
        withTimeout(5_000) {
            while (!predicate()) delay(20)
        }
        require(predicate()) { "timed out awaiting: $what" }
    }

    private fun ApplicationTestBuilder.wire(): HttpClient {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            routing {
                approvalRoutes(
                    config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore,
                    core.userGroupStore, resultStore, core.roleResolver,
                    core.authz, runExecService,
                )
            }
        }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private fun ApplicationTestBuilder.wireAuthenticated(): HttpClient {
        val cfg = config.copy(authDebug = false)
        val sessionStore = PrincipalSessionStore(dataSource, null)
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(Sessions) { webSessionCookie(sessionStore, cfg.sessionSecret) }
            routing {
                post("/test/session/{principal}") {
                    val deviceId = call.ensureDeviceCookie(secure = false)
                    call.sessions.set(
                        WebSessionRef(sessionStore.mintWeb(requireNotNull(call.parameters["principal"]), null, 7200, 900, deviceId)),
                    )
                    call.respond(HttpStatusCode.NoContent)
                }
                approvalRoutes(
                    cfg, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore,
                    core.userGroupStore, resultStore, core.roleResolver, core.authz, runExecService,
                )
            }
        }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    /** A QUERY request elevating [requester] to a fresh role R on [datasource], already APPROVED —
     *  modeling a request legitimately approved earlier so this test isolates the /execute DENY-under-R
     *  branch alone (roleId populates req.roleName, selecting the execute-under-R branch). */
    private fun seedApprovedRoleRequest(roleName: String, decidedBy: String = executor): Long {
        val roleId = core.policyStore.createRole(RoleInput(roleName)).id
        val id = core.accessStore.createQueryRequest(
            principal = requester, datasourceId = datasource.id, sql = "select ssn from users",
            denyReason = null, sourceDecisionId = null, reason = "need it", title = null,
            evaluatedDecision = "DENY", roleId = roleId,
        ).id
        // decided_by defaults to the executor so the /execute approver=executor gate passes; a test can
        // seed a DIFFERENT approver of record to exercise that gate's 403.
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status='APPROVED', decided_by=? WHERE id=?").use { ps ->
                ps.setString(1, decidedBy)
                ps.setLong(2, id)
                ps.executeUpdate()
            }
        }
        return id
    }

    private fun storedResultCount(requestId: Long): Long = dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, requestId)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    @Test
    fun `a DENY-under-R at execute leaks no result and stores nothing (fail-closed floor)`() = testApplication {
        val client = wire()
        val roleR = "exec-deny-role"
        val id = seedApprovedRoleRequest(roleR)

        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            val responseDeferred = async { client.post("/api/approvals/$id/execute") }
            val open = withTimeout(5_000) { event.await() }.openRunChannel

            // Resolve the route-minted ephemeral decide token NOW, while run() still holds it live (it is
            // revoked in run()'s finally once the exchange ends). This is the ONLY way to prove the execute-
            // under-R wiring (Approvals.kt:626-632) minted a token carrying EXACTLY role R on the APPROVER_EXEC
            // (workflow-executor) kind — the fake proxy's fabricated DENY below never inspects the token, so
            // without this the test would still pass if assumeRoles were dropped or the legacy self-exec path
            // were taken. Assertions come after the response so a mismatch never deadlocks the in-flight POST.
            val ephemeralIdentity = core.tokenStore.resolve(open.ephemeralToken)

            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> proxyRequests.send(
                            proxyRunMsg {
                                decision = runDecision {
                                    decision = WireEnfAction.DENY
                                    denyReason = "policy denies column ssn"
                                }
                            },
                        )
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyRunMsg { serving = runServing {} })

            val response = withTimeout(5_000) { responseDeferred.await() }
            withTimeout(5_000) { proxy.await() }

            assertEquals(HttpStatusCode.Accepted, response.status)
            assertEquals("EXECUTING", response.body<ExecuteApprovalResponse>().decision)
            awaitUntil("DENY marks task and child failed") {
                core.accessStore.getRequest(id)?.status == "FAILED" && resultStore.meta(id)?.status == "FAILED"
            }
            assertEquals(1L, storedResultCount(id), "the pre-created statement child remains as failed execution metadata")
            assertEquals("approval.execute_denied", resultStore.meta(id)?.errorCode)

            // Pin the route→token→decide wiring the DENY playback can't see: the ephemeral decide token must
            // carry EXACTLY role R and be the APPROVER_EXEC (workflow-executor) kind — so this is genuinely a
            // DENY *under R*, not a DENY produced with the requester's own roles or via the legacy self path.
            assertEquals(
                listOf(roleR), ephemeralIdentity?.roles,
                "execute-under-R must mint the decide token carrying EXACTLY role R, never the requester's own roles or an empty set",
            )
            assertEquals(
                TokenKind.APPROVER_EXEC.name, ephemeralIdentity?.kind,
                "execute-under-R decides on the APPROVER_EXEC (workflow-executor) kind — grant-ineligible, R-unmask channel",
            )
            assertEquals(
                executor, ephemeralIdentity?.principal,
                "execute-under-R runs AS the approver (run(principal = executor)) — the decide token's principal " +
                    "must be the approver who initiated the run, so a run left on the requester's identity is caught here",
            )

            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    private fun rowsChunk(columns: List<String>, rows: List<List<String?>>): ProxyRunMsg = proxyRunMsg {
        resultRows = runResultRows {
            this.columns += columns
            this.rows += rows.map { values ->
                runRow {
                    this.values += values.map { value ->
                        runValue {
                            if (value == null) isNull = true else this.value = value
                        }
                    }
                }
            }
        }
    }

    /**
     * The execute-once guard, end to end over the real HTTP + fake-proxy wire: a first successful
     * execute stores exactly one result, and a SECOND execute call (deliberately made WITHOUT attaching
     * any fake proxy) sees 409 `approval.already_executed` — the pre-dial CAS claim rejects it before
     * `RunExecService.run` ever looks for a proxy, which is itself the proof the target is dialed at
     * most once: if the guard didn't fire before the dial, this second call would hang/fail on
     * `NoProxyAttachedException` instead of returning the typed 409.
     */
    @Test
    fun `a second execute after a successful first is rejected with 409 approval_already_executed, storing exactly one result`() = testApplication {
        val client = wire()
        val roleR = "exec-once-role"
        val id = seedApprovedRoleRequest(roleR)

        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            val responseDeferred = async { client.post("/api/approvals/$id/execute") }
            val open = withTimeout(5_000) { event.await() }.openRunChannel

            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            proxyRequests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(rowsChunk(listOf("ssn"), listOf(listOf("some-value"))))
                            proxyRequests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyRunMsg { serving = runServing {} })

            val response = withTimeout(5_000) { responseDeferred.await() }
            withTimeout(5_000) { proxy.await() }

            assertEquals(HttpStatusCode.Accepted, response.status)
            assertEquals("EXECUTING", response.body<ExecuteApprovalResponse>().decision)
            awaitUntil("successful run completes") {
                core.accessStore.getRequest(id)?.status == "EXECUTED" && resultStore.meta(id)?.status == "DONE"
            }
            assertEquals(1L, storedResultCount(id))

            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }

        // Deliberately no proxy is attached for this second call — the guard must fire BEFORE
        // RunExecService.run even tries to dial one.
        val second = client.post("/api/approvals/$id/execute")
        assertEquals(HttpStatusCode.Conflict, second.status)
        val secondBody = second.body<ApiError>()
        assertEquals("approval.already_executed", secondBody.code)

        assertEquals(1L, storedResultCount(id), "the second, rejected execute must not add or replace a stored result")
        val stored = resultStore.accessFor(id)!!.decrypted!!
        assertEquals(listOf(listOf("some-value")), stored.rows, "the original stored rows must be unchanged by the rejected second execute")
    }

    /**
     * The async-submit contract itself: `/execute` returns 202 `EXECUTING` while the run is still in
     * flight, NOT after the proxy finishes. The fake proxy sends ALLOW + rows but withholds `Done`; the
     * test proves the HTTP response has already returned AND the durable task/child are observably
     * EXECUTING/RUNNING before `Done` is released — a synchronous route that blocked on `Done` would
     * deadlock this test instead of passing. Releasing `Done` then drives the atomic EXECUTED/DONE
     * terminal (parent + child + audit in one commit) and the encrypted rows become readable.
     */
    @Test
    fun `execute returns 202 EXECUTING while the run is still in flight, then completes to EXECUTED and DONE`() = testApplication {
        val client = wire()
        val id = seedApprovedRoleRequest("exec-async-role")

        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            val responseDeferred = async { client.post("/api/approvals/$id/execute") }
            val open = withTimeout(5_000) { event.await() }.openRunChannel

            val releaseDone = CompletableDeferred<Unit>()
            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> launch {
                            proxyRequests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(rowsChunk(listOf("ssn"), listOf(listOf("some-value"))))
                            // Withhold Done until the test has proven the route already returned 202 and
                            // the task/child are observably in flight.
                            releaseDone.await()
                            proxyRequests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
                        }
                        control.hasCancel() -> Unit
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyRunMsg { serving = runServing {} })

            // The response must come back BEFORE Done — the whole point of the async submit.
            val response = withTimeout(5_000) { responseDeferred.await() }
            assertEquals(HttpStatusCode.Accepted, response.status)
            assertEquals("EXECUTING", response.body<ExecuteApprovalResponse>().decision)

            // ...and while the proxy still holds Done, the durable state is observably in flight.
            awaitUntil("task EXECUTING and child RUNNING while in flight") {
                core.accessStore.getRequest(id)?.status == "EXECUTING" && resultStore.meta(id)?.status == "RUNNING"
            }

            releaseDone.complete(Unit)
            withTimeout(5_000) { proxy.await() }

            awaitUntil("run completes to EXECUTED and DONE") {
                core.accessStore.getRequest(id)?.status == "EXECUTED" && resultStore.meta(id)?.status == "DONE"
            }
            assertEquals(1L, storedResultCount(id))
            assertEquals(listOf(listOf("some-value")), resultStore.accessFor(id)!!.decrypted!!.rows)

            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    @Test
    fun `canceling an in-flight approval terminalizes both rows and emits RunCancel`() = testApplication {
        val client = wire()
        val id = seedApprovedRoleRequest("exec-cancel-role")

        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            val execute = async { client.post("/api/approvals/$id/execute") }
            val open = withTimeout(5_000) { event.await() }.openRunChannel
            val release = CompletableDeferred<Unit>()
            val cancelObserved = CompletableDeferred<Unit>()
            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> launch { release.await() }
                        control.hasCancel() -> cancelObserved.complete(Unit)
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyRunMsg { serving = runServing {} })
            assertEquals(HttpStatusCode.Accepted, withTimeout(5_000) { execute.await() }.status)
            awaitUntil("approval child RUNNING") { resultStore.meta(id)?.status == "RUNNING" }
            assertEquals(true, client.get("/api/approvals/$id").body<ApprovalDetail>().canCancel)

            val cancelled = client.post("/api/approvals/$id/cancel")
            assertEquals(HttpStatusCode.OK, cancelled.status)
            assertEquals("CANCELLED", cancelled.body<AccessRequest>().status)
            assertEquals("CANCELLED", core.accessStore.getRequest(id)?.status)
            assertEquals("CANCELLED", resultStore.meta(id)?.status)
            assertEquals("approval.canceled", resultStore.meta(id)?.errorCode)
            withTimeout(5_000) { cancelObserved.await() }

            release.complete(Unit)
            proxyRequests.close()
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `V46 allows the requester to cancel and denies an unrelated principal without sending control`() = testApplication {
        val client = wireAuthenticated()
        val approver = "cancel-approver@example.com"
        val unrelated = "cancel-unrelated@example.com"
        for (principal in listOf(requester, approver, unrelated)) {
            if (core.userGroupStore.getUserByPrincipal(principal) == null) {
                core.userGroupStore.createUser(
                    AppUserInput(principal = principal), core.tokenStore, core.accessStore,
                    PrincipalSessionStore(dataSource, null),
                )
            }
        }
        val id = seedApprovedRoleRequest("exec-cancel-authz-role", decidedBy = approver)
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = 'EXECUTING' WHERE id = ?").use { ps ->
                ps.setLong(1, id); ps.executeUpdate()
            }
        }
        assertNotNull(resultStore.startRun(id, approver))

        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$unrelated").status)
        val denied = client.post("/api/approvals/$id/cancel")
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertEquals("approval.cancel_forbidden", denied.body<ApiError>().code)
        assertEquals("EXECUTING", core.accessStore.getRequest(id)?.status)

        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$requester").status)
        val allowed = client.post("/api/approvals/$id/cancel")
        assertEquals(HttpStatusCode.OK, allowed.status)
        assertEquals("CANCELLED", allowed.body<AccessRequest>().status)
    }

    @Test
    fun `cancel is idempotent after execution and rejects pending tasks`() = testApplication {
        val client = wire()
        val executed = seedApprovedRoleRequest("exec-cancel-terminal-role")
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = 'EXECUTED' WHERE id = ?").use { ps ->
                ps.setLong(1, executed); ps.executeUpdate()
            }
        }
        val terminal = client.post("/api/approvals/$executed/cancel")
        assertEquals(HttpStatusCode.OK, terminal.status)
        assertEquals("EXECUTED", terminal.body<AccessRequest>().status)

        val pending = seedApprovedRoleRequest("exec-cancel-pending-role")
        dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status = 'PENDING' WHERE id = ?").use { ps ->
                ps.setLong(1, pending); ps.executeUpdate()
            }
        }
        val denied = client.post("/api/approvals/$pending/cancel")
        assertEquals(HttpStatusCode.Conflict, denied.status)
        assertEquals("approval.not_cancelable", denied.body<ApiError>().code)
    }

    /** The async task model exposes no /release or /withhold routes; hitting them 404s. */
    @Test
    fun `removed release and withhold routes return 404`() = testApplication {
        val client = wire()
        val id = seedApprovedRoleRequest("exec-removed-routes-role")
        assertEquals(HttpStatusCode.NotFound, client.post("/api/approvals/$id/release").status)
        assertEquals(HttpStatusCode.NotFound, client.post("/api/approvals/$id/withhold").status)
    }

    /**
     * The approver of record must be the one who executes (executedBy = decided_by = the approver). An
     * eligible approver B who did not approve THIS task cannot run a task approved by A: /execute rejects
     * with 403 `approval.not_the_approver` BEFORE the execute-once claim, so nothing runs and the task
     * stays APPROVED. Under authDebug the R-scoped authority gate (`mayDecide`) short-circuits true, so this
     * identity check — which has NO authDebug bypass — is the sole gate under test here. The positive case
     * (the approver of record executes and proceeds) is the default `decidedBy = executor` seed the other
     * tests above exercise.
     */
    @Test
    fun `execute by an approver other than the approver of record is 403 not_the_approver and runs nothing`() = testApplication {
        val client = wire()
        // Approved by a DIFFERENT approver A; the /execute caller is the authDebug principal debug-user (B).
        val id = seedApprovedRoleRequest("exec-wrong-approver-role", decidedBy = "approver-a@example.com")

        val denied = client.post("/api/approvals/$id/execute")
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertEquals("approval.not_the_approver", denied.body<ApiError>().code)

        // The gate fires before claimExecution, so the task never leaves APPROVED and the pre-created
        // statement child is never run (no result is stored).
        assertEquals("APPROVED", core.accessStore.getRequest(id)?.status)
        assertEquals(null, resultStore.meta(id)?.status, "no child was ever run")
    }

    /**
     * The concurrency proof for the execute-once guard: [AccessStore.claimExecution] is a single conditional
     * UPDATE, so Postgres's row-level MVCC alone (no `SELECT ... FOR UPDATE`) serializes two concurrent
     * callers racing the SAME request id — exactly one observes `executed_at IS NULL` and wins.
     */
    @Test
    fun `claimExecution is race-safe - two concurrent callers on separate connections yield exactly one winner`() {
        val id = seedApprovedRoleRequest("exec-race-role")
        val pool = Executors.newFixedThreadPool(2)
        try {
            val start = CountDownLatch(1)
            val results = java.util.Collections.synchronizedList(ArrayList<Boolean>())
            val tasks = (1..2).map {
                pool.submit {
                    start.await()
                    // Each task uses AccessStore's own dataSource, which hands out a fresh JDBC connection
                    // per call — a genuinely separate connection per racing caller, not a shared one.
                    results += core.accessStore.claimExecution(id)
                }
            }
            start.countDown()
            tasks.forEach { it.get(5, TimeUnit.SECONDS) }

            assertEquals(2, results.size)
            assertEquals(1, results.count { it }, "exactly one of the two concurrent claims must win")
            assertEquals("EXECUTING", core.accessStore.getRequest(id)?.status, "the winning claim must move the task to EXECUTING")
        } finally {
            pool.shutdownNow()
        }
    }

}
