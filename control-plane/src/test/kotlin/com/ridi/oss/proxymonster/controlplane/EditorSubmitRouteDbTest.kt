package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.ControlRunMsg
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
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.fail

/**
 * End-to-end route/DB coverage for the async editor submit, over the REAL fake-proxy-over-gRPC wire (the
 * SAME [ControlPlaneCore] wired into both [RunExecService] and [ControlPlaneGrpcService], so the persistent
 * editor session dials the exact `proxyEventsHub`). A submit is an auto-approved EDITOR task: the route
 * returns 202 while the run proceeds async on the held session, the enforced result is SAVED (not returned
 * inline), and the client observes completion by polling. Delete-on-close removes the tab's task + rows.
 *
 * Runs under `authDebug=true`, so the caller is the literal `debug-user` (given a role so the fail-closed
 * "own roles" gate passes) and the editor self-approve Cedar gate is bypassed — the V44 self-approve policy
 * gets its own isolated coverage in [EditorSelfApproveAuthzDbTest]. The masked re-decision at GET /result
 * (the shared `decideResultView`) is covered by the Approval result tests; here the result view's GATING
 * (not-ready 409, non-owner task.assume 404) is exercised, which never reaches the analyzer.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EditorSubmitRouteDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var runExecService: RunExecService
    private lateinit var resultStore: QueryResultStore
    private lateinit var datasource: Datasource
    private lateinit var config: Config
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: ManagedChannel
    private lateinit var appScope: CoroutineScope

    private val caller = "debug-user" // the authDebug fallback principal (no session cookie is sent)

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_editor_submit"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        runExecService = RunExecService(core)
        resultStore = QueryResultStore(dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        datasource = core.datasourceStore.create(
            DatasourceInput(name = "editor-submit-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        core.userGroupStore.createUser(
            AppUserInput(principal = caller), core.tokenStore, core.accessStore,
            PrincipalSessionStore(dataSource, null),
        )
        // The editor requires the caller to have ≥1 own role (fail-closed) — give debug-user one.
        val roleId = core.policyStore.createRole(RoleInput("editor-analyst")).id
        core.policyStore.createAssignment(RoleAssignmentInput(caller, roleId))

        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "editor-submit-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )

        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)
    }

    @AfterAll
    fun teardown() {
        appScope.cancel()
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private suspend fun awaitUntil(what: String, predicate: () -> Boolean) {
        withTimeout(5_000) { while (!predicate()) delay(20) }
        require(predicate()) { "timed out awaiting: $what" }
    }

    private fun ApplicationTestBuilder.wire(cfg: Config = config, hub: TaskCompletionHub? = null): HttpClient {
        application {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            routing {
                editorSessionRoutes(
                    cfg, core.datasourceStore, core.accessStore, resultStore,
                    core.policyStore, core.userGroupStore, core.roleResolver, core.authz, runExecService,
                    appScope, core.systemClassification, hub,
                )
            }
        }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    // A session-authenticated wiring for the non-authDebug Cedar gate: [cfg] must have authDebug=false, so
    // requireApi needs a real web-session cookie. A /test/session/{principal} route mints one (the same
    // webSessionCookie transport App uses), and [login] sets it on the client before driving the route.
    private fun ApplicationTestBuilder.wireAuthenticated(cfg: Config): HttpClient {
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
                editorSessionRoutes(
                    cfg, core.datasourceStore, core.accessStore, resultStore,
                    core.policyStore, core.userGroupStore, core.roleResolver, core.authz, runExecService,
                    appScope, core.systemClassification,
                )
            }
        }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private suspend fun HttpClient.login(principal: String) {
        assertEquals(HttpStatusCode.NoContent, post("/test/session/$principal").status)
    }

    private fun rowsChunk(columns: List<String>, rows: List<List<String?>>): ProxyRunMsg = proxyRunMsg {
        resultRows = runResultRows {
            this.columns += columns
            this.rows += rows.map { values ->
                runRow { this.values += values.map { v -> runValue { if (v == null) isNull = true else value = v } } }
            }
        }
    }

    private class FakeSession(
        val sessionId: String,
        val proxyRequests: Channel<ProxyRunMsg>,
        val controls: Channel<ControlRunMsg>,
        val await: suspend () -> Unit,
    )

    /**
     * Open a persistent editor session over the fake proxy: attach the Events stream, drive the HTTP open,
     * hand the proxy a per-query responder, and return the live session id. The proxy loop stays running
     * until the session is closed (a `close` control message completes it).
     */
    private suspend fun CoroutineScope.openFakeSession(
        client: HttpClient,
        onQuery: suspend (SendChannel<ProxyRunMsg>, ControlRunMsg) -> Unit,
    ): FakeSession {
        val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
        awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
        val openDeferred = async {
            client.post("/api/editor/sessions") {
                contentType(ContentType.Application.Json); setBody(OpenEditorSessionInput(datasource.id))
            }
        }
        val open = withTimeout(5_000) { event.await() }.openRunChannel
        val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
        val controls = Channel<ControlRunMsg>(Channel.UNLIMITED)
        val proxy = async {
            stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                controls.send(control)
                when {
                    control.hasQuery() -> launch { onQuery(proxyRequests, control) }
                    control.hasCancel() -> Unit
                    control.hasClose() -> proxyRequests.close()
                    else -> fail("control plane sent an empty editor control message")
                }
            }
        }
        proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
        proxyRequests.send(proxyRunMsg { serving = runServing {} })
        val sessionId = withTimeout(5_000) { openDeferred.await() }.body<EditorSessionOpened>().sessionId
        return FakeSession(sessionId, proxyRequests, controls) { withTimeout(5_000) { proxy.await() } }
    }

    @Test
    fun `submit returns 202 then the run completes async, saves the result, polls DONE, and delete-on-close removes it`() = testApplication {
        val client = wire()
        supervisorScope {
            val session = openFakeSession(client) { req, _ ->
                req.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                req.send(rowsChunk(listOf("id"), listOf(listOf("1"), listOf("2"))))
                req.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
            }

            val submit = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select id from t", 100))
            }
            assertEquals(HttpStatusCode.Accepted, submit.status)
            val ack = submit.body<EditorSubmitResponse>()
            assertEquals(core.accessStore.editorChildId(ack.taskId), ack.childId)

            awaitUntil("task EXECUTED and child DONE") {
                core.accessStore.getRequest(ack.taskId)?.status == "EXECUTED" && resultStore.meta(ack.taskId)?.status == "DONE"
            }
            // The enforced rows were SAVED (not returned inline) — the whole point of the async submit.
            assertEquals(listOf(listOf("1"), listOf("2")), resultStore.accessFor(ack.taskId)!!.decrypted!!.rows)

            val poll = client.get("/api/editor/tasks/${ack.taskId}")
            assertEquals(HttpStatusCode.OK, poll.status)
            val status = poll.body<EditorTaskStatus>()
            assertEquals("EXECUTED", status.status)
            assertEquals("DONE", status.result?.status)
            assertEquals(2, status.result?.rowCount)

            // Delete-on-close removes the tab's task (CASCADE to its rows), idempotently.
            assertEquals(HttpStatusCode.NoContent, client.delete("/api/editor/tasks/${ack.taskId}").status)
            assertNull(core.accessStore.getRequest(ack.taskId))
            assertEquals(HttpStatusCode.NoContent, client.delete("/api/editor/tasks/${ack.taskId}").status)

            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `submit pushes a terminal task event to the owner's stream on completion`() = testApplication {
        val hub = TaskCompletionHub()
        val events = hub.subscribe(caller)
        val client = wire(hub = hub)
        supervisorScope {
            val session = openFakeSession(client) { req, _ ->
                req.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                req.send(rowsChunk(listOf("id"), listOf(listOf("1"))))
                req.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
            }
            val ack = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select id from t", 100))
            }.body<EditorSubmitResponse>()
            awaitUntil("task EXECUTED") { core.accessStore.getRequest(ack.taskId)?.status == "EXECUTED" }
            // The push carries the task's actual terminal state, keyed to the completed task.
            val pushed = withTimeout(5_000) { events.receive() }
            assertEquals(TaskEvent(ack.taskId, "EXECUTED"), pushed)
            client.delete("/api/editor/tasks/${ack.taskId}")
            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `a DENY at execute marks the task and child FAILED and saves no rows`() = testApplication {
        val client = wire()
        supervisorScope {
            val session = openFakeSession(client) { req, _ ->
                req.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.DENY; denyReason = "policy denies" } })
            }
            val ack = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select ssn from t", 100))
            }.body<EditorSubmitResponse>()

            awaitUntil("DENY marks task and child FAILED") {
                core.accessStore.getRequest(ack.taskId)?.status == "FAILED" && resultStore.meta(ack.taskId)?.status == "FAILED"
            }
            assertEquals("approval.execute_denied", resultStore.meta(ack.taskId)?.errorCode)
            assertNull(resultStore.accessFor(ack.taskId)?.decrypted, "a DENY saves no readable rows")
            // A denial is a decision, so the reason must reach the polling client: it is what the console
            // shows instead of a generic failure, and what the approval request is composed against. The
            // proxy sent this exact string above; an error code alone leaves the requester nowhere to go.
            assertEquals("policy denies", resultStore.meta(ack.taskId)?.denyReason)

            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `result on a still-running task is 409 not_ready then gates status codes`() = testApplication {
        val client = wire()
        supervisorScope {
            // Hold the run in-flight: ALLOW + rows but withhold Done, so the child stays RUNNING.
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            val session = openFakeSession(client) { req, _ ->
                req.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                req.send(rowsChunk(listOf("id"), listOf(listOf("1"))))
                release.await()
                req.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
            }
            val ack = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select id from t", 100))
            }.body<EditorSubmitResponse>()

            awaitUntil("child RUNNING while in flight") { resultStore.meta(ack.taskId)?.status == "RUNNING" }
            // task.assume passes (owner is a party), but the result isn't DONE yet → 409.
            assertEquals(HttpStatusCode.Conflict, client.get("/api/editor/tasks/${ack.taskId}/result").status)

            release.complete(Unit)
            awaitUntil("completes to DONE") { resultStore.meta(ack.taskId)?.status == "DONE" }

            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `cancel terminalizes an in-flight editor task and emits RunCancel without closing the session`() = testApplication {
        val client = wire()
        supervisorScope {
            val held = CompletableDeferred<Unit>()
            val session = openFakeSession(client) { req, _ ->
                req.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                held.await()
            }
            val ack = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select id from t", 100))
            }.body<EditorSubmitResponse>()
            awaitUntil("editor child RUNNING") { resultStore.meta(ack.taskId)?.status == "RUNNING" }
            withTimeout(5_000) { while (!session.controls.receive().hasQuery()) Unit }

            val cancelled = client.post("/api/editor/tasks/${ack.taskId}/cancel")
            assertEquals(HttpStatusCode.OK, cancelled.status)
            assertEquals("CANCELLED", cancelled.body<EditorTaskStatus>().status)
            assertEquals("CANCELLED", resultStore.meta(ack.taskId)?.status)
            assertEquals("approval.canceled", resultStore.meta(ack.taskId)?.errorCode)
            assertEquals(true, withTimeout(5_000) { session.controls.receive() }.hasCancel())

            val poll = client.get("/api/editor/tasks/${ack.taskId}").body<EditorTaskStatus>()
            assertEquals("CANCELLED", poll.status)
            held.complete(Unit)
            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `canceling a queued editor task sends no cancel or query for the queued statement`() = testApplication {
        val client = wire()
        supervisorScope {
            val firstRelease = CompletableDeferred<Unit>()
            val session = openFakeSession(client) { req, control ->
                if (control.query.sql == "select first") {
                    req.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                    firstRelease.await()
                    req.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
                } else {
                    fail("queued canceled statement crossed the wire: ${control.query.sql}")
                }
            }
            val first = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select first", 100))
            }.body<EditorSubmitResponse>()
            awaitUntil("first editor child RUNNING") { resultStore.meta(first.taskId)?.status == "RUNNING" }
            withTimeout(5_000) { while (!session.controls.receive().hasQuery()) Unit }

            val queued = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select queued", 100))
            }.body<EditorSubmitResponse>()
            awaitUntil("queued child RUNNING") { resultStore.meta(queued.taskId)?.status == "RUNNING" }
            val cancelled = client.post("/api/editor/tasks/${queued.taskId}/cancel").body<EditorTaskStatus>()
            assertEquals("CANCELLED", cancelled.status)
            assertEquals(true, session.controls.tryReceive().isFailure, "queued cancellation must not target the running statement")

            firstRelease.complete(Unit)
            awaitUntil("first task completes") { resultStore.meta(first.taskId)?.status == "DONE" }
            awaitUntil("queued task remains canceled") { resultStore.meta(queued.taskId)?.status == "CANCELLED" }
            assertEquals(true, session.controls.tryReceive().isFailure, "preflight must suppress the queued query")
            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `delete of an executing editor task emits RunCancel then removes the task`() = testApplication {
        val client = wire()
        supervisorScope {
            val held = CompletableDeferred<Unit>()
            val session = openFakeSession(client) { _, _ -> held.await() }
            val ack = client.post("/api/editor/sessions/${session.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest("select id from t", 100))
            }.body<EditorSubmitResponse>()
            awaitUntil("editor child RUNNING") { resultStore.meta(ack.taskId)?.status == "RUNNING" }
            withTimeout(5_000) { while (!session.controls.receive().hasQuery()) Unit }

            assertEquals(HttpStatusCode.NoContent, client.delete("/api/editor/tasks/${ack.taskId}").status)
            assertEquals(true, withTimeout(5_000) { session.controls.receive() }.hasCancel())
            assertNull(core.accessStore.getRequest(ack.taskId))
            held.complete(Unit)
            client.delete("/api/editor/sessions/${session.sessionId}")
            session.await()
        }
    }

    @Test
    fun `submit guards - blank sql is 400 and an unknown session is 404`() = testApplication {
        val client = wire()
        val blank = client.post("/api/editor/sessions/whatever/query") {
            contentType(ContentType.Application.Json); setBody(QueryRequest("   ", 100))
        }
        assertEquals(HttpStatusCode.BadRequest, blank.status)

        val unknown = client.post("/api/editor/sessions/no-such-session/query") {
            contentType(ContentType.Application.Json); setBody(QueryRequest("select id from t", 100))
        }
        assertEquals(HttpStatusCode.NotFound, unknown.status)
    }

    @Test
    fun `a task_read forbid denies the owner's poll with 404`() = testApplication {
        // The other route tests run under authDebug (Cedar bypassed). task.read gates the poll metadata, so a
        // Cedar forbid must override the owner self-read permit — the owner guard alone is not the authorization.
        // Wire the route with authDebug=false so the gate actually runs, authenticating as the task owner via a
        // real web-session cookie. The CedarEngine polls stateVersion, so a freshly-inserted forbid takes effect
        // live and its deletion restores the baseline.
        val client = wireAuthenticated(config.copy(authDebug = false))
        client.login(caller)
        val task = core.accessStore.createEditorTask(
            caller, datasource.id, "select id from t", listOf("editor-analyst"), caller,
        )
        // Baseline: the owner's self-read permit (V33/V38 task.read on own Request) lets the poll through.
        assertEquals(HttpStatusCode.OK, client.get("/api/editor/tasks/${task.id}").status)

        val forbidId = core.cedarPolicyStore.create(
            com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput(
                name = "editor-poll-task-read-forbid",
                cedarSrc = """forbid(principal, action == Action::"task.read", resource) when { principal == User::"$caller" };""",
            ),
            updatedBy = "test-fixture",
        ).id
        try {
            assertEquals(
                HttpStatusCode.NotFound,
                client.get("/api/editor/tasks/${task.id}").status,
                "a task.read forbid must override the self-read permit and 404 the poll",
            )
        } finally {
            core.cedarPolicyStore.delete(forbidId) // restore the class-shared policy set
        }
        // With the forbid gone the owner polls again — proving the 404 was the forbid, not a route bug.
        assertEquals(HttpStatusCode.OK, client.get("/api/editor/tasks/${task.id}").status)
        core.accessStore.deleteEditorTask(task.id, caller)
    }

    @Test
    fun `poll and result for a non-owner editor task are 404`() = testApplication {
        val client = wire()
        // A task owned by someone OTHER than the authDebug caller (debug-user): poll is owner-scoped and
        // result is task.assume-scoped, so both 404 for debug-user.
        val other = core.accessStore.createEditorTask(
            "someone-else@example.com", datasource.id, "select id from t", listOf("editor-analyst"), "someone-else@example.com",
        )
        assertEquals(HttpStatusCode.NotFound, client.get("/api/editor/tasks/${other.id}").status)
        assertEquals(HttpStatusCode.NotFound, client.get("/api/editor/tasks/${other.id}/result").status)
        // Delete by a non-owner is a silent no-op (idempotent 204) and leaves the task intact.
        assertEquals(HttpStatusCode.NoContent, client.delete("/api/editor/tasks/${other.id}").status)
        assertEquals("APPROVED", core.accessStore.getRequest(other.id)?.status)
    }
}
