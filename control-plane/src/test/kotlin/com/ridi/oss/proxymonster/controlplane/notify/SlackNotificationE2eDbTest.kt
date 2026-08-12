package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.AppUserInput
import com.ridi.oss.proxymonster.controlplane.Config
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.CreateApprovalResponse
import com.ridi.oss.proxymonster.controlplane.PRINCIPAL_SESSION_STORE
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.QueryResultStore
import com.ridi.oss.proxymonster.controlplane.ResultCrypto
import com.ridi.oss.proxymonster.controlplane.RoleAssignmentInput
import com.ridi.oss.proxymonster.controlplane.RoleInput
import com.ridi.oss.proxymonster.controlplane.RunExecService
import com.ridi.oss.proxymonster.controlplane.approvalRoutes
import com.ridi.oss.proxymonster.controlplane.grpc.CONTROL_PROTOCOL_VERSION
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.runApprovedTask
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.MockSlack
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runReady
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runServing
import com.ridi.oss.proxymonster.grpc.runValue
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The Slack approval loop end to end, from the requester creating the workflow through the approved query
 * actually running and its result landing in the database — against a real mock Slack, real PostgreSQL +
 * Cedar, and a real fake proxy over gRPC (the same [ControlPlaneCore] wired into [RunExecService] and
 * [ControlPlaneGrpcService], so the run plays back over the true execute-under-R wire path, as in
 * `ApprovalExecuteRouteDbTest`).
 *
 * Only Slack and the target DB are mocked; the compose route, `decideQuery` + the disclosure hint,
 * the notification drain, the Socket Mode click, the Cedar `task.approve`, and the production run path
 * (`claimAndStartRun` → `runApprovedTask` → `runExecService.run`) are the real classes.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SlackNotificationE2eDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var core: ControlPlaneCore
    private lateinit var resultStore: QueryResultStore
    private lateinit var runExecService: RunExecService
    private lateinit var config: Config
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: ManagedChannel
    private lateinit var slack: MockSlack
    private lateinit var http: HttpClient
    private lateinit var svc: NotificationService
    private lateinit var socket: SlackSocketMode
    private lateinit var sessionStore: PrincipalSessionStore

    // The requester signs in to the compose route; the Slack click resolves the approver's verified email to
    // its own active app_user principal.
    private val requester = "dev@example.com"
    private val approver = "admin@example.com"
    private var runnerRoleId = 0L
    private val runScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val log = LoggerFactory.getLogger("e2e")

    // The class shares one MockSlack (@BeforeAll), so drop its recorded call log per test — every case then
    // counts only its own posts, instead of accumulating across the class in method-order-dependent ways.
    @BeforeEach
    fun resetSlackLog() {
        slack.clearRecorded()
    }

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        core = ControlPlaneCore(fx.dataSource)
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        runExecService = RunExecService(core)
        sessionStore = PrincipalSessionStore(fx.dataSource, null)
        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "e2e-test-secret", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )

        // The approver: a provisioned system:admin, so the real Cedar task.approve on the `slack` channel passes.
        core.policyStore.createAssignment(
            RoleAssignmentInput(approver, core.policyStore.listRoles().first { it.name == "system:admin" }.id),
        )
        core.userGroupStore.createUser(
            AppUserInput(principal = approver, email = approver),
            core.tokenStore, core.accessStore, PrincipalSessionStore(fx.dataSource, null),
        )
        // The elevation role R the requester picks; the fake proxy fabricates the run decision, so R only has
        // to be a live role the run executes under.
        runnerRoleId = core.policyStore.createRole(RoleInput("e2e-runner")).id

        // The fake proxy's transport: the SAME core, so a run dialed here attaches to the exact proxyEventsHub
        // runExecService.run dials.
        server = GrpcServer(0, ControlPlaneGrpcService(core), secretToken = null).also { it.start() }
        rawChannel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(rawChannel)

        slack = MockSlack.start()
        slack.userIdByEmail[approver] = "U_ADMIN"
        slack.usersById["U_ADMIN"] = MockSlack.SlackUser(email = approver)
        http = slackHttpClient()
        val transport = SlackTransport(http, "xoxb-e2e", "https://console.example", NotificationRenderer(), api = slack.apiBase)
        svc = NotificationService(
            store = NotificationStore(fx.dataSource),
            recipients = RecipientResolver(core.authz, core.roleResolver) { listOf(approver) },
            transports = listOf(transport),
            accessStore = core.accessStore,
            queryResultStore = resultStore,
            webBaseUrl = "https://console.example",
            // `auto`, the default: a cleared statement is shown (approve-and-run offered), a flagged one is
            // withheld (no button). The two E2E cases below exercise both branches on the real hint path.
            disclosure = StatementDisclosure.AUTO,
            defaultLocale = "en",
        )
        val handler = SlackDecisionHandler(
            accessStore = core.accessStore,
            datasourceStore = core.datasourceStore,
            authz = core.authz,
            auditRecorder = ManagementAuditRecorder(core.auditStore),
            notifications = svc,
            defaultLocale = "en",
            onApproved = { approved -> realRun(approved) },
        )
        socket = SlackSocketMode(
            http, "xoxb-e2e", "xapp-e2e",
            principalForEmail = core.userGroupStore::activePrincipalByEmail,
            onInteraction = { handler.handle(it) },
            api = slack.apiBase,
        )
    }

    @AfterAll
    fun teardown() {
        runScope.cancel()
        rawChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
        http.close()
        slack.close()
    }

    /** The production approve-and-run path (NotificationsWiring.onApproved), verbatim: claim, then run. */
    private suspend fun realRun(approved: AccessRequest) {
        val ds = approved.datasourceId?.let(core.datasourceStore::get)
        val sql = approved.sql
        val executeAs = core.policyStore.liveRoleNames(approved.executeAs).toSet()
        require(ds != null && sql != null && executeAs.isNotEmpty()) { "cannot run task ${approved.id}" }
        val claimed = resultStore.claimAndStartRun(approved.id, approved.decidedBy ?: approved.principal) { c ->
            core.accessStore.claimExecution(approved.id, c)
        } != null
        if (claimed) {
            runScope.launch {
                runApprovedTask(
                    id = approved.id, executor = approved.decidedBy ?: approved.principal,
                    ds = ds, sql = sql, executeAs = executeAs, requesterIp = null,
                    requesterPrincipal = approved.principal, req = approved, config = config,
                    accessStore = core.accessStore, store = resultStore, auditStore = core.auditStore,
                    runExecService = runExecService, taskCompletionHub = null, notifications = svc, log = log,
                )
            }
        }
    }

    /** The compose route plus a client already signed in as [requester]. */
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
                    notifications = svc,
                )
            }
        }
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$requester").status)
        return client
    }

    private suspend fun awaitUntil(what: String, predicate: () -> Boolean) {
        withTimeout(10_000) { while (!predicate()) delay(20) }
        require(predicate()) { "timed out awaiting: $what" }
    }

    private fun rowsChunk(columns: List<String>, rows: List<List<String?>>): ProxyRunMsg = proxyRunMsg {
        resultRows = runResultRows {
            this.columns += columns
            this.rows += rows.map { values -> runRow { this.values += values.map { v -> runValue { if (v == null) isNull = true else value = v } } } }
        }
    }

    // Both statements are quote-free of `"`; single quotes are valid inside a JSON string, so inline is safe.
    private suspend fun HttpClient.createApproval(sql: String) = post("/api/approvals") {
        contentType(ContentType.Application.Json)
        setBody("""{"datasourceId":${fx.datasource.id},"sql":"$sql","title":"read","reason":"audit","roleId":$runnerRoleId}""")
    }

    private fun MockSlack.Recorded.actionElements(): List<Map<String, kotlinx.serialization.json.JsonElement>> =
        json!!["blocks"]!!.jsonArray.map { it.jsonObject }
            .first { it["type"]?.jsonPrimitive?.content == "actions" }["elements"]!!.jsonArray.map { it.jsonObject }

    private fun MockSlack.Recorded.sectionText(): String =
        json!!["blocks"]!!.jsonArray.map { it.jsonObject }
            .first { it["type"]?.jsonPrimitive?.content == "section" }["text"]!!.jsonObject["text"]!!.jsonPrimitive.content

    private fun storedResultCount(id: Long): Long = fx.dataSource.connection.use { c ->
        c.prepareStatement("SELECT count(*) FROM query_result WHERE task_id = ?").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    @Test
    fun `requester creates the workflow, the approver approves in Slack, and the approved run stores its result`() = testApplication {
        val client = wire()

        // 1. The requester composes and submits through the REAL route — decideQuery + the disclosure hint +
        //    createQueryRequest + the request notification, all in one HTTP call.
        val created = client.createApproval("SELECT ssn FROM users")
        assertEquals(HttpStatusCode.Created, created.status)
        val req = created.body<CreateApprovalResponse>().request

        // 2. Drain: the approver is notified, and a clean statement offers approve-and-run.
        svc.drainOnce()
        val post = slack.lastRequest("chat.postMessage")!!
        assertTrue(
            post.actionElements().any { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_APPROVE },
            "a clean statement offers approve-and-run",
        )

        supervisorScope {
            // The Events stream must be attached before the click so the run's open-channel lands on it.
            val event = async { stub.events(eventsRequest { datasourceName = fx.datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { fx.datasource.name in core.proxyEventsHub.attached() }

            // 3. The approver clicks approve over Socket Mode → Cedar task.approve → onApproved → the real run.
            val pump = launch(Dispatchers.IO) { socket.run() }
            try {
                slack.awaitConnection()
                slack.pushEnvelope(
                    """
                    {"envelope_id":"env-run","type":"interactive",
                     "payload":{"type":"block_actions","team":{"id":"${slack.teamId}"},"user":{"id":"U_ADMIN"},
                       "actions":[{"action_id":"${SlackTransport.ACTION_APPROVE}","value":"${req.id}"}],
                       "response_url":"${slack.responseUrl}","channel":{"id":"C_MOCK"},
                       "message":{"ts":"1700000000001.000100"}}}
                    """.trimIndent(),
                )

                // 4. The run opens its channel; the fake proxy replays ALLOW + one row + Done.
                val open = withTimeout(10_000) { event.await() }.openRunChannel
                val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
                val proxy = async {
                    stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                        when {
                            control.hasQuery() -> {
                                proxyRequests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                                proxyRequests.send(rowsChunk(listOf("ssn"), listOf(listOf("123-45-6789"))))
                                proxyRequests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
                            }
                            control.hasClose() -> proxyRequests.close()
                            else -> fail("empty control message")
                        }
                    }
                }
                proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
                proxyRequests.send(proxyRunMsg { serving = runServing {} })

                awaitUntil("run completes to EXECUTED and DONE") {
                    core.accessStore.getRequest(req.id)?.status == "EXECUTED" && resultStore.meta(req.id)?.status == "DONE"
                }
                withTimeout(5_000) { proxy.await() }
            } finally {
                pump.cancel()
            }
        }

        // 5. THE POINT: the approved run actually executed and its result is stored in the DB.
        assertEquals(1L, storedResultCount(req.id), "exactly one query_result row was stored")
        assertEquals(
            listOf(listOf("123-45-6789")),
            resultStore.accessFor(req.id)!!.decrypted!!.rows,
            "the run's row is stored (encrypted at rest, decrypted here)",
        )

        // 6. The decided event edits the original message in place rather than posting a second one.
        svc.drainOnce()
        val update = slack.lastRequest("chat.update")!!
        assertEquals("C_MOCK", update.json!!["channel"]!!.jsonPrimitive.content, "the original message is edited")
        assertEquals(1, slack.requestsFor("chat.postMessage").size, "no second message was posted")
    }

    @Test
    fun `a request whose predicate carries a protected literal is announced with the statement withheld and no approve button`() = testApplication {
        val client = wire()
        val created = client.createApproval("SELECT id FROM users WHERE ssn = '987-65-4320'")
        assertEquals(HttpStatusCode.Created, created.status)

        svc.drainOnce()
        val post = slack.lastRequest("chat.postMessage")!!
        assertTrue(!post.sectionText().contains("987-65-4320"), "the protected literal is withheld from the message")
        assertTrue(
            post.actionElements().none { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_APPROVE },
            "a withheld statement offers no approve-and-run — you cannot vouch for what you cannot read",
        )
    }

    /**
     * The mode is a property of the draining service, not the enqueued row, so a FULL-mode drainer renders the
     * same flagged request the AUTO case above withholds. FULL shows it to a pending approver on purpose — they
     * must read it to decide — where AUTO never would. The hint reasserts itself once the task is handled
     * (discloseStatement, unit-tested); the withhold render path is the same one the AUTO case exercises.
     */
    @Test
    fun `under full a pending approver sees even a flagged statement`() = testApplication {
        val fullSvc = NotificationService(
            store = NotificationStore(fx.dataSource),
            recipients = RecipientResolver(core.authz, core.roleResolver) { listOf(approver) },
            transports = listOf(SlackTransport(http, "xoxb-e2e", "https://console.example", NotificationRenderer(), api = slack.apiBase)),
            accessStore = core.accessStore,
            queryResultStore = resultStore,
            webBaseUrl = "https://console.example",
            disclosure = StatementDisclosure.FULL,
            defaultLocale = "en",
        )
        val client = wire()
        assertEquals(HttpStatusCode.Created, client.createApproval("SELECT id FROM users WHERE ssn = '987-65-4320'").status)

        fullSvc.drainOnce()
        val post = slack.lastRequest("chat.postMessage")!!
        assertTrue(
            post.sectionText().contains("987-65-4320"),
            "full shows a pending approver the whole statement, flagged or not — they must read it to decide",
        )
        assertTrue(
            post.actionElements().any { it["action_id"]?.jsonPrimitive?.content == SlackTransport.ACTION_APPROVE },
            "a fully-shown statement offers approve-and-run",
        )
    }
}
