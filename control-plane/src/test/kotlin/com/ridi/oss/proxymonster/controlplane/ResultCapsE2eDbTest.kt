package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.grpc.CONTROL_PROTOCOL_VERSION
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.management.ManagementAuditRecorder
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.testLoginRoute
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import com.ridi.oss.proxymonster.controlplane.authz.cedarPolicyRoutes
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.ControlRunMsg
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.decisionRequest
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
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
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
import kotlinx.coroutines.channels.Channel as CoChannel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.time.Duration
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Every result-cap path through the control plane's real surfaces (docs/result-caps.md): the shipped
 * policies, the gRPC Decide the wire proxy calls, the editor run channel, the workflow execute + view, the
 * rate-reset request and admin routes, and policy-save validation. MySQL target; a fake proxy over gRPC
 * answers the run channel.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ResultCapsE2eDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var pcf: PerConnectionCatalogFixture
    private lateinit var core: ControlPlaneCore
    private lateinit var runExecService: RunExecService
    private lateinit var resultStore: QueryResultStore
    private lateinit var config: Config
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: ManagedChannel
    private lateinit var appScope: CoroutineScope
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var schema: String
    private var analystRoleId = 0L
    private var exporterRoleId = 0L

    private val analyst = "analyst@example.com"
    private val admin = "admin@example.com"
    private val approver = "approver@example.com"
    private val requester = "requester@example.com"
    private val exporter = "system:production-exporter"
    private val hour = Duration.ofHours(1)

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        pcf = PerConnectionCatalogFixture(fx)
        core = pcf.core
        runExecService = RunExecService(core)
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        sessionStore = PrincipalSessionStore(fx.dataSource, null)
        schema = fx.datasource.defaultSchemas.first()

        val roles = fx.policyStore.listRoles()
        analystRoleId = roles.first { it.name == "analyst" }.id
        exporterRoleId = roles.first { it.name == exporter }.id
        val adminRoleId = roles.first { it.name == "system:admin" }.id
        for (principal in listOf(analyst, admin, approver, requester)) {
            fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        }
        fx.policyStore.createAssignment(RoleAssignmentInput(admin, adminRoleId))
        fx.policyStore.createAssignment(RoleAssignmentInput(approver, adminRoleId))
        // The shipped production presets ship disabled, so the exporter gets the fixture's own read grants.
        val usersTable = "${fx.datasource.name}/${fx.datasource.engine.catalogName(fx.datasource.dbName)}/$schema/users"
        policy(
            "e2e-exporter-reads",
            """permit(
                principal in Role::"$exporter",
                action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"stmt.cat.metadata", Action::"result.read.unmasked"],
                resource
            );""",
        )
        policy(
            "e2e-analyst-pii",
            """permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource in Table::"$usersTable");""",
        )

        config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "result-caps-e2e-secret", oidc = null, resultKey = null, scimToken = null,
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
        withTimeout(10_000) { while (!predicate()) delay(20) }
        require(predicate()) { "timed out awaiting: $what" }
    }

    private fun ApplicationTestBuilder.wire() {
        application {
            attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(Sessions) { webSessionCookie(sessionStore, config.sessionSecret) }
            routing {
                testLoginRoute(sessionStore, config)
                editorSessionRoutes(
                    config, core.datasourceStore, core.accessStore, resultStore,
                    core.policyStore, core.userGroupStore, core.roleResolver, core.authz, runExecService,
                    appScope, core.systemClassification, null, core.auditStore,
                )
                approvalRoutes(
                    config, core.accessStore, core.auditStore, core.datasourceStore, core.policyStore,
                    core.userGroupStore, resultStore, core.roleResolver, core.authz, runExecService,
                )
                accessRoutes(config, core.accessStore, core.authz, core.datasourceStore, core.roleResolver, ManagementAuditRecorder(core.auditStore))
                cedarPolicyRoutes(config, core.authz, core.cedarPolicyStore)
            }
        }
    }

    private suspend fun ApplicationTestBuilder.login(principal: String): HttpClient {
        val client = createClient {
            expectSuccess = false
            install(HttpCookies)
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
        return client
    }

    /** Both engines (the fixture's and the core's) share the DB but version their caches in-process. */
    private fun policy(name: String, src: String) {
        core.cedarPolicyStore.create(CedarPolicyInput(name, src), updatedBy = "test")
        fx.cedarPolicyStore.markCommittedMutation()
    }

    private fun completion(principal: String, rows: Long, bytes: Long = 0, ageSeconds: Long = 60) {
        fx.auditStore.insert(
            AuditEvent(
                ts = Instant.now().minusSeconds(ageSeconds).toString(), principal = principal,
                datasource = fx.datasource.name, statement = "select id from users",
                decision = Decision.ALLOW, kind = "completion", rowsReturned = rows, bytesReturned = bytes,
            ),
        )
    }

    private fun relayed(principal: String) = fx.auditStore.relayedVolume(principal, listOf(hour), Instant.now()).getValue(hour)

    /** A wire client's real Decide: a USER token, a per-connection catalog, the gRPC handler. */
    private inner class WireClient(val principal: String) {
        val token = core.tokenStore.issue(TokenKind.USER, principal, emptyList(), null, 3600).token
        val connectionId = runBlocking { pcf.openAndPush(principal, listOf(schema)).connectionId }

        fun decide(sql: String) = runBlocking {
            stub.decide(decisionRequest {
                this.token = this@WireClient.token
                datasourceName = fx.datasource.name
                connectionId = this@WireClient.connectionId
                this.sql = sql
                searchPath.add(schema)
            }).verdict
        }
    }

    private fun rowsChunk(columns: List<String>, rows: List<List<String?>>): ProxyRunMsg = proxyRunMsg {
        resultRows = runResultRows {
            this.columns += columns
            this.rows += rows.map { values ->
                runRow { this.values += values.map { v -> runValue { if (v == null) isNull = true else value = v } } }
            }
        }
    }

    private class FakeProxy(val proxyRequests: SendChannel<ProxyRunMsg>, val controls: List<ControlRunMsg>, val await: suspend () -> Unit)

    /**
     * Attach a fake proxy, let [open] drive the HTTP side that opens a run channel, and answer each query
     * with [onQuery]. Returns once the channel is serving.
     */
    private suspend fun <T> CoroutineScope.withFakeProxy(
        open: suspend () -> T,
        onQuery: suspend (SendChannel<ProxyRunMsg>, ControlRunMsg) -> Unit,
    ): Pair<T, FakeProxy> {
        val event = async { stub.events(eventsRequest { datasourceName = fx.datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
        awaitUntil("Events stream attached") { fx.datasource.name in core.proxyEventsHub.attached() }
        val opened = async { open() }
        val channel = withTimeout(10_000) { event.await() }.openRunChannel
        val proxyRequests = CoChannel<ProxyRunMsg>(CoChannel.UNLIMITED)
        val controls = java.util.concurrent.CopyOnWriteArrayList<ControlRunMsg>()
        val proxy = async {
            stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                controls += control
                when {
                    control.hasQuery() -> launch { onQuery(proxyRequests, control) }
                    control.hasCancel() -> Unit
                    control.hasClose() -> proxyRequests.close()
                    else -> fail("control plane sent an empty run control message")
                }
            }
        }
        proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = channel.sessionId } })
        proxyRequests.send(proxyRunMsg { serving = runServing {} })
        return withTimeout(10_000) { opened.await() } to FakeProxy(proxyRequests, controls) { withTimeout(10_000) { proxy.await() } }
    }

    private fun decisionRow(principal: String, sql: String, channel: Channel) = core.auditStore.insert(
        AuditEvent(principal = principal, datasource = fx.datasource.name, statement = sql, decision = Decision.ALLOW, channel = channel.contextValue),
    )

    // Editor: a capped run reaches the tab as a truncated result, charges the rate, and its view is never
    // rate-gated; the wire Decide for the same principal is.
    @Test
    fun `editor run capped at the verdict, charged once, viewable after the rate is spent`() = testApplication {
        wire()
        val client = login(analyst)
        val sql = "select id from users"
        val before = relayed(analyst)
        val fingerprint = fx.decide(sql, channel = Channel.EDITOR).resultFingerprint
        val decisionId = decisionRow(analyst, sql, Channel.EDITOR)
        supervisorScope {
            val (opened, proxy) = withFakeProxy(
                open = {
                    client.post("/api/editor/sessions") {
                        contentType(ContentType.Application.Json); setBody(OpenEditorSessionInput(fx.datasource.id))
                    }.body<EditorSessionOpened>()
                },
            ) { req, control ->
                assertEquals(100, control.query.maxRows, "the editor forwards the tab's page size")
                req.send(proxyRunMsg {
                    decision = runDecision {
                        decision = WireEnfAction.ALLOW; this.decisionId = decisionId; maxRows = 3
                        resultFingerprint.addAll(fingerprint)
                    }
                })
                req.send(rowsChunk(listOf("id"), listOf(listOf("1"), listOf("2"), listOf("3"))))
                req.send(proxyRunMsg { done = runDone { rowsAffected = -1; truncatedByCap = true } })
            }
            val ack = client.post("/api/editor/sessions/${opened.sessionId}/query") {
                contentType(ContentType.Application.Json); setBody(QueryRequest(sql, 100))
            }.body<EditorSubmitResponse>()
            awaitUntil("editor child DONE") { resultStore.meta(ack.taskId)?.status == "DONE" }

            val after = relayed(analyst)
            assertEquals(before.rows + 3, after.rows, "the run channel charges exactly the relayed rows")
            assertEquals(1, core.auditStore.recent(100).count { it.kind == "completion" && it.decisionId == decisionId })

            val view = client.get("/api/editor/tasks/${ack.taskId}/result")
            assertEquals(HttpStatusCode.OK, view.status, view.bodyAsText())
            val body = view.body<QueryResultView>()
            assertEquals(3, body.rows.size)
            assertTrue(body.truncatedByCap, "the execution's cap marks the stored result")
            assertNull(body.truncatedAt, "the viewer's own cap (5000) releases every stored row")

            // Spend the hour: the next wire Decide denies, the already-relayed view does not.
            completion(analyst, 10_000)
            val wire = WireClient(analyst)
            val denied = wire.decide(sql)
            assertEquals(WireEnfAction.DENY, denied.decision)
            assertEquals("$RATE_SPENT_DENY 10000/1h spent", denied.denyReason)
            assertEquals(HttpStatusCode.OK, client.get("/api/editor/tasks/${ack.taskId}/result").status)
            // Session statements pass through a spent rate; a row-returning one does not.
            assertNotEquals(WireEnfAction.DENY, wire.decide("commit").decision)
            assertEquals(WireEnfAction.DENY, wire.decide("select 1").decision)

            client.delete("/api/editor/tasks/${ack.taskId}")
            client.delete("/api/editor/sessions/${opened.sessionId}")
            proxy.await()
        }
    }

    // Wire: the shipped caps per shape, then a spent rate, then the admin reset route clears it.
    @Test
    fun `wire Decide stamps the shipped caps and an admin reset lifts a spent rate`() = testApplication {
        wire()
        val principal = "wire-rate@example.com"
        fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        fx.policyStore.createAssignment(RoleAssignmentInput(principal, analystRoleId))
        val wire = WireClient(principal)

        val plain = wire.decide("select id from users")
        assertEquals(WireEnfAction.ALLOW, plain.decision, plain.denyReason)
        assertEquals(5000L to 50_000_000L, plain.maxRows to plain.maxBytes)
        val pii = wire.decide("select ssn from users")
        assertEquals(WireEnfAction.ALLOW, pii.decision, pii.denyReason)
        assertEquals(500L to 5_000_000L, pii.maxRows to pii.maxBytes, "a tagged column in the clear takes the tight row")

        completion(principal, 0, bytes = 100_000_000)
        val denied = wire.decide("select id from users")
        assertEquals(WireEnfAction.DENY, denied.decision)
        assertEquals("$RATE_SPENT_DENY 100MB/1h spent", denied.denyReason)

        val adminClient = login(admin)
        assertEquals(HttpStatusCode.NoContent, adminClient.get("/api/access/principals/$principal/rate-reset").status, "never reset yet")
        val blank = adminClient.post("/api/access/principals/$principal/rate-reset") {
            contentType(ContentType.Application.Json); setBody(RateResetInput(" "))
        }
        assertEquals(HttpStatusCode.BadRequest, blank.status)
        val reset = adminClient.post("/api/access/principals/$principal/rate-reset") {
            contentType(ContentType.Application.Json); setBody(RateResetInput("false positive"))
        }
        assertEquals(HttpStatusCode.OK, reset.status, reset.bodyAsText())
        assertEquals(admin, reset.body<RateReset>().resetBy)
        assertEquals("false positive", adminClient.get("/api/access/principals/$principal/rate-reset").body<RateReset>().reason)

        val lifted = wire.decide("select id from users")
        assertEquals(WireEnfAction.ALLOW, lifted.decision, lifted.denyReason)
        assertEquals(5000L, lifted.maxRows, "a reset leaves the statement cap alone")
        assertNotNull(core.auditStore.recent(50).firstOrNull { it.kind == "admin" && it.principal == admin && "reset spent result rates" in it.statement })

        // Only an admin resets directly.
        val analystClient = login(analyst)
        assertEquals(HttpStatusCode.Forbidden, analystClient.post("/api/access/principals/$principal/rate-reset") {
            contentType(ContentType.Application.Json); setBody(RateResetInput("please"))
        }.status)
        assertEquals(HttpStatusCode.Forbidden, analystClient.get("/api/access/principals/$principal/rate-reset").status)
    }

    // Workflow: the user files a RATE_RESET request, an approver approves it, the rate is clear again.
    @Test
    fun `a RATE_RESET request approved on the workflow surface clears the requester's rate`() = testApplication {
        wire()
        val principal = "quota@example.com"
        fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        fx.policyStore.createAssignment(RoleAssignmentInput(principal, analystRoleId))
        val wire = WireClient(principal)
        completion(principal, 10_000)
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", wire.decide("select id from users").denyReason)

        val user = login(principal)
        assertEquals(HttpStatusCode.BadRequest, user.post("/api/access-requests/rate-reset") {
            contentType(ContentType.Application.Json); setBody(RateResetRequestInput("", denyReason = "rate 10000/1h spent"))
        }.status)
        val created = user.post("/api/access-requests/rate-reset") {
            contentType(ContentType.Application.Json); setBody(RateResetRequestInput("monthly export re-run", denyReason = "rate 10000/1h spent"))
        }
        assertEquals(HttpStatusCode.Created, created.status, created.bodyAsText())
        val request = created.body<AccessRequest>()
        assertEquals("RATE_RESET", request.kind)
        assertEquals("PENDING", request.status)
        assertEquals("rate 10000/1h spent", request.denyReason)
        assertTrue(user.get("/api/access-requests").body<List<AccessRequest>>().any { it.id == request.id }, "the requester sees their own row")
        assertNull(core.auditStore.lastRateReset(principal))

        // The requester cannot approve their own request; an unrelated non-approver cannot either.
        assertEquals(HttpStatusCode.Forbidden, user.post("/api/access-requests/${request.id}/approve").status)
        assertEquals(HttpStatusCode.Forbidden, login(analyst).post("/api/access-requests/${request.id}/approve").status)
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", wire.decide("select id from users").denyReason)

        val approverClient = login(approver)
        assertTrue(approverClient.get("/api/access-requests?status=PENDING").body<List<AccessRequest>>().any { it.id == request.id })
        val approved = approverClient.post("/api/access-requests/${request.id}/approve")
        assertEquals(HttpStatusCode.OK, approved.status, approved.bodyAsText())
        assertEquals("APPROVED", approved.body<AccessRequest>().status)
        assertEquals(approver, core.auditStore.lastRateReset(principal)?.resetBy)
        val lifted = wire.decide("select id from users")
        assertEquals(WireEnfAction.ALLOW, lifted.decision, lifted.denyReason)

        // Volume after the reset counts again, and a rejected request resets nothing.
        completion(principal, 10_000, ageSeconds = 0)
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", wire.decide("select id from users").denyReason)
        val second = user.post("/api/access-requests/rate-reset") {
            contentType(ContentType.Application.Json); setBody(RateResetRequestInput("again"))
        }.body<AccessRequest>()
        val rejected = approverClient.post("/api/access-requests/${second.id}/reject") {
            contentType(ContentType.Application.Json); setBody(RejectInput("wait for the window"))
        }
        assertEquals(HttpStatusCode.OK, rejected.status, rejected.bodyAsText())
        assertEquals("REJECTED", rejected.body<AccessRequest>().status)
        assertEquals(approver, core.auditStore.lastRateReset(principal)?.resetBy, "the earlier marker is the only one")
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", wire.decide("select id from users").denyReason)
    }

    // Workflow: an approved query executed under the exporter role runs uncapped and unrated; the requester
    // views the whole stored result while a capped viewer of the same rows is cut.
    @Test
    fun `an exporter-role workflow executes uncapped and its view releases every row`() = testApplication {
        wire()
        val sql = "select ssn from users"
        val approverExec = fx.decide(sql, principal = approver, channel = Channel.WORKFLOW_EXECUTOR, providedRoles = setOf(exporter))
        assertEquals(WireEnfAction.ALLOW, approverExec.action, approverExec.denyReason)
        assertNull(approverExec.maxRows)
        assertNull(approverExec.maxBytes)
        // Bury the executor's own rate: the exporter forbid drops every rate, so this must not matter.
        completion(approver, 100_000)

        val id = fx.accessStore.createQueryRequest(
            principal = requester, datasourceId = fx.datasource.id, statements = listOf(sql),
            denyReason = null, sourceDecisionId = null, reason = "export", title = null,
            evaluatedDecision = "DENY", roleId = exporterRoleId,
        ).id
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status='APPROVED', decided_by=? WHERE id=?").use { ps ->
                ps.setString(1, approver); ps.setLong(2, id); ps.executeUpdate()
            }
        }
        val approverClient = login(approver)
        val stored = (1..5000).map { listOf("987-65-%04d".format(it)) }
        supervisorScope {
            val (response, proxy) = withFakeProxy(
                open = { approverClient.post("/api/approvals/$id/execute") },
            ) { req, control ->
                assertEquals(5000, control.query.maxRows, "the workflow asks for the channel ceiling")
                req.send(proxyRunMsg {
                    decision = runDecision {
                        decision = WireEnfAction.ALLOW; maxRows = 0
                        resultFingerprint.addAll(approverExec.resultFingerprint)
                    }
                })
                stored.chunked(1000).forEach { req.send(rowsChunk(listOf("ssn"), it)) }
                req.send(proxyRunMsg { done = runDone { rowsAffected = -1; truncatedByCap = false } })
            }
            assertEquals(HttpStatusCode.Accepted, response.status, response.bodyAsText())
            proxy.await()
        }
        awaitUntil("workflow EXECUTED") { core.accessStore.getRequest(id)?.status == "EXECUTED" && resultStore.meta(id)?.status == "DONE" }

        val view = login(requester).get("/api/approvals/$id/result")
        assertEquals(HttpStatusCode.OK, view.status, view.bodyAsText())
        val body = view.body<QueryResultView>()
        assertEquals(5000, body.rows.size)
        assertFalse(body.truncatedByCap)
        assertNull(body.truncatedAt)
        assertEquals("987-65-0001", body.rows.first().single(), "the exporter reads PII in the clear")

        // The same stored rows under a capped role: the viewer's -306 row (500) cuts the release.
        val cappedRole = fx.policyStore.createRole(RoleInput("e2e-capped-viewer")).id
        policy(
            "e2e-capped-viewer-reads",
            """permit(principal in Role::"e2e-capped-viewer", action in [Action::"datasource.connect", Action::"stmt.cat.read", Action::"result.read.unmasked"], resource);""",
        )
        val cappedId = fx.accessStore.createQueryRequest(
            principal = requester, datasourceId = fx.datasource.id, statements = listOf(sql),
            denyReason = null, sourceDecisionId = null, reason = "export", title = null,
            evaluatedDecision = "DENY", roleId = cappedRole,
        ).id
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status='APPROVED', decided_by=? WHERE id=?").use { ps ->
                ps.setString(1, approver); ps.setLong(2, cappedId); ps.executeUpdate()
            }
        }
        val cappedFingerprint = fx.decide(sql, principal = approver, channel = Channel.WORKFLOW_EXECUTOR, providedRoles = setOf("e2e-capped-viewer")).resultFingerprint
        assertNotNull(resultStore.startNextRun(cappedId, approver))
        assertNotNull(resultStore.completeRun(cappedId, DecryptedResult(listOf("ssn"), stored, resultFingerprint = fingerprintOf(cappedFingerprint)), 3600))
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE access_request SET status='EXECUTED' WHERE id=?").use { ps -> ps.setLong(1, cappedId); ps.executeUpdate() }
        }
        val cappedView = login(requester).get("/api/approvals/$cappedId/result")
        assertEquals(HttpStatusCode.OK, cappedView.status, cappedView.bodyAsText())
        val capped = cappedView.body<QueryResultView>()
        assertEquals(500, capped.rows.size)
        assertEquals(500, capped.truncatedAt)
        assertFalse(capped.truncatedByCap, "the execution stored every row; only this view is cut")

        // A spent rate never gates a workflow view (the rows were charged at execution); the same viewer's
        // next editor-channel Decide is denied.
        completion(requester, 10_000)
        val spentView = login(requester).get("/api/approvals/$cappedId/result")
        assertEquals(HttpStatusCode.OK, spentView.status, spentView.bodyAsText())
        assertEquals(500, spentView.body<QueryResultView>().rows.size)
        fx.policyStore.createAssignment(RoleAssignmentInput(requester, analystRoleId))
        val editorToken = core.tokenStore.issue(TokenKind.EDITOR, requester, emptyList(), null, 3600).token
        val editorConnection = pcf.openAndPush(requester, listOf(schema), tokenKind = TokenKind.EDITOR.name).connectionId
        val denied = stub.decide(decisionRequest {
            token = editorToken; datasourceName = fx.datasource.name; connectionId = editorConnection
            this.sql = "select id from users"; searchPath.add(schema)
        }).verdict
        assertEquals(WireEnfAction.DENY, denied.decision)
        assertEquals("$RATE_SPENT_DENY 10000/1h spent", denied.denyReason)
    }

    // Policy save: the cap grammar is enforced where an admin types it.
    @Test
    fun `saving a malformed or misplaced cap annotation is refused with the errors`() = testApplication {
        wire()
        val adminClient = login(admin)
        suspend fun save(src: String) = adminClient.post("/api/policies") {
            contentType(ContentType.Application.Json); setBody(CedarPolicyInput("e2e-cap-${System.nanoTime()}", src))
        }
        for (bad in listOf(
            """@cap("5M") permit(principal, action == Action::"result.cap", resource);""",
            """@cap("1/32d") permit(principal, action == Action::"result.cap", resource);""",
            """@cap("10/1x") permit(principal, action == Action::"result.cap", resource);""",
            """@cap("5") permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource);""",
        )) {
            val response = save(bad)
            assertEquals(HttpStatusCode.BadRequest, response.status, bad)
            val errors = Json.parseToJsonElement(response.bodyAsText()).let { it.toString() }
            assertTrue("errors" in errors && ("@cap" in errors || "result.cap" in errors), "$bad -> $errors")
        }
        val ok = save("""@cap("2000, 3MB, 100KB/10m, 7GB/31d") permit(principal in Role::"analyst", action == Action::"result.cap", resource);""")
        assertTrue(ok.status.value in 200..201, ok.bodyAsText())
        assertEquals(HttpStatusCode.Forbidden, login(analyst).post("/api/policies") {
            contentType(ContentType.Application.Json); setBody(CedarPolicyInput("e2e-cap-nope", """@cap("1") permit(principal, action == Action::"result.cap", resource);"""))
        }.status)
    }
}
