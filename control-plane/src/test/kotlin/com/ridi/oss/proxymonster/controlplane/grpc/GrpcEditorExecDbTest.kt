package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.support.openEditorConnection
import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.effectiveCatalog
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.EditorExecService
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.NoProxyAttachedException
import com.ridi.oss.proxymonster.controlplane.PendingSession
import com.ridi.oss.proxymonster.controlplane.ProxyRunException
import com.ridi.oss.proxymonster.controlplane.ProxyRunTimeoutException
import com.ridi.oss.proxymonster.controlplane.QueryResponse
import com.ridi.oss.proxymonster.controlplane.TargetDbRunException
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EditorQuery
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyEditorMsg
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.editorDecision
import com.ridi.oss.proxymonster.grpc.editorDone
import com.ridi.oss.proxymonster.grpc.editorError
import com.ridi.oss.proxymonster.grpc.editorResultRows
import com.ridi.oss.proxymonster.grpc.editorRow
import com.ridi.oss.proxymonster.grpc.editorProgress
import com.ridi.oss.proxymonster.grpc.editorReady
import com.ridi.oss.proxymonster.grpc.editorServing
import com.ridi.oss.proxymonster.grpc.editorValue
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyEditorMsg
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** DB-backed end-to-end coverage for the control-plane half of the proxy-dialed editor session. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcEditorExecDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var service: EditorExecService
    private lateinit var datasource: Datasource
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: io.grpc.ManagedChannel

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_grpc_editor"))
        core = ControlPlaneCore(dataSource)
        service = EditorExecService(core)
        datasource = core.datasourceStore.create(
            DatasourceInput(
                name = "editor-ds",
                engine = "postgres",
                host = "localhost",
                port = 5432,
                dbName = "app",
            ),
        )
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

    private fun audit(decision: Decision, piiTouched: List<String>): Long = core.auditStore.insert(
        AuditEvent(
            principal = "editor-user",
            datasource = datasource.name,
            statement = "select test",
            decision = decision,
            piiTouched = piiTouched,
        ),
    )

    private suspend fun exchange(
        sql: String,
        maxRows: Int = 500,
        requesterIp: String? = null,
        playProxy: suspend (EditorQuery, Channel<ProxyEditorMsg>) -> Unit,
    ): Result<QueryResponse> = supervisorScope {
        val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
        awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

        val result = async { runCatching { service.run("editor-user", datasource, sql, maxRows, requesterIp = requesterIp) } }
        val open = withTimeout(5_000) { event.await() }.openEditorSession
        val identity = core.tokenStore.resolve(open.ephemeralToken)
        assertEquals("editor-user", identity?.principal, "the ephemeral token resolves during the editor window")
        assertEquals(emptyList(), identity?.roles)
        assertTrue(
            core.tokenStore.list("editor-user").none { it.kind == "EDITOR" },
            "transient editor tokens stay off the user-visible token list",
        )

        val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
        val proxy = async {
            stub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                when {
                    control.hasQuery() -> {
                        assertEquals(requesterIp.orEmpty(), control.query.requesterIp, "the query carries the requester's IP")
                        playProxy(control.query, proxyRequests)
                    }
                    control.hasClose() -> proxyRequests.close()
                    else -> fail("control plane sent an empty editor control message")
                }
            }
        }
        proxyRequests.send(
            proxyEditorMsg {
                sessionReady = editorReady { sessionId = open.sessionId }
            },
        )
        // EditorReady (the run id) is sent first; the CP then waits for EditorServing (the target-DB open
        // finishing) before it sends the query. A real proxy heartbeats EditorProgress; a fast fake just serves.
        proxyRequests.send(proxyEditorMsg { serving = editorServing {} })

        val outcome = withTimeout(5_000) { result.await() }
        withTimeout(5_000) { proxy.await() }
        assertNull(core.tokenStore.resolve(open.ephemeralToken), "the ephemeral token is revoked after the exchange")
        awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        outcome
    }

    @Test
    fun `an editor session's requesterIp rides its EditorQuery`() = runBlocking {
        // exchange() asserts each query carries the requesterIp passed in; the other exchange()-based tests pin
        // the empty case.
        exchange("select 1", requesterIp = "203.0.113.99") { _, requests ->
            requests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
            requests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
        }.getOrThrow()
        Unit
    }

    @Test
    fun `ALLOW assembles chunked rows, nulls, metadata, audit PII, and SELECT rowsAffected`() = runBlocking {
        val decisionId = audit(Decision.ALLOW, listOf("app.public.users.email"))
        val response = exchange("select id, email from users", maxRows = 9_000) { query, requests ->
            assertEquals("select id, email from users", query.sql)
            assertEquals(5_000, query.maxRows, "maxRows is clamped before crossing the wire")
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.ALLOW
                        this.decisionId = decisionId
                        effectiveRoles += listOf("analyst", "reader")
                    }
                },
            )
            requests.send(rowsChunk(listOf("id", "email"), listOf(listOf("1", "a@example.com"))))
            requests.send(rowsChunk(listOf("id", "email"), listOf(listOf("2", null))))
            requests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
        }.getOrThrow()

        assertEquals(EnfAction.ALLOW, response.decision)
        assertEquals(decisionId, response.decisionId)
        assertNull(response.denyReason)
        assertEquals(emptyList(), response.maskedColumns)
        assertEquals(listOf("app.public.users.email"), response.piiTouched)
        assertEquals(listOf("analyst", "reader"), response.effectiveRoles)
        assertEquals(listOf("id", "email"), response.columns)
        assertEquals(listOf(listOf("1", "a@example.com"), listOf("2", null)), response.rows)
        assertNull(response.rowsAffected)
        assertTrue(response.latencyMs >= 0)
    }

    @Test
    fun `MASK preserves masked-column metadata and returns only proxy-produced values`() = runBlocking {
        val decisionId = audit(Decision.MASK, listOf("app.public.users.ssn"))
        val response = exchange("select ssn from users", maxRows = 0) { query, requests ->
            assertEquals(0, query.maxRows, "maxRows=0 crosses the wire as the proxy's default-500 sentinel (proxy re-coerces)")
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.MASK
                        this.decisionId = decisionId
                        maskedColumns += "ssn"
                        effectiveRoles += "analyst"
                    }
                },
            )
            requests.send(rowsChunk(listOf("ssn"), listOf(listOf("######-#######"))))
            requests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
        }.getOrThrow()

        assertEquals(EnfAction.MASK, response.decision)
        assertEquals(decisionId, response.decisionId)
        assertNull(response.denyReason)
        assertEquals(listOf("ssn"), response.maskedColumns)
        assertEquals(listOf("app.public.users.ssn"), response.piiTouched)
        assertEquals(listOf("analyst"), response.effectiveRoles)
        assertEquals(listOf("ssn"), response.columns)
        assertEquals(listOf(listOf("######-#######")), response.rows)
        assertNull(response.rowsAffected)
    }

    @Test
    fun `a cap-truncated run carries the verdict cap and its notice flag`() = runBlocking {
        val decisionId = audit(Decision.ALLOW, emptyList())
        val response = exchange("select id from users") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.ALLOW
                        this.decisionId = decisionId
                        maxRows = 100
                        maxBytes = 4000
                    }
                },
            )
            requests.send(rowsChunk(listOf("id"), listOf(listOf("1"))))
            requests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1; truncatedByCap = true } })
        }.getOrThrow()

        assertEquals(EnfAction.ALLOW, response.decision)
        assertEquals(100L, response.capRows)
        assertTrue(response.truncatedByCap)

        val uncapped = exchange("select id from users") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision { decision = WireEnfAction.ALLOW; this.decisionId = decisionId }
                },
            )
            requests.send(rowsChunk(listOf("id"), listOf(listOf("1"))))
            requests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
        }.getOrThrow()

        assertNull(uncapped.capRows)
        assertFalse(uncapped.truncatedByCap)
    }

    @Test
    fun `DENY is terminal and never returns rows`() = runBlocking {
        val decisionId = audit(Decision.DENY, listOf("app.public.users.ssn"))
        val response = exchange("select ssn from users") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.DENY
                        this.decisionId = decisionId
                        denyReason = "policy denies column ssn"
                        effectiveRoles += "contractor"
                    }
                },
            )
        }.getOrThrow()

        assertEquals(EnfAction.DENY, response.decision)
        assertEquals(decisionId, response.decisionId)
        assertEquals("policy denies column ssn", response.denyReason)
        assertEquals(emptyList(), response.maskedColumns)
        assertEquals(listOf("app.public.users.ssn"), response.piiTouched)
        assertEquals(listOf("contractor"), response.effectiveRoles)
        assertEquals(emptyList(), response.columns)
        assertEquals(emptyList(), response.rows)
        assertNull(response.rowsAffected)
    }

    @Test
    fun `an unspecified wire decision fails closed to DENY`() = runBlocking {
        val response = exchange("select 1") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.ENF_ACTION_UNSPECIFIED
                        denyReason = "unspecified verdict"
                    }
                },
            )
        }.getOrThrow()

        assertEquals(EnfAction.DENY, response.decision)
        assertNull(response.decisionId)
        assertEquals("unspecified verdict", response.denyReason)
        assertEquals(emptyList(), response.rows)
    }

    @Test
    fun `EditorError fails the whole exchange without exposing earlier rows`() = runBlocking {
        val failure = exchange("select broken") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.ALLOW
                        decisionId = audit(Decision.ALLOW, listOf("app.public.users.email"))
                    }
                },
            )
            requests.send(rowsChunk(listOf("email"), listOf(listOf("must-not-escape@example.com"))))
            requests.send(proxyEditorMsg { error = editorError { message = "target DB disconnected" } })
        }.exceptionOrNull()

        assertIs<ProxyRunException>(failure)
        assertEquals("target DB disconnected", failure.message)
    }

    @Test
    fun `a post-serving EditorError tagged target_db_error becomes a surfaceable TargetDbRunException`() = runBlocking {
        val failure = exchange("select from a missing table") { _, requests ->
            requests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
            requests.send(
                proxyEditorMsg {
                    error = editorError {
                        message = "ERROR: 42P01 undefined_table"
                        targetDbError = true
                        rawMessage = "ERROR: relation \"nope\" does not exist"
                    }
                },
            )
        }.exceptionOrNull()

        // A tagged target-DB statement ERR that ran under a recorded ALLOW decision is the one provenance the
        // CP may carry into error_detail — its raw form (raw_message) for a full reader, the redacted `message`
        // for a masked viewer.
        val tdbErr = assertIs<TargetDbRunException>(failure)
        assertEquals("ERROR: relation \"nope\" does not exist", tdbErr.message, "raw text rides on the exception message")
        assertEquals("ERROR: 42P01 undefined_table", tdbErr.redactedMessage, "the value-free form is the redacted field")
        assertEquals(tdbErr.message, tdbErr.decidedMessage, "a decision that did not sanitize releases the raw form")
        // toDiagnostic keeps the two forms in the right EditorError fields — raw in raw_message, redacted in
        // message — so the store persists both and the sync route / view release the correct one.
        val diagnostic = tdbErr.toDiagnostic()
        assertEquals("ERROR: relation \"nope\" does not exist", diagnostic.rawMessage)
        assertEquals("ERROR: 42P01 undefined_table", diagnostic.message)
        assertTrue(diagnostic.targetDbError)
    }

    @Test
    fun `a sanitizing decision's target ERR releases only the redacted form as its decided message`() = runBlocking {
        val failure = exchange("insert into users values (1)") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    decision = editorDecision {
                        decision = WireEnfAction.MASK
                        sanitizeDiagnostics = true
                    }
                },
            )
            requests.send(
                proxyEditorMsg {
                    error = editorError {
                        message = "ERROR: 23505 unique_violation"
                        targetDbError = true
                        rawMessage = "ERROR: duplicate key value (ssn)=(123-45-6789)"
                    }
                },
            )
        }.exceptionOrNull()

        val tdbErr = assertIs<TargetDbRunException>(failure)
        assertEquals(tdbErr.redactedMessage, tdbErr.decidedMessage, "a sanitizing decision releases the redacted form")
    }

    @Test
    fun `a target_db_error with no recorded decision does not surface the raw backend text`() = runBlocking {
        // A target ERR implies the statement executed under an ALLOW/MASK decision. If the flag arrives with no
        // decision frame (a protocol violation), the CP must not surface the raw text — it degrades to a generic
        // failure carrying only the proxy's redacted `message`.
        val failure = exchange("select from a missing table") { _, requests ->
            requests.send(
                proxyEditorMsg {
                    error = editorError {
                        message = "ERROR: 42P01 undefined_table"
                        targetDbError = true
                        rawMessage = "ERROR: relation \"nope\" does not exist"
                    }
                },
            )
        }.exceptionOrNull()

        assertIs<ProxyRunException>(failure)
        assertFalse(failure is TargetDbRunException, "a target ERR with no decision must not become surfaceable")
        assertFalse(failure.message!!.contains("nope"), "the raw backend text must not surface without a decision")
        assertEquals("ERROR: 42P01 undefined_table", failure.message, "only the proxy's redacted form")
    }

    @Test
    fun `a post-serving EditorError without target_db_error stays a generic ProxyRunException`() = runBlocking {
        // A decode/decision/mask-binding failure the proxy also reports post-serving — no flag set.
        val failure = exchange("select 1") { _, requests ->
            requests.send(proxyEditorMsg { error = editorError { message = "decision failed: analyzer unavailable" } })
        }.exceptionOrNull()

        assertIs<ProxyRunException>(failure)
        assertFalse(
            failure is TargetDbRunException,
            "a non-target post-serving failure must never be promoted to a TargetDbRunException",
        )
        assertEquals("decision failed: analyzer unavailable", failure.message)
    }

    @Test
    fun `no attached proxy returns the typed service-unavailable outcome and revokes its token`() = runBlocking {
        awaitUntil("no Events stream attached") { datasource.name !in core.proxyEventsHub.attached() }
        val failure = try {
            service.run("no-proxy-user", datasource, "select 1", 500)
            fail("expected NoProxyAttachedException")
        } catch (e: NoProxyAttachedException) {
            e
        }

        assertIs<NoProxyAttachedException>(failure)
        assertEquals(0, activeEditorTokens("no-proxy-user"), "the no-proxy path must revoke its ephemeral token")
    }

    @Test
    fun `dial timeout is typed, leaves no active token, and never needs a proxy stream`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // Inject a short dial bound: the production one is sized for a slow open against a remote
            // target DB, and waiting it out here would buy nothing but a two-minute test.
            val result = async {
                runCatching { service.run("timeout-user", datasource, "select 1", 500, dialTimeoutMs = 1_000) }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            assertEquals("timeout-user", core.tokenStore.resolve(open.ephemeralToken)?.principal)
            val failure = withTimeout(15_000) { result.await() }.exceptionOrNull()
            assertIs<ProxyRunTimeoutException>(failure)
            assertNull(core.tokenStore.resolve(open.ephemeralToken), "dial timeout revokes the ephemeral token")
            assertEquals(0, activeEditorTokens("timeout-user"))
            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    @Test
    fun `an editor stream cut before EditorServing fails the run fast, not on the dial budget`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            val result = async { runCatching { service.run("cut-user", datasource, "select 1", 500) } }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            // The proxy sends EditorReady (its run id), then dies mid target-DB open: it closes the stream WITHOUT ever
            // sending EditorServing (the redeploy-cut scenario). Because the stream was already matched to the run,
            // the CP sees the broken stream at once and fails the run — it does not ride out the dial budget.
            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async { stub.editorExec(proxyRequests.receiveAsFlow()).collect {} }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            proxyRequests.close()

            val failure = withTimeout(5_000) { result.await() }.exceptionOrNull()
            assertIs<ProxyRunException>(failure)
            assertEquals(0, activeEditorTokens("cut-user"), "a target-DB open cut before serving must revoke its token")
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `an openSession cut before EditorServing fails the open fast and revokes its session token`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // The persistent editor path (openSession) must fail-close on a target-DB open cut exactly like the
            // one-shot run() path above: the proxy sends EditorReady then dies before EditorServing, and openSession
            // must fail fast and revoke its per-session token instead of returning a session id whose stream is
            // already dead. Exercises openSession's own cleanup path, not just run()'s.
            val opened = async { runCatching { service.openSession("cut-session-user", datasource) } }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async { stub.editorExec(proxyRequests.receiveAsFlow()).collect {} }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            proxyRequests.close()

            val failure = withTimeout(5_000) { opened.await() }.exceptionOrNull()
            assertIs<ProxyRunException>(failure)
            assertEquals(
                0, activeEditorTokens("cut-session-user"),
                "a cut openSession target-DB open must revoke its session token",
            )
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `a target-DB open that stops heartbeating after EditorReady fails at the no-progress bound`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // A short no-progress bound: waiting out the production one would only slow the test.
            val result = async {
                runCatching { service.run("stall-user", datasource, "select 1", 500, noProgressMs = 750) }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            // The proxy sends EditorReady, then stalls: it holds the stream open but never heartbeats and never serves.
            // The no-progress bound fires — a slow-but-live open would have kept the bound reset with heartbeats.
            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async { stub.editorExec(proxyRequests.receiveAsFlow()).collect {} }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })

            val failure = withTimeout(5_000) { result.await() }.exceptionOrNull()
            assertIs<ProxyRunTimeoutException>(failure)
            assertEquals(0, activeEditorTokens("stall-user"), "a stalled target-DB open must revoke its token")
            proxyRequests.close()
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `EditorProgress heartbeats reset the no-progress bound so a slow-but-live open serves`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // Short no-progress bound; the open heartbeats in gaps well under it, for a TOTAL longer than the
            // bound. It can only serve if each heartbeat RESETS the bound — a single deadline from the first
            // frame would fire mid-way.
            val result = async {
                runCatching { service.run("live-user", datasource, "select 1", 500, noProgressMs = 600) }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            proxyRequests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            repeat(8) {
                delay(200)
                proxyRequests.send(proxyEditorMsg { progress = editorProgress {} })
            }
            proxyRequests.send(proxyEditorMsg { serving = editorServing {} })

            val response = withTimeout(10_000) { result.await() }.getOrThrow()
            assertEquals(EnfAction.ALLOW, response.decision)
            proxy.cancel()
        }
    }

    @Test
    fun `an EditorError during the target-DB open surfaces as-is instead of waiting to serve`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            val result = async { runCatching { service.run("open-err-user", datasource, "select 1", 500) } }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async { stub.editorExec(proxyRequests.receiveAsFlow()).collect {} }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            // The target-DB open fails mid-flight, before serving.
            proxyRequests.send(proxyEditorMsg { error = editorError { message = "target-DB connection failed: connection refused" } })

            val failure = withTimeout(5_000) { result.await() }.exceptionOrNull()
            assertIs<ProxyRunException>(failure)
            // An open failure carries no target_db_error flag: its text can echo proxy-internal detail, so it
            // must stay a generic ProxyRunException and never be promoted to a surfaceable TargetDbRunException.
            assertFalse(failure is TargetDbRunException, "an open failure must never become a TargetDbRunException")
            assertEquals("target-DB connection failed: connection refused", failure.message)
            assertEquals(0, activeEditorTokens("open-err-user"), "a failed target-DB open must revoke its token")
            proxyRequests.close()
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `a target-DB open that heartbeats but never serves fails at the absolute ceiling`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // The proxy heartbeats faster than the no-progress bound but never serves (its target-DB read is
            // wedged though the proxy is alive). Only the absolute open ceiling can end this — a heartbeat is
            // liveness, not target DB progress. Short ceiling so the test is fast.
            val result = async {
                runCatching { service.run("wedged-user", datasource, "select 1", 500, noProgressMs = 5_000, openTimeoutMs = 800) }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async { stub.editorExec(proxyRequests.receiveAsFlow()).collect {} }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            val heartbeat = launch {
                while (isActive) {
                    proxyRequests.trySend(proxyEditorMsg { progress = editorProgress {} })
                    delay(100)
                }
            }

            val failure = withTimeout(5_000) { result.await() }.exceptionOrNull()
            assertIs<ProxyRunTimeoutException>(failure)
            assertEquals(0, activeEditorTokens("wedged-user"), "a ceiling-timed-out open must revoke its token")
            heartbeat.cancel()
            proxyRequests.close()
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `an abandoned one-shot run tears down the gRPC handler, not retaining it until the proxy ends`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // Short ceiling; the proxy heartbeats forever and never serves, so run() abandons at the ceiling.
            val result = async {
                runCatching { service.run("leak-user", datasource, "select 1", 500, noProgressMs = 5_000, openTimeoutMs = 600) }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession

            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async { stub.editorExec(proxyRequests.receiveAsFlow()).collect {} }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            val heartbeat = launch {
                while (isActive) {
                    proxyRequests.trySend(proxyEditorMsg { progress = editorProgress {} })
                    delay(100)
                }
            }

            assertIs<ProxyRunTimeoutException>(withTimeout(5_000) { result.await() }.exceptionOrNull())
            // The handler must end on abandon (run() closes inbound), so the proxy's stream completes WITHOUT
            // the test closing proxyRequests. Without that teardown the handler keeps forwarding heartbeats and
            // this awaits forever.
            withTimeout(5_000) { proxy.await() }
            proxyRequests.close()
            heartbeat.cancel()
        }
    }

    // A separate server whose editorExec handler bounds only the first frame by [firstFrameMs] — short, so the
    // "no overall stream cap" behavior can be exercised without a multi-minute wait.
    private fun shortFirstFrameServer(firstFrameMs: Long): Pair<ControlPlaneGrpcKt.ControlPlaneCoroutineStub, () -> Unit> {
        val srv = GrpcServer(0, ControlPlaneGrpcService(core, firstFrameMs), secretToken = null).also { it.start() }
        val ch = NettyChannelBuilder.forAddress("localhost", srv.boundPort).usePlaintext().build()
        val stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(ch)
        return stub to {
            ch.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
            srv.shutdown()
        }
    }

    @Test
    fun `an EditorExec stream that sends no first frame is reaped at the first-frame bound, not parked forever`() = runBlocking {
        val (shortStub, cleanup) = shortFirstFrameServer(400)
        // A stream the proxy opens but never identifies (no EditorReady) and never closes.
        val silent = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
        try {
            val started = System.nanoTime()
            val failure = runCatching { shortStub.editorExec(silent.receiveAsFlow()).collect() }.exceptionOrNull()
            val elapsedMs = (System.nanoTime() - started) / 1_000_000
            assertIs<StatusException>(failure)
            assertEquals(Status.Code.DEADLINE_EXCEEDED, failure.status.code)
            assertTrue(elapsedMs < 5_000, "a silent stream must be reaped near the 400ms bound, not parked (was ${elapsedMs}ms)")
        } finally {
            silent.close()
            cleanup()
        }
    }

    @Test
    fun `an attached editor session outlives the first-frame bound — no overall cap cuts a live session`() = runBlocking {
        val (shortStub, cleanup) = shortFirstFrameServer(400)
        try {
            supervisorScope {
                val event = async { shortStub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
                awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
                val sessionIdDeferred = async { service.openSession("live-session-user", datasource) }
                val open = withTimeout(5_000) { event.await() }.openEditorSession

                val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
                val proxy = async {
                    shortStub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                        when {
                            control.hasQuery() -> {
                                proxyRequests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
                                proxyRequests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
                            }
                            control.hasClose() -> proxyRequests.close()
                            else -> fail("control plane sent an empty editor control message")
                        }
                    }
                }
                proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
                proxyRequests.send(proxyEditorMsg { serving = editorServing {} })
                val sessionId = withTimeout(5_000) { sessionIdDeferred.await() }

                // Hold the attached stream idle PAST the 400ms first-frame bound. The old fixed overall stream
                // cap would have force-closed it here; there is none now, so the session stays usable.
                delay(1_200)
                val response = withTimeout(5_000) { service.runOnSession(sessionId, "live-session-user", "select 1", 500) }
                assertEquals(EnfAction.ALLOW, response.decision)

                service.closeSessionOwnedBy(sessionId, "live-session-user")
                withTimeout(5_000) { proxy.await() }
            }
        } finally {
            cleanup()
        }
    }

    @Test
    fun `unknown and duplicate session ids fail NOT_FOUND claim-once`() = runBlocking {
        val unknown = statusOf {
            stub.editorExec(
                flowOf(proxyEditorMsg { sessionReady = editorReady { sessionId = "unknown" } }),
            ).collect()
        }
        assertEquals(Status.Code.NOT_FOUND, unknown)

        supervisorScope {
            val sessionId = UUID.randomUUID().toString()
            val pending = PendingSession(sessionId, "claim-user", 1L, CompletableDeferred())
            core.editorSessions.register(pending)
            val firstRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val first = async {
                stub.editorExec(firstRequests.receiveAsFlow()).collect()
            }
            firstRequests.send(
                proxyEditorMsg { sessionReady = editorReady { this.sessionId = sessionId } },
            )
            withTimeout(5_000) { pending.ready.await() }

            val duplicate = statusOf {
                stub.editorExec(
                    flowOf(proxyEditorMsg { sessionReady = editorReady { this.sessionId = sessionId } }),
                ).collect()
            }
            assertEquals(Status.Code.NOT_FOUND, duplicate)

            firstRequests.close()
            withTimeout(5_000) { first.await() }
        }
    }

    @Test
    fun `a non-ready first message fails FAILED_PRECONDITION`() = runBlocking {
        val code = statusOf {
            stub.editorExec(
                flowOf(
                    proxyEditorMsg {
                        error = editorError { message = "not ready" }
                    },
                ),
            ).collect()
        }
        assertEquals(Status.Code.FAILED_PRECONDITION, code)
    }

    private suspend fun statusOf(block: suspend () -> Unit): Status.Code = try {
        block()
        fail("expected a gRPC StatusException")
    } catch (e: StatusException) {
        e.status.code
    }

    @Test
    fun `a persistent session runs multiple queries on ONE held stream, then closes and revokes`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            // openSession completes once the fake proxy attaches its editorExec stream (attach completes the
            // pending session's ready). Run it async so the fake proxy below can service the dial.
            val sessionIdDeferred = async { service.openSession("session-user", datasource) }
            val open = withTimeout(5_000) { event.await() }.openEditorSession
            val ephemeralToken = open.ephemeralToken

            // ONE fake-proxy stream that services N queries then a close — the proof the CP reuses one stream
            // (one target-DB connection) across queries rather than dialing fresh per statement.
            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val queriesSeen = java.util.Collections.synchronizedList(ArrayList<String>())
            val requesterIps = java.util.Collections.synchronizedList(ArrayList<String>())
            val proxy = async {
                stub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            queriesSeen += control.query.sql
                            requesterIps += control.query.requesterIp
                            proxyRequests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(rowsChunk(listOf("echo"), listOf(listOf(control.query.sql))))
                            proxyRequests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyEditorMsg { serving = editorServing {} })

            val sessionId = withTimeout(5_000) { sessionIdDeferred.await() }
            assertEquals(
                "session-user", core.tokenStore.resolve(ephemeralToken)?.principal,
                "the per-session token stays valid across the session (not revoked per query)",
            )

            // Each query carries its own request's IP; one whose IP can't be resolved (null) carries none.
            val r1 = withTimeout(5_000) { service.runOnSession(sessionId, "session-user", "select 1", 500, requesterIp = "203.0.113.50") }
            val r2 = withTimeout(5_000) { service.runOnSession(sessionId, "session-user", "select 2", 500, requesterIp = null) }
            assertEquals(EnfAction.ALLOW, r1.decision)
            assertEquals(listOf(listOf("select 1")), r1.rows)
            assertEquals(listOf(listOf("select 2")), r2.rows)

            // A different principal cannot use someone else's session.
            assertIs<ProxyRunException>(
                runCatching { service.runOnSession(sessionId, "other-user", "select 3", 500, requesterIp = "203.0.113.60") }.exceptionOrNull(),
            )

            // ...nor CLOSE it: a leaked sessionId must not let another principal tear down the connection or
            // revoke the token (the DELETE route's ownership check). The non-owner close is a no-op — the
            // session stays live and usable — while the owner's close works.
            assertTrue(!service.closeSessionOwnedBy(sessionId, "other-user"), "a non-owner must not close the session")
            assertEquals(
                "session-user", core.tokenStore.resolve(ephemeralToken)?.principal,
                "a rejected non-owner close must leave the session token valid",
            )
            val r3 = withTimeout(5_000) { service.runOnSession(sessionId, "session-user", "select 4", 500, requesterIp = "203.0.113.51") }
            assertEquals(listOf(listOf("select 4")), r3.rows, "the session still runs after a rejected non-owner close")

            assertTrue(service.closeSessionOwnedBy(sessionId, "session-user"), "the owner closes their own session")
            withTimeout(5_000) { proxy.await() }

            assertEquals(listOf("select 1", "select 2", "select 4"), queriesSeen.toList(), "all queries ran on the SAME held stream")
            assertEquals(listOf("203.0.113.50", "", "203.0.113.51"), requesterIps.toList(), "each query carried its own requester's IP")
            assertNull(core.tokenStore.resolve(ephemeralToken), "the session token is revoked on close")
            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    @Test
    fun `active task registry sends EditorCancel on the attached stream`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            val taskId = 991L
            val runResult = async {
                runCatching {
                    service.run("cancel-user", datasource, "select 1", 500, taskId = taskId)
                }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession
            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val querySeen = CompletableDeferred<Unit>()
            val cancelSeen = CompletableDeferred<Unit>()
            val proxy = async {
                stub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> querySeen.complete(Unit)
                        control.hasCancel() -> cancelSeen.complete(Unit)
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyEditorMsg { serving = editorServing {} })
            withTimeout(5_000) { querySeen.await() }
            assertTrue(service.cancelActiveRun(taskId))
            withTimeout(5_000) { cancelSeen.await() }
            proxyRequests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
            proxyRequests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
            withTimeout(5_000) { runResult.await() }.getOrThrow()
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `runBatch opens the target connection in the requested default schema`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            val batch = async {
                runCatching {
                    service.runBatch(
                        principal = "batch-user",
                        ds = datasource,
                        statementCount = 1,
                        maxRows = 500,
                        statementAt = { if (it == 0) "select 1" else null },
                        onStatement = { _, _ -> true },
                        defaultSchema = "orders",
                    )
                }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession
            assertEquals("orders", open.defaultSchema)
            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            proxyRequests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyEditorMsg { serving = editorServing {} })
            withTimeout(5_000) { batch.await() }.getOrThrow()
            withTimeout(5_000) { proxy.await() }
            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    @Test
    fun `closeSessionsForPrincipal closes only the matching principal's streams`() = runBlocking {
        supervisorScope {
            val events = Channel<com.ridi.oss.proxymonster.grpc.CpEvent>(Channel.UNLIMITED)
            val eventJob = launch {
                stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).collect { events.send(it) }
            }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            suspend fun open(principal: String): Triple<String, String, CompletableDeferred<Unit>> {
                val opening = async { service.openSession(principal, datasource) }
                val open = withTimeout(5_000) { events.receive() }.openEditorSession
                val requests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
                val closed = CompletableDeferred<Unit>()
                launch {
                    stub.editorExec(requests.receiveAsFlow()).collect { control ->
                        if (control.hasClose()) {
                            closed.complete(Unit)
                            requests.close()
                        }
                    }
                }
                requests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
                requests.send(proxyEditorMsg { serving = editorServing {} })
                return Triple(withTimeout(5_000) { opening.await() }, open.ephemeralToken, closed)
            }

            val first = open("principal-a")
            val second = open("principal-b")
            service.closeSessionsForPrincipal("principal-a")
            withTimeout(5_000) { first.third.await() }
            assertNull(core.tokenStore.resolve(first.second))
            assertEquals("principal-b", core.tokenStore.resolve(second.second)?.principal)
            service.closeSession(second.first)
            withTimeout(5_000) { second.third.await() }
            eventJob.cancel()
        }
    }

    @Test
    fun `an approval run's requester_ip reaches a real gRPC decide on the workflow-executor channel`() = runBlocking {
        // APPROVER_EXEC tokens are minted only by run(approverExec = true), so this covers that path end to end.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "editor-run-approver-exec-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${datasource.name}")
                    when { context has channel && context.channel == "workflow-executor" && context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            val runResult = async {
                runCatching {
                    service.run("approver-exec-user", datasource, "select 1 from t", 500, approverExec = true, assumeRoles = setOf("ip-approver"), requesterIp = "203.0.113.55")
                }
            }
            val open = withTimeout(5_000) { event.await() }.openEditorSession
            val connectionId = stub.openEditorConnection(open, datasource.name)

            // The fake proxy decides with the EditorQuery's requester_ip as client_addr, as goproxy does. The ip-gated
            // connect permit fires, so the deny moves off the connect gate to the statement-kind gate.
            var denyReason = ""
            val proxyRequests = Channel<ProxyEditorMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.editorExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            denyReason = stub.decide(
                                decisionRequest {
                                    token = open.ephemeralToken
                                    datasourceName = datasource.name
                                    currentCatalog = datasource.effectiveCatalog
                                    this.connectionId = connectionId
                                    sql = control.query.sql
                                    clientAddr = control.query.requesterIp
                                },
                            ).verdict.denyReason
                            proxyRequests.send(proxyEditorMsg { decision = editorDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(proxyEditorMsg { done = editorDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyEditorMsg { sessionReady = editorReady { sessionId = open.sessionId } })
            proxyRequests.send(proxyEditorMsg { serving = editorServing {} })
            withTimeout(5_000) { runResult.await() }.getOrThrow()
            withTimeout(5_000) { proxy.await() }
            assertTrue("statement kind 'select' is not permitted" in denyReason, "the run's APPROVER_EXEC requester IP must reach Cedar: $denyReason")
            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    private fun rowsChunk(columns: List<String>, rows: List<List<String?>>): ProxyEditorMsg = proxyEditorMsg {
        resultRows = editorResultRows {
            this.columns += columns
            this.rows += rows.map { values ->
                editorRow {
                    this.values += values.map { value ->
                        editorValue {
                            if (value == null) {
                                isNull = true
                            } else {
                                this.value = value
                            }
                        }
                    }
                }
            }
        }
    }

    private fun activeEditorTokens(principal: String): Int = dataSource.connection.use { c ->
        c.prepareStatement(
            """SELECT count(*) FROM proxy_token
               WHERE principal = ? AND kind = 'EDITOR' AND revoked_at IS NULL AND expires_at > now()""",
        ).use { ps ->
            ps.setString(1, principal)
            ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
        }
    }
}
