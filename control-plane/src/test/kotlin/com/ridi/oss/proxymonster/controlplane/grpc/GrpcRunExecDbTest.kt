package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.Decision
import com.ridi.oss.proxymonster.controlplane.AuditEvent
import com.ridi.oss.proxymonster.controlplane.RunExecService
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.NoProxyAttachedException
import com.ridi.oss.proxymonster.controlplane.PendingSession
import com.ridi.oss.proxymonster.controlplane.ProxyRunException
import com.ridi.oss.proxymonster.controlplane.ProxyRunTimeoutException
import com.ridi.oss.proxymonster.controlplane.QueryResponse
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.tokenHash
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.RunQuery
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runError
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runReady
import com.ridi.oss.proxymonster.grpc.runValue
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** DB-backed end-to-end coverage for the control-plane half of the proxy-dialed editor channel. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GrpcRunExecDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var service: RunExecService
    private lateinit var datasource: Datasource
    private lateinit var server: GrpcServer
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub
    private lateinit var rawChannel: io.grpc.ManagedChannel

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_grpc_editor"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        service = RunExecService(core)
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
        playProxy: suspend (RunQuery, Channel<ProxyRunMsg>) -> Unit,
    ): Result<QueryResponse> = supervisorScope {
        val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
        awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

        val result = async { runCatching { service.run("editor-user", datasource, sql, maxRows, requesterIp = requesterIp) } }
        val open = withTimeout(5_000) { event.await() }.openRunChannel
        val identity = core.tokenStore.resolve(open.ephemeralToken)
        assertEquals("editor-user", identity?.principal, "the ephemeral token resolves during the editor window")
        assertEquals(emptyList(), identity?.roles)
        assertTrue(
            core.tokenStore.list("editor-user").none { it.kind == "EDITOR" },
            "transient editor tokens stay off the user-visible token list",
        )
        // The requester IP observed at mint time is carried on ControlPlaneCore, keyed by
        // this ephemeral token's hash, for the life of the token.
        assertEquals(
            requesterIp, core.runRequesterIps.get(tokenHash(open.ephemeralToken)),
            "the requester-IP carrier must hold exactly the requesterIp run() was called with",
        )

        val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
        val proxy = async {
            stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                when {
                    control.hasQuery() -> playProxy(control.query, proxyRequests)
                    control.hasClose() -> proxyRequests.close()
                    else -> fail("control plane sent an empty editor control message")
                }
            }
        }
        proxyRequests.send(
            proxyRunMsg {
                sessionReady = runReady { sessionId = open.sessionId }
            },
        )

        val outcome = withTimeout(5_000) { result.await() }
        withTimeout(5_000) { proxy.await() }
        assertNull(core.tokenStore.resolve(open.ephemeralToken), "the ephemeral token is revoked after the exchange")
        assertNull(
            core.runRequesterIps.get(tokenHash(open.ephemeralToken)),
            "the requester-IP registry entry must be removed alongside the token revoke — entry lifetime == token lifetime",
        )
        awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        outcome
    }

    @Test
    fun `run's requesterIp is carried on ControlPlaneCore for the life of the ephemeral token`() = runBlocking {
        // exchange() itself asserts the registry holds exactly the requesterIp passed in, both while the
        // token is live and (as null/absent) after the exchange completes — this pins the explicit,
        // non-default case end to end (every other exchange()-based test in this file implicitly pins the
        // null/no-op case, since they call exchange without a requesterIp).
        exchange("select 1", requesterIp = "203.0.113.99") { _, requests ->
            requests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
            requests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
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
                proxyRunMsg {
                    decision = runDecision {
                        decision = WireEnfAction.ALLOW
                        this.decisionId = decisionId
                        effectiveRoles += listOf("analyst", "reader")
                    }
                },
            )
            requests.send(rowsChunk(listOf("id", "email"), listOf(listOf("1", "a@example.com"))))
            requests.send(rowsChunk(listOf("id", "email"), listOf(listOf("2", null))))
            requests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
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
        val decisionId = audit(Decision.MASK, listOf("app.public.users.rrn"))
        val response = exchange("select rrn from users", maxRows = 0) { query, requests ->
            assertEquals(0, query.maxRows, "maxRows=0 crosses the wire as the proxy's default-500 sentinel (proxy re-coerces)")
            requests.send(
                proxyRunMsg {
                    decision = runDecision {
                        decision = WireEnfAction.MASK
                        this.decisionId = decisionId
                        maskedColumns += "rrn"
                        effectiveRoles += "analyst"
                    }
                },
            )
            requests.send(rowsChunk(listOf("rrn"), listOf(listOf("######-#######"))))
            requests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
        }.getOrThrow()

        assertEquals(EnfAction.MASK, response.decision)
        assertEquals(decisionId, response.decisionId)
        assertNull(response.denyReason)
        assertEquals(listOf("rrn"), response.maskedColumns)
        assertEquals(listOf("app.public.users.rrn"), response.piiTouched)
        assertEquals(listOf("analyst"), response.effectiveRoles)
        assertEquals(listOf("rrn"), response.columns)
        assertEquals(listOf(listOf("######-#######")), response.rows)
        assertNull(response.rowsAffected)
    }

    @Test
    fun `DENY is terminal and never returns rows`() = runBlocking {
        val decisionId = audit(Decision.DENY, listOf("app.public.users.rrn"))
        val response = exchange("select rrn from users") { _, requests ->
            requests.send(
                proxyRunMsg {
                    decision = runDecision {
                        decision = WireEnfAction.DENY
                        this.decisionId = decisionId
                        denyReason = "policy denies column rrn"
                        effectiveRoles += "contractor"
                    }
                },
            )
        }.getOrThrow()

        assertEquals(EnfAction.DENY, response.decision)
        assertEquals(decisionId, response.decisionId)
        assertEquals("policy denies column rrn", response.denyReason)
        assertEquals(emptyList(), response.maskedColumns)
        assertEquals(listOf("app.public.users.rrn"), response.piiTouched)
        assertEquals(listOf("contractor"), response.effectiveRoles)
        assertEquals(emptyList(), response.columns)
        assertEquals(emptyList(), response.rows)
        assertNull(response.rowsAffected)
    }

    @Test
    fun `an unspecified wire decision fails closed to DENY`() = runBlocking {
        val response = exchange("select 1") { _, requests ->
            requests.send(
                proxyRunMsg {
                    decision = runDecision {
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
    fun `RunError fails the whole exchange without exposing earlier rows`() = runBlocking {
        val failure = exchange("select broken") { _, requests ->
            requests.send(
                proxyRunMsg {
                    decision = runDecision {
                        decision = WireEnfAction.ALLOW
                        decisionId = audit(Decision.ALLOW, listOf("app.public.users.email"))
                    }
                },
            )
            requests.send(rowsChunk(listOf("email"), listOf(listOf("must-not-escape@example.com"))))
            requests.send(proxyRunMsg { error = runError { message = "backend disconnected" } })
        }.exceptionOrNull()

        assertIs<ProxyRunException>(failure)
        assertEquals("backend disconnected", failure.message)
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
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            // Inject a short dial bound: the production one is sized for a cold session against a remote
            // backend, and waiting it out here would buy nothing but a two-minute test.
            val result = async {
                runCatching { service.run("timeout-user", datasource, "select 1", 500, dialTimeoutMs = 1_000) }
            }
            val open = withTimeout(5_000) { event.await() }.openRunChannel

            assertEquals("timeout-user", core.tokenStore.resolve(open.ephemeralToken)?.principal)
            val failure = withTimeout(15_000) { result.await() }.exceptionOrNull()
            assertIs<ProxyRunTimeoutException>(failure)
            assertNull(core.tokenStore.resolve(open.ephemeralToken), "dial timeout revokes the ephemeral token")
            assertEquals(0, activeEditorTokens("timeout-user"))
            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    @Test
    fun `unknown and duplicate session ids fail NOT_FOUND claim-once`() = runBlocking {
        val unknown = statusOf {
            stub.runExec(
                flowOf(proxyRunMsg { sessionReady = runReady { sessionId = "unknown" } }),
            ).collect()
        }
        assertEquals(Status.Code.NOT_FOUND, unknown)

        supervisorScope {
            val sessionId = UUID.randomUUID().toString()
            val pending = PendingSession(sessionId, "claim-user", 1L, CompletableDeferred())
            core.runChannels.register(pending)
            val firstRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val first = async {
                stub.runExec(firstRequests.receiveAsFlow()).collect()
            }
            firstRequests.send(
                proxyRunMsg { sessionReady = runReady { this.sessionId = sessionId } },
            )
            withTimeout(5_000) { pending.ready.await() }

            val duplicate = statusOf {
                stub.runExec(
                    flowOf(proxyRunMsg { sessionReady = runReady { this.sessionId = sessionId } }),
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
            stub.runExec(
                flowOf(
                    proxyRunMsg {
                        error = runError { message = "not ready" }
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
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            // openSession completes once the fake proxy attaches its runExec stream (attach completes the
            // pending session's ready). Run it async so the fake proxy below can service the dial.
            val sessionIdDeferred = async { service.openSession("session-user", datasource, requesterIp = "203.0.113.42") }
            val open = withTimeout(5_000) { event.await() }.openRunChannel
            val ephemeralToken = open.ephemeralToken
            // openSession's requesterIp is carried on ControlPlaneCore, keyed by the session
            // token's hash, for the life of the session — every query decided on this session sees it.
            assertEquals("203.0.113.42", core.runRequesterIps.get(tokenHash(ephemeralToken)))

            // ONE fake-proxy stream that services N queries then a close — the proof the CP reuses one stream
            // (one backend connection) across queries rather than dialing fresh per statement.
            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val queriesSeen = java.util.Collections.synchronizedList(ArrayList<String>())
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            queriesSeen += control.query.sql
                            proxyRequests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(rowsChunk(listOf("echo"), listOf(listOf(control.query.sql))))
                            proxyRequests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })

            val sessionId = withTimeout(5_000) { sessionIdDeferred.await() }
            assertEquals(
                "session-user", core.tokenStore.resolve(ephemeralToken)?.principal,
                "the per-session token stays valid across the session (not revoked per query)",
            )

            // Each query REFRESHES the carried requester_ip to THIS request's IP (resolved
            // fresh per decision), never the stale open-time one. A query whose IP can't be resolved (null)
            // CLEARS the entry fail-closed — a session opened from a trusted network then queried from an
            // untrusted one must NOT inherit the open-time (trusted) IP.
            val r1 = withTimeout(5_000) { service.runOnSession(sessionId, "session-user", "select 1", 500, requesterIp = "203.0.113.50") }
            assertEquals(
                "203.0.113.50", core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "runOnSession refreshes the carried requester_ip to the current request's IP, not the open-time 203.0.113.42",
            )
            val r2 = withTimeout(5_000) { service.runOnSession(sessionId, "session-user", "select 2", 500, requesterIp = null) }
            assertNull(
                core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "a session query from an unresolvable IP clears the stale open-time IP — the anti-staleness invariant",
            )
            assertEquals(EnfAction.ALLOW, r1.decision)
            assertEquals(listOf(listOf("select 1")), r1.rows)
            assertEquals(listOf(listOf("select 2")), r2.rows)

            // A different principal cannot use someone else's session — the ownership check throws before the
            // registry is touched, so it neither runs nor perturbs the carried IP.
            assertIs<ProxyRunException>(
                runCatching { service.runOnSession(sessionId, "other-user", "select 3", 500, requesterIp = "203.0.113.60") }.exceptionOrNull(),
            )
            assertNull(
                core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "a rejected non-owner query must not plant a requester_ip on the owner's session",
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
            assertEquals(
                "203.0.113.51", core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "the latest query's requester_ip is the one carried for the session's next decision",
            )

            assertTrue(service.closeSessionOwnedBy(sessionId, "session-user"), "the owner closes their own session")
            withTimeout(5_000) { proxy.await() }

            assertEquals(listOf("select 1", "select 2", "select 4"), queriesSeen.toList(), "all queries ran on the SAME held stream")
            assertNull(core.tokenStore.resolve(ephemeralToken), "the session token is revoked on close")
            assertNull(
                core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "the requester-IP registry entry is removed alongside the session token on close",
            )
            awaitUntil("Events stream detached") { datasource.name !in core.proxyEventsHub.attached() }
        }
    }

    @Test
    fun `active task registry sends RunCancel on the attached stream`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }
            val taskId = 991L
            val runResult = async {
                runCatching {
                    service.run("cancel-user", datasource, "select 1", 500, taskId = taskId)
                }
            }
            val open = withTimeout(5_000) { event.await() }.openRunChannel
            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val querySeen = CompletableDeferred<Unit>()
            val cancelSeen = CompletableDeferred<Unit>()
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> querySeen.complete(Unit)
                        control.hasCancel() -> cancelSeen.complete(Unit)
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
            withTimeout(5_000) { querySeen.await() }
            assertTrue(service.cancelActiveRun(taskId))
            withTimeout(5_000) { cancelSeen.await() }
            proxyRequests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
            proxyRequests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
            withTimeout(5_000) { runResult.await() }.getOrThrow()
            withTimeout(5_000) { proxy.await() }
        }
    }

    @Test
    fun `closeSessionsForPrincipal closes only the matching principal's streams`() = runBlocking {
        supervisorScope {
            val events = Channel<com.ridi.oss.proxymonster.grpc.ControlEvent>(Channel.UNLIMITED)
            val eventJob = launch {
                stub.events(eventsRequest { datasourceName = datasource.name }).collect { events.send(it) }
            }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            suspend fun open(principal: String): Triple<String, String, CompletableDeferred<Unit>> {
                val opening = async { service.openSession(principal, datasource) }
                val open = withTimeout(5_000) { events.receive() }.openRunChannel
                val requests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
                val closed = CompletableDeferred<Unit>()
                launch {
                    stub.runExec(requests.receiveAsFlow()).collect { control ->
                        if (control.hasClose()) {
                            closed.complete(Unit)
                            requests.close()
                        }
                    }
                }
                requests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
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
    fun `a run-minted APPROVER_EXEC token's requester_ip reaches a real gRPC decide (approverExec=true, the ONLY APPROVER_EXEC minter)`() = runBlocking {
        // An ip-gated connect permit proves the run-supplied IP actually reaches Cedar at decide time — not
        // just that the registry map holds it. APPROVER_EXEC tokens are minted ONLY by run(approverExec=true),
        // so this exercises the production mint path the manual-insert decide tests can't.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "editor-run-approver-exec-ip-gate",
                cedarSrc = """permit(principal, action == Action::"datasource.connect", resource == Datasource::"${datasource.name}")
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
        )
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            // run(approverExec = true) mints an APPROVER_EXEC token and records the requester IP under its hash.
            val runResult = async {
                runCatching {
                    service.run("approver-exec-user", datasource, "select 1 from t", 500, approverExec = true, requesterIp = "203.0.113.55")
                }
            }
            val open = withTimeout(5_000) { event.await() }.openRunChannel
            val ephemeralToken = open.ephemeralToken

            // The minted token carries the run-supplied IP under its hash...
            assertEquals("approver-exec-user", core.tokenStore.resolve(ephemeralToken)?.principal)
            assertEquals("203.0.113.55", core.runRequesterIps.get(tokenHash(ephemeralToken)))

            // ...and a REAL gRPC decide against that live token sees it: the ip-gated connect permit fires, so
            // the deny moves off the connect gate to sql.select. An impl that registered IPs only for EDITOR
            // would leave connect denied here — the exact regression a manual-insert test can't catch.
            // The OpenRunChannel carries the editor connection identity minted by the CP.
            val decideResponse = stub.decide(
                decisionRequest {
                    token = ephemeralToken
                    datasourceName = datasource.name
                    connectionId = open.connectionId
                    sql = "select 1 from t"
                },
            )
            assertTrue("sql.select" in decideResponse.verdict.denyReason, "the run-minted APPROVER_EXEC IP must reach Cedar: ${decideResponse.verdict.denyReason}")

            // Service the dial so run() completes cleanly and the registry entry is removed on token revoke.
            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            proxyRequests.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.ALLOW } })
                            proxyRequests.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
                        }
                        control.hasClose() -> proxyRequests.close()
                        else -> fail("control plane sent an empty editor control message")
                    }
                }
            }
            proxyRequests.send(proxyRunMsg { sessionReady = runReady { sessionId = open.sessionId } })
            withTimeout(5_000) { runResult.await() }.getOrThrow()
            withTimeout(5_000) { proxy.await() }
            assertNull(
                core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "the APPROVER_EXEC registry entry is removed alongside the token revoke",
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
