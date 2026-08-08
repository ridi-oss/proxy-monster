package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.ControlPlaneCore
import com.ridi.oss.proxymonster.controlplane.Datasource
import com.ridi.oss.proxymonster.controlplane.DatasourceInput
import com.ridi.oss.proxymonster.controlplane.RunExecService
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.tokenHash
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction as WireEnfAction
import com.ridi.oss.proxymonster.grpc.ProxyRunMsg
import com.ridi.oss.proxymonster.grpc.decisionRequest
import com.ridi.oss.proxymonster.grpc.runDecision
import com.ridi.oss.proxymonster.grpc.runDone
import com.ridi.oss.proxymonster.grpc.runResultRows
import com.ridi.oss.proxymonster.grpc.runRow
import com.ridi.oss.proxymonster.grpc.runReady
import com.ridi.oss.proxymonster.grpc.runValue
import com.ridi.oss.proxymonster.grpc.eventsRequest
import com.ridi.oss.proxymonster.grpc.proxyRunMsg
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.Collections
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.fail

/**
 * Timing regression for [RunExecService.runOnSession]'s per-query requester_ip refresh.
 *
 * The refresh MUST happen BEFORE the query crosses the wire, so the gRPC `Decide` the proxy triggers for THAT
 * query reads the CURRENT request's IP, never the stale open-time / previous-query one. [GrpcRunExecDbTest]'s
 * persistent-session test asserts the registry value only AFTER `runOnSession` returns — which holds regardless
 * of whether the refresh ran before or after the send — and its fake proxy never invokes the real `Decide`. So
 * moving the refresh to after the send leaves it green.
 *
 * Here the fake proxy invokes the REAL gRPC `Decide` (with the session's ephemeral token) WHILE servicing each
 * query, against a policy gated on `requester_ip`. A session that first queries from an ALLOWED IP then from a
 * null/out-of-range IP must see: first query → ALLOW, second query → DENY. The DENY proves the second query's
 * decision reflects its own (absent) IP, not the stale allowed one still sitting in the registry — i.e. the
 * refresh happened before the decide. Moving the refresh after the send makes the second query's Decide read
 * the stale allowed IP → ALLOW → this test goes red.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EditorSessionDecideTimingDbTest {
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
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_editor_decide_timing"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        service = RunExecService(core)
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "timing-ds", engine = "postgres", host = "localhost", port = 5432, dbName = "app"),
        )
        // connect + sql.select granted to ANY principal ONLY when requester_ip is inside 203.0.113.0/24. A null
        // or out-of-range IP fails `context has requester_ip` / the range test → the permit never fires →
        // deny-by-default at the connect gate. So the Decide verdict is a pure function of the current IP.
        core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "timing-ip-gated-connect-select",
                cedarSrc = """permit(
                    principal,
                    action in [Action::"datasource.connect", Action::"stmt.cat.read"],
                    resource in Datasource::"${datasource.name}"
                ) when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
            updatedBy = null,
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
        withTimeout(5_000) { while (!predicate()) delay(20) }
        require(predicate()) { "timed out awaiting: $what" }
    }

    @Test
    fun `each session query's real gRPC Decide sees THAT query's refreshed requester_ip, proving refresh-before-send`() = runBlocking {
        supervisorScope {
            val event = async { stub.events(eventsRequest { datasourceName = datasource.name }).first() }
            awaitUntil("Events stream attached") { datasource.name in core.proxyEventsHub.attached() }

            // Open from an ALLOWED IP; the open-time entry is in-range, so a stale read would ALLOW — the trap
            // the second (null-IP) query must not fall into.
            val sessionIdDeferred = async { service.openSession("timing-user", datasource, requesterIp = "203.0.113.42") }
            val open = withTimeout(5_000) { event.await() }.openRunChannel
            val ephemeralToken = open.ephemeralToken

            // The fake proxy invokes the REAL Decide (session token) WHILE servicing each query, then fabricates
            // an ALLOW so runOnSession returns normally. The Decide verdict is what pins the refresh timing.
            val decideByQuery = Collections.synchronizedMap(LinkedHashMap<String, WireEnfAction>())
            val proxyRequests = Channel<ProxyRunMsg>(Channel.UNLIMITED)
            val proxy = async {
                stub.runExec(proxyRequests.receiveAsFlow()).collect { control ->
                    when {
                        control.hasQuery() -> {
                            val response = stub.decide(
                                decisionRequest {
                                    token = ephemeralToken
                                    datasourceName = datasource.name
                                    connectionId = open.connectionId
                                    sql = control.query.sql
                                },
                            )
                            decideByQuery[control.query.sql] = response.verdict.decision
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

            // Query 1 from an ALLOWED IP → the refreshed IP reaches the decide → ALLOW.
            withTimeout(5_000) { service.runOnSession(sessionId, "timing-user", "select 1", 500, requesterIp = "203.0.113.50") }
            // Query 2 from a null (unresolvable) IP → the refresh CLEARS the stale allowed IP before the send, so
            // this query's decide sees no requester_ip → the ip-gated connect permit can't fire → DENY.
            withTimeout(5_000) { service.runOnSession(sessionId, "timing-user", "select 2", 500, requesterIp = null) }

            assertEquals(
                WireEnfAction.ALLOW, decideByQuery["select 1"],
                "the first query's Decide must see the refreshed allowed IP 203.0.113.50",
            )
            assertEquals(
                WireEnfAction.DENY, decideByQuery["select 2"],
                "the second query's Decide must see the CURRENT null IP, not the stale allowed one — refresh happens BEFORE the send",
            )
            assertNull(
                core.runRequesterIps.get(tokenHash(ephemeralToken)),
                "a null-IP session query clears the stale allowed IP fail-closed",
            )

            service.closeSessionOwnedBy(sessionId, "timing-user")
            withTimeout(5_000) { proxy.await() }
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
}
