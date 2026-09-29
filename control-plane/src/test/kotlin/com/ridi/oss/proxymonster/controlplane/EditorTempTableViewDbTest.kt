package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.grpc.CONTROL_PROTOCOL_VERSION
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
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
import com.ridi.oss.proxymonster.grpc.tempColumn
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel as KChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Editor results over connection-only structure on PostgreSQL: while the session is open the view re-decides
 * against that connection's catalog. A fake proxy holds one real target connection and calls the real Decide.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EditorTempTableViewDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var pcf: PerConnectionCatalogFixture
    private lateinit var core: ControlPlaneCore
    private lateinit var runExecService: RunExecService
    private lateinit var service: EditorTaskService
    private lateinit var resultStore: QueryResultStore
    private lateinit var appScope: CoroutineScope
    private lateinit var server: GrpcServer
    private lateinit var rawChannel: ManagedChannel
    private lateinit var stub: ControlPlaneGrpcKt.ControlPlaneCoroutineStub

    private val principal = "temp-architect@example.com"
    private val other = "temp-other@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = '[\"system:development\"]'::jsonb WHERE id = ?").use { ps ->
                ps.setLong(1, fx.datasource.id)
                ps.executeUpdate()
            }
        }
        pcf = PerConnectionCatalogFixture(fx)
        core = pcf.core
        val roles = fx.policyStore.listRoles().associateBy { it.name }
        for (p in listOf(principal, other)) {
            for (role in listOf("system:development-architect", "system:development-viewer")) {
                fx.policyStore.createAssignment(RoleAssignmentInput(p, roles.getValue(role).id))
            }
        }
        runExecService = RunExecService(core)
        resultStore = QueryResultStore(fx.dataSource, ResultCrypto(ByteArray(32) { it.toByte() }))
        appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "editor-temp-view-secret", oidc = null, resultKey = ByteArray(32), scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        service = EditorTaskService(
            config, core.datasourceStore, core.accessStore, resultStore, core.policyStore, core.userGroupStore,
            core.roleResolver, core.authz, runExecService, appScope, core.systemClassification, null, core.auditStore,
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

    @Test
    fun `a select from a session temp table is viewable while the session is open, refused after it closes`() = runBlocking {
        var select = 0L
        withSession { session, verdicts ->
            val create = submit(session, "create temp table t3 as select 7 as n")
            assertEquals("EXECUTED", core.accessStore.getRequest(create)?.status)
            select = submit(session, "select n from t3")
            assertEquals("EXECUTED", core.accessStore.getRequest(select)?.status)
            assertEquals(listOf(WireEnfAction.ALLOW, WireEnfAction.ALLOW), verdicts.toList())

            val view = service.result(principal, null, select, null)
            assertEquals(listOf("n"), view.columns)
            assertEquals(listOf(listOf<String?>("7")), view.rows)
        }
        assertDenied(select)
    }

    @Test
    fun `a select from a table the session just created is viewable before any global refresh`() = runBlocking {
        withSession { session, verdicts ->
            submit(session, "create table t4 as select 8 as n")
            val select = submit(session, "select n from t4")
            assertEquals(listOf(WireEnfAction.ALLOW, WireEnfAction.ALLOW), verdicts.toList())
            assertTrue(core.datasourceStore.catalog(fx.datasource.id).columns.none { it.table == "t4" })

            assertEquals(listOf(listOf<String?>("8")), service.result(principal, null, select, null).rows)
        }
    }

    @Test
    fun `another principal cannot view against someone else's open session`() = runBlocking {
        withSession { session, _ ->
            submit(session, "create temp table t5 as select 9 as n")
            val select = submit(session, "select n from t5")
            val ds = core.datasourceStore.get(fx.datasource.id)!!
            assertNull(runExecService.openSessionStructure(select, other, ds))
            assertNotNull(runExecService.openSessionStructure(select, principal, ds))
            val denied = assertFailsWith<TaskServiceException> { service.result(other, null, select, null) }
            assertEquals("common.not_found", denied.error.code)
        }
    }

    private suspend fun assertDenied(taskId: Long) {
        val denied = assertFailsWith<TaskServiceException> { service.result(principal, null, taskId, null) }
        assertEquals("approval.result_view_denied", denied.error.code)
    }

    private suspend fun submit(session: String, sql: String): Long {
        val submission = service.submitOnSession(principal, null, session, sql, 100)
        withTimeout(10_000) { submission.job.join() }
        return submission.response.taskId
    }

    /** Opens an editor session served by a fake proxy on one real target connection, closing it after [body]. */
    private suspend fun withSession(body: suspend (String, List<WireEnfAction>) -> Unit) {
        val ds = core.datasourceStore.get(fx.datasource.id)!!
        DriverManager.getConnection(fx.targetJdbcUrl, fx.targetUser, fx.targetPassword).use { held ->
            supervisorScope {
                val event = async { stub.events(eventsRequest { datasourceName = ds.name; protocolVersion = CONTROL_PROTOCOL_VERSION }).first() }
                withTimeout(10_000) { while (ds.name !in core.proxyEventsHub.attached()) delay(20) }
                val sessionId = async { runExecService.openSession(principal, ds) }
                val open = withTimeout(10_000) { event.await() }.openRunChannel
                val verdicts = CopyOnWriteArrayList<WireEnfAction>()
                val out = KChannel<ProxyRunMsg>(KChannel.UNLIMITED)
                val proxy = async {
                    stub.runExec(out.receiveAsFlow()).collect { control ->
                        when {
                            control.hasQuery() -> serve(held, open.ephemeralToken, open.connectionId, control.query.sql, out, verdicts)
                            control.hasClose() -> out.close()
                        }
                    }
                }
                out.send(proxyRunMsg { sessionReady = runReady { this.sessionId = open.sessionId } })
                out.send(proxyRunMsg { serving = runServing {} })
                val session = withTimeout(10_000) { sessionId.await() }
                try {
                    body(session, verdicts)
                } finally {
                    runExecService.closeSessionOwnedBy(session, principal)
                    withTimeout(10_000) { proxy.await() }
                    withTimeout(10_000) { while (ds.name in core.proxyEventsHub.attached()) delay(20) }
                }
            }
        }
    }

    /** What the proxy does per statement: probe the session's temps, Decide (answering refetches), run it. */
    private suspend fun serve(
        held: Connection,
        token: String,
        connectionId: com.google.protobuf.ByteString,
        sql: String,
        out: KChannel<ProxyRunMsg>,
        verdicts: MutableList<WireEnfAction>,
    ) {
        val searchPath = held.createStatement().use { st ->
            st.executeQuery("SELECT pg_catalog.current_schemas(true)").use { rs ->
                rs.next(); (rs.getArray(1).array as Array<*>).map { it.toString() }
            }
        }
        val temps = held.createStatement().use { st ->
            st.executeQuery(TEMP_COLUMNS_PROBE).use { rs ->
                buildList {
                    while (rs.next()) {
                        add(tempColumn {
                            schema = rs.getString(1); table = rs.getString(2); column = rs.getString(3)
                            sqlType = rs.getString(4); ordinal = rs.getInt(5)
                            catalog = fx.datasource.effectiveCatalog
                        })
                    }
                }
            }
        }
        val request = decisionRequest {
            this.token = token
            datasourceName = fx.datasource.name
            currentCatalog = fx.datasource.effectiveCatalog
            this.connectionId = connectionId
            this.sql = sql
            this.searchPath.addAll(searchPath)
            tempColumns.addAll(temps)
        }
        var response = stub.decide(request)
        repeat(5) {
            if (response.hasBeforeDecide()) {
                response.beforeDecide.commandsList.forEach { pcf.pushFromTarget(held, connectionId, it.refetch.schema) }
                response = stub.decide(request)
            }
        }
        val verdict = response.verdict
        verdicts += verdict.decision
        if (verdict.decision == WireEnfAction.DENY) {
            out.send(proxyRunMsg { decision = runDecision { decision = WireEnfAction.DENY; decisionId = verdict.decisionId; denyReason = verdict.denyReason } })
            return
        }
        out.send(proxyRunMsg {
            decision = runDecision {
                decision = verdict.decision; decisionId = verdict.decisionId
                resultFingerprint += verdict.resultFingerprintList
            }
        })
        held.createStatement().use { st ->
            if (st.execute(sql)) {
                st.resultSet.use { rs ->
                    val width = rs.metaData.columnCount
                    val columns = (1..width).map { rs.metaData.getColumnLabel(it) }
                    val rows = buildList { while (rs.next()) add((1..width).map { rs.getString(it) }) }
                    out.send(proxyRunMsg {
                        resultRows = runResultRows {
                            this.columns += columns
                            this.rows += rows.map { r -> runRow { values += r.map { v -> runValue { if (v == null) isNull = true else value = v } } } }
                        }
                    })
                }
                out.send(proxyRunMsg { done = runDone { rowsAffected = -1 } })
            } else {
                out.send(proxyRunMsg { done = runDone { rowsAffected = st.updateCount } })
            }
        }
    }

    private companion object {
        // goproxy/db PgDb.TempColumnsProbeSQL.
        const val TEMP_COLUMNS_PROBE = """SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnum
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname LIKE 'pg_temp%' AND pg_catalog.pg_table_is_visible(c.oid)
  AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum"""
    }
}
