package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.grpc.CONTROL_PROTOCOL_VERSION
import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.eventsRequest
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

private const val WINDOW_MILLIS = 1_000L

abstract class ConfigCatalogRefreshDbContract {
    protected abstract fun createEnforcement(): EnforcementFixture
    private lateinit var fixture: PerConnectionCatalogFixture
    private lateinit var server: GrpcServer
    private lateinit var channel: ManagedChannel

    @BeforeAll
    fun setup() {
        requireDocker()
        val enforcement = createEnforcement()
        enforcement.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "ddl-writer-session",
                cedarSrc = """permit(principal in Role::"ddl-writer", action in [Action::"stmt.cat.session"], resource in Datasource::"${enforcement.datasource.name}");""",
            ),
            updatedBy = "test-fixture",
        )
        fixture = PerConnectionCatalogFixture(enforcement, configCatalogRefreshWindowMillis = WINDOW_MILLIS)
        server = GrpcServer(0, ControlPlaneGrpcService(fixture.core), null).also { it.start() }
        channel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
    }

    @AfterAll
    fun teardown() {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS)
        server.shutdown()
    }

    private val ds get() = fixture.datasource
    private val writer = "writer@example.com"

    private fun schema(): String = if (ds.engine.isMySql) ds.dbName else ds.defaultSchemas.first { it !in ds.engine.systemSchemas }

    private fun target(): Connection = DriverManager.getConnection(
        fixture.enforcement.targetJdbcUrl, fixture.enforcement.targetUser, fixture.enforcement.targetPassword,
    )

    private fun table(name: String) = if (ds.engine.isMySql) "`${schema()}`.`$name`" else "\"${schema()}\".\"$name\""

    /**
     * RefreshCatalog events a proxy attached on the Events stream receives while [body] runs and one window
     * after; each one re-introspects the committed target state into the config catalog, as the proxy does.
     */
    private suspend fun refreshesSeenBy(body: suspend () -> Unit): Int = supervisorScope {
        val seen = AtomicInteger()
        val stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(channel)
        val proxy = launch {
            stub.events(eventsRequest { datasourceName = ds.name; protocolVersion = CONTROL_PROTOCOL_VERSION })
                .collect {
                    if (!it.hasRefreshCatalog()) return@collect
                    fixture.core.datasourceStore.pushTestCatalog(
                        ds, fixture.enforcement.targetJdbcUrl, fixture.enforcement.targetUser, fixture.enforcement.targetPassword,
                    )
                    seen.incrementAndGet()
                }
        }
        try {
            withTimeout(5_000) { while (ds.name !in fixture.core.proxyEventsHub.attached()) delay(20) }
            body()
            delay(WINDOW_MILLIS * 2)
        } finally {
            proxy.cancel()
            withTimeout(5_000) { while (ds.name in fixture.core.proxyEventsHub.attached()) delay(20) }
        }
        seen.get()
    }

    private suspend fun open(held: Connection, principal: String = writer): OpenConnection {
        val opened = fixture.core.connectionCatalog.open(Binding(ds.name, principal, "USER", ds.effectiveCatalog), ds.namespaces(listOf(schema())))
        fixture.pushFromTarget(held, opened.connectionId, schema())
        return opened
    }

    private suspend fun decide(opened: OpenConnection, sql: String, principal: String = writer) = assertIs<EnforcementOutcome.Verdict>(
        decideConnection(fixture.core, opened.connectionId, principal, ds, sql, listOf(schema()), null)
            ?: fail("connection disappeared"),
    )

    private suspend fun runDdl(held: Connection, opened: OpenConnection, sql: String) {
        val verdict = decide(opened, sql)
        assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
        assertTrue(verdict.afterStatement.any { it.schema == schema() }, "DDL schedules an after-statement refetch")
        held.createStatement().use { it.execute(sql) }
        fixture.pushFromTarget(held, opened.connectionId, schema())
    }

    private fun dropTables(vararg names: String) = target().use { t ->
        t.createStatement().use { st -> names.forEach { st.execute("DROP TABLE IF EXISTS ${table(it)}") } }
    }

    @Test
    fun `a DDL whose refetch changes the fragment sends one config catalog refresh`() = runBlocking {
        val name = "cfgref_one_${System.nanoTime()}"
        try {
            val refreshes = refreshesSeenBy {
                target().use { held -> runDdl(held, open(held), "CREATE TABLE ${table(name)} (id BIGINT)") }
            }
            assertEquals(1, refreshes)
        } finally {
            dropTables(name)
        }
    }

    @Test
    fun `several DDLs inside the window send one refresh`() = runBlocking {
        val names = (1..3).map { "cfgref_many_${it}_${System.nanoTime()}" }
        try {
            val refreshes = refreshesSeenBy {
                target().use { held ->
                    val opened = open(held)
                    names.forEach { runDdl(held, opened, "CREATE TABLE ${table(it)} (id BIGINT)") }
                }
            }
            assertEquals(1, refreshes)
        } finally {
            dropTables(*names.toTypedArray())
        }
    }

    private fun configCatalogHas(table: String) =
        fixture.core.datasourceStore.catalog(ds.id).columns.any { it.schema == schema() && it.table == table }

    @Test
    fun `a COMMIT after in-transaction DDL refreshes the config catalog again`() = runBlocking {
        val name = "cfgref_tx_${System.nanoTime()}"
        try {
            val refreshes = refreshesSeenBy {
                target().use { held ->
                    held.autoCommit = false
                    val opened = open(held)
                    runDdl(held, opened, "CREATE TABLE ${table(name)} (id BIGINT)")
                    delay(WINDOW_MILLIS * 2)
                    val commit = decide(opened, "COMMIT")
                    assertEquals(EnfAction.ALLOW, commit.ctx.action, commit.ctx.denyReason)
                    assertEquals(listOf(schema()), commit.afterStatement.map { it.schema }, "COMMIT re-measures the DDL's schema")
                    held.commit()
                    fixture.pushFromTarget(held, opened.connectionId, schema(), unchanged = true)
                }
            }
            assertEquals(2, refreshes, "one after the DDL, one after the COMMIT")
            assertTrue(configCatalogHas(name), "the committed table reaches the config catalog")
        } finally {
            dropTables(name)
        }
    }

    @Test
    fun `a ROLLBACK after in-transaction DDL sends no further refresh`() = runBlocking {
        val name = "cfgref_rollback_${System.nanoTime()}"
        try {
            val refreshes = refreshesSeenBy {
                target().use { held ->
                    held.autoCommit = false
                    val opened = open(held)
                    runDdl(held, opened, "CREATE TABLE ${table(name)} (id BIGINT)")
                    val rollback = decide(opened, "ROLLBACK")
                    assertEquals(EnfAction.ALLOW, rollback.ctx.action, rollback.ctx.denyReason)
                    assertEquals(emptyList(), rollback.afterStatement)
                    held.rollback()
                    delay(WINDOW_MILLIS * 2)
                    val commit = decide(opened, "COMMIT")
                    assertEquals(emptyList(), commit.afterStatement, "ROLLBACK cleared the connection's DDL")
                }
            }
            assertEquals(1, refreshes, "only the in-transaction DDL's own refresh")
        } finally {
            dropTables(name)
        }
    }

    @Test
    fun `temporary table DDL sends no refresh`() = runBlocking {
        val refreshes = refreshesSeenBy {
            target().use { held ->
                val opened = open(held)
                val sql = "CREATE TEMPORARY TABLE cfgref_temp (id BIGINT)"
                val verdict = decide(opened, sql)
                assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
                assertEquals(emptyList(), verdict.afterStatement)
                held.createStatement().use { it.execute(sql) }
            }
        }
        assertEquals(0, refreshes)
    }

    @Test
    fun `a plain SELECT sends no refresh`() = runBlocking {
        val refreshes = refreshesSeenBy {
            target().use { held ->
                val principal = "analyst@example.com"
                val opened = open(held, principal)
                val verdict = decide(opened, "SELECT id FROM users", principal)
                assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
                assertEquals(emptyList(), verdict.afterStatement)
            }
        }
        assertEquals(0, refreshes)
    }

    @Test
    fun `an unchanged after-statement push sends no refresh`() = runBlocking {
        val refreshes = refreshesSeenBy {
            target().use { held ->
                val opened = open(held)
                val verdict = decide(opened, "CREATE TABLE ${table("cfgref_never_run")} (id BIGINT)")
                assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
                assertTrue(verdict.afterStatement.isNotEmpty())
                fixture.pushFromTarget(held, opened.connectionId, schema(), unchanged = true)
            }
        }
        assertEquals(0, refreshes)
    }

    @Test
    fun `a refresh with no attached proxy does not fail the push`() = runBlocking {
        assertTrue(ds.name !in fixture.core.proxyEventsHub.attached())
        val name = "cfgref_detached_${System.nanoTime()}"
        try {
            target().use { held -> runDdl(held, open(held), "CREATE TABLE ${table(name)} (id BIGINT)") }
            delay(WINDOW_MILLIS * 2)
        } finally {
            dropTables(name)
        }
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ConfigCatalogRefreshMysqlDbTest : ConfigCatalogRefreshDbContract() {
    override fun createEnforcement() = EnforcementFixture.mysql()
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ConfigCatalogRefreshPostgresDbTest : ConfigCatalogRefreshDbContract() {
    override fun createEnforcement() = EnforcementFixture.postgres()
}
