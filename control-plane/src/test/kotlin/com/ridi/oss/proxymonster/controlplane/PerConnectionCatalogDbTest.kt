package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.grpc.ControlPlaneGrpcService
import com.ridi.oss.proxymonster.controlplane.grpc.GrpcServer
import com.ridi.oss.proxymonster.grpc.ControlPlaneGrpcKt
import com.ridi.oss.proxymonster.grpc.decisionRequest
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import com.ridi.oss.proxymonster.analyzer.pb.sessionObservation
import com.ridi.oss.proxymonster.analyzer.pb.mySqlSession
import com.ridi.oss.proxymonster.analyzer.pb.postgresSession
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.pushTestCatalog
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.systemSchemas
import com.ridi.oss.proxymonster.controlplane.isPostgres
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

abstract class PerConnectionCatalogDbContract {
    protected abstract val enforcement: EnforcementFixture
    private lateinit var fixture: PerConnectionCatalogFixture

    @BeforeAll
    fun setupConnectionFixture() {
        requireDocker()
        fixture = PerConnectionCatalogFixture(enforcement)
    }

    @Test
    fun `decision uses held structure after the global catalog is cleared`() = runBlocking {
        if (fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        val opened = fixture.openAndPush(schemas = listOf(schema))
        enforcement.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET catalog = NULL WHERE id = ?").use { ps ->
                ps.setLong(1, fixture.datasource.id)
                ps.executeUpdate()
            }
        }
        val outcome = decideConnection(
            fixture.core,
            opened.connectionId,
            "analyst@example.com",
            fixture.datasource,
            "select id from users",
            listOf(schema),
            null,
        )
        val verdict = assertIs<EnforcementOutcome.Verdict>(outcome)
        assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
        assertEquals(1L, verdict.generation)
    }

    @Test
    fun `ANSI_QUOTES threads through decideConnection so a double-quoted pii column masks`() = runBlocking {
        // ANSI_QUOTES seam: the gRPC handler forwards the proxy's observed sql_mode=ANSI_QUOTES as
        // decideConnection(session.mysqlAnsiQuotes=true), which must reach the analyzer's EngineConfig so `"ssn"` is read
        // as the masked pii column, not a string literal — MASK, not a cleartext leak. With the flag false
        // (default mode) `"ssn"` is the constant string 'ssn' (no pii column touched) → ALLOW. Proven through
        // the real per-connection catalog path the wire Decide RPC actually runs.
        if (fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        // Introspect the fragment straight from the target (not fixture.openAndPush, which reads the global
        // catalog a sibling test deletes) — this also mirrors the proxy's real push flow exactly.
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER", fixture.datasource.effectiveCatalog), fixture.datasource.namespaces(listOf(schema)),
        )
        java.sql.DriverManager.getConnection(
            fixture.enforcement.targetJdbcUrl, fixture.enforcement.targetUser, fixture.enforcement.targetPassword,
        ).use { target -> fixture.pushFromTarget(target, opened.connectionId, schema) }

        val masked = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            """select "ssn" from users""", listOf(schema), null, session = sessionObservation { mysql = mySqlSession { ansiQuotes = true } },
        )
        val maskedVerdict = assertIs<EnforcementOutcome.Verdict>(masked)
        assertEquals(EnfAction.MASK, maskedVerdict.ctx.action, maskedVerdict.ctx.denyReason)

        val allowed = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            """select "ssn" from users""", listOf(schema), null, session = sessionObservation { mysql = mySqlSession { ansiQuotes = false } },
        )
        val allowedVerdict = assertIs<EnforcementOutcome.Verdict>(allowed)
        assertEquals(EnfAction.ALLOW, allowedVerdict.ctx.action, allowedVerdict.ctx.denyReason)
    }


    @Test
    fun `PostgreSQL safe function rewrite survives target shadowing`() = runBlocking {
        if (!fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first { it !in fixture.datasource.engine.systemSchemas }
        val shadowSchema = "pm_abs_shadow"
        val sql = "select abs(1)"

        java.sql.DriverManager.getConnection(
            fixture.enforcement.targetJdbcUrl,
            fixture.enforcement.targetUser,
            fixture.enforcement.targetPassword,
        ).use { target ->
            target.createStatement().use { statement ->
                statement.execute("drop schema if exists $shadowSchema cascade")
                statement.execute("create schema $shadowSchema")
                statement.execute(
                    "create function $shadowSchema.abs(integer) returns integer language sql immutable as 'select 777'",
                )
            }
            try {
                // Re-introspect AFTER creating the shadow, the way the proxy's catalog refresh would.
                fixture.core.datasourceStore.pushTestCatalog(
                    fixture.datasource,
                    fixture.enforcement.targetJdbcUrl,
                    fixture.enforcement.targetUser,
                    fixture.enforcement.targetPassword,
                )
                val opened = fixture.openAndPush(schemas = listOf(shadowSchema, "pg_catalog", schema))
                // With the shadow schema FIRST on the live search_path, the bare abs resolves to the
                // user function $shadowSchema.abs — an ungranted UDF Function grant — so the statement
                // DENIES instead of relaying a call the target would resolve to user code.
                val verdict = assertIs<EnforcementOutcome.Verdict>(
                    decideConnection(
                        fixture.core,
                        opened.connectionId,
                        "analyst@example.com",
                        fixture.datasource,
                        sql,
                        listOf(shadowSchema, "pg_catalog", schema),
                        null,
                    ),
                )
                assertEquals(EnfAction.DENY, verdict.ctx.action, verdict.ctx.toString())
                // Without the shadow on the path, the same call resolves to the pg_catalog builtin and
                // relays verbatim.
                val clean = assertIs<EnforcementOutcome.Verdict>(
                    decideConnection(
                        fixture.core,
                        opened.connectionId,
                        "analyst@example.com",
                        fixture.datasource,
                        sql,
                        listOf("pg_catalog", schema),
                        null,
                    ),
                )
                assertEquals(EnfAction.ALLOW, clean.ctx.action, clean.ctx.denyReason)
                assertEquals(null, clean.ctx.rewrittenSql, clean.ctx.toString())
            } finally {
                target.createStatement().use { it.execute("drop schema if exists $shadowSchema cascade") }
                fixture.core.datasourceStore.pushTestCatalog(
                    fixture.datasource,
                    fixture.enforcement.targetJdbcUrl,
                    fixture.enforcement.targetUser,
                    fixture.enforcement.targetPassword,
                )
            }
        }
    }


    @Test
    fun `PostgreSQL function visibility threads through decideConnection`() = runBlocking {
        if (!fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        val opened = fixture.openAndPush(schemas = listOf(schema))
        val sql = "select unnest from unnest(array[1])"

        // unnest resolves to the pg_catalog builtin through the live engine catalog and relays
        // VERBATIM — resolution is report-only, no pin rewrite.
        val observed = assertIs<EnforcementOutcome.Verdict>(
            decideConnection(
                fixture.core,
                opened.connectionId,
                "analyst@example.com",
                fixture.datasource,
                sql,
                listOf("pg_catalog", schema),
                null,
                session = sessionObservation { postgres = postgresSession { functionShadowingObserved = true } },
            ),
        )
        assertEquals(EnfAction.ALLOW, observed.ctx.action, observed.ctx.denyReason)
        assertEquals(null, observed.ctx.rewrittenSql, observed.ctx.toString())
    }

    @Test
    fun `missing search path fragment returns before-decide without audit`() = runBlocking {
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER", fixture.datasource.effectiveCatalog),
            emptyList(),
        )
        val outcome = decideConnection(
            fixture.core,
            opened.connectionId,
            "analyst@example.com",
            fixture.datasource,
            "select id from users",
            listOf("missing_schema"),
            null,
        )
        val before = assertIs<EnforcementOutcome.BeforeDecide>(outcome)
        assertEquals(listOf("missing_schema"), before.commands.map { it.schema })
    }



    @Test
    fun `the gRPC Decide handler forwards the session observation`() = runBlocking {
        // The one proxy-to-analyzer handoff: DecisionRequest.session must reach EngineConfig unchanged. A handler
        // that dropped it would read `"ssn"` as a string literal and relay the pii column in the clear.
        if (fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        val token = fixture.core.tokenStore.issue(TokenKind.USER, "analyst@example.com", emptyList(), null, 3600).token
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER", fixture.datasource.effectiveCatalog), fixture.datasource.namespaces(listOf(schema)),
        )
        java.sql.DriverManager.getConnection(
            fixture.enforcement.targetJdbcUrl, fixture.enforcement.targetUser, fixture.enforcement.targetPassword,
        ).use { target -> fixture.pushFromTarget(target, opened.connectionId, schema) }

        val server = GrpcServer(0, ControlPlaneGrpcService(fixture.core), null).also { it.start() }
        val channel = NettyChannelBuilder.forAddress("localhost", server.boundPort).usePlaintext().build()
        try {
            val stub = ControlPlaneGrpcKt.ControlPlaneCoroutineStub(channel)
            suspend fun decide(ansiQuotes: Boolean) = stub.decide(decisionRequest {
                this.token = token
                datasourceName = fixture.datasource.name
                currentCatalog = fixture.datasource.effectiveCatalog
                connectionId = opened.connectionId
                sql = """select "ssn" from users"""
                searchPath.add(schema)
                session = sessionObservation { mysql = mySqlSession { this.ansiQuotes = ansiQuotes } }
            }).verdict
            val masked = decide(true)
            assertEquals(EnfAction.MASK, masked.decision, masked.denyReason)
            assertEquals(EnfAction.ALLOW, decide(false).decision)
        } finally {
            channel.shutdownNow().awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)
            server.shutdown()
        }
    }

    @Test
    fun `routine DDL refetches the held schema and the fragment carries the new routine`() = runBlocking {
        val schema = fixture.datasource.defaultSchemas.first { it !in fixture.datasource.engine.systemSchemas }
        val principal = "writer@example.com"
        val opened = fixture.core.connectionCatalog.open(Binding(fixture.datasource.name, principal, "USER", fixture.datasource.effectiveCatalog), fixture.datasource.namespaces(listOf(schema)))
        val connection = fixture.core.connectionCatalog.find(opened.connectionId)!!
        val name = "pccat_identity_${System.nanoTime()}"
        val (create, drop) = if (fixture.datasource.engine.isPostgres) {
            "create function $schema.$name(v integer) returns integer language sql immutable as 'select v'" to
                "drop function $schema.$name(integer)"
        } else {
            "CREATE FUNCTION `$schema`.$name(v BIGINT) RETURNS BIGINT DETERMINISTIC RETURN v" to
                "DROP FUNCTION `$schema`.$name"
        }
        fun held() = fixture.core.connectionCatalog.heldRoutines(connection)[schema].orEmpty().filter { it == name.lowercase() }
        java.sql.DriverManager.getConnection(
            fixture.enforcement.targetJdbcUrl, fixture.enforcement.targetUser, fixture.enforcement.targetPassword,
        ).use { target ->
            fixture.pushFromTarget(target, opened.connectionId, schema)
            assertEquals(emptyList(), held())
            val verdict = assertIs<EnforcementOutcome.Verdict>(
                decideConnection(fixture.core, opened.connectionId, principal, fixture.datasource, create, listOf(schema), null),
            )
            assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
            assertEquals(listOf(schema), verdict.afterStatement.map { it.schema }, "routine DDL refetches the schema it lives in")
            // MySQL's binlog refuses CREATE FUNCTION from a non-SUPER account, so the DDL runs as root there.
            try {
                if (fixture.datasource.engine.isPostgres) target.createStatement().use { it.execute(create) } else SharedMySql.executeAdmin(create)
                fixture.pushFromTarget(target, opened.connectionId, schema)
                assertEquals(listOf(name.lowercase()), held(), "the refreshed fragment holds the routine")
            } finally {
                if (fixture.datasource.engine.isPostgres) target.createStatement().use { it.execute(drop) } else SharedMySql.executeAdmin(drop)
            }
        }
    }

    @Test
    fun `PostgreSQL xid visibility threads through decideConnection`() = runBlocking {
        if (!fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first { it !in fixture.datasource.engine.systemSchemas }
        val opened = fixture.openAndPush(schemas = listOf("pg_catalog", schema))
        val path = listOf("pg_temp_3", "pg_catalog", schema)

        suspend fun decide(
            visible: Boolean?,
            searchPath: List<String> = path,
        ) = assertIs<EnforcementOutcome.Verdict>(
            decideConnection(
                fixture.core,
                opened.connectionId,
                "analyst@example.com",
                fixture.datasource,
                "select '1'::xid",
                searchPath,
                null,
                session = sessionObservation { postgres = postgresSession { visible?.let { systemXidVisible = it } } },
            ),
        )

        assertEquals(EnfAction.DENY, decide(null).ctx.action)
        val visible = decide(true)
        assertEquals(EnfAction.ALLOW, visible.ctx.action)
        assertEquals(null, visible.ctx.rewrittenSql, visible.ctx.toString())
        assertEquals(EnfAction.DENY, decide(false).ctx.action)
        val userFirst = decide(true, listOf(schema, "pg_catalog"))
        assertEquals(EnfAction.DENY, userFirst.ctx.action, userFirst.ctx.toString())
    }

}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogMysqlDbTest : PerConnectionCatalogDbContract() {
    override val enforcement by lazy { EnforcementFixture.mysql() }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogPostgresDbTest : PerConnectionCatalogDbContract() {
    override val enforcement by lazy { EnforcementFixture.postgres() }

}
