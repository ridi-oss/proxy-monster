package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.PerConnectionCatalogFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
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
    fun `decision uses held structure after global catalog rows are deleted`() = runBlocking {
        if (fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        val opened = fixture.openAndPush(schemas = listOf(schema))
        enforcement.dataSource.connection.use { c ->
            c.prepareStatement("DELETE FROM catalog_column WHERE datasource_id = ?").use { ps ->
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
        // decideConnection(ansiQuotes=true), which must reach the analyzer's EngineConfig so `"ssn"` is read
        // as the masked pii column, not a string literal — MASK, not a cleartext leak. With the flag false
        // (default mode) `"ssn"` is the constant string 'ssn' (no pii column touched) → ALLOW. Proven through
        // the real per-connection catalog path the wire Decide RPC actually runs.
        if (fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        // Introspect the fragment straight from the target (not fixture.openAndPush, which reads the global
        // catalog a sibling test deletes) — this also mirrors the proxy's real push flow exactly.
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER"), listOf(schema),
        )
        java.sql.DriverManager.getConnection(
            fixture.enforcement.targetJdbcUrl, fixture.enforcement.targetUser, fixture.enforcement.targetPassword,
        ).use { target -> fixture.pushFromTarget(target, opened.connectionId, schema) }

        val masked = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            """select "ssn" from users""", listOf(schema), null, ansiQuotes = true,
        )
        val maskedVerdict = assertIs<EnforcementOutcome.Verdict>(masked)
        assertEquals(EnfAction.MASK, maskedVerdict.ctx.action, maskedVerdict.ctx.denyReason)

        val allowed = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            """select "ssn" from users""", listOf(schema), null, ansiQuotes = false,
        )
        val allowedVerdict = assertIs<EnforcementOutcome.Verdict>(allowed)
        assertEquals(EnfAction.ALLOW, allowedVerdict.ctx.action, allowedVerdict.ctx.denyReason)
    }

    @Test
    fun `PostgreSQL function visibility threads through decideConnection`() = runBlocking {
        if (!fixture.datasource.engine.isPostgres) return@runBlocking
        val schema = fixture.datasource.defaultSchemas.first()
        val opened = fixture.openAndPush(schemas = listOf(schema))
        val sql = "select unnest from unnest(array[1])"

        val unobserved = assertIs<EnforcementOutcome.Verdict>(
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
        assertEquals(EnfAction.DENY, unobserved.ctx.action)

        val observed = assertIs<EnforcementOutcome.Verdict>(
            decideConnection(
                fixture.core,
                opened.connectionId,
                "analyst@example.com",
                fixture.datasource,
                sql,
                listOf("pg_catalog", schema),
                null,
                postgresFunctionShadowingObserved = true,
                postgresShadowedFunctions = emptyList(),
            ),
        )
        assertEquals(EnfAction.ALLOW, observed.ctx.action, observed.ctx.denyReason)
        assertTrue(
            observed.ctx.rewrittenSql.orEmpty()
                .lowercase()
                .replace("\"", "")
                .contains("pg_catalog.unnest"),
            observed.ctx.toString(),
        )
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
            val opened = fixture.openAndPush(schemas = listOf(shadowSchema, "pg_catalog", schema))
            try {
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
                assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
                val rewritten = verdict.ctx.rewrittenSql ?: error("safe function query was not rewritten")
                assertEquals("select pg_catalog.abs(1)", rewritten)

                target.autoCommit = false
                target.createStatement().use { statement ->
                    statement.execute("set local search_path to $shadowSchema, pg_catalog, $schema")
                    statement.executeQuery(sql).use { result ->
                        assertTrue(result.next())
                        assertEquals(777, result.getInt(1))
                    }
                    statement.executeQuery(rewritten).use { result ->
                        assertTrue(result.next())
                        assertEquals(1, result.getInt(1))
                    }
                }
                target.rollback()
            } finally {
                target.autoCommit = true
                target.createStatement().use { it.execute("drop schema if exists $shadowSchema cascade") }
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
                postgresSystemXidVisible = visible,
            ),
        )

        assertEquals(EnfAction.DENY, decide(null).ctx.action)
        val visible = decide(true)
        assertEquals(EnfAction.ALLOW, visible.ctx.action)
        assertTrue(
            visible.ctx.rewrittenSql.orEmpty().lowercase().replace("\"", "").contains("pg_catalog.xid"),
            visible.ctx.toString(),
        )
        assertEquals(EnfAction.DENY, decide(false).ctx.action)
        val userFirst = decide(true, listOf(schema, "pg_catalog"))
        assertEquals(EnfAction.DENY, userFirst.ctx.action, userFirst.ctx.toString())
    }

    @Test
    fun `missing search path fragment returns before-decide without audit`() = runBlocking {
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER"),
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
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogMysqlDbTest : PerConnectionCatalogDbContract() {
    override val enforcement by lazy { EnforcementFixture.mysql() }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogPostgresDbTest : PerConnectionCatalogDbContract() {
    override val enforcement by lazy { EnforcementFixture.postgres() }
}
