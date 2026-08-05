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
        // decideConnection(ansiQuotes=true), which must reach the analyzer's EngineConfig so `"rrn"` is read
        // as the masked pii column, not a string literal — MASK, not a cleartext leak. With the flag false
        // (default mode) `"rrn"` is the constant string 'rrn' (no pii column touched) → ALLOW. Proven through
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
            """select "rrn" from users""", listOf(schema), null, ansiQuotes = true,
        )
        val maskedVerdict = assertIs<EnforcementOutcome.Verdict>(masked)
        assertEquals(EnfAction.MASK, maskedVerdict.ctx.action, maskedVerdict.ctx.denyReason)

        val allowed = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            """select "rrn" from users""", listOf(schema), null, ansiQuotes = false,
        )
        val allowedVerdict = assertIs<EnforcementOutcome.Verdict>(allowed)
        assertEquals(EnfAction.ALLOW, allowedVerdict.ctx.action, allowedVerdict.ctx.denyReason)
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

    @Test
    fun `ending a transaction re-measures the schemas read inside it`() = runBlocking {
        // A reading taken in a transaction is private to it — the manager never shares it, and freshnessGate
        // sees no moved hash to re-check against, so nothing else can true it up. The end of the transaction
        // is the one moment the same content can be re-read from outside, which is where the shared state
        // catches up instead of waiting on the re-measure clock.
        val schema = "tx_dirty_commit"
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER"),
            listOf(schema),
        )
        fixture.pushDirty(opened.connectionId, schema)

        val outcome = decideConnection(
            fixture.core,
            opened.connectionId,
            "analyst@example.com",
            fixture.datasource,
            "COMMIT",
            listOf(schema),
            null,
        )
        val verdict = assertIs<EnforcementOutcome.Verdict>(outcome)
        assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
        assertEquals(
            listOf(schema),
            verdict.afterStatement.map { it.schema },
            "the transaction's end must re-measure what was read inside it",
        )
    }

    @Test
    fun `ending a transaction re-measures nothing when nothing was read inside it`() = runBlocking {
        // The re-measure is owed by dirty content, not by the COMMIT itself. Re-measuring every schema on
        // every COMMIT would put a backend round-trip behind an ordinary transaction that read nothing.
        val schema = "tx_clean_commit"
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER"),
            listOf(schema),
        )
        fixture.pushSynthetic(opened.connectionId, schema)

        val outcome = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            "COMMIT", listOf(schema), null,
        )
        val verdict = assertIs<EnforcementOutcome.Verdict>(outcome)
        assertTrue(verdict.afterStatement.isEmpty(), "a settled reading owes nothing")
    }

    @Test
    fun `a statement that does not end a transaction re-measures nothing`() = runBlocking {
        // The re-measure is attached to the transaction ENDING, not to any session statement: BEGIN opens
        // one, so re-measuring there would read the same private state again and confirm nothing.
        val schema = "tx_dirty_begin"
        val opened = fixture.core.connectionCatalog.open(
            Binding(fixture.datasource.name, "analyst@example.com", "USER"),
            listOf(schema),
        )
        fixture.pushDirty(opened.connectionId, schema)

        val outcome = decideConnection(
            fixture.core, opened.connectionId, "analyst@example.com", fixture.datasource,
            "BEGIN", listOf(schema), null,
        )
        val verdict = assertIs<EnforcementOutcome.Verdict>(outcome)
        assertEquals(EnfAction.ALLOW, verdict.ctx.action, verdict.ctx.denyReason)
        assertTrue(verdict.afterStatement.isEmpty(), "opening a transaction cannot settle a reading taken inside one")
    }
}

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PerConnectionCatalogPostgresDbTest : PerConnectionCatalogDbContract() {
    override val enforcement by lazy { EnforcementFixture.postgres() }
}
