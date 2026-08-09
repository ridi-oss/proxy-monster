package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.RequireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.RequireStatementExecGrant
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.analyzer.pb.columnResource
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.analyzer.pb.requireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.requireStatementExecGrant
import com.ridi.oss.proxymonster.analyzer.pb.statementFacts
import com.ridi.oss.proxymonster.analyzer.pb.tableResource
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Drives the production [decideQuery] grant walk over SYNTHETIC [StatementFacts] (the `factsOverride`
 * test seam) against a real Cedar/catalog fixture. This is the only way to exercise the fail-closed
 * contract branches a resolved Go analyzer can never emit — an UNSPECIFIED disposition, a resourceless
 * result-read, a missing execute grant, an out-of-range ordinal — plus the disposition triad, resource-kind dispatch,
 * multi-ordinal first-wins, and metadata preservation, each against the fixture's live authorization.
 *
 * Fixture (EnforcementFixture.postgres): `analyst@example.com` may read `users` unmasked except the pii
 * `ssn` column (masked with `last4`); the `orders` table has no grant at all (deny-by-default).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StatementFactsGrantLoopTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var fixtureCatalog: List<CatalogColumn>
    private lateinit var ssn: CatalogColumn
    private lateinit var region: CatalogColumn
    private lateinit var amount: CatalogColumn

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        fixtureCatalog = fx.datasourceStore.catalog(fx.datasource.id)
        ssn = col("users", "ssn")
        region = col("users", "region")
        amount = col("orders", "amount")
    }

    private fun col(table: String, name: String): CatalogColumn =
        fixtureCatalog.first { it.table == table && it.column == name }

    private fun decide(facts: StatementFacts, channel: Channel = Channel.EDITOR): DecisionContext =
        decideQuery(
            principal = "analyst@example.com",
            ds = fx.datasource,
            sql = "-- synthetic facts --",
            channel = channel,
            catalog = fixtureCatalog,
            policyStore = fx.policyStore,
            accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore,
            roleResolver = fx.roleResolver,
            authz = fx.authz,
            factsOverride = facts,
        )

    private fun columnGrant(
        c: CatalogColumn,
        disposition: MaskedDisposition,
        ordinals: List<Int> = emptyList(),
    ): RequireResultReadGrant = requireResultReadGrant {
        column = columnResource {
            this.catalog = c.catalog
            identity = relationIdentity {
                this.schema = c.schema
                this.table = c.table
                this.column = c.column
            }
        }
        maskedDisposition = disposition
        this.outputOrdinals.addAll(ordinals)
    }

    private fun analyzed(
        vararg grants: RequireResultReadGrant,
        kind: StatementKind = StatementKind.STATEMENT_KIND_SELECT,
        outputCols: List<String> = emptyList(),
        rewrite: String? = null,
    ): StatementFacts = statementFacts {
        resolved = true
        detail = "synthetic"
        statementExec = executeGrant(kind)
        resultReads.addAll(grants.toList())
        outputColumns.addAll(outputCols)
        if (rewrite != null) rewrittenSql = rewrite
    }

    // The single per-statement authorization signal: the statement-execution grant carrying the kind the
    // control-plane gates as stmt.kind.<k>.
    private fun executeGrant(kind: StatementKind): RequireStatementExecGrant = requireStatementExecGrant {
        statementKind = kind
    }

    // ---- happy paths / disposition triad --------------------------------------------------------

    @Test
    fun `all-granted analyzed statement allows`() {
        val ctx = decide(
            analyzed(
                columnGrant(region, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("region"),
            ),
        )
        assertEquals(EnfAction.ALLOW, ctx.action, ctx.denyReason)
        assertTrue(ctx.masks.isEmpty())
    }

    @Test
    fun `masked verdict with MASK_OUTPUT applies the configured mask`() {
        val ctx = decide(
            analyzed(
                columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("ssn"),
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals(1, ctx.masks.size)
        assertEquals("ssn", ctx.masks[0].column)
        assertEquals("last4", ctx.masks[0].maskFn)
    }

    @Test
    fun `masked verdict with REDACT_OUTPUT_NULL redacts to NULL`() {
        val ctx = decide(
            analyzed(
                columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL, listOf(0)),
                outputCols = listOf("ssn"),
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals("redact", ctx.masks[0].maskFn)
        assertEquals("NULL", ctx.masks[0].kind)
    }

    @Test
    fun `masked verdict with DENY_STATEMENT disposition denies`() {
        val ctx = decide(analyzed(columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT)))
        assertEquals(EnfAction.DENY, ctx.action)
    }

    @Test
    fun `write read-set membership of a masked column denies`() {
        val ctx = decide(
            analyzed(columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT)),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.denyReason?.contains("cannot be masked") == true, ctx.denyReason)
    }

    @Test
    fun `denied verdict denies regardless of disposition`() {
        val ctx = decide(
            analyzed(
                columnGrant(amount, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("amount"),
            ),
        )
        assertEquals(EnfAction.DENY, ctx.action)
    }

    @Test
    fun `multi-grant same ordinal is first-wins`() {
        val ctx = decide(
            analyzed(
                columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL, listOf(0)),
                columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("ssn"),
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals(1, ctx.masks.size)
        assertEquals("NULL", ctx.masks[0].kind, "the first grant for an ordinal wins")
    }

    @Test
    fun `output columns and rewritten sql are preserved on the decision`() {
        val ctx = decide(
            analyzed(
                columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("ssn"),
                rewrite = "SELECT ssn FROM users",
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals(listOf("ssn"), ctx.outputColumns)
        assertEquals("SELECT ssn FROM users", ctx.rewrittenSql)
    }

    // ---- fail-closed contract branches (unreachable from real SQL) ------------------------------

    @Test
    fun `result-read grant with no resource fails closed`() {
        // A result-read naming no resource is invisible to the has*-filtered walk; with a valid execute
        // grant present (so the kind gate passes), the resourceless read must still structurally deny.
        val facts = statementFacts {
            resolved = true
            statementExec = executeGrant(StatementKind.STATEMENT_KIND_SELECT)
            resultReads.add(requireResultReadGrant {})
        }
        val ctx = decide(facts)
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
    }

    @Test
    fun `masked verdict with an unspecified disposition fails closed`() {
        val ctx = decide(analyzed(columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_UNSPECIFIED)))
        assertEquals(EnfAction.DENY, ctx.action)
    }

    @Test
    fun `an out-of-range mask ordinal fails closed`() {
        val ctx = decide(
            analyzed(
                columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(5)),
                outputCols = listOf("ssn"),
            ),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertEquals("mask-binding", ctx.failedStage)
    }

    @Test
    fun `unspecified disposition on an UNMASKED column fails closed`() {
        // `region` authorizes to UNMASKED, whose branch never inspects the disposition — so an UNSPECIFIED
        // disposition must be rejected by the up-front contract validation, not silently allowed.
        val ctx = decide(
            analyzed(
                columnGrant(region, MaskedDisposition.MASKED_DISPOSITION_UNSPECIFIED, listOf(0)),
                outputCols = listOf("region"),
            ),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
    }

    @Test
    fun `out-of-range ordinal on an UNMASKED column fails closed`() {
        // Same independence: a bogus ordinal on a column that authorizes to UNMASKED must still fail closed.
        val ctx = decide(
            analyzed(
                columnGrant(region, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(9)),
                outputCols = listOf("region"),
            ),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertEquals("mask-binding", ctx.failedStage)
    }

    @Test
    fun `unanalyzable deny carries schema candidates for a bounded catalog refetch`() {
        // An UNANALYZABLE statement referencing an uncatalogued schema denies (analyst lacks sql.unanalyzable)
        // but must surface its schema qualifiers + catalogMiss so ConnectionDecide can refetch and retry.
        val ctx = decide(
            statementFacts {
                // A lineage-failed SELECT parsed and classified (statement_exec=SELECT) but could not resolve;
                // the kind gate allows the read, then the unresolved path routes it through
                // sql.unanalyzable, which carries the schema candidates for the bounded refetch.
                resolved = false
                statementExec = executeGrant(StatementKind.STATEMENT_KIND_SELECT)
                failureClass = FailureClass.FAILURE_CLASS_UNANALYZABLE
                schemaQualifierCandidates.add("newly_created_schema")
            },
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.catalogMiss)
        assertEquals(setOf("newly_created_schema"), ctx.schemaCandidates)
    }

    @Test
    fun `a resolved statement with no execute grant fails closed`() {
        // A resolved statement must carry its statement_exec grant (the kind); absent one it would default
        // to the grantable sql.unanalyzable gate. A result-read alone must be a structural deny. The
        // execute grant is a bare message field now, so "two execute grants" and "a non-execute datasource
        // grant" are structurally impossible and no longer need tests.
        val ctx = decide(
            statementFacts {
                resolved = true
                resultReads.add(columnGrant(ssn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)))
                outputColumns.add("ssn")
            },
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
    }

    @Test
    fun `an unknown-kind statement is a policy deny via sql-unanalyzable`() {
        val ctx = decide(analyzed(kind = StatementKind.STATEMENT_KIND_STMT_UNKNOWN))
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(!ctx.structural, "STMT_UNKNOWN routes to sql.unanalyzable — a policy deny, not structural")
    }

    @Test
    fun `a resolved DDL statement is gated by its ddl kind`() {
        // DDL resolves as ANALYZED carrying only its execute grant — a DDL kind Cedar maps to stmt.cat.ddl —
        // and no columns. The fixture analyst holds no ddl, so this is a POLICY deny at the kind gate, not a
        // structural one: it reaches Cedar and is denied on the kind.
        val ctx = decide(analyzed(kind = StatementKind.STATEMENT_KIND_CREATE_TABLE))
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(!ctx.structural, "a resolved DDL fact is authorized off its kind, not structurally denied")
    }

    @Test
    fun `ungranted table grant denies through table dispatch`() {
        val tableGrant = requireResultReadGrant {
            table = tableResource {
                this.catalog = amount.catalog
                this.schema = amount.schema
                this.table = amount.table
            }
            maskedDisposition = MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT
        }
        assertEquals(EnfAction.DENY, decide(analyzed(tableGrant)).action)
    }

    // ---- empty-grant channel matrix -------------------------------------------------------------

    @Test
    fun `metadata with no resource grants is an allow passthrough`() {
        val facts = statementFacts {
            resolved = true
            statementExec = executeGrant(StatementKind.STATEMENT_KIND_SHOW_METADATA)
            schemaQualifierCandidates.add("public")
        }
        val ctx = decide(facts)
        assertEquals(EnfAction.ALLOW, ctx.action)
        assertTrue(ctx.passthrough)
        assertEquals(setOf("public"), ctx.schemaCandidates)
    }

    @Test
    fun `session statement passes through only on persistent-connection channels`() {
        val session = statementFacts {
            resolved = true
            statementExec = executeGrant(StatementKind.STATEMENT_KIND_SET_SESSION_VAR)
        }
        assertEquals(EnfAction.ALLOW, decide(session, Channel.WIRE).action)
        assertEquals(EnfAction.ALLOW, decide(session, Channel.EDITOR).action)
        assertEquals(EnfAction.DENY, decide(session, Channel.MCP).action)
        assertEquals(EnfAction.DENY, decide(session, Channel.WORKFLOW_EXECUTOR).action)
    }

    @Test
    fun `session rewrite rides the passthrough on persistent-connection channels`() {
        // The analyzer's results-charset pin (issue #81) is emitted as a rewrite on a session SET; it must
        // survive the session passthrough so the data plane relays utf8mb4 to the backend. Denied channels
        // (MCP/workflow) never execute the SET, so no rewrite reaches them.
        val pinned = statementFacts {
            resolved = true
            statementExec = executeGrant(StatementKind.STATEMENT_KIND_SET_SESSION_VAR)
            rewrittenSql = "SET character_set_results = utf8mb4"
        }
        val wire = decide(pinned, Channel.WIRE)
        assertEquals(EnfAction.ALLOW, wire.action)
        assertTrue(wire.passthrough)
        assertEquals("SET character_set_results = utf8mb4", wire.rewrittenSql)
        assertEquals("SET character_set_results = utf8mb4", decide(pinned, Channel.EDITOR).rewrittenSql)
        assertEquals(EnfAction.DENY, decide(pinned, Channel.MCP).action)
    }
}
