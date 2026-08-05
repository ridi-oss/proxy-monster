package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.FailureClass
import com.ridi.oss.proxymonster.analyzer.pb.GrantAction
import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.RequiredGrant
import com.ridi.oss.proxymonster.analyzer.pb.StatementClass
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.columnResource
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.analyzer.pb.requiredGrant
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
 * contract branches a resolved Go analyzer can never emit — UNSPECIFIED action/disposition/class, an
 * out-of-range ordinal, a resourceless grant — plus the disposition triad, resource-kind dispatch,
 * multi-ordinal first-wins, and metadata preservation, each against the fixture's live authorization.
 *
 * Fixture (EnforcementFixture.postgres): `analyst@example.com` may read `users` unmasked except the pii
 * `rrn` column (masked with `last4`); the `orders` table has no grant at all (deny-by-default).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StatementFactsGrantLoopTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var fixtureCatalog: List<CatalogColumn>
    private lateinit var rrn: CatalogColumn
    private lateinit var region: CatalogColumn
    private lateinit var amount: CatalogColumn

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
        fixtureCatalog = fx.datasourceStore.catalog(fx.datasource.id)
        rrn = col("users", "rrn")
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
        action: GrantAction = GrantAction.GRANT_ACTION_RESULT_READ,
    ): RequiredGrant = requiredGrant {
        this.action = action
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
        vararg grants: RequiredGrant,
        isWrite: Boolean = false,
        outputCols: List<String> = emptyList(),
        rewrite: String? = null,
    ): StatementFacts = statementFacts {
        resolved = true
        statementClass = StatementClass.STATEMENT_CLASS_ANALYZED
        detail = "synthetic"
        this.isWrite = isWrite
        requiredGrants.addAll(grants.toList())
        outputColumns.addAll(outputCols)
        if (rewrite != null) rewrittenSql = rewrite
    }

    private fun datasourceGrant(action: GrantAction): RequiredGrant = requiredGrant {
        this.action = action
        datasource = true
        maskedDisposition = MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT
    }

    // ---- happy paths / disposition triad --------------------------------------------------------

    @Test
    fun `all-granted analyzed statement allows`() {
        val ctx = decide(
            analyzed(
                datasourceGrant(GrantAction.GRANT_ACTION_SQL_SELECT),
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
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("rrn"),
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals(1, ctx.masks.size)
        assertEquals("rrn", ctx.masks[0].column)
        assertEquals("last4", ctx.masks[0].maskFn)
    }

    @Test
    fun `masked verdict with REDACT_OUTPUT_NULL redacts to NULL`() {
        val ctx = decide(
            analyzed(
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL, listOf(0)),
                outputCols = listOf("rrn"),
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals("redact", ctx.masks[0].maskFn)
        assertEquals("NULL", ctx.masks[0].kind)
    }

    @Test
    fun `masked verdict with DENY_STATEMENT disposition denies`() {
        val ctx = decide(analyzed(columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT)))
        assertEquals(EnfAction.DENY, ctx.action)
    }

    @Test
    fun `write read-set membership of a masked column denies`() {
        val ctx = decide(
            analyzed(columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT), isWrite = true),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.denyReason?.contains("write") == true, ctx.denyReason)
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
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_REDACT_OUTPUT_NULL, listOf(0)),
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("rrn"),
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
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)),
                outputCols = listOf("rrn"),
                rewrite = "SELECT rrn FROM users",
            ),
        )
        assertEquals(EnfAction.MASK, ctx.action, ctx.denyReason)
        assertEquals(listOf("rrn"), ctx.outputColumns)
        assertEquals("SELECT rrn FROM users", ctx.rewrittenSql)
    }

    // ---- fail-closed contract branches (unreachable from real SQL) ------------------------------

    @Test
    fun `grant with no resource fails closed`() {
        val facts = statementFacts {
            resolved = true
            statementClass = StatementClass.STATEMENT_CLASS_METADATA
            requiredGrants.add(requiredGrant { action = GrantAction.GRANT_ACTION_UNSPECIFIED })
        }
        val ctx = decide(facts)
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
    }

    @Test
    fun `resource grant with a non-RESULT_READ action fails closed`() {
        val ctx = decide(
            analyzed(
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0), action = GrantAction.GRANT_ACTION_SQL_SELECT),
                outputCols = listOf("rrn"),
            ),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
    }

    @Test
    fun `masked verdict with an unspecified disposition fails closed`() {
        val ctx = decide(analyzed(columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_UNSPECIFIED)))
        assertEquals(EnfAction.DENY, ctx.action)
    }

    @Test
    fun `an out-of-range mask ordinal fails closed`() {
        val ctx = decide(
            analyzed(
                columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(5)),
                outputCols = listOf("rrn"),
            ),
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertEquals("mask-binding", ctx.failedStage)
    }

    @Test
    fun `unspecified statement class fails closed`() {
        val ctx = decide(
            statementFacts {
                resolved = true
                statementClass = StatementClass.STATEMENT_CLASS_UNSPECIFIED
            },
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
    }

    @Test
    fun `unspecified statement class with a column grant fails closed independent of the verdict`() {
        // A resolved statement carrying a column grant skips the empty-grant class switch, so the class must
        // be validated up front — an UNSPECIFIED class must deny even though the grant would otherwise mask.
        val ctx = decide(
            statementFacts {
                resolved = true
                statementClass = StatementClass.STATEMENT_CLASS_UNSPECIFIED
                requiredGrants.add(columnGrant(rrn, MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT, listOf(0)))
                outputColumns.add("rrn")
            },
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.structural)
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
                resolved = false
                failureClass = FailureClass.FAILURE_CLASS_UNANALYZABLE
                schemaQualifierCandidates.add("newly_created_schema")
            },
        )
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(ctx.catalogMiss)
        assertEquals(setOf("newly_created_schema"), ctx.schemaCandidates)
    }

    @Test
    fun `datasource grant with an unspecified action is a policy deny`() {
        val ctx = decide(analyzed(datasourceGrant(GrantAction.GRANT_ACTION_UNSPECIFIED)))
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(!ctx.structural, "kind-not-permitted is a policy deny, not structural")
    }

    @Test
    fun `a resolved DDL statement authorizes off its sql-ddl grant like any grant-only write`() {
        // DDL resolves as ANALYZED carrying a single sql.ddl datasource grant and no columns — the same
        // shape INSERT takes. The fixture analyst holds no sql.ddl, so this is a POLICY deny at the
        // datasource-grant loop, not a structural one: it reaches Cedar and is denied on the grant.
        val ctx = decide(analyzed(datasourceGrant(GrantAction.GRANT_ACTION_SQL_DDL), isWrite = true))
        assertEquals(EnfAction.DENY, ctx.action)
        assertTrue(!ctx.structural, "a resolved DDL fact is authorized off its grant, not structurally denied")
    }

    @Test
    fun `ungranted table grant denies through table dispatch`() {
        val tableGrant = requiredGrant {
            action = GrantAction.GRANT_ACTION_RESULT_READ
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
    fun `metadata with no grants is an allow passthrough`() {
        val facts = statementFacts {
            resolved = true
            statementClass = StatementClass.STATEMENT_CLASS_METADATA
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
            statementClass = StatementClass.STATEMENT_CLASS_SESSION
        }
        assertEquals(EnfAction.ALLOW, decide(session, Channel.WIRE).action)
        assertEquals(EnfAction.ALLOW, decide(session, Channel.EDITOR).action)
        assertEquals(EnfAction.DENY, decide(session, Channel.MCP).action)
        assertEquals(EnfAction.DENY, decide(session, Channel.WORKFLOW_EXECUTOR).action)
    }
}
