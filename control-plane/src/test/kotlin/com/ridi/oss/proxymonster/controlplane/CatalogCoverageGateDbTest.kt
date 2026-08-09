package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.StatementFacts
import com.ridi.oss.proxymonster.analyzer.pb.StatementKind
import com.ridi.oss.proxymonster.analyzer.pb.columnResource
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.analyzer.pb.requireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.requireStatementExecGrant
import com.ridi.oss.proxymonster.analyzer.pb.statementFacts
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Catalog-coverage as a Cedar decision (docs "authorization belongs to Cedar"). When the
 * analyzer resolves a statement and traces a column with NO row in the catalog index, decideQuery no
 * longer hard-denies. It routes the miss through the SAME `exception.unanalyzable` escape hatch as an
 * unanalyzable statement, carrying catalogMiss + the qualifier so decideConnection still runs its
 * bounded refetch-first retry:
 *  - production floor (no exception policy) → DENY, fail-closed. A non-admin
 *    never holds `exception.unanalyzable`, so a regular analyst always lands here — the safety property.
 *  - a datasource that shipped a `exception.unanalyzable` permit → ALLOW, relaying verbatim (passthrough, no
 *    masks) — the admin escape hatch, unmasked as that grant already means.
 *
 * A genuine coverage miss is an analyzer/catalog KEY divergence a real resolved statement cannot
 * reproduce, so the uncatalogued column is injected via the synthetic-facts `factsOverride` seam (a real
 * `users` catalog+schema+table with a column name that exists nowhere). Run on BOTH engines — the gate is
 * engine-agnostic, but MySQL is the priority engine, so it must be exercised explicitly.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CatalogCoverageGateDbTest {
    private lateinit var pg: EnforcementFixture
    private lateinit var my: EnforcementFixture
    private val principal = "analyst@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        pg = EnforcementFixture.postgres()
        my = EnforcementFixture.mysql()
    }

    @Test
    fun `postgres coverage miss denies on the floor, then a sql-unanalyzable permit relays it`() =
        runGate(pg, "test-coverage-unanalyzable-pg")

    @Test
    fun `mysql coverage miss denies on the floor, then a sql-unanalyzable permit relays it`() =
        runGate(my, "test-coverage-unanalyzable-my")

    private fun coverageMissFacts(fx: EnforcementFixture): StatementFacts {
        val users = fx.datasourceStore.catalog(fx.datasource.id).first { it.table == "users" }
        return statementFacts {
            resolved = true
            detail = "synthetic coverage miss"
            schemaQualifierCandidates.add(users.schema)
            statementExec = requireStatementExecGrant {
                statementKind = StatementKind.STATEMENT_KIND_SELECT
            }
            resultReads.add(
                requireResultReadGrant {
                    column = columnResource {
                        catalog = users.catalog
                        identity = relationIdentity {
                            schema = users.schema
                            table = users.table
                            column = "ghost_uncovered_column"
                        }
                    }
                    // Any valid, specified disposition: coverage is checked BEFORE the disposition-driven
                    // grant walk, so this value never decides the outcome — the "absent from catalog" detail
                    // assertion below proves the coverage gate (not a disposition deny) produced the verdict.
                    maskedDisposition = MaskedDisposition.MASKED_DISPOSITION_DENY_STATEMENT
                },
            )
        }
    }

    private fun decide(fx: EnforcementFixture): DecisionContext = decideQuery(
        principal = principal, ds = fx.datasource, sql = "-- synthetic coverage miss --", channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        factsOverride = coverageMissFacts(fx),
    )

    // Ordered within one method per engine: the floor DENY must be observed BEFORE the permit is created
    // (the permit persists on the PER_CLASS fixture). Each engine has its own fixture, so its permit does
    // not contaminate the other.
    private fun runGate(fx: EnforcementFixture, permitName: String) {
        val missSchema = fx.datasourceStore.catalog(fx.datasource.id).first { it.table == "users" }.schema

        // 1. No exception policy → fail-closed deny, carrying catalogMiss + the qualifier so decideConnection
        //    runs refetch-first before this verdict can stand. A regular analyst has no exception.unanalyzable.
        val floor = decide(fx)
        assertEquals(EnfAction.DENY, floor.action, "no exception.unanalyzable policy → coverage miss denies fail-closed")
        assertTrue(floor.catalogMiss, "the deny carries catalogMiss so decideConnection refetches + retries first")
        assertEquals(setOf(missSchema), floor.schemaCandidates, "the miss surfaces its qualifier schema for the refetch")
        assertTrue(floor.detail?.contains("absent from catalog") == true, "the fail-closed reason is preserved: ${floor.detail}")

        // 2. A datasource that shipped the exception.unanalyzable exception → relay the uncovered read verbatim.
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = permitName,
                cedarSrc = """permit(principal, action == Action::"exception.unanalyzable", resource == Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val permitted = decide(fx)
        assertEquals(EnfAction.ALLOW, permitted.action, "exception.unanalyzable permit → relay the uncovered read")
        assertTrue(permitted.passthrough, "an uncovered-column relay is a verbatim passthrough (no rewrite, no masks)")
        assertTrue(permitted.masks.isEmpty(), "no masks are applied to a relayed uncovered read")
        assertTrue(permitted.catalogMiss, "the relay still carries catalogMiss so refetch-first runs before it stands")
        assertTrue(permitted.detail?.contains("exception.unanalyzable") == true, "the ALLOW is attributed to the exception: ${permitted.detail}")
    }
}
