package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Unanalyzable-statement gate (docs/facts-emission.md) end-to-end on real PostgreSQL + real Cedar. The
 * analyzer cannot resolve an unknown output column → `resolved=false`.
 * decideQuery asks the datasource for the `exception.unanalyzable` exception:
 *  - production floor (no exception policy) → DENY; and
 *  - a datasource that shipped a `exception.unanalyzable` permit → ALLOW, relaying the ORIGINAL statement verbatim
 *    (passthrough, no masks) — the permissive development-datasource posture.
 * The gate fires before the column/table/function gates (an unresolved probe emits no facts for them), so a
 * missing read grant on the referenced tables is irrelevant here — this isolates the analyzable decision.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UnanalyzableGateDbTest {
    private lateinit var fx: EnforcementFixture
    private val principal = "analyst@example.com"

    // Admitted as SELECT but unresolved against the catalog.
    private val unanalyzable = "select missing_column from orders"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    private fun decide(sql: String) = decideQuery(
        principal = principal, ds = fx.datasource, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
    )

    // One ordered test: the floor DENY must be observed BEFORE the permit is created (the permit persists on
    // the PER_CLASS fixture), so the two assertions live in one method to fix their order.
    @Test
    fun `unanalyzable denies on the floor, then a sql-unanalyzable permit relays it verbatim`() {
        // 1. Production floor — no exception policy → deny-by-default (fail-closed).
        val floor = decide(unanalyzable)
        assertEquals(EnfAction.DENY, floor.action, "no exception.unanalyzable policy → deny-by-default")
        assertTrue(floor.detail?.contains("could not analyze") == true, "the fail-closed reason is preserved: ${floor.detail}")

        // 2. A datasource that shipped the exception (the permissive development posture) → relay verbatim.
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-dev-unanalyzable",
                cedarSrc = """permit(principal, action == Action::"exception.unanalyzable", resource == Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val permitted = decide(unanalyzable)
        assertEquals(EnfAction.ALLOW, permitted.action, "exception.unanalyzable permit → relay the original statement verbatim")
        assertTrue(permitted.passthrough, "an unanalyzable relay is a verbatim passthrough (no rewrite, no masks)")
        assertTrue(permitted.masks.isEmpty(), "no masks are applied to an unanalyzable relay")
        assertTrue(permitted.detail?.contains("exception.unanalyzable") == true, "the ALLOW is attributed to the exception: ${permitted.detail}")
        // Both verdicts must ask for a refetch first. A cross-schema statement whose qualifier this connection
        // never fetched is unresolvable for that reason alone, and reaches this gate indistinguishable from a
        // genuinely unanalyzable one — so without catalogMiss the relay stands on a catalog that never held
        // the schema, and every column the analyzer would have masked is relayed in the clear.
        assertTrue(floor.catalogMiss, "the deny carries catalogMiss so decideConnection refetches + retries first")
        assertTrue(permitted.catalogMiss, "the relay carries catalogMiss so refetch-first runs before it stands")
    }

    // The cross-schema case the flag exists for, driven through the REAL analyzer rather than a synthetic
    // failure: a statement qualifying a schema absent from the decision's catalog resolves nowhere, so it
    // lands on the unanalyzable gate carrying that schema as a refetch candidate.
    @Test
    fun `a statement naming an unheld schema asks for that schema before relaying`() {
        val candidate = "goods_store"
        // Assert the premise rather than assume it: were this schema ever added to the fixture, the statement
        // would resolve and the test would pass without exercising the gate at all.
        assertTrue(
            fx.datasourceStore.catalog(fx.datasource.id).none { it.schema == candidate },
            "the probe schema must be absent from the catalog for this test to mean anything",
        )
        val ctx = decide("select id from $candidate.orders")
        assertTrue(ctx.catalogMiss, "an unheld-schema statement must request a refetch, not stand on the partial catalog")
        assertTrue(
            candidate in ctx.schemaCandidates,
            "the unheld schema must be named for the refetch, got ${ctx.schemaCandidates}",
        )
    }
}
