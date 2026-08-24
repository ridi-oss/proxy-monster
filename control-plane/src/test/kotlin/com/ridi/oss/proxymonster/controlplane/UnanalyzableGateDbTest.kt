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
    }
}
