package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFalse

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UnprovedRelationGateDbTest {
    private lateinit var fx: EnforcementFixture
    private val principal = "analyst@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    private fun decide(sql: String, catalog: Catalog) = decideQuery(
        principal = principal, ds = fx.datasource, sql = sql, channel = Channel.WIRE,
        catalog = catalog, policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
    )

    @Test
    fun `a statement naming an unproved relation denies even where exception unanalyzable is permitted`() {
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-unproved-unanalyzable",
                cedarSrc = """permit(principal, action == Action::"exception.unanalyzable", resource == Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
        val stored = fx.datasourceStore.catalog(fx.datasource.id)
        val schema = stored.columns.first { it.table == "orders" }.schema
        val catalog = stored.copy(unprovedRelations = listOf(tableRef(fx.datasource.effectiveCatalog, schema, "order_view")))

        assertEquals(EnfAction.ALLOW, decide("select missing_column from orders", catalog).action, "premise: the permit relays an unanalyzable statement")
        for (sql in listOf("select * from order_view", "select id from $schema.order_view")) {
            val denied = decide(sql, catalog)
            assertEquals(EnfAction.DENY, denied.action, "an unproved relation is inadmissible: ${denied.detail}")
            assertFalse(denied.passthrough, "an unproved relation is never relayed verbatim")
        }
    }
}
