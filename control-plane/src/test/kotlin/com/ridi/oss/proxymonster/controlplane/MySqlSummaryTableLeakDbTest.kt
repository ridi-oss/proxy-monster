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
 * End-to-end regression on real MySQL + real Cedar for the value-bearing summary-table leak: on a CERTIFIED
 * (governed) MySQL datasource, `performance_schema.user_variables_by_thread` and the `sys.x$…` statistics
 * twins used to default to `system:catalog` and were readable by any viewer through the role-agnostic
 * catalog permit. With the manifest families added they carry a dangerous tag, so the shipped forbid denies
 * them even under a broad Datasource grant. The `mysql`/`performance_schema` system DBs are not in the
 * fixture's introspected catalog (connection privileges), so the tables are seeded explicitly — this
 * exercises the tag→Cedar path, not introspection. The named-table deny reason distinguishes the tag forbid
 * overriding the broad grant from an uncovered deny.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MySqlSummaryTableLeakDbTest {
    private lateinit var fx: EnforcementFixture
    private val classifier = SystemClassificationService()
    private val broad = "summary-broad@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        fx.datasourceStore.storePushedCatalog(
            id = fx.datasource.id,
            defaultSchemas = listOf(fx.datasource.dbName),
            mysqlLowerCaseTableNames = 0,
            engineVersion = "8.0.44",
            columns = listOf(
                DatasourceStore.PushedColumn("performance_schema", "user_variables_by_thread", "VARIABLE_NAME", "varchar", 1, true),
                DatasourceStore.PushedColumn("performance_schema", "user_variables_by_thread", "VARIABLE_VALUE", "longtext", 2, true),
                DatasourceStore.PushedColumn("sys", "x\$schema_table_statistics", "table_name", "varchar", 1, true),
                // A genuinely structural catalog view stays browsable — proves the fix did not over-classify.
                DatasourceStore.PushedColumn("information_schema", "TABLES", "TABLE_NAME", "varchar", 1, true),
            ),
        )
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = '[\"system:production\"]'::jsonb WHERE id = ?").use {
                it.setLong(1, fx.datasource.id)
                it.executeUpdate()
            }
        }
        val role = fx.policyStore.createRole(RoleInput("summary-broad-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-summary-broad-grant",
                cedarSrc = """permit(principal in Role::"summary-broad-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
    }

    // Decide with the classifier active, OR with it disabled (null) — the null run is the control: with no
    // system tag the broad Datasource grant permits the read, so an ALLOW there proves the grant is live and
    // the table is analyzable; flipping to DENY only when the classifier is present proves the tag is what
    // closes it (not deny-by-default, which would deny in both runs).
    private fun decide(who: String, sql: String, classify: SystemClassificationService?) = decideQuery(
        principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = classify,
    )

    @Test
    fun `governed value-bearing summary tables deny under a broad grant while structural catalog still browses`() {
        // count(*) exercises the table gate — the surface this classification closes.
        val targets = listOf(
            "select count(*) from performance_schema.user_variables_by_thread",
            "select count(*) from sys.x\$schema_table_statistics",
        )
        for (sql in targets) {
            val table = sql.substringAfter("from ").trim()
            // Control: with the classifier OFF, the broad grant permits the read.
            assertEquals(EnfAction.ALLOW, decide(broad, sql, null).action, "broad grant permits [$sql] with no classifier (control)")
            // With the classifier ON, the tag forbid overrides that same broad grant, and the deny names the
            // table (the tag-forbid table path), not an unrelated stage.
            val ctx = decide(broad, sql, classifier)
            assertEquals(EnfAction.DENY, ctx.action, "classifier tag must deny [$sql] (reason=${ctx.denyReason})")
            assertTrue(ctx.denyReason.orEmpty().contains(table.substringAfter('.')), "deny must name $table: ${ctx.denyReason}")
        }
        // Structural catalog metadata is unchanged — still browsable with the classifier on.
        assertEquals(EnfAction.ALLOW, decide(broad, "select count(*) from information_schema.TABLES", classifier).action, "structural catalog still browses")
    }
}
