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
 * MySQL end-to-end coverage for the no-governing-manifest system-table floor (GHSA-j984-q948-4xq8) — the
 * primary engine, on real MySQL + real Cedar. The unit test proves the tags; this proves they reach Cedar
 * through `decideQuery` and that the shipped forbids override a broad Datasource grant.
 *
 * The fixture connection cannot see the `mysql`/`performance_schema` system databases in
 * `information_schema.columns`, so those tables never enter the introspected catalog. They are seeded here
 * explicitly — this test exercises the tag→Cedar ENFORCEMENT path, not catalog introspection. The version is
 * an UNCERTIFIED-but-present string (`5.7.44`): that is the advisory's real posture (no governing manifest,
 * fallback off) and the one the MySQL analyzer can resolve schemas under — a truly blank version is a
 * degenerate pre-registration state with no catalog at all.
 *
 * Each deny is asserted to carry the table-authorization reason naming the table, which distinguishes the tag
 * forbid overriding the broad grant from an unanalyzable/uncovered deny: under a broad grant an UNtagged table
 * would ALLOW, so a named-table deny is the load-bearing signal that the floor tagged it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SystemClassificationEnforcementMySqlDbTest {
    private lateinit var fx: EnforcementFixture
    private val classifier = SystemClassificationService()
    private val broad = "broad-mysql@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        fx.datasourceStore.storePushedCatalog(
            id = fx.datasource.id,
            defaultSchemas = listOf(fx.datasource.dbName),
            mysqlLowerCaseTableNames = 0,
            engineVersion = "5.7.44",
            columns = listOf(
                // An explicit system:critical credential table.
                DatasourceStore.PushedColumn("mysql", "user", "User", "char", 1, false),
                DatasourceStore.PushedColumn("mysql", "user", "authentication_string", "text", 2, true),
                // A value-bearing table NO shipped manifest classifies — the fail-closed critical default; the
                // raw cross-session-variable surface the advisory closes.
                DatasourceStore.PushedColumn("performance_schema", "user_variables_by_thread", "VARIABLE_NAME", "varchar", 1, true),
                DatasourceStore.PushedColumn("performance_schema", "user_variables_by_thread", "VARIABLE_VALUE", "longtext", 2, true),
                // An explicit system:data-leak table — kept at its tag (not force-critical), so system:development still relaxes it.
                DatasourceStore.PushedColumn("information_schema", "COLUMN_STATISTICS", "SCHEMA_NAME", "varchar", 1, true),
            ),
        )
        val role = fx.policyStore.createRole(RoleInput("broad-mysql-reader"))
        fx.policyStore.createAssignment(RoleAssignmentInput(broad, role.id))
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-broad-mysql-grant",
                cedarSrc = """permit(principal in Role::"broad-mysql-reader", action, resource in Datasource::"${fx.datasource.name}");""",
            ),
            updatedBy = "test",
        )
    }

    private fun setEngineVersion(v: String) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET engine_version = ? WHERE id = ?").use { ps ->
                ps.setString(1, v)
                ps.setLong(2, fx.datasource.id)
                ps.executeUpdate()
            }
        }
    }

    private fun setTags(json: String) {
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = ?::jsonb WHERE id = ?").use { ps ->
                ps.setString(1, json)
                ps.setLong(2, fx.datasource.id)
                ps.executeUpdate()
            }
        }
    }

    private fun decideAs(who: String, sql: String) = decideQuery(
        principal = who, ds = fx.datasourceStore.get(fx.datasource.id)!!, sql = sql, channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id), policyStore = fx.policyStore, accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore, roleResolver = fx.roleResolver, authz = fx.authz,
        systemClassification = classifier,
    )

    @Test
    fun `an uncertified MySQL broad grant cannot read a fixed system table`() {
        setEngineVersion("5.7.44")
        setTags("""["system:production"]""")
        // mysql.user (explicit critical) and performance_schema.user_variables_by_thread (catalog-default →
        // critical default) both deny THROUGH the table forbid — the named-table reason proves the tag
        // overrode the broad grant rather than an uncovered-table deny.
        for (table in listOf("mysql.user", "performance_schema.user_variables_by_thread")) {
            val ctx = decideAs(broad, "select count(*) from $table")
            assertEquals(EnfAction.DENY, ctx.action, "broad grant must not read $table (reason=${ctx.denyReason})")
            assertTrue(
                ctx.denyReason.orEmpty().contains(table.substringAfter('.')),
                "the deny must be the table forbid overriding the broad grant, not an uncovered deny: ${ctx.denyReason}",
            )
        }
        // The column path inherits the table's tag, so a projected column of a critical table denies too.
        // (Project authentication_string, not User — a bare `User` parses as the USER() builtin, not a column.)
        val col = decideAs(broad, "select authentication_string from mysql.user")
        assertEquals(EnfAction.DENY, col.action, "column path must deny too (reason=${col.denyReason})")
    }

    @Test
    fun `an uncertified MySQL explicit data-leak table is kept not forced critical so dev relaxes it`() {
        setEngineVersion("5.7.44")
        // information_schema.COLUMN_STATISTICS is an explicit data-leak in the manifests; the floor keeps that
        // tag rather than promoting everything to critical. On the production floor it denies…
        setTags("""["system:production"]""")
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from information_schema.COLUMN_STATISTICS").action, "data-leak denies on the production floor")
        // …and on a development datasource the shipped data-leak relaxation still applies, proving the floor
        // did not force it to the unconditional critical forbid.
        setTags("""["system:development"]""")
        assertEquals(EnfAction.ALLOW, decideAs(broad, "select count(*) from information_schema.COLUMN_STATISTICS").action, "data-leak is relaxed on system:development")
    }

    @Test
    fun `a governed MySQL datasource is unaffected by the no-manifest floor`() {
        // With a certified version the classifier owns the decision: mysql.user is still critical (denied),
        // proving the governed path is untouched by the floor.
        setEngineVersion("8.0.44")
        setTags("""["system:production"]""")
        assertEquals(EnfAction.DENY, decideAs(broad, "select count(*) from mysql.user").action, "governed mysql.user stays denied")
    }
}
