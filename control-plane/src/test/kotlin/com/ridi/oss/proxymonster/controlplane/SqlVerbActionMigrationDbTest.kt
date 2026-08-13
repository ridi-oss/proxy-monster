package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarSchema
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The pre-classification `sql.<verb>` datasource actions are gone from the schema. V18 rewrites any policy
 * that still names one to the statement category it maps to, so operator policies keep authorizing after the
 * removal; and a new policy naming a removed verb fails validation rather than validating and then going
 * silently inert (a `==` form matched nothing; a `forbid` doing so was a silent fail-open). Real PostgreSQL.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SqlVerbActionMigrationDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `V18 rewrites every sql-verb policy form to its statement category`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v18"))
        // Migrate to just before V18, then plant operator policies in each legacy form the migration handles:
        // the exact-match scope form (permit and forbid), the single-action in-list, and a multi-action in-list.
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("17")).load().migrate()
        val planted = mapOf(
            "eq-permit" to """permit(principal in Role::"r", action == Action::"sql.select", resource in Datasource::"d");""",
            "in-permit" to """permit(principal in Role::"r", action in [Action::"sql.insert"], resource in Datasource::"d");""",
            "in-list" to """permit(principal in Role::"r", action in [Action::"sql.select", Action::"sql.ddl"], resource in Datasource::"d");""",
            "eq-forbid" to """forbid(principal in Role::"r", action == Action::"sql.delete", resource in Datasource::"d");""",
            // Whitespace around `==` and `::` is valid Cedar and the migration must still convert it.
            "spaced" to """permit(principal in Role::"r", action == Action :: "sql.update", resource in Datasource::"d");""",
            // The shape of the one real prod USER verb policy: two write verbs in a channel-scoped in-list.
            "prod-workflow-write" to """permit(principal in Role::"r", action in [Action::"sql.insert", Action::"sql.update"], resource in Datasource::"d") when { context has channel && context.channel == "workflow-executor" };""",
        )
        ds.connection.use { c ->
            c.prepareStatement("INSERT INTO policy (name, cedar_src) VALUES (?, ?)").use { ps ->
                planted.forEach { (name, src) -> ps.setString(1, name); ps.setString(2, src); ps.addBatch() }
                ps.executeBatch()
            }
        }
        Flyway.configure().dataSource(ds).load().migrate() // runs V18

        val expected = mapOf(
            "eq-permit" to """permit(principal in Role::"r", action in [Action::"stmt.cat.read"], resource in Datasource::"d");""",
            "in-permit" to """permit(principal in Role::"r", action in [Action::"stmt.cat.write.insert"], resource in Datasource::"d");""",
            "in-list" to """permit(principal in Role::"r", action in [Action::"stmt.cat.read", Action::"stmt.cat.ddl"], resource in Datasource::"d");""",
            "eq-forbid" to """forbid(principal in Role::"r", action in [Action::"stmt.cat.write.delete"], resource in Datasource::"d");""",
            "spaced" to """permit(principal in Role::"r", action in [Action::"stmt.cat.write.update"], resource in Datasource::"d");""",
            "prod-workflow-write" to """permit(principal in Role::"r", action in [Action::"stmt.cat.write.insert", Action::"stmt.cat.write.update"], resource in Datasource::"d") when { context has channel && context.channel == "workflow-executor" };""",
        )
        ds.connection.use { c ->
            c.prepareStatement("SELECT cedar_src FROM policy WHERE name = ?").use { ps ->
                expected.forEach { (name, want) ->
                    ps.setString(1, name)
                    ps.executeQuery().use { rs ->
                        assertTrue(rs.next(), "policy $name missing after migration")
                        assertEquals(want, rs.getString("cedar_src"), "V18 must rewrite $name to its category")
                    }
                }
            }
            c.createStatement().use { st ->
                st.executeQuery("""SELECT count(*) FROM policy WHERE cedar_src ~ 'Action[[:space:]]*::[[:space:]]*"sql\.(select|insert|update|delete|ddl)"'""").use { rs ->
                    rs.next()
                    assertEquals(0, rs.getInt(1), "no policy may still name a sql.<verb> action after V18")
                }
            }
        }
        // Boot the real Cedar engine over the fully-migrated store: it fails fast if any policy — including
        // the rewritten USER-origin ones planted above — still names a removed sql.<verb> action.
        com.ridi.oss.proxymonster.controlplane.authz.CedarEngine(
            com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore(ds),
        )
    }

    @Test
    fun `a policy naming a removed sql-verb action fails validation, its category form validates`() {
        assertTrue(
            CedarSchema.validate("""permit(principal, action == Action::"sql.select", resource);""").isNotEmpty(),
            "a removed sql.<verb> action must fail validation, not validate then go inert",
        )
        assertTrue(
            CedarSchema.validate("""permit(principal, action in [Action::"stmt.cat.read"], resource);""").isEmpty(),
            "the category form the migration produces must validate",
        )
    }
}
