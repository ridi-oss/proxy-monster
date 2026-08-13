package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.MigrationVersion
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * V19 renames the two datasource exception-gate actions `sql.unanalyzable`/`sql.unmaskable` → `exception.*`.
 * It rewrites only the Cedar ACTION reference, so an unrelated identifier that happens to spell the old name
 * — a `Role::`/`Tag::` literally named `sql.unanalyzable` — is left untouched. A bare substring swap would
 * silently retarget such a policy (a forbid keyed on the role would stop matching: a fail-open). Real PostgreSQL.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ExceptionGateRenameMigrationDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    @Test
    fun `V19 rewrites only the exception-gate action reference, never a like-named role`() {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_v19"))
        // Migrate to just before V19, then plant operator policies in each form: the exact-match and in-list
        // action references, a whitespace-around-`::` spelling, and — the fail-open guard — a forbid whose
        // ROLE is literally named `sql.unanalyzable` alongside a real action reference.
        Flyway.configure().dataSource(ds).target(MigrationVersion.fromVersion("18")).load().migrate()
        val planted = mapOf(
            "unanalyzable-eq" to """permit(principal in Role::"r", action == Action::"sql.unanalyzable", resource in Datasource::"d");""",
            "unmaskable-in" to """permit(principal in Role::"r", action in [Action::"sql.unmaskable"], resource in Datasource::"d");""",
            "spaced" to """permit(principal in Role::"r", action == Action :: "sql.unanalyzable", resource in Datasource::"d");""",
            "role-collision" to """forbid(principal in Role::"sql.unanalyzable", action == Action::"sql.unmaskable", resource in Datasource::"d");""",
        )
        ds.connection.use { c ->
            c.prepareStatement("INSERT INTO policy (name, cedar_src) VALUES (?, ?)").use { ps ->
                planted.forEach { (name, src) -> ps.setString(1, name); ps.setString(2, src); ps.addBatch() }
                ps.executeBatch()
            }
        }
        Flyway.configure().dataSource(ds).load().migrate() // runs V19

        val expected = mapOf(
            "unanalyzable-eq" to """permit(principal in Role::"r", action == Action::"exception.unanalyzable", resource in Datasource::"d");""",
            "unmaskable-in" to """permit(principal in Role::"r", action in [Action::"exception.unmaskable"], resource in Datasource::"d");""",
            "spaced" to """permit(principal in Role::"r", action == Action::"exception.unanalyzable", resource in Datasource::"d");""",
            // The action reference is renamed; the like-named ROLE is untouched.
            "role-collision" to """forbid(principal in Role::"sql.unanalyzable", action == Action::"exception.unmaskable", resource in Datasource::"d");""",
        )
        ds.connection.use { c ->
            c.prepareStatement("SELECT name, cedar_src FROM policy WHERE name = ANY(?)").use { ps ->
                ps.setArray(1, c.createArrayOf("text", planted.keys.toTypedArray()))
                ps.executeQuery().use { rs ->
                    var seen = 0
                    while (rs.next()) {
                        seen++
                        val name = rs.getString("name")
                        assertEquals(expected.getValue(name), rs.getString("cedar_src"), "V19 rewrite of '$name'")
                    }
                    assertEquals(expected.size, seen, "every planted policy was found and checked")
                }
            }
        }
        // The control-plane boots only if every stored policy validates against the schema. A user policy
        // the migration failed to rewrite — still naming the removed `sql.*` action — would throw here, so
        // this proves the rewritten USER policies (not just the seeded rows) boot clean.
        com.ridi.oss.proxymonster.controlplane.authz.CedarEngine(
            com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore(ds),
        )
    }
}
