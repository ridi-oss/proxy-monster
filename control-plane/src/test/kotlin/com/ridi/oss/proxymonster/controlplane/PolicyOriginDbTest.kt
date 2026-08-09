package com.ridi.oss.proxymonster.controlplane

import com.cedarpolicy.formatter.PolicyFormatter
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.SQLException
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Real PostgreSQL proof for docs/policy-store.md: the shipped SYSTEM rows land with the source, key,
 * name, and enabled defaults the access model depends on, and the store's constraints mechanically
 * separate the negative SYSTEM id/name/key space from the positive USER one.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicyOriginDbTest {
    @BeforeAll
    fun requireDatabase() {
        requireDockerOrSkip()
    }

    /**
     * The whole shipped security posture, pinned as one digest. The per-row assertions below cover a
     * handful of policies by name; this covers ALL of them plus the roles, groups, and group-to-role
     * links, so narrowing a Cedar body that no named assertion happens to mention cannot pass.
     *
     * A system policy's `id` and `system_key` are written as literals by the seed, not handed out by a
     * sequence, so both are pinned here: they address the row that a later migration or an operator
     * override targets, and swapping either silently redirects that edit to a different policy while
     * leaving the effective posture identical today. `origin` is pinned for the same reason — it is
     * what makes a row immutable to the API. Only `updated_at` is excluded, being a clock reading.
     *
     * When this fails: a seeded policy body, id, key, origin, enabled flag, role, group, or
     * group-to-role link changed. That is a change to what a FRESH INSTALL enforces. Confirm the change
     * is intended, then update the expected digest in the same commit.
     */
    @Test
    fun `the shipped default security posture is unchanged`() {
        val ds = fullyMigrated("pm_policy_posture")
        val digest = ds.connection.use { c ->
            c.createStatement().use { st ->
                st.executeQuery(
                    """
                    SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
                      SELECT 'p:' || id::text || coalesce(system_key, '') || name
                             || coalesce(cedar_src, '') || enabled::text || origin AS x FROM policy
                      UNION ALL SELECT 'r:' || name FROM app_role
                      UNION ALL SELECT 'g:' || name FROM app_group
                      UNION ALL SELECT 'gr:' || g.name || '->' || r.name
                        FROM group_role gr
                        JOIN app_group g ON g.id = gr.group_id
                        JOIN app_role r ON r.id = gr.role_id
                    ) t(x)
                    """.trimIndent() + "\n",
                ).use { rs -> rs.next(); rs.getString(1) }
            }
        }
        assertEquals(
            "1f2b23ded56d2adc270004c30b06666c",
            digest,
            "the seeded security posture changed: a policy body, id, key, origin, enabled flag, role, " +
                "group, or group-to-role link differs from what a fresh install is supposed to enforce",
        )
    }

    /**
     * Every seeded policy source is stored in canonical Cedar format. The formatter (cedar-java's
     * PolicyFormatter, the same Cedar formatter that produced V12) is idempotent on a canonical policy, so a
     * stored source that differs from its formatted form was hand-written out of format. The console displays
     * this source verbatim (#86), so an ad-hoc single-line body would render inconsistently; this guards every
     * migration that seeds or updates a policy against re-introducing that. Fix a failure with `cedar format`.
     */
    @Test
    fun `every seeded SYSTEM policy is in canonical Cedar format`() {
        val ds = fullyMigrated("pm_policy_format")
        val policies = ds.connection.use { c ->
            c.createStatement().use { st ->
                st.executeQuery("SELECT id, cedar_src FROM policy WHERE origin = 'SYSTEM' AND cedar_src IS NOT NULL ORDER BY id").use { rs ->
                    buildList { while (rs.next()) add(rs.getLong("id") to rs.getString("cedar_src")) }
                }
            }
        }
        assertTrue(policies.isNotEmpty(), "expected seeded SYSTEM policies")
        val unformatted = policies.filter { (_, src) ->
            PolicyFormatter.policiesStrToPretty(src).trim() != src.trim()
        }.map { it.first }
        assertTrue(unformatted.isEmpty(), "seeded SYSTEM policies not in canonical Cedar format (run `cedar format`): $unformatted")
    }

    @Test
    fun `a clean database installs the admin and audit system rows`() {
        val ds = fullyMigrated("pm_policy_origin_clean")
        val store = CedarPolicyStore(ds)

        val expected = mapOf(
            -1L to Triple("bootstrap.pm-admin", "system:admin", ADMIN_SOURCE),
            -2L to Triple("workflow.no-self-approval", "system:no-self-approval", NO_SELF_APPROVAL_SOURCE),
            -3L to Triple("workflow.pm-admin-approve", "system:admin-approver", APPROVER_SOURCE),
        )
        val rows = store.list().filter { it.id in expected.keys }
        assertEquals(expected.keys, rows.map { it.id }.toSet())
        for (row in rows) {
            val (key, name, source) = expected.getValue(row.id)
            assertEquals("SYSTEM", row.origin)
            assertEquals(key, row.systemKey)
            assertEquals(name, row.name)
            assertEquals(source, row.cedarSrc)
            assertTrue(row.enabled)
        }

        // Audit reads: -4 is every principal's own-record read, -5 grants the whole log to system:admin.
        val auditSeeds = store.list().filter { it.systemKey in setOf("audit.read-own", "audit.read-admin") }
        assertEquals(setOf(-4L, -5L), auditSeeds.map { it.id }.toSet())
        assertEquals(
            setOf("system:audit-read-own", "system:audit-read-admin"),
            auditSeeds.map { it.name }.toSet(),
        )
        assertTrue(auditSeeds.all { it.origin == "SYSTEM" && it.enabled })
        CedarEngine(store)
    }

    @Test
    fun `the development preset ships enabled and the production preset ships disabled`() {
        // The shipped enabled defaults are security-significant: production access must be OFF until an
        // explicit, audited toggle, and the -300 trusted-network producer must be off until production
        // is enabled (otherwise the readiness dangling-tag lint trips on a producer with no consumer).
        val ds = fullyMigrated("pm_preset_enabled_defaults")
        val enabledById = CedarPolicyStore(ds).list().associate { it.id to it.enabled }

        val shippedEnabled = listOf(-4L, -5L, -100L, -110L, -120L, -130L, -200L, -201L, -202L) +
            (230L..235L).map { -it }
        for (id in shippedEnabled) {
            assertTrue(enabledById[id] == true, "policy $id must ship ENABLED (got ${enabledById[id]})")
        }
        val shippedDisabled = (250L..259L).map { -it } + listOf(-300L)
        for (id in shippedDisabled) {
            assertTrue(enabledById[id] == false, "policy $id must ship DISABLED (got ${enabledById[id]})")
        }
    }

    @Test
    fun `the four origin constraints reject every cross-namespace raw insert`() {
        val ds = fullyMigrated("pm_policy_origin_constraints")
        val constraintNames = ds.connection.use { c ->
            c.prepareStatement(
                "SELECT conname FROM pg_constraint WHERE conrelid='policy'::regclass",
            ).use { ps ->
                ps.executeQuery().use { rs ->
                    buildSet { while (rs.next()) add(rs.getString(1)) }
                }
            }
        }
        assertTrue(
            constraintNames.containsAll(
                setOf(
                    "policy_origin_check",
                    "policy_id_origin_check",
                    "policy_name_origin_check",
                    "policy_system_key_unique",
                ),
            ),
        )

        assertRejected(ds, "INSERT INTO policy (name, cedar_src, origin) VALUES ('bad-origin', '${ADMIN_SOURCE.sqlLiteral()}', 'MIGRATION')")
        assertRejected(ds, "INSERT INTO policy (id, name, cedar_src, origin) VALUES (-1001, 'negative-user', '${ADMIN_SOURCE.sqlLiteral()}', 'USER')")
        assertRejected(
            ds,
            "INSERT INTO policy (id, system_key, name, cedar_src, origin) VALUES " +
                "(1001, 'test.positive-system', 'system:positive-system', '${ADMIN_SOURCE.sqlLiteral()}', 'SYSTEM')",
        )
        assertRejected(
            ds,
            "INSERT INTO policy (id, name, cedar_src, origin) VALUES " +
                "(-1002, 'system:missing-key', '${ADMIN_SOURCE.sqlLiteral()}', 'SYSTEM')",
        )
        assertRejected(ds, "INSERT INTO policy (name, cedar_src, origin) VALUES ('system:user-name', '${ADMIN_SOURCE.sqlLiteral()}', 'USER')")
        assertRejected(
            ds,
            "INSERT INTO policy (id, system_key, name, cedar_src, origin) VALUES " +
                "(-1003, 'test.bad-system-name', 'bad-system-name', '${ADMIN_SOURCE.sqlLiteral()}', 'SYSTEM')",
        )
        assertRejected(
            ds,
            "INSERT INTO policy (id, system_key, name, cedar_src, origin) VALUES " +
                "(-1004, 'bootstrap.pm-admin', 'system:duplicate-key', '${ADMIN_SOURCE.sqlLiteral()}', 'SYSTEM')",
        )
    }

    @Test
    fun `explicit negative ids do not disturb the user sequence and a system upsert preserves disabled`() {
        val ds = fullyMigrated("pm_policy_origin_upsert")
        val store = CedarPolicyStore(ds)
        store.setEnabled(-1, enabled = false, updatedBy = "operator@example.com")
        val updatedSource =
            "permit(principal in Role::\"system:admin\", action == Action::\"admin.policies\", resource);"

        ds.connection.use { c ->
            c.prepareStatement(
                """INSERT INTO policy
                       (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at)
                   VALUES
                       (-1, 'bootstrap.pm-admin', 'system:admin-v2', ?, true, 'SYSTEM', 'migration:test', now())
                   ON CONFLICT (id) DO UPDATE SET
                       name = EXCLUDED.name,
                       cedar_src = EXCLUDED.cedar_src,
                       origin = 'SYSTEM',
                       updated_by = EXCLUDED.updated_by,
                       updated_at = now()
                   WHERE policy.cedar_src IS DISTINCT FROM EXCLUDED.cedar_src
                      OR policy.name IS DISTINCT FROM EXCLUDED.name""",
            ).use { ps ->
                ps.setString(1, updatedSource)
                ps.executeUpdate()
            }
        }

        val system = store.get(-1)!!
        assertEquals("bootstrap.pm-admin", system.systemKey)
        assertEquals("system:admin-v2", system.name)
        assertEquals(updatedSource, system.cedarSrc)
        assertFalse(system.enabled, "enabled must be absent from a system-policy upgrade UPDATE list")

        val user = store.create(
            CedarPolicyInput("sequence-user", ADMIN_SOURCE),
            updatedBy = "operator@example.com",
        )
        assertTrue(user.id > 0, "explicit negative system ids must not advance or reset the BIGSERIAL sequence")
        assertEquals("USER", user.origin)
        assertNull(user.systemKey)
    }

    private fun fullyMigrated(prefix: String): DataSource {
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase(prefix))
        Flyway.configure().dataSource(ds).load().migrate()
        return ds
    }

    private fun assertRejected(ds: DataSource, sql: String) {
        assertFailsWith<SQLException> {
            ds.connection.use { c -> c.createStatement().use { it.executeUpdate(sql) } }
        }
    }

    private fun String.sqlLiteral(): String = replace("'", "''")

    private companion object {
        val ADMIN_SOURCE =
            """
            permit (
              principal in Role::"system:admin",
              action in
                [Action::"admin.datasources",
                 Action::"admin.policies",
                 Action::"admin.identity"],
              resource
            );
            """.trimIndent() + "\n"
        val NO_SELF_APPROVAL_SOURCE =
            """
            forbid (
              principal,
              action == Action::"task.approve",
              resource
            )
            when { principal == resource.requester }
            unless
            {
              context has channel &&
              (context.channel == "editor" || context.channel == "wire")
            };
            """.trimIndent() + "\n"
        val APPROVER_SOURCE =
            """
            permit (
              principal in Role::"system:admin",
              action in
                [Action::"task.approve",
                 Action::"task.read",
                 Action::"grant.revoke",
                 Action::"task.request",
                 Action::"task.cancel",
                 Action::"task.delete"],
              resource
            );
            """.trimIndent() + "\n"
    }
}
