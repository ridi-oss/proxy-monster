package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicy
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.InvalidCedarPolicyException
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import javax.sql.DataSource

/** [CedarPolicyStore] against a real, fully Flyway-migrated Postgres: CRUD, V20 system-policy
 *  provenance, the shipped policy seeds, write-time schema validation (valid accepted / invalid
 *  rejected with errors), and enable/disable round-tripping into [CedarPolicyStore.enabledSources]. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CedarPolicyStoreTest {
    private lateinit var ds: DataSource
    private lateinit var store: CedarPolicyStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_cedar_policy"))
        store = CedarPolicyStore(ds)
    }

    @Test
    fun `V20 system seeds and the V32-converted audit seeds are enabled and validate as one Cedar engine`() {
        // Scope the assertions to migration seed rows — other tests in this PER_CLASS suite share the DB
        // and leave rows behind, and JUnit's method order is not the declaration order.
        val expectedSystemSeeds = mapOf(
            -1L to ("system:admin" to "bootstrap.pm-admin"),
            -2L to ("system:no-self-approval" to "workflow.no-self-approval"),
            -3L to ("system:admin-approver" to "workflow.pm-admin-approve"),
        )
        val systemSeeds = store.list().filter { it.id in expectedSystemSeeds.keys }
        assertEquals(expectedSystemSeeds.keys, systemSeeds.map { it.id }.toSet())
        for (seed in systemSeeds) {
            val (name, key) = expectedSystemSeeds.getValue(seed.id)
            assertEquals(name, seed.name)
            assertEquals("SYSTEM", seed.origin)
            assertEquals(key, seed.systemKey)
            assertTrue(seed.enabled, "system seed ${seed.id} must be enabled on a clean database")
        }

        // Two SYSTEM audit rows ship at -4/-5, both enabled: -4 is every principal's own-record read,
        // -5 grants the whole log to system:admin.
        val auditSeeds = store.list().filter { it.systemKey in setOf("audit.read-own", "audit.read-admin") }
        assertEquals(setOf(-4L, -5L), auditSeeds.map { it.id }.toSet(), "V32 ships the two audit-read SYSTEM rows")
        assertEquals(
            setOf("system:audit-read-own", "system:audit-read-admin"),
            auditSeeds.map { it.name }.toSet(),
        )
        assertTrue(auditSeeds.all { it.enabled && it.origin == "SYSTEM" }, "the audit seeds must be enabled SYSTEM rows")

        val assumeSeeds = store.list().filter { it.id in setOf(-21L, -22L) }
        assertEquals(setOf(-21L, -22L), assumeSeeds.map { it.id }.toSet())
        assertEquals(setOf("task.assume-parties", "task.assume-auditor"), assumeSeeds.mapNotNull { it.systemKey }.toSet())
        assertTrue(assumeSeeds.all { it.enabled && it.origin == "SYSTEM" })
        ds.connection.use { c ->
            c.createStatement().use { st ->
                st.executeQuery("SELECT r.id, count(pr.id) FROM app_role r LEFT JOIN principal_role pr ON pr.role_id = r.id WHERE r.name = 'system:auditor' GROUP BY r.id").use { rs ->
                    assertTrue(rs.next(), "V40 must seed system:auditor")
                    assertEquals(0, rs.getInt(2), "system:auditor starts with no assignments")
                }
            }
        }

        val seeds = systemSeeds + auditSeeds + assumeSeeds
        val enabledIds = store.enabledSources().map { it.first }.toSet()
        assertTrue(enabledIds.containsAll(seeds.map { it.id }), "enabled seed rows must appear in enabledSources()")
        CedarEngine(store)
    }

    @Test
    fun `a schema-valid policy is created`() {
        val created = store.create(
            CedarPolicyInput(
                name = "test-valid-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"system:admin", action == Action::"admin.datasources", resource);""",
            ),
            updatedBy = "tester",
        )
        assertNotNull(store.get(created.id))
        assertTrue(created.id > 0)
        assertEquals("USER", created.origin)
        assertNull(created.systemKey)
        assertEquals("tester", created.updatedBy)
        assertTrue(created.enabled)
        assertTrue(store.enabledSources().any { it.first == created.id })
    }

    @Test
    fun `an unparseable policy is rejected with errors, not written`() {
        val before = store.list().size
        val ex = assertFailsWith<InvalidCedarPolicyException> {
            store.create(CedarPolicyInput(name = "test-garbage-${System.nanoTime()}", cedarSrc = "this is not cedar at all"), updatedBy = null)
        }
        assertTrue(ex.errors.isNotEmpty())
        assertEquals(before, store.list().size, "a rejected create must not persist a row")
    }

    @Test
    fun `a policy referencing an unknown action is rejected — schema validation, not just syntax`() {
        val ex = assertFailsWith<InvalidCedarPolicyException> {
            store.create(
                CedarPolicyInput(
                    name = "test-unknown-action-${System.nanoTime()}",
                    cedarSrc = """permit(principal in Role::"system:admin", action == Action::"totally.unknown", resource);""",
                ),
                updatedBy = null,
            )
        }
        assertTrue(ex.errors.isNotEmpty())
    }

    @Test
    fun `update rejects invalid cedar and leaves the existing row untouched`() {
        val created = store.create(
            CedarPolicyInput(
                name = "test-update-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"system:admin", action == Action::"admin.identity", resource);""",
            ),
            updatedBy = "tester",
        )
        assertFailsWith<InvalidCedarPolicyException> {
            store.update(created.id, CedarPolicyInput(name = created.name, cedarSrc = "not cedar"), updatedBy = "tester2")
        }
        val stillThere = store.get(created.id)
        assertNotNull(stillThere)
        assertEquals(created.cedarSrc, stillThere.cedarSrc)
        assertEquals("tester", stillThere.updatedBy)
    }

    @Test
    fun `enable and disable round-trip into enabledSources`() {
        val created: CedarPolicy = store.create(
            CedarPolicyInput(
                name = "test-toggle-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"system:admin", action == Action::"admin.policies", resource);""",
                enabled = true,
            ),
            updatedBy = null,
        )
        assertTrue(store.enabledSources().any { it.first == created.id })

        val disabled = store.setEnabled(created.id, enabled = false, updatedBy = "tester")
        assertNotNull(disabled)
        assertFalse(disabled.enabled)
        assertFalse(store.enabledSources().any { it.first == created.id })

        val reenabled = store.setEnabled(created.id, enabled = true, updatedBy = "tester")
        assertNotNull(reenabled)
        assertTrue(reenabled.enabled)
        assertTrue(store.enabledSources().any { it.first == created.id })
    }

    @Test
    fun `enabling a stored-malformed row is rejected and leaves it disabled (validated on load)`() {
        // create() validates, so a malformed row can only arrive out-of-band (manual seed / import /
        // schema drift). Simulate that with a raw insert of an invalid, disabled row, then prove the
        // API refuses to make it live — otherwise CedarEngine would load it and error-Deny every decision.
        val id = ds.connection.use { c ->
            c.prepareStatement("INSERT INTO policy (name, cedar_src, enabled) VALUES (?, ?, false) RETURNING id").use { ps ->
                ps.setString(1, "test-malformed-${System.nanoTime()}"); ps.setString(2, "this is not cedar")
                ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
            }
        }
        val ex = assertFailsWith<InvalidCedarPolicyException> { store.setEnabled(id, enabled = true, updatedBy = "tester") }
        assertTrue(ex.errors.isNotEmpty())
        assertFalse(store.get(id)!!.enabled, "a rejected enable must leave the row disabled")
        assertFalse(store.enabledSources().any { it.first == id }, "a malformed row must never reach enabledSources()")
    }

    @Test
    fun `delete removes the row`() {
        val created = store.create(
            CedarPolicyInput(
                name = "test-delete-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"system:admin", action == Action::"admin.datasources", resource);""",
            ),
            updatedBy = null,
        )
        assertTrue(store.delete(created.id))
        assertNull(store.get(created.id))
        assertFalse(store.delete(created.id), "deleting an already-deleted row returns false")
    }

    @Test
    fun `stateVersion monotonically bumps on create, setEnabled, and delete — CedarEngine's cache-invalidation signal`() {
        val v0 = store.stateVersion()
        val created = store.create(
            CedarPolicyInput(
                name = "test-version-${System.nanoTime()}",
                cedarSrc = """permit(principal in Role::"system:admin", action == Action::"admin.identity", resource);""",
            ),
            updatedBy = null,
        )
        val v1 = store.stateVersion()
        assertTrue(v1 > v0, "create must bump stateVersion")

        store.setEnabled(created.id, enabled = false, updatedBy = null)
        val v2 = store.stateVersion()
        assertTrue(v2 > v1, "setEnabled must bump stateVersion")

        store.delete(created.id)
        val v3 = store.stateVersion()
        assertTrue(v3 > v2, "delete must bump stateVersion")
    }
}
