package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Soft delete for Cedar policies (V16). The inverted-risk case: deleting a policy — permit OR forbid — must
 * remove it from the evaluated policy set. For a forbid that means it stops denying (deleting a deny is
 * intentional and matches the old hard delete); the concern is only that the engine's cached PolicySet
 * actually rebuilds without it. The name is freed for reuse.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicySoftDeleteDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: CedarPolicyStore
    private lateinit var engine: CedarEngine
    private lateinit var authz: Authz
    private val roles = mutableMapOf<String, Set<String>>()

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_policy_soft_delete"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = CedarPolicyStore(ds)
        engine = CedarEngine(store)
        authz = Authz(engine, store, RoleSource { principal -> roles[principal] ?: emptySet() })
    }

    @AfterAll
    fun close() {
        (ds as? AutoCloseable)?.close()
    }

    @Test
    fun `soft-deleting a forbid removes it from the evaluated policy set`() {
        val principal = "policy-softdel-${System.nanoTime()}"
        val role = "policy-role-${System.nanoTime()}"
        roles[principal] = setOf(role)
        val n = System.nanoTime()
        store.create(
            CedarPolicyInput(
                name = "permit-$n",
                cedarSrc = """permit(principal in Role::"$role", action == Action::"admin.datasources", resource);""",
            ),
            updatedBy = null,
        )
        val forbid = store.create(
            CedarPolicyInput(
                name = "forbid-$n",
                cedarSrc = """forbid(principal in Role::"$role", action == Action::"admin.datasources", resource);""",
            ),
            updatedBy = null,
        )
        assertIs<AuthzDecision.Deny>(
            authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System),
            "sanity: the forbid overrides the permit",
        )

        assertTrue(store.delete(forbid.id))

        assertEquals(
            AuthzDecision.Allow,
            authz.authorize(principal, AuthzAction.ADMIN_DATASOURCES, AuthzResource.System),
            "a soft-deleted forbid must leave the engine — the surviving permit now decides",
        )
        assertNull(store.get(forbid.id), "and is invisible to live reads")
        assertEquals(0, store.list().count { it.id == forbid.id })
        assertEquals(1, rawCount("SELECT count(*) FROM policy WHERE id = ${forbid.id} AND deleted_at IS NOT NULL"), "row survives")
    }

    @Test
    fun `a soft-deleted policy name is free for a new policy`() {
        val name = "reused-policy-${System.nanoTime()}"
        val src = """permit(principal in Role::"reuse-nobody-$name", action == Action::"admin.datasources", resource);"""
        val first = store.create(CedarPolicyInput(name = name, cedarSrc = src), updatedBy = null)
        assertTrue(store.delete(first.id))

        val second = store.create(CedarPolicyInput(name = name, cedarSrc = src), updatedBy = null)
        assertNotEquals(first.id, second.id)
        assertEquals(second.id, store.getByName(name)?.id, "the live name resolves to the new policy")
    }

    private fun rawCount(sql: String): Int = ds.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) } }
    }
}
