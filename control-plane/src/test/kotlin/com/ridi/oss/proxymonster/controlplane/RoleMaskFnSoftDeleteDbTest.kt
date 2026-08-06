package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Soft delete for roles and mask functions (V14). The security-critical property: a soft-deleted role
 * must drop out of EVERY role-resolution source (direct assignment, group membership, JIT grant) and out
 * of the frozen `execute_as` snapshot, so it grants nothing — while the referencing rows survive and the
 * name is freed for reuse. A soft-deleted mask function falls back to FIXED masking (the column stays
 * masked). Mirrors the make-inert approach: a delete just stops the entity working everywhere.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RoleMaskFnSoftDeleteDbTest {
    private lateinit var ds: DataSource
    private lateinit var policyStore: PolicyStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var accessStore: AccessStore
    private lateinit var tokenStore: TokenStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var roleResolver: RoleResolver
    private lateinit var datasourceStore: DatasourceStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_role_maskfn_soft_delete"))
        Flyway.configure().dataSource(ds).load().migrate()
        policyStore = PolicyStore(ds)
        userGroupStore = UserGroupStore(ds)
        accessStore = AccessStore(ds)
        tokenStore = TokenStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        roleResolver = RoleResolver(ds, userGroupStore, accessStore)
        datasourceStore = DatasourceStore(ds)
    }

    @AfterAll
    fun close() {
        (ds as? AutoCloseable)?.close()
    }

    @Test
    fun `a soft-deleted role drops out of every resolution source`() {
        val principal = "role-softdel-${System.nanoTime()}@example.com"
        val direct = policyStore.createRole(RoleInput("direct-${System.nanoTime()}"))
        val viaGroup = policyStore.createRole(RoleInput("group-${System.nanoTime()}"))
        val viaGrant = policyStore.createRole(RoleInput("grant-${System.nanoTime()}"))

        policyStore.createAssignment(RoleAssignmentInput(principal, direct.id))
        val user = userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
        val group = userGroupStore.createGroup(AppGroupInput(name = "grp-${System.nanoTime()}"))
        userGroupStore.addMember(group.id, user.id)
        userGroupStore.addGroupRole(group.id, viaGroup.id)
        val request = accessStore.createRequest(principal, AccessRequestInput(roleId = viaGrant.id))
        accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com")

        assertEquals(setOf(direct.name, viaGroup.name, viaGrant.name), roleResolver.resolve(principal), "sanity")

        // Soft-delete each role: it must vanish from resolve() while its referencing rows survive.
        assertTrue(policyStore.deleteRole(direct.id))
        assertTrue(policyStore.deleteRole(viaGroup.id))
        assertTrue(policyStore.deleteRole(viaGrant.id))

        assertEquals(emptySet(), roleResolver.resolve(principal), "a soft-deleted role grants nothing")
        assertNull(policyStore.getRole(direct.id), "and is invisible to live reads")
        assertEquals(0, policyStore.listRoles().count { it.id == direct.id })
        // History survives: the assignment / grant rows still reference the tombstoned role.
        assertEquals(1, rawCount("SELECT count(*) FROM principal_role WHERE role_id = ${direct.id}"))
        assertEquals(1, rawCount("SELECT count(*) FROM access_grant WHERE role_id = ${viaGrant.id}"))
        assertEquals(1, rawCount("SELECT count(*) FROM app_role WHERE id = ${direct.id} AND deleted_at IS NOT NULL"))
    }

    @Test
    fun `a soft-deleted role name is free for a new role, and the new role resolves`() {
        val principal = "role-reuse-${System.nanoTime()}@example.com"
        val name = "reused-role-${System.nanoTime()}"
        val first = policyStore.createRole(RoleInput(name))
        assertTrue(policyStore.deleteRole(first.id))

        val second = policyStore.createRole(RoleInput(name))
        assertNotEquals(first.id, second.id)
        assertEquals(second.id, policyStore.getRoleByName(name)?.id, "the live name resolves to the new role")

        policyStore.createAssignment(RoleAssignmentInput(principal, second.id))
        assertEquals(setOf(name), roleResolver.resolve(principal), "the reused name grants via the new role")
    }

    @Test
    fun `liveRoleNames drops a role soft-deleted after an execute-as snapshot`() {
        val live = policyStore.createRole(RoleInput("exec-live-${System.nanoTime()}"))
        val gone = policyStore.createRole(RoleInput("exec-gone-${System.nanoTime()}"))
        assertTrue(policyStore.deleteRole(gone.id))

        assertEquals(
            setOf(live.name),
            policyStore.liveRoleNames(listOf(live.name, gone.name)),
            "a stored execute_as re-authorizes only under roles that still exist",
        )
    }

    @Test
    fun `a soft-deleted mask function falls back and its name is reusable`() {
        val datasource = datasourceStore.create(DatasourceInput("maskfn-ds-${System.nanoTime()}", "mysql"))
        val name = "email-mask-${System.nanoTime()}"
        val fn = policyStore.createMaskFn(MaskFnInput(name, "LAST_N"))
        datasourceStore.upsertClassification(
            datasource.id,
            ClassificationInput("app", "users", "email", listOf("pii"), fn.id),
        )
        assertEquals(name, datasourceStore.classificationsFor(datasource.id).values.single().maskFnName, "sanity")

        assertTrue(policyStore.deleteMaskFn(fn.id))

        assertNull(
            datasourceStore.classificationsFor(datasource.id).values.single().maskFnName,
            "a column keeps its classification but the deleted fn resolves to null -> FIXED masking (still masked)",
        )
        assertEquals(0, policyStore.listMaskFns().count { it.id == fn.id }, "and is gone from the live list")

        val reused = policyStore.createMaskFn(MaskFnInput(name, "FIXED"))
        assertNotEquals(fn.id, reused.id, "the freed name is reusable")
    }

    private fun rawCount(sql: String): Int = ds.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) } }
    }
}
