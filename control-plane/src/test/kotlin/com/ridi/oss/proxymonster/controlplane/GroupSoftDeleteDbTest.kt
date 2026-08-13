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
 * Soft delete for groups (V15). Security-critical: a soft-deleted group must grant NO roles — its
 * lingering group_member / group_role rows must stop resolving — and be invisible to every live read.
 * Its name and SCIM external_id are freed for reuse.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GroupSoftDeleteDbTest {
    private lateinit var ds: DataSource
    private lateinit var policyStore: PolicyStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var accessStore: AccessStore
    private lateinit var tokenStore: TokenStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var roleResolver: RoleResolver

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_group_soft_delete"))
        Flyway.configure().dataSource(ds).load().migrate()
        policyStore = PolicyStore(ds)
        userGroupStore = UserGroupStore(ds)
        accessStore = AccessStore(ds)
        tokenStore = TokenStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        roleResolver = RoleResolver(ds, userGroupStore, accessStore)
    }

    @AfterAll
    fun close() {
        (ds as? AutoCloseable)?.close()
    }

    /** Put [principal] in a fresh group that grants a fresh role; returns (group, roleName). */
    private fun groupGrantingRole(principal: String): Pair<AppGroup, String> {
        val role = policyStore.createRole(RoleInput("grp-role-${System.nanoTime()}"))
        val user = userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
        val group = userGroupStore.createGroup(AppGroupInput(name = "grp-${System.nanoTime()}"))
        userGroupStore.addMember(group.id, user.id)
        userGroupStore.addGroupRole(group.id, role.id)
        return group to role.name
    }

    @Test
    fun `a soft-deleted group grants no roles and keeps its membership rows`() {
        val principal = "grp-softdel-${System.nanoTime()}@example.com"
        val (group, roleName) = groupGrantingRole(principal)
        assertEquals(setOf(roleName), roleResolver.resolve(principal), "sanity: the group grants its role")

        assertTrue(userGroupStore.deleteGroup(group.id))

        assertEquals(emptySet(), roleResolver.resolve(principal), "a soft-deleted group grants nothing")
        assertNull(userGroupStore.getGroup(group.id), "and is invisible to reads")
        assertEquals(0, userGroupStore.listGroups().count { it.id == group.id })
        assertEquals(emptyList(), userGroupStore.getUserByPrincipal(principal)!!.groups, "not embedded on the user")
        // History survives: the membership + group-role rows still reference the tombstoned group.
        assertEquals(1, rawCount("SELECT count(*) FROM group_member WHERE group_id = ${group.id}"))
        assertEquals(1, rawCount("SELECT count(*) FROM group_role WHERE group_id = ${group.id}"))
    }

    @Test
    fun `hasActiveAssignee stops counting a role granted only through a soft-deleted group`() {
        val principal = "grp-assignee-${System.nanoTime()}@example.com"
        val (group, roleName) = groupGrantingRole(principal)
        assertTrue(roleResolver.hasActiveAssignee(roleName), "sanity: a live group with an active member is an assignee")

        assertTrue(userGroupStore.deleteGroup(group.id))

        assertEquals(false, roleResolver.hasActiveAssignee(roleName), "a soft-deleted group is no longer an active assignee")
    }

    @Test
    fun `a soft-deleted group's name is free for a new group that resolves`() {
        val principal = "grp-reuse-${System.nanoTime()}@example.com"
        val name = "reused-grp-${System.nanoTime()}"
        val first = userGroupStore.createGroup(AppGroupInput(name = name))
        assertTrue(userGroupStore.deleteGroup(first.id))

        val second = userGroupStore.createGroup(AppGroupInput(name = name))
        assertNotEquals(first.id, second.id)
        assertEquals(second.id, userGroupStore.getGroupByName(name)?.id, "the live name resolves to the new group")

        val role = policyStore.createRole(RoleInput("reuse-role-${System.nanoTime()}"))
        val user = userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)
        userGroupStore.addMember(second.id, user.id)
        userGroupStore.addGroupRole(second.id, role.id)
        assertEquals(setOf(role.name), roleResolver.resolve(principal), "the reused-name group grants via the new group")
    }

    private fun rawCount(sql: String): Int = ds.connection.use { c ->
        c.prepareStatement(sql).use { ps -> ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) } }
    }
}
