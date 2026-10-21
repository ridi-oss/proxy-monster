package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed tests for [UserGroupStore]'s SCIM group surface (docs/auth-model.md "SCIM 2.0
 * provisioning"): `upsertScimGroup` provisions/updates `app_group(source='SCIM', external_id=...)`
 * idempotently, `findGroupByExternalId` round-trips, and group membership PATCH reuses the existing
 * `addMember`/`removeMember` (no SCIM-specific membership table — `group_member` is the only
 * one). Role mapping itself (group_role) is untouched by SCIM — the IdP supplies membership only.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ScimGroupsDbTest {
    private lateinit var userGroupStore: UserGroupStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_scim_groups"))
        userGroupStore = UserGroupStore(ds)
    }

    @Test
    fun `upsertScimGroup provisions a source=SCIM group keyed on externalId`() {
        val group = userGroupStore.upsertScimGroup(externalId = "okta-group-100", displayName = "Engineering")
        assertEquals("SCIM", group.source)
        assertEquals("okta-group-100", group.externalId)
        assertEquals("Engineering", group.name)
    }

    @Test
    fun `upsertScimGroup is idempotent on repeated pushes for the same externalId`() {
        val first = userGroupStore.upsertScimGroup(externalId = "okta-group-101", displayName = "Before Rename")
        val second = userGroupStore.upsertScimGroup(externalId = "okta-group-101", displayName = "After Rename")
        assertEquals(first.id, second.id, "same externalId must update the same row, not create a duplicate")
        assertEquals("After Rename", userGroupStore.getGroup(first.id)?.name)
    }

    @Test
    fun `findGroupByExternalId finds a provisioned group and is null for an unknown id`() {
        val group = userGroupStore.upsertScimGroup(externalId = "okta-group-200", displayName = "Findable Group")
        assertEquals(group.id, userGroupStore.findGroupByExternalId("okta-group-200")?.id)
        assertNull(userGroupStore.findGroupByExternalId("no-such-external-id"))
    }

    @Test
    fun `distinct externalIds never collide into the same group row`() {
        val a = userGroupStore.upsertScimGroup(externalId = "okta-group-300a", displayName = "Group A")
        val b = userGroupStore.upsertScimGroup(externalId = "okta-group-300b", displayName = "Group B")
        assertNotEquals(a.id, b.id)
    }

    @Test
    fun `SCIM group membership PATCH reuses addMember-removeMember (group_member)`() {
        val group = userGroupStore.upsertScimGroup(externalId = "okta-group-400", displayName = "Membership Group")
        val userA = userGroupStore.upsertScimUser(
            externalId = "okta-400a", principal = "member-a@example.com", email = "member-a@example.com", displayName = null, active = true,
        )
        val userB = userGroupStore.upsertScimUser(
            externalId = "okta-400b", principal = "member-b@example.com", email = "member-b@example.com", displayName = null, active = true,
        )

        assertTrue(userGroupStore.addMember(group.id, userA.id))
        assertTrue(userGroupStore.addMember(group.id, userB.id))
        assertEquals(setOf(userA.id, userB.id), userGroupStore.listMembers(group.id).map { it.userId }.toSet())

        assertTrue(userGroupStore.removeMember(group.id, userA.id))
        assertEquals(setOf(userB.id), userGroupStore.listMembers(group.id).map { it.userId }.toSet())
    }

    @Test
    fun `a group with roles mapped via group_role is unaffected by SCIM provisioning`() {
        // Role mapping stays CP-local (docs/auth-model.md): SCIM never touches app_role/group_role,
        // only app_group/group_member. Re-provisioning the same group must not disturb its roles.
        val group = userGroupStore.upsertScimGroup(externalId = "okta-group-500", displayName = "Roled Group")
        assertEquals(0, userGroupStore.getGroup(group.id)?.roles?.size)
        val reprovisioned = userGroupStore.upsertScimGroup(externalId = "okta-group-500", displayName = "Roled Group Renamed")
        assertEquals(group.id, reprovisioned.id)
        assertEquals(0, userGroupStore.getGroup(group.id)?.roles?.size)
    }
}
