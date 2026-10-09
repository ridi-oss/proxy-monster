package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed tests for the first-admin bootstrap (docs/backlog.md): the shipped seed
 * (`system:admin` SYSTEM group + `system:admin` role + their `group_role` link) and the system-group
 * immutability predicate.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class BootstrapAdminDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: UserGroupStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_bootstrap_admin"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = UserGroupStore(ds)
    }

    @Test
    fun `the seed installs the system-admin group (SYSTEM), the system-admin role, and their link`() {
        val group = store.listGroups().first { it.name == "system:admin" }
        assertEquals("SYSTEM", group.source)
        assertTrue(store.isSystemGroup(group.id), "system:admin must be a SYSTEM group")
        assertTrue(
            store.listGroupRoles(group.id).any { it.roleName == "system:admin" },
            "system:admin must be linked to the system:admin role",
        )
    }

    @Test
    fun `isSystemGroup distinguishes the seeded system group from a user-created one`() {
        val systemId = store.listGroups().first { it.name == "system:admin" }.id
        assertTrue(store.isSystemGroup(systemId))
        assertFalse(store.isSystemGroup(store.createGroup(AppGroupInput(name = "eng")).id))
        // The SCIM POST upsert guards by name (it matches an existing group by displayName).
        assertTrue(store.isSystemGroupByName("system:admin"), "SCIM upsert must recognize system:admin by name")
        assertFalse(store.isSystemGroupByName("eng"))
    }

    @Test
    fun `upsertScimGroup refuses to mutate the SYSTEM group atomically (by name and by externalId)`() {
        // The system-group guard is INSIDE upsertScimGroup, atomic with the write (resolve
        // → FOR UPDATE source check → mutate the one resolved id, in one tx), so a SCIM POST can neither
        // create nor hijack system:admin regardless of which key resolves it. A route-level pre-check on a
        // separate connection was defeatable by a concurrent PUT re-pointing an external_id between the
        // check and the write; this test asserts the mechanism the fix relies on — the store method itself
        // refuses a SYSTEM target and leaves the row untouched.
        val before = store.listGroups().first { it.name == "system:admin" }

        // By NAME: a POST naming system:admin with any external_id throws and does not flip/stamp the row.
        assertFailsWith<SystemGroupImmutableException> {
            store.upsertScimGroup(externalId = "hijack-ext", displayName = "system:admin")
        }
        store.getGroup(before.id)!!.let {
            assertEquals("SYSTEM", it.source, "a by-name POST must not flip system:admin to SCIM")
            assertNull(it.externalId, "a by-name POST must not stamp an external_id on system:admin")
        }

        // By EXTERNAL_ID: plant an external_id on the system row (the seed leaves it NULL, but the guard must hold
        // regardless), then a POST carrying that external_id with a DIFFERENT name is STILL refused — the
        // exact resolve-by-extId path a route-level guard would race on.
        ds.connection.use { c ->
            c.prepareStatement("UPDATE app_group SET external_id='sys-ext' WHERE id=?").use { it.setLong(1, before.id); it.executeUpdate() }
        }
        try {
            assertFailsWith<SystemGroupImmutableException> {
                store.upsertScimGroup(externalId = "sys-ext", displayName = "a-different-name")
            }
            store.getGroup(before.id)!!.let {
                assertEquals("SYSTEM", it.source, "a by-externalId POST must not flip system:admin to SCIM")
                assertEquals("system:admin", it.name, "a by-externalId POST must not rename system:admin")
            }
        } finally {
            ds.connection.use { c ->
                c.prepareStatement("UPDATE app_group SET external_id=NULL WHERE id=?").use { it.setLong(1, before.id); it.executeUpdate() }
            }
        }

        // A non-system POST still provisions normally (no regression).
        assertEquals("SCIM", store.upsertScimGroup(externalId = "ok-ext", displayName = "ok-group").source)
    }

    @Test
    fun `isSystemRole protects the system-admin role wired into system-admin`() {
        // system:admin (linked to the SYSTEM group) must be immutable, so PUT/DELETE /api/roles
        // can't rename it (breaks the name-based admin policy) or delete it (CASCADE-drops the bootstrap link).
        val policyStore = PolicyStore(ds)
        val pmAdmin = policyStore.listRoles().first { it.name == "system:admin" }
        assertTrue(policyStore.isSystemRole(pmAdmin.id), "system:admin is wired into system:admin — a system role")
        val plain = policyStore.createRole(RoleInput(name = "reporting"))
        assertFalse(policyStore.isSystemRole(plain.id), "a plain role is not protected")
    }

    @Test
    fun `the seeded system-admin group carries only the intended wiring and no members`() {
        // The admin group ships with exactly one role link and zero members: WHO is an admin comes only
        // from the IdP group claim at login, never from a seeded or hand-added membership. It also
        // carries no external_id, which is what keeps the SCIM by-externalId hijack unavailable — a
        // stored external_id could otherwise be replayed on a later POST /Groups to re-match this row.
        //
        // Its own database: the class-scoped one is shared, and a sibling test provisions an admin
        // member into it, so "no members" only holds on an untouched store.
        val fresh = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_bootstrap_seed_shape"))
        Flyway.configure().dataSource(fresh).load().migrate()
        val freshStore = UserGroupStore(fresh)

        val group = freshStore.listGroups().first { it.name == "system:admin" }
        assertNull(group.externalId, "the admin group carries no external_id")
        assertEquals(0, freshStore.listMembers(group.id).size, "membership comes only from the IdP claim")
        assertEquals(
            listOf("system:admin"),
            freshStore.listGroupRoles(group.id).map { it.roleName },
            "the admin group confers the admin role and only that",
        )
    }
}
