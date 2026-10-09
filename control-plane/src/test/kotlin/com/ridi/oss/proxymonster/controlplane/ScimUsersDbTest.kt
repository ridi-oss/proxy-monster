package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.seedOidcUser
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.sql.SQLException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed tests for [UserGroupStore]'s SCIM surface (docs/auth-model.md "SCIM 2.0 provisioning"):
 * `upsertScimUser` provisions/updates `app_user(source='SCIM', external_id=...)`, is idempotent on
 * repeated pushes for the same `externalId`, reconciles a JIT-provisioned `source='OIDC'` row instead
 * of duplicating it, and `setUserActive`/`findUserByExternalId` round-trip through the same table
 * everything else (RoleResolver, group_role, …) already reads.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ScimUsersDbTest {
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var tokenStore: TokenStore
    private lateinit var accessStore: AccessStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var policyStore: PolicyStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_scim_users"))
        Flyway.configure().dataSource(ds).load().migrate()
        userGroupStore = UserGroupStore(ds)
        tokenStore = TokenStore(ds)
        accessStore = AccessStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        policyStore = PolicyStore(ds)
    }

    @Test
    fun `upsertScimUser provisions a source=SCIM row keyed on externalId`() {
        val user = userGroupStore.upsertScimUser(
            externalId = "okta-100",
            principal = "scim-user-1@example.com",
            email = "scim-user-1@example.com",
            displayName = "SCIM User One",
            active = true,
        )
        assertEquals("SCIM", user.source)
        assertEquals("okta-100", user.externalId)
        assertEquals("scim-user-1@example.com", user.principal)
        assertEquals("SCIM User One", user.displayName)
        assertTrue(user.active)
    }

    @Test
    fun `upsertScimUser is idempotent on repeated pushes for the same externalId`() {
        val first = userGroupStore.upsertScimUser(
            externalId = "okta-101",
            principal = "scim-user-2@example.com",
            email = "scim-user-2@example.com",
            displayName = "Before Update",
            active = true,
        )
        val second = userGroupStore.upsertScimUser(
            externalId = "okta-101",
            principal = "scim-user-2@example.com",
            email = "scim-user-2@example.com",
            displayName = "After Update",
            active = true,
        )
        assertEquals(first.id, second.id, "same externalId must update the same row, not create a duplicate")
        assertEquals("After Update", userGroupStore.getUser(first.id)?.displayName)
    }

    @Test
    fun `upsertScimUser active=false deactivates the row`() {
        val user = userGroupStore.upsertScimUser(
            externalId = "okta-102",
            principal = "scim-user-3@example.com",
            email = "scim-user-3@example.com",
            displayName = null,
            active = false,
        )
        assertEquals(false, user.active)
    }

    @Test
    fun `upsertScimUser reconciles an existing OIDC-provisioned row instead of duplicating it`() {
        // JIT-on-login provisions this principal first (source=OIDC), matching docs/auth-model.md's
        // "SCIM vs JIT" decision: "a JIT (source=OIDC) user is reconciled to SCIM when the IdP later
        // manages it via SCIM."
        val jit = userGroupStore.seedOidcUser("reconcile-me@example.com", "reconcile-me@example.com")
        assertEquals("OIDC", jit.source)
        assertNull(jit.externalId)

        val reconciled = userGroupStore.upsertScimUser(
            externalId = "okta-200",
            principal = "reconcile-me@example.com",
            email = "reconcile-me@example.com",
            displayName = "Reconciled",
            active = true,
        )
        assertEquals(jit.id, reconciled.id, "SCIM must reconcile the existing OIDC row by identity, not create a second one")
        assertEquals("SCIM", reconciled.source)
        assertEquals("okta-200", reconciled.externalId)
        assertEquals(1, userGroupStore.listUsers().count { it.principal == "reconcile-me@example.com" })
    }

    @Test
    fun `upsertScimUser never clobbers a SCIM row's source`() {
        val user = userGroupStore.upsertScimUser(
            externalId = "okta-300",
            principal = "already-scim@example.com",
            email = "already-scim@example.com",
            displayName = "Already SCIM",
            active = true,
        )
        val again = userGroupStore.upsertScimUser(
            externalId = "okta-300",
            principal = "already-scim@example.com",
            email = "already-scim@example.com",
            displayName = "Still SCIM",
            active = true,
        )
        assertEquals(user.id, again.id)
        assertEquals("SCIM", again.source)
    }

    @Test
    fun `findUserByExternalId finds a provisioned user and is null for an unknown id`() {
        val user = userGroupStore.upsertScimUser(
            externalId = "okta-400",
            principal = "findable@example.com",
            email = "findable@example.com",
            displayName = null,
            active = true,
        )
        assertEquals(user.id, userGroupStore.findUserByExternalId("okta-400")?.id)
        assertNull(userGroupStore.findUserByExternalId("no-such-external-id"))
    }

    @Test
    fun `setUserActive toggles active and persists`() {
        val user = userGroupStore.upsertScimUser(
            externalId = "okta-500",
            principal = "deactivate-me@example.com",
            email = "deactivate-me@example.com",
            displayName = null,
            active = true,
        )
        assertTrue(userGroupStore.setUserActive(user.principal, false))
        assertEquals(false, userGroupStore.getUser(user.id)?.active)

        assertTrue(userGroupStore.setUserActive(user.principal, true))
        assertEquals(true, userGroupStore.getUser(user.id)?.active)
    }

    @Test
    fun `distinct externalIds never collide into the same row`() {
        val a = userGroupStore.upsertScimUser(
            externalId = "okta-600a", principal = "distinct-a@example.com", email = "distinct-a@example.com", displayName = null, active = true,
        )
        val b = userGroupStore.upsertScimUser(
            externalId = "okta-600b", principal = "distinct-b@example.com", email = "distinct-b@example.com", displayName = null, active = true,
        )
        assertNotEquals(a.id, b.id)
        assertNotNull(userGroupStore.findUserByExternalId("okta-600a"))
        assertNotNull(userGroupStore.findUserByExternalId("okta-600b"))
    }

    @Test
    fun `replaceScimUserById mutates the row AT this id — never a different row a body-key match would have resolved`() {
        val target = userGroupStore.upsertScimUser(
            externalId = "okta-put-target", principal = "put-target@example.com", email = "put-target@example.com", displayName = "Target", active = true,
        )
        // A second, unrelated row sharing the EMAIL the PUT body will (accidentally or maliciously)
        // reuse. A PUT that resolved existingId by externalId -> email ->
        // principal would let a body whose email matched a DIFFERENT row silently mutate THAT row
        // instead. (externalId itself is deliberately kept distinct — externalId is a unique key —
        // so a REAL externalId collision is covered by the dedicated test below.)
        val other = userGroupStore.upsertScimUser(
            externalId = "okta-put-other", principal = "put-other@example.com", email = "shared-email@example.com", displayName = "Other", active = true,
        )

        val replaced = userGroupStore.replaceScimUserById(
            id = target.id,
            principal = "put-target-renamed@example.com",
            email = "shared-email@example.com", // collides with `other`'s email
            displayName = "Target Renamed",
            externalId = "okta-put-target", // target's OWN externalId, unrelated to `other`'s
            active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )

        assertNotNull(replaced)
        assertEquals(target.id, replaced!!.id, "PUT must mutate the row at THIS id")
        assertEquals("put-target-renamed@example.com", replaced.principal)
        assertEquals("Target Renamed", replaced.displayName)

        // `other` must be completely untouched — a stray email collision in the PUT body must never
        // leak into mutating a different resource.
        val otherAfter = userGroupStore.getUser(other.id)
        assertEquals("put-other@example.com", otherAfter?.principal, "the OTHER row must be untouched by a PUT addressed at `target`'s id")
        assertEquals("Other", otherAfter?.displayName)
    }

    @Test
    fun `replaceScimUserById rejects an externalId that already belongs to a DIFFERENT row`() {
        userGroupStore.upsertScimUser(externalId = "okta-uniq-a", principal = "uniq-a@example.com", email = null, displayName = null, active = true)
        val b = userGroupStore.upsertScimUser(externalId = "okta-uniq-b", principal = "uniq-b@example.com", email = null, displayName = null, active = true)

        assertFailsWith<SQLException> {
            userGroupStore.replaceScimUserById(
                id = b.id, principal = "uniq-b@example.com", email = null, displayName = null,
                externalId = "okta-uniq-a", // already owned by a DIFFERENT row
                active = true, tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
            )
        }
    }

    @Test
    fun `a retired principal's direct principal_role grant does not silently transfer to whoever reuses the string`() {
        val role = policyStore.createRole(RoleInput("role-leak-test-role"))
        val extId = "okta-role-leak"
        userGroupStore.upsertScimUser(externalId = extId, principal = "role-leak-a@example.com", email = null, displayName = null, active = true)
        // A direct grant, keyed purely on the principal STRING (independent of app_user entirely).
        policyStore.createAssignment(RoleAssignmentInput("role-leak-a@example.com", role.id))
        assertTrue(policyStore.listAssignments(null, null).any { it.principal == "role-leak-a@example.com" && it.roleId == role.id })

        // Rename away — tombstones `role-leak-a@example.com`. The stale grant is harmless while the
        // string stays tombstoned (RoleResolver short-circuits a deactivated principal to zero
        // roles), but must NOT survive to reattach once the string is handed to someone else.
        userGroupStore.upsertScimUser(
            externalId = extId, principal = "role-leak-b@example.com", email = null, displayName = null, active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertTrue(userGroupStore.isDeactivated("role-leak-a@example.com"))

        // A DIFFERENT identity now claims the retired `role-leak-a@example.com` string.
        userGroupStore.upsertScimUser(
            externalId = "okta-role-leak-2", principal = "role-leak-a@example.com", email = null, displayName = null, active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertFalse(userGroupStore.isDeactivated("role-leak-a@example.com"), "sanity: the string is active again under its new owner")

        assertTrue(
            policyStore.listAssignments(null, null).none { it.principal == "role-leak-a@example.com" },
            "the retired identity's direct role grant must not silently transfer to the new claimant of the string",
        )
    }

    @Test
    fun `replaceScimUserById is null (404) for a nonexistent id`() {
        val missing = userGroupStore.replaceScimUserById(
            id = 999_999_999L, principal = "nobody@example.com", email = null, displayName = null, externalId = "okta-missing", active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertNull(missing)
    }

    @Test
    fun `a retired (tombstoned) principal can be reused by a later rename — no permanent unique-constraint block`() {
        // Rename away@example.com -> elsewhere@example.com — this tombstones `away@example.com`.
        val user = userGroupStore.upsertScimUser(
            externalId = "okta-tombstone-reuse", principal = "away@example.com", email = null, displayName = null, active = true,
        )
        userGroupStore.upsertScimUser(
            externalId = "okta-tombstone-reuse", principal = "elsewhere@example.com", email = null, displayName = null, active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertTrue(userGroupStore.isDeactivated("away@example.com"), "sanity: the retired principal is tombstoned")

        // A DIFFERENT identity is now renamed onto the retired `away@example.com` string — before the
        // fix, this 500s on app_user's UNIQUE(principal) constraint against the tombstone row.
        val reused = userGroupStore.upsertScimUser(
            externalId = "okta-tombstone-reuse-2", principal = "away@example.com", email = null, displayName = null, active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertEquals("away@example.com", reused.principal)
        assertEquals("SCIM", reused.source)
        assertFalse(userGroupStore.isDeactivated("away@example.com"), "the reused principal must be active under its new owner")
        assertNotEquals(user.id, reused.id, "the reuse must be a genuinely distinct identity (different externalId), not a merge into the old row")
    }

    @Test
    fun `replaceScimUserById can rename BACK onto its own just-retired principal string`() {
        val extId = "okta-put-rename-back"
        val user = userGroupStore.upsertScimUser(externalId = extId, principal = "back-a@example.com", email = null, displayName = null, active = true)
        // Rename a -> b (tombstones a), then PUT it back to a — must not collide with the tombstone
        // it just created for itself.
        userGroupStore.replaceScimUserById(
            id = user.id, principal = "back-b@example.com", email = null, displayName = null, externalId = extId, active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        val backToA = userGroupStore.replaceScimUserById(
            id = user.id, principal = "back-a@example.com", email = null, displayName = null, externalId = extId, active = true,
            tokenStore = tokenStore, accessStore = accessStore, daemonSessionStore = daemonSessionStore,
        )
        assertEquals("back-a@example.com", backToA?.principal)
        assertFalse(userGroupStore.isDeactivated("back-a@example.com"))
    }
}
