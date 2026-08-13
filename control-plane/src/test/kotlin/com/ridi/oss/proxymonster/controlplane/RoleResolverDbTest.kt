package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * DB-backed tests for [RoleResolver] (docs/authz-model.md, Layer 1 — identity, no Cedar).
 *
 * [RoleResolver.resolve] is the real, server-side union of a direct `principal_role` assignment, a
 * group-derived role, and an active JIT grant — fail-closed: a revoked grant drops out and an unknown
 * principal resolves to the empty set (a client-asserted `baseRoles` is never honored).
 * [RoleResolver.listActivePrincipals] projects that same union to "who exists" for notification routing —
 * deduped and sorted, with deprovisioning and grant expiry/revocation dropping a principal.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RoleResolverDbTest {
    private lateinit var policyStore: PolicyStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var accessStore: AccessStore
    private lateinit var tokenStore: TokenStore
    private lateinit var daemonSessionStore: PrincipalSessionStore
    private lateinit var roleResolver: RoleResolver

    private lateinit var directRole: Role
    private lateinit var groupRole: Role
    private lateinit var grantRole: Role

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_role_resolver"))
        Flyway.configure().dataSource(ds).load().migrate()
        policyStore = PolicyStore(ds)
        userGroupStore = UserGroupStore(ds)
        accessStore = AccessStore(ds)
        tokenStore = TokenStore(ds)
        daemonSessionStore = PrincipalSessionStore(ds, null)
        roleResolver = RoleResolver(ds, userGroupStore, accessStore)

        directRole = policyStore.createRole(RoleInput("direct-role"))
        groupRole = policyStore.createRole(RoleInput("group-role"))
        grantRole = policyStore.createRole(RoleInput("grant-role"))

        // direct: a principal_role assignment.
        policyStore.createAssignment(RoleAssignmentInput(PRINCIPAL, directRole.id))

        // group: app_user + group_member + group_role.
        val user = userGroupStore.createUser(AppUserInput(principal = PRINCIPAL), tokenStore, accessStore, daemonSessionStore)
        val group = userGroupStore.createGroup(AppGroupInput(name = "resolve-roles-group"))
        userGroupStore.addMember(group.id, user.id)
        userGroupStore.addGroupRole(group.id, groupRole.id)

        // JIT: an approved access_grant.
        val request = accessStore.createRequest(PRINCIPAL, AccessRequestInput(roleId = grantRole.id))
        accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com")
    }

    // ---- resolve: the effective role set ------------------------------------------------------

    @Test
    fun `resolve unions direct, group, and JIT grant roles`() {
        assertEquals(setOf("direct-role", "group-role", "grant-role"), roleResolver.resolve(PRINCIPAL))
    }

    @Test
    fun `a revoked grant is excluded from resolve (activeOnly)`() {
        val principal = "revoked-grant@example.com"
        policyStore.createAssignment(RoleAssignmentInput(principal, directRole.id))
        val request = accessStore.createRequest(principal, AccessRequestInput(roleId = grantRole.id))
        accessStore.approve(request.id, durationSec = 3600, decidedBy = "approver@example.com")
        val grant = accessStore.listGrants(principal, activeOnly = true).first()
        assertTrue(accessStore.revoke(grant.id))

        assertEquals(setOf("direct-role"), roleResolver.resolve(principal), "a revoked grant must not contribute a role")
    }

    @Test
    fun `an expired grant is excluded from resolve (activeOnly)`() {
        val principal = "expired-grant@example.com"
        policyStore.createAssignment(RoleAssignmentInput(principal, directRole.id))
        val request = accessStore.createRequest(principal, AccessRequestInput(roleId = grantRole.id))
        // Approve with a duration already in the past so expires_at <= now(): the grant row exists but is
        // stale. resolve() must fail closed on expires_at, not just on revoked_at.
        accessStore.approve(request.id, durationSec = -3600, decidedBy = "approver@example.com")

        assertEquals(setOf("direct-role"), roleResolver.resolve(principal), "an expired grant must not contribute a role")
    }

    @Test
    fun `unknown principal resolves to the empty set (fail-closed)`() {
        assertEquals(emptySet(), roleResolver.resolve("nobody@example.com"))
    }

    // ---- listActivePrincipals: who exists -----------------------------------------------------

    @Test
    fun `listActivePrincipals enumerates every active identity source, once each and sorted`() {
        createUser("active-user@example.com") // directory app_user, active
        policyStore.createAssignment(RoleAssignmentInput("direct-only@example.com", directRole.id)) // principal_role, no app_user
        approveGrant("grant-only@example.com", durationSec = 3600) // active JIT grant, no other source
        createUser("multi@example.com") // present via all three sources — must appear exactly once
        policyStore.createAssignment(RoleAssignmentInput("multi@example.com", directRole.id))
        approveGrant("multi@example.com", durationSec = 3600)

        createUser("inactive@example.com") // deactivated, though still role-holding
        policyStore.createAssignment(RoleAssignmentInput("inactive@example.com", directRole.id))
        userGroupStore.setUserActive("inactive@example.com", false)
        approveGrant("revoked-only@example.com", durationSec = 3600) // sole source, then revoked
        assertTrue(accessStore.revoke(accessStore.listGrants("revoked-only@example.com", activeOnly = true).first().id))
        approveGrant("expired-only@example.com", durationSec = -3600) // sole source, already expired

        val result = roleResolver.listActivePrincipals()

        assertEquals(result.sorted(), result, "principals are returned sorted")
        assertEquals(result.toSet().size, result.size, "a principal present via several sources appears once")
        assertTrue(
            result.containsAll(
                listOf("active-user@example.com", "direct-only@example.com", "grant-only@example.com", "multi@example.com"),
            ),
            "every active identity source is enumerated; was: $result",
        )
        assertTrue(
            result.none { it in setOf("inactive@example.com", "revoked-only@example.com", "expired-only@example.com") },
            "a deprovisioned user and a revoked/expired grant are not active principals; was: $result",
        )
    }

    private fun createUser(principal: String) =
        userGroupStore.createUser(AppUserInput(principal = principal), tokenStore, accessStore, daemonSessionStore)

    private fun approveGrant(principal: String, durationSec: Long) {
        val req = accessStore.createRequest(principal, AccessRequestInput(roleId = grantRole.id))
        accessStore.approve(req.id, durationSec = durationSec, decidedBy = "approver@example.com")
    }

    companion object {
        private const val PRINCIPAL = "resolve-roles@example.com"
    }
}
