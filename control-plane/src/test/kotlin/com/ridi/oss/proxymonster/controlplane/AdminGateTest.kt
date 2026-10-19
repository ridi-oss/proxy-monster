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
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertTrue

/**
 * The "admin = any session" hole, decision-level floor (docs/authz-model.md, admin-gating).
 *
 * A seeded policy set, then `authorize(...)` asserted directly through the admin action set
 * (`AuthzAction.ADMIN_POLICIES`) — a principal with no admin role must DENY, a principal holding
 * `system:admin` must ALLOW. It intentionally overlaps [AuthzTest] (same decision service), but
 * exercises it through the admin-gating lens, so admin gating has its own proof the gate is real.
 *
 * Not covered here: a full end-to-end boot of `Application.module` behind a real HTTP call
 * (`ktor-server-test-host` is on the test classpath) — POST `/api/roles` with no session -> 403,
 * with a `system:admin` session cookie -> 2xx, and 200 under `authDebug = true` (the dev bypass). The
 * decision-level floor below is the deliverable; the HTTP boot would only strengthen it.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AdminGateTest {
    private lateinit var policyStore: PolicyStore
    private lateinit var userGroupStore: UserGroupStore
    private lateinit var accessStore: AccessStore
    private lateinit var cedarPolicyStore: CedarPolicyStore
    private lateinit var authz: Authz

    private val noAdminPrincipal = "analyst@example.com"
    private val pmAdminPrincipal = "admin@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        val ds = SharedPostgres.hikari(SharedPostgres.migratedDatabase("pm_admin_gate"))

        policyStore = PolicyStore(ds)
        userGroupStore = UserGroupStore(ds)
        accessStore = AccessStore(ds)
        cedarPolicyStore = CedarPolicyStore(ds)
        val cedarEngine = CedarEngine(cedarPolicyStore)
        val roleResolver = RoleResolver(ds, userGroupStore, accessStore)
        authz = Authz(cedarEngine, cedarPolicyStore, RoleSource { p -> roleResolver.resolve(p) })

        // Layer 1: pmAdminPrincipal directly holds the system:admin role (principal_role) — no group, no JIT.
        // system:admin is seeded by the shipped bootstrap, so reuse it rather than re-create it.
        val pmAdminRole = policyStore.listRoles().first { it.name == "system:admin" }
        policyStore.createAssignment(RoleAssignmentInput(principal = pmAdminPrincipal, roleId = pmAdminRole.id))

        // Layer 2: the system:admin grant, straight from the worked example in docs/authz-model.md.
        // (the seed already ships an equivalent `system:admin` row; this makes the dependency explicit.)
        cedarPolicyStore.create(
            CedarPolicyInput(
                name = "test-admin-grant",
                cedarSrc = "permit(principal in Role::\"system:admin\", " +
                    "action in [Action::\"admin.datasources\", Action::\"admin.policies\", Action::\"admin.identity\"], " +
                    "resource);",
            ),
            updatedBy = null,
        )
    }

    @Test
    fun `no admin role is denied admin_policies`() {
        val decision = authz.authorize(noAdminPrincipal, AuthzAction.ADMIN_POLICIES, AuthzResource.System)
        assertTrue(decision is AuthzDecision.Deny, "expected Deny for a principal with no admin role, got $decision")
    }

    @Test
    fun `system-admin role is allowed admin_policies`() {
        val decision = authz.authorize(pmAdminPrincipal, AuthzAction.ADMIN_POLICIES, AuthzResource.System)
        assertTrue(decision is AuthzDecision.Allow, "expected Allow for a system:admin principal, got $decision")
    }
}
