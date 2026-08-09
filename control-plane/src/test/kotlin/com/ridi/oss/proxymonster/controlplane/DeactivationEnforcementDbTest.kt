package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The authoritative fail-closed regression for deprovisioning under the enforcement engine
 * (RoleResolver erasing roles is the wrong signal — `decideQuery` only builds
 * column actions from role-attached policies, and [PolicyEvaluator] ALLOWs when no masks result, so
 * a deactivated principal's role set collapsing to empty flips a MASK'd query to cleartext ALLOW —
 * MORE access after deprovision). [decideQuery] emits a structural DENY for a deactivated
 * principal before role resolution ever runs, closing that hole. This exercises [runEnforcedForTest]
 * end-to-end (decide -> broker -> mask), not just [RoleResolver.resolve] in isolation — checking only
 * the empty role set is exactly the signal that is fail-open.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeactivationEnforcementDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    /** Grant [principal] the fixture's seeded `analyst` (MASK-on-ssn) role via a direct assignment. */
    private fun grantAnalystRole(principal: String) {
        val roleId = fx.policyStore.listRoles().first { it.name == fx.role }.id
        fx.policyStore.createAssignment(RoleAssignmentInput(principal, roleId))
    }

    @Test
    fun `a deactivated principal is denied instead of falling open to cleartext`() {
        val principal = "deactivated-analyst-1@example.com"
        grantAnalystRole(principal)

        // Sanity: while active, the same query MASKs the PII column as expected.
        val active = fx.run("select id, ssn from users order by id", principal = principal)
        assertEquals(EnfAction.MASK, active.decision, "sanity: query must MASK while the principal is active")

        // Deprovision: an app_user row now exists for this principal and is deactivated (the SCIM
        // active=false / IdP-liveness-failure path). Without the fail-closed gate, RoleResolver would
        // resolve to the empty set, no column policy would match, and PolicyEvaluator would ALLOW —
        // cleartext ssn leaking to a deprovisioned user.
        fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        fx.userGroupStore.setUserActive(principal, false)
        assertTrue(fx.userGroupStore.isDeactivated(principal))

        val r = fx.run("select id, ssn from users order by id", principal = principal)
        assertEquals(EnfAction.DENY, r.decision, "a deactivated principal must be denied, not fall open to ALLOW")
        assertTrue(r.rows.isEmpty(), "a DENY must not return rows (no cleartext ssn leak)")
        assertTrue(
            r.denyReason?.contains("deprovision", ignoreCase = true) == true,
            "deny reason should call out deprovisioning: ${r.denyReason}",
        )
    }

    @Test
    fun `a deactivated principal is denied even for a non-sensitive lineage query`() {
        val principal = "deactivated-nonsensitive@example.com"
        fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        fx.userGroupStore.setUserActive(principal, false)

        // Even a query touching no PII at all (would otherwise ALLOW cleanly) must still be denied —
        // the deactivation gate sits before the lineage triad, not folded into it.
        val r = fx.run("select id, region from users order by id", principal = principal)
        assertEquals(EnfAction.DENY, r.decision, "deactivation must deny regardless of the query's own sensitivity")
        assertTrue(r.rows.isEmpty())
    }

    @Test
    fun `a deactivated principal is denied even a READONLY_META passthrough (the gate dominates passthrough)`() {
        val principal = "deactivated-passthrough@example.com"
        // The datasource.connect gate runs ahead of passthrough classification too, so a
        // `select version()` needs a connect grant to ALLOW even while active — grant `analyst` (which
        // has one) so the sanity check below isolates the deactivation gate, not the connect gate.
        grantAnalystRole(principal)
        // `select version()` is admitted as a READONLY_META passthrough (no lineage, no policy) — for
        // any non-deactivated, connected principal it ALLOWs straight through. Sanity-check that first
        // (this principal has no app_user row yet, so isDeactivated is false).
        val activePass = fx.run("select version()", principal = principal)
        assertEquals(EnfAction.ALLOW, activePass.decision, "sanity: a READONLY_META statement passes through while active")

        fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        fx.userGroupStore.setUserActive(principal, false)

        // The SAME passthrough statement must now DENY: the deactivation gate is placed BEFORE
        // adm.passthroughClass, so it dominates READONLY_META/TX_CONTROL/SESSION_MUTATING passthroughs.
        // A regression moving the gate after passthrough classification would silently reopen this.
        val r = fx.run("select version()", principal = principal)
        assertEquals(EnfAction.DENY, r.decision, "deactivation must dominate passthrough classification")
        assertTrue(r.rows.isEmpty())
    }

    @Test
    fun `reactivating a principal restores normal enforcement`() {
        val principal = "reactivated-analyst@example.com"
        grantAnalystRole(principal)
        fx.userGroupStore.createUser(AppUserInput(principal = principal), fx.tokenStore, fx.accessStore, fx.daemonSessionStore)
        fx.userGroupStore.setUserActive(principal, false)
        assertEquals(EnfAction.DENY, fx.run("select id, ssn from users order by id", principal = principal).decision)

        fx.userGroupStore.setUserActive(principal, true)
        val r = fx.run("select id, ssn from users order by id", principal = principal)
        assertEquals(EnfAction.MASK, r.decision, "reactivation must restore normal (masked) enforcement, not a stuck DENY")
    }
}
