package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * End-to-end: soft-deleting the mask function a column is classified with must never un-mask it — the
 * column falls back to FIXED masking and the value stays hidden (fail-safe).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MaskFnSoftDeleteEnforcementDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    @Test
    fun `soft-deleting a column's mask function keeps it masked (FIXED fallback), never cleartext`() {
        val cleartext = fx.execOnTarget("select rrn from users order by id").rows.map { it.single() }

        val before = fx.run("select id, rrn from users order by id")
        assertEquals(EnfAction.MASK, before.decision, "sanity: rrn masks under the analyst role + last4 fn")
        val rrn = before.columns.indexOf("rrn")
        val maskedBefore = before.rows.map { it[rrn] }
        assertEquals(emptyList(), maskedBefore.filter { it in cleartext }, "sanity: nothing cleartext while masked")

        // Delete the mask function the classification points at.
        fx.policyStore.deleteMaskFn(fx.policyStore.listMaskFns().first { it.name == "last4" }.id)

        val after = fx.run("select id, rrn from users order by id")
        assertEquals(EnfAction.MASK, after.decision, "the column stays MASK — a deleted mask fn must not un-mask it")
        val maskedAfter = after.rows.map { it[rrn] }
        assertEquals(emptyList(), maskedAfter.filter { it in cleartext }, "and no rrn is cleartext after the delete")
        assertNotEquals(maskedBefore, maskedAfter, "the mask fell back from last4 to FIXED, so the masked output changed")
    }
}

/**
 * End-to-end: a task's frozen execute_as role snapshot re-authorizes at the decision. A role soft-deleted
 * after the snapshot (or after the route-level liveness check, before the async proxy Decide) is re-filtered
 * to live roles at decideQuery, so the run denies rather than authorizing under a role that no longer exists.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RoleExecuteAsSoftDeleteEnforcementDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.postgres()
    }

    @Test
    fun `a soft-deleted execute-as role is re-filtered at the decision so the stored run denies`() {
        val executeAs = setOf(fx.role) // the seeded analyst role, which masks rrn

        val live = fx.decide("select id, rrn from users", providedRoles = executeAs)
        assertEquals(EnfAction.MASK, live.action, "sanity: the run authorizes and masks under its execute_as role")

        fx.policyStore.deleteRole(fx.policyStore.listRoles().first { it.name == fx.role }.id)

        val gone = fx.decide("select id, rrn from users", providedRoles = executeAs)
        assertEquals(
            EnfAction.DENY,
            gone.action,
            "a soft-deleted execute_as role must not still authorize the run (TOCTOU re-check at decideQuery)",
        )
    }
}
