package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.columnMask
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * APPROVAL role discovery (approval-workflow.md) — pure logic, exercised through a stub `decide` closure
 * that stands in for the real decideQuery.
 *
 * Candidates are previewed on WORKFLOW_EXECUTOR, the channel an approved query actually runs on, and each
 * option carries the outcome it would deliver there. Previewing on the requester's own channel hid roles a
 * channel-scoped grant would have unlocked, and offering only roles that beat the requester's own dropped
 * ones that run the query while still masking — an answer the requester needs.
 */
class RoleDiscoveryTest {
    private fun ctx(action: EnfAction, maskedCols: List<String> = emptyList()) = DecisionContext(
        action = action,
        denyReason = if (action == EnfAction.DENY) "denied" else null,
        masks = maskedCols.mapIndexed { i, c -> columnMask { column = c; maskFn = "mask"; kind = "FIXED"; ordinal = i } },
        piiTouched = emptyList(),
        effectiveRoles = emptyList(),
        failedStage = null,
        detail = null,
        passthrough = false,
    )

    private val roles = listOf(Role(1, "analyst"), Role(2, "pii-reader"), Role(3, "auditor"))

    @Test
    fun `a role that unmasks a baseline-masked column is offered with the unmasked column`() {
        // own role analyst masks ssn; pii-reader unmasks it; auditor still masks it (no improvement).
        val decide = { r: Set<String>, _: Channel ->
            when {
                "pii-reader" in r -> ctx(EnfAction.ALLOW) // ssn unmasked → no masks
                else -> ctx(EnfAction.MASK, listOf("ssn"))
            }
        }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertTrue(res.baselineAllowed, "a MASK baseline is 'allowed' (not denied)")
        // Both candidates run Q, so both are listed; what distinguishes them is the reported gain.
        assertEquals(listOf("pii-reader", "auditor"), res.options.map { it.roleName })
        assertEquals(listOf("ssn"), res.options.single { it.roleName == "pii-reader" }.unmasksColumns)
        assertEquals(emptyList(), res.options.single { it.roleName == "auditor" }.unmasksColumns)
    }

    @Test
    fun `a role that denies the query is not offered`() {
        val decide = { r: Set<String>, _: Channel -> if ("auditor" in r) ctx(EnfAction.DENY) else ctx(EnfAction.MASK, listOf("ssn")) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertTrue(res.options.none { it.roleName == "auditor" }, "a role that denies Q cannot be the answer")
        assertTrue(res.options.any { it.roleName == "pii-reader" }, "a role that CAN run Q is still listed")
    }

    @Test
    fun `when baseline is denied, a role that makes Q runnable is offered`() {
        // requester's own roles can't run Q at all (no read grant); pii-reader can.
        val decide = { r: Set<String>, _: Channel -> if ("pii-reader" in r) ctx(EnfAction.ALLOW) else ctx(EnfAction.DENY) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertFalse(res.baselineAllowed, "baseline is denied")
        assertEquals(listOf("pii-reader"), res.options.map { it.roleName }, "a role that makes a denied Q runnable is offered")
    }

    @Test
    fun `a role the requester already holds is never offered`() {
        val decide = { _: Set<String>, _: Channel -> ctx(EnfAction.MASK, listOf("ssn")) }
        val res = discoverRoles(setOf("analyst", "pii-reader"), roles, decide)
        assertTrue(res.options.none { it.roleName in setOf("analyst", "pii-reader") }, "already-held roles are filtered out")
    }

    @Test
    fun `a candidate is previewed on the channel an approved query executes on`() {
        // The shipped -259 unmasks production PII for a pii-accessor on WORKFLOW_EXECUTOR alone. Previewed on
        // the requester's own channel that grant never fires, so the role reads as no better than baseline
        // and was filtered out — leaving a requester who asked to see ssn told that no role would help.
        val decide = { r: Set<String>, channel: Channel ->
            if ("pii-reader" in r && channel == Channel.WORKFLOW_EXECUTOR) ctx(EnfAction.ALLOW)
            else ctx(EnfAction.MASK, listOf("ssn"))
        }
        val res = discoverRoles(setOf("analyst"), roles, decide)

        val option = res.options.single { it.roleName == "pii-reader" }
        assertEquals(Decision.ALLOW, option.decision)
        assertEquals(emptyList(), option.maskedColumns)
        assertEquals(listOf("ssn"), option.unmasksColumns)
    }

    @Test
    fun `the baseline is decided on the requester's own channel, never the executor's`() {
        // The baseline answers "what do I get right now", so previewing it as the workflow would overstate
        // what the requester already has and understate what an elevation buys them.
        val seen = mutableListOf<Channel>()
        val decide = { r: Set<String>, channel: Channel ->
            if (r == setOf("analyst")) seen.add(channel)
            ctx(EnfAction.MASK, listOf("ssn"))
        }
        discoverRoles(setOf("analyst"), roles, decide)
        assertEquals(listOf(Channel.EDITOR), seen)
    }

    @Test
    fun `a role that runs the query but still masks is offered, marked masked`() {
        val decide = { _: Set<String>, _: Channel -> ctx(EnfAction.MASK, listOf("ssn")) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        val option = res.options.first()
        assertEquals(Decision.MASK, option.decision)
        assertEquals(listOf("ssn"), option.maskedColumns)
        assertEquals(emptyList(), option.unmasksColumns, "it unmasks nothing relative to the baseline")
    }

    @Test
    fun `a candidate is previewed under R ALONE, not unioned with the requester's own roles`() {
        // decide ALLOWs only when BOTH "analyst" (the requester's own role) AND "pii-reader" (the candidate)
        // are present together — modeling a policy whose grant only fires on the union. A unioned
        // preview would compute decide({analyst, pii-reader}) = ALLOW and offer pii-reader — but
        // execution decides under {pii-reader} ALONE and would DENY there, so offering it would be a lie.
        val decide = { r: Set<String>, _: Channel -> if ("analyst" in r && "pii-reader" in r) ctx(EnfAction.ALLOW) else ctx(EnfAction.DENY) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertTrue(res.options.isEmpty(), "R-alone preview must DENY (analyst is not in {pii-reader} alone) → pii-reader must not be offered")
    }
}
