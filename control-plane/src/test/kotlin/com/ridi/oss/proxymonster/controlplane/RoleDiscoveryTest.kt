package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.columnMask
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * APPROVAL role discovery (approval-workflow.md) — pure logic, exercised through a stub `decide` closure that
 * stands in for the real decideQuery.
 *
 * The model is deliberately flat: list every role the statement runs under. No baseline and no held-vs-not
 * concept — a role is offered whether or not the requester holds it. Each role is previewed under {R} ALONE
 * on WORKFLOW_EXECUTOR, the channel an approved query actually runs on and the role set it runs under.
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
    fun `every role that runs the statement is listed`() {
        val decide = { _: Int, _: Set<String>, _: Channel -> ctx(EnfAction.ALLOW) }
        val res = discoverRoles(roles, statementCount = 1, decide = decide)
        assertEquals(listOf("analyst", "pii-reader", "auditor"), res.options.map { it.roleName })
    }

    @Test
    fun `a role that runs but still masks is listed, marked masked`() {
        val decide = { _: Int, _: Set<String>, _: Channel -> ctx(EnfAction.MASK, listOf("ssn")) }
        val res = discoverRoles(roles, statementCount = 1, decide = decide)
        val option = res.options.first()
        assertEquals(Decision.MASK, option.decision)
        assertEquals(listOf("ssn"), option.maskedColumns)
    }

    @Test
    fun `a role that returns cleartext is marked ALLOW`() {
        val decide = { _: Int, r: Set<String>, _: Channel ->
            if ("pii-reader" in r) ctx(EnfAction.ALLOW) else ctx(EnfAction.MASK, listOf("ssn"))
        }
        val res = discoverRoles(roles, statementCount = 1, decide = decide)
        val option = res.options.single { it.roleName == "pii-reader" }
        assertEquals(Decision.ALLOW, option.decision)
        assertEquals(emptyList(), option.maskedColumns)
    }

    @Test
    fun `a role that denies the statement is not listed`() {
        val decide = { _: Int, r: Set<String>, _: Channel -> if ("auditor" in r) ctx(EnfAction.DENY) else ctx(EnfAction.ALLOW) }
        val res = discoverRoles(roles, statementCount = 1, decide = decide)
        assertTrue(res.options.none { it.roleName == "auditor" }, "a role that denies cannot run the statement")
        assertEquals(listOf("analyst", "pii-reader"), res.options.map { it.roleName })
    }

    @Test
    fun `a candidate is previewed on the channel an approved query executes on`() {
        // The shipped -259 unmasks production PII for a pii-accessor on WORKFLOW_EXECUTOR alone. Previewed on
        // any other channel that grant never fires, so the role would read as denied/masked and be dropped.
        val decide = { _: Int, r: Set<String>, channel: Channel ->
            if ("pii-reader" in r && channel == Channel.WORKFLOW_EXECUTOR) ctx(EnfAction.ALLOW) else ctx(EnfAction.DENY)
        }
        val res = discoverRoles(roles, statementCount = 1, decide = decide)
        assertEquals(listOf("pii-reader"), res.options.map { it.roleName })
        assertEquals(Decision.ALLOW, res.options.single().decision)
    }

    @Test
    fun `a candidate is previewed under R ALONE, not unioned with the requester's own roles`() {
        // decide ALLOWs only when BOTH "analyst" AND "pii-reader" are present — a policy whose grant only fires
        // on the union. A unioned preview would offer pii-reader, but execution decides under {pii-reader}
        // ALONE and would DENY there, so offering it would be a lie.
        val decide = { _: Int, r: Set<String>, _: Channel -> if ("analyst" in r && "pii-reader" in r) ctx(EnfAction.ALLOW) else ctx(EnfAction.DENY) }
        val res = discoverRoles(roles, statementCount = 1, decide = decide)
        assertTrue(res.options.isEmpty(), "R-alone preview must DENY, so no role is offered")
    }
}
