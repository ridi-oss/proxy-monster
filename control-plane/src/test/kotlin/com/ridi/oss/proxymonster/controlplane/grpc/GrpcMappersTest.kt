package com.ridi.oss.proxymonster.controlplane.grpc

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.controlplane.DecisionContext
import com.ridi.oss.proxymonster.grpc.ColumnMask
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.Refetch
import com.ridi.oss.proxymonster.grpc.columnMask
import com.ridi.oss.proxymonster.grpc.refetch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GrpcMappersTest {
    private fun ctx(
        action: EnfAction,
        masks: List<ColumnMask> = emptyList(),
        effectiveRoles: List<String> = emptyList(),
        rewrittenSql: String? = null,
        denyReason: String? = null,
        unmaskablePermitted: Boolean = false,
        sanitizeDiagnostics: Boolean = false,
    ) = DecisionContext(
        action = action,
        denyReason = denyReason,
        masks = masks,
        piiTouched = emptyList(),
        effectiveRoles = effectiveRoles,
        failedStage = null,
        detail = null,
        passthrough = false,
        rewrittenSql = rewrittenSql,
        unmaskablePermitted = unmaskablePermitted,
        sanitizeDiagnostics = sanitizeDiagnostics,
    )

    @Test
    fun `MASK decision carries the proto action and every mask field and generation`() {
        val d = ctx(
            EnfAction.MASK,
            masks = listOf(columnMask { column = "email"; maskFn = "email_mask"; kind = "PARTIAL"; ordinal = 0 }),
            effectiveRoles = listOf("analyst"),
            rewrittenSql = "select email from users",
            unmaskablePermitted = true,
            sanitizeDiagnostics = true,
        ).toWireDecision(42, 7, emptyList())

        assertTrue(d.hasVerdict())
        assertFalse(d.hasBeforeDecide())
        assertEquals(EnfAction.MASK, d.verdict.decision)
        assertEquals(42L, d.verdict.decisionId)
        assertEquals(7L, d.verdict.generation)
        assertEquals(0, d.verdict.masksList.single().ordinal)
        assertTrue(d.verdict.hasRewrittenSql())
        assertTrue(d.verdict.unmaskablePermitted)
        assertTrue(d.verdict.sanitizeDiagnostics)
    }

    @Test
    fun `targeted after-statement refetch maps schema and hash`() {
        val hash = ByteString.copyFromUtf8("h1")
        val d = ctx(EnfAction.ALLOW).toWireDecision(
            1,
            9,
            listOf(refetch { schema = "app"; ifHashDiffers = hash }),
        )

        val cmd: Refetch = d.verdict.afterStatementList.single().refetch
        assertEquals("app", cmd.schema)
        assertEquals(hash, cmd.ifHashDiffers)
        assertEquals(9L, d.verdict.generation)
    }

    @Test
    fun `before-decide is structurally exclusive from verdict`() {
        val d = beforeDecideDecision(listOf(refetch { schema = "app" }))
        assertTrue(d.hasBeforeDecide())
        assertFalse(d.hasVerdict())
        assertEquals("app", d.beforeDecide.commandsList.single().refetch.schema)
        assertTrue(d.beforeDecide.commandsList.single().refetch.ifHashDiffers.isEmpty)
    }

    @Test
    fun `ALLOW with no rewrite leaves rewrittenSql absent`() {
        val d = ctx(EnfAction.ALLOW, effectiveRoles = listOf("admin"))
            .toWireDecision(7, 0, emptyList())
        assertFalse(d.verdict.hasRewrittenSql())
        assertEquals(emptyList(), d.verdict.afterStatementList)
        assertFalse(d.verdict.sanitizeDiagnostics)
    }
}
