package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.runError

import com.ridi.oss.proxymonster.grpc.EnfAction
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** failedDiagnosticForViewer: raw to a raw-relaying view decision, redacted to a sanitizing one, null else. */
class FailedDiagnosticForViewerTest {
    private val diagnostic = runError { message = "ERROR: 42P01 undefined_table"; rawMessage = "ERROR: null value in column \"ssn\" — 987-65-4320"; targetDbError = true }

    private fun ctx(action: EnfAction, sanitize: Boolean) = DecisionContext(
        action = action, denyReason = null, masks = emptyList(), piiTouched = emptyList(),
        effectiveRoles = emptyList(), failedStage = null, detail = null, passthrough = false,
        sanitizeDiagnostics = sanitize,
    )

    @Test
    fun `no live re-decision withholds everything`() {
        assertNull(failedDiagnosticForViewer(null, diagnostic))
    }

    @Test
    fun `no stored diagnostic yields nothing`() {
        assertNull(failedDiagnosticForViewer(ctx(EnfAction.ALLOW, sanitize = false), null))
    }

    @Test
    fun `a viewer whose re-decision denies gets nothing, not the redacted form`() {
        assertNull(failedDiagnosticForViewer(ctx(EnfAction.DENY, sanitize = true), diagnostic))
    }

    @Test
    fun `a MASK viewer gets the value-free redacted form`() {
        assertEquals(diagnostic.message, failedDiagnosticForViewer(ctx(EnfAction.MASK, sanitize = true), diagnostic))
    }

    @Test
    fun `a PostgreSQL ALLOW that still sanitizes (a partial reader) gets the redacted form`() {
        assertEquals(diagnostic.message, failedDiagnosticForViewer(ctx(EnfAction.ALLOW, sanitize = true), diagnostic))
    }

    @Test
    fun `a full-cleartext reader gets the raw target-DB text`() {
        assertEquals(diagnostic.rawMessage, failedDiagnosticForViewer(ctx(EnfAction.ALLOW, sanitize = false), diagnostic))
    }
}
