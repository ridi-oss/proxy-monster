package com.ridi.oss.proxymonster.controlplane.grpc

import com.ridi.oss.proxymonster.controlplane.DecisionContext
import com.ridi.oss.proxymonster.grpc.Refetch
import com.ridi.oss.proxymonster.grpc.WireDecision
import com.ridi.oss.proxymonster.grpc.beforeDecide
import com.ridi.oss.proxymonster.grpc.proxyCommand
import com.ridi.oss.proxymonster.grpc.verdict
import com.ridi.oss.proxymonster.grpc.wireDecision

/**
 * Build the wire decision from an internal [DecisionContext]. The action and masks are already the proto
 * types (EnfAction / ColumnMask), so they cross the wire verbatim — no name/ordinal mapping. Optional wire
 * fields carry the load-bearing absence semantics: `rewritten_sql` is left UNSET when there is no
 * `*`-expansion rewrite (= forward the client's original SQL), and `decision_id` is left 0 when there is no
 * audit id. Each after-statement [Refetch] is wrapped in the generic ProxyCommand envelope the proxy runs.
 */
internal fun DecisionContext.toWireDecision(
    auditId: Long,
    generation: Long,
    afterStatement: List<Refetch>,
): WireDecision {
    val ctx = this
    return wireDecision {
        verdict = verdict {
            decision = ctx.action
            ctx.denyReason?.let { denyReason = it }
            masks.addAll(ctx.masks)
            effectiveRoles.addAll(ctx.effectiveRoles)
            ctx.rewrittenSql?.let { rewrittenSql = it }
            if (auditId != 0L) decisionId = auditId
            unmaskablePermitted = ctx.unmaskablePermitted
            this.generation = generation
            this.afterStatement.addAll(afterStatement.map { proxyCommand { refetch = it } })
            // The diagnostic-redaction decision (docs/diagnostic-redaction.md), computed per
            // decision in decideQuery (Cedar + engine capability + action).
            this.sanitizeDiagnostics = ctx.sanitizeDiagnostics
            // Echoed back on RunDecision so an execute-under-R run freezes it with the stored result and a
            // later view denies authorization drift (decideResultView). The proxy does not read these.
            resultFingerprint.addAll(ctx.resultFingerprint)
        }
    }
}

internal fun beforeDecideDecision(commands: List<Refetch>): WireDecision = wireDecision {
    beforeDecide = beforeDecide { this.commands.addAll(commands.map { proxyCommand { refetch = it } }) }
}
