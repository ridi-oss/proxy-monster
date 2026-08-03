package grpcsvc

import (
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// toWireDecision is `DecisionContext.toWireDecision(auditId, generation, afterStatement)`
// (GrpcMappers.kt, 10-grpc.md §3.2).
//
// 🔒 INV-A10-37 — ABSENCE IS THE SIGNAL, on two fields:
//   - rewritten_sql is left UNSET when there is no `*`-expansion rewrite, which means "forward the
//     client's original SQL verbatim". A plain proto3 string would collapse that to "", making the
//     mapper send an EMPTY QUERY for every non-rewritten decision.
//   - decision_id is left 0 when there is no audit id (BIGSERIAL starts at 1, so 0 is a safe
//     sentinel).
//
// 🔒 INV-A10-51 / INV-A10-52 — the action and the masks are ALREADY the proto types, so they cross
// verbatim with no name/ordinal mapping, and ColumnMask.ordinal's explicit presence survives
// untouched. A control plane that rebuilt masks from a domain struct with a plain int32 ordinal would
// bind a malformed/omitted mask to result column 0 — masking the wrong column and leaking the
// intended one.
//
// 🔒 INV-A10-53 — if a Go port ever introduces a DOMAIN EnfAction enum, map it by NAME. The proto's
// numbers deliberately do not match the Kotlin ordinals, and 0 is a fail-closed UNSPECIFIED
// sentinel. Today DecisionContext.Action IS pb.EnfAction, so the hazard stays latent.
func toWireDecision(ctx query.DecisionContext, auditID int64, generation int64, afterStatement []*pb.Refetch) *pb.WireDecision {
	v := &pb.Verdict{
		Decision:            ctx.Action,
		Masks:               ctx.Masks,
		EffectiveRoles:      ctx.EffectiveRoles,
		UnmaskablePermitted: ctx.UnmaskablePermitted,
		Generation:          uint64(generation),
		SanitizeDiagnostics: ctx.SanitizeDiagnostics,
	}
	// `denyReason` is a plain proto3 string: Kotlin leaves it at "" when the context carries none.
	if ctx.DenyReason != nil {
		v.DenyReason = *ctx.DenyReason
	}
	// `rewritten_sql` is `optional`: nil, NOT proto.String(""). See INV-A10-37.
	if ctx.RewrittenSQL != nil {
		s := *ctx.RewrittenSQL
		v.RewrittenSql = &s
	}
	if auditID != 0 {
		v.DecisionId = auditID
	}
	v.AfterStatement = proxyCommands(afterStatement)
	return &pb.WireDecision{Outcome: &pb.WireDecision_Verdict{Verdict: v}}
}

// beforeDecideDecision is `beforeDecideDecision(commands)`.
//
// 🔒 INV-A10-38 — Verdict and BeforeDecide are structurally exclusive and a message with NEITHER arm
// set must fail closed. Two constructors over one `oneof` is what enforces that by construction. The
// Go client checks GetBeforeDecide() FIRST, so a server that ever set both arms would have its
// verdict silently ignored — do not replace the oneof with two plain fields.
//
// INV-A10-39 — a before-decide Refetch may carry an EMPTY if_hash_differs, which means
// "unconditional fetch (fail-safe)". It is not a bug to be normalised away.
func beforeDecideDecision(commands []*pb.Refetch) *pb.WireDecision {
	return &pb.WireDecision{
		Outcome: &pb.WireDecision_BeforeDecide{
			BeforeDecide: &pb.BeforeDecide{Commands: proxyCommands(commands)},
		},
	}
}

// proxyCommands wraps each Refetch in the generic ProxyCommand envelope. REFETCH is today's only arm;
// the envelope exists so a future command needs no shape change, and the proxy fails closed on an
// unknown arm.
func proxyCommands(refetches []*pb.Refetch) []*pb.ProxyCommand {
	if len(refetches) == 0 {
		return nil
	}
	out := make([]*pb.ProxyCommand, 0, len(refetches))
	for _, r := range refetches {
		out = append(out, &pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: r}})
	}
	return out
}
