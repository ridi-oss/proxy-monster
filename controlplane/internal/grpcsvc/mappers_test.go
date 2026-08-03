package grpcsvc

// GrpcMappersTest — 4 cases, pure (10-grpc.md §4).

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

func strptr(s string) *string { return &s }

// TestToWireDecisionCarriesTheVerdictArm is case 1: a MASK context maps onto the Verdict arm with
// every field carried across, and the masks cross VERBATIM (INV-A10-51).
func TestToWireDecisionCarriesTheVerdictArm(t *testing.T) {
	ordinal := int32(3)
	ctx := query.DecisionContext{
		Action:              pb.EnfAction_MASK,
		DenyReason:          nil,
		Masks:               []*pb.ColumnMask{{Column: "rrn", MaskFn: "last4", Kind: "LAST_N", Ordinal: &ordinal}},
		EffectiveRoles:      []string{"analyst"},
		RewrittenSQL:        strptr(`select "id", "rrn" from users`),
		UnmaskablePermitted: true,
		SanitizeDiagnostics: true,
	}
	got := toWireDecision(ctx, 42, 7, []*pb.Refetch{{Schema: "app"}})

	v := got.GetVerdict()
	if v == nil {
		t.Fatalf("wire decision = %v, want the verdict arm", got)
	}
	if got.GetBeforeDecide() != nil {
		t.Error("both oneof arms are set; they are structurally exclusive (INV-A10-38)")
	}
	if v.GetDecision() != pb.EnfAction_MASK {
		t.Errorf("decision = %v, want MASK", v.GetDecision())
	}
	if v.GetDecisionId() != 42 || v.GetGeneration() != 7 {
		t.Errorf("decision_id/generation = %d/%d, want 42/7", v.GetDecisionId(), v.GetGeneration())
	}
	if !v.GetUnmaskablePermitted() || !v.GetSanitizeDiagnostics() {
		t.Error("unmaskable_permitted / sanitize_diagnostics were not carried across")
	}
	if len(v.GetMasks()) != 1 || v.GetMasks()[0] != ctx.Masks[0] {
		t.Error("masks must cross VERBATIM — they are already the proto type, so no rebuild happens (INV-A10-51)")
	}
	// 🔒 INV-A10-52 — explicit presence survives the mapper untouched. A mapper that rebuilt the mask
	// from a domain struct with a plain int32 would bind an absent ordinal to result column 0, masking
	// the wrong column and leaking the intended one.
	if v.GetMasks()[0].Ordinal == nil || *v.GetMasks()[0].Ordinal != 3 {
		t.Error("the mask ordinal's explicit presence did not survive the mapper")
	}
	if len(v.GetAfterStatement()) != 1 || v.GetAfterStatement()[0].GetRefetch().GetSchema() != "app" {
		t.Errorf("after_statement = %v, want one Refetch wrapped in a ProxyCommand", v.GetAfterStatement())
	}
}

// TestToWireDecisionLeavesRewrittenSqlUnsetWithoutARewrite is case 4 — INV-A10-37's sharpest half.
//
// 🔒 ABSENT means "forward the client's original SQL verbatim". A plain proto3 string would collapse
// that to "", making the mapper send an EMPTY QUERY for every non-rewritten decision.
func TestToWireDecisionLeavesRewrittenSqlUnsetWithoutARewrite(t *testing.T) {
	got := toWireDecision(query.DecisionContext{Action: pb.EnfAction_ALLOW}, 1, 1, nil)
	v := got.GetVerdict()
	if v.RewrittenSql != nil {
		t.Fatalf("rewritten_sql = %q, want ABSENT", v.GetRewrittenSql())
	}
	if v.GetDenyReason() != "" {
		t.Errorf("deny_reason = %q, want the empty proto3 default for an ALLOW", v.GetDenyReason())
	}
}

// TestToWireDecisionLeavesDecisionIdZeroWithoutAnAuditRow is INV-A10-37's other half. 0 is a safe
// sentinel because BIGSERIAL audit ids start at 1.
func TestToWireDecisionLeavesDecisionIdZeroWithoutAnAuditRow(t *testing.T) {
	got := toWireDecision(query.DecisionContext{Action: pb.EnfAction_DENY, DenyReason: strptr("nope")}, 0, 2, nil)
	if got.GetVerdict().GetDecisionId() != 0 {
		t.Errorf("decision_id = %d, want 0", got.GetVerdict().GetDecisionId())
	}
	if got.GetVerdict().GetDenyReason() != "nope" {
		t.Errorf("deny_reason = %q, want it carried", got.GetVerdict().GetDenyReason())
	}
}

// TestBeforeDecideDecisionSetsOnlyItsOwnArm is case 3.
//
// 🔒 The Go client checks GetBeforeDecide() FIRST, so a server that ever set both arms would have its
// verdict silently ignored. INV-A10-39 is the second assertion: an empty if_hash_differs means
// "unconditional fetch (fail-safe)" and must not be normalised away.
func TestBeforeDecideDecisionSetsOnlyItsOwnArm(t *testing.T) {
	got := beforeDecideDecision([]*pb.Refetch{{Schema: "app"}})
	if got.GetBeforeDecide() == nil {
		t.Fatalf("wire decision = %v, want the before_decide arm", got)
	}
	if got.GetVerdict() != nil {
		t.Fatal("the verdict arm is set on a before_decide; the two are structurally exclusive")
	}
	cmds := got.GetBeforeDecide().GetCommands()
	if len(cmds) != 1 || cmds[0].GetRefetch().GetSchema() != "app" {
		t.Fatalf("commands = %v, want one Refetch for \"app\"", cmds)
	}
	if len(cmds[0].GetRefetch().GetIfHashDiffers()) != 0 {
		t.Error("if_hash_differs must stay EMPTY on a fresh refetch — empty means unconditional fetch")
	}
}
