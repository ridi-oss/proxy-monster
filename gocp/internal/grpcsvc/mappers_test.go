package grpcsvc

// GrpcMappersTest — 4 cases, pure (10-grpc.md §4).

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
)

func strptr(s string) *string { return &s }

// TestToWireDecisionCarriesTheVerdictArm is case 1: a MASK context maps onto the Verdict arm with
// every field carried across, and the masks cross VERBATIM (INV-A10-51).
//
// KT: GrpcMappersTest.kt#MASK decision carries the proto action and every mask field and generation
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
	// The Kotlin's `assertTrue(d.verdict.hasRewrittenSql())`, which is the PRESENT half of INV-A10-37 —
	// TestToWireDecisionLeavesRewrittenSqlUnsetWithoutARewrite only covers the ABSENT half, and a mapper
	// that dropped the field entirely would pass that one.
	if v.RewrittenSql == nil || v.GetRewrittenSql() != `select "id", "rrn" from users` {
		t.Errorf("rewritten_sql = %v, want the rewrite carried across as PRESENT", v.RewrittenSql)
	}
	if len(v.GetAfterStatement()) != 1 || v.GetAfterStatement()[0].GetRefetch().GetSchema() != "app" {
		t.Errorf("after_statement = %v, want one Refetch wrapped in a ProxyCommand", v.GetAfterStatement())
	}
}

// TestToWireDecisionLeavesRewrittenSqlUnsetWithoutARewrite is case 4 — INV-A10-37's sharpest half.
//
// 🔒 ABSENT means "forward the client's original SQL verbatim". A plain proto3 string would collapse
// that to "", making the mapper send an EMPTY QUERY for every non-rewritten decision.
//
// KT: GrpcMappersTest.kt#ALLOW with no rewrite leaves rewrittenSql absent
func TestToWireDecisionLeavesRewrittenSqlUnsetWithoutARewrite(t *testing.T) {
	got := toWireDecision(query.DecisionContext{
		Action:         pb.EnfAction_ALLOW,
		EffectiveRoles: []string{"admin"},
	}, 7, 0, nil)
	v := got.GetVerdict()
	if v.RewrittenSql != nil {
		t.Fatalf("rewritten_sql = %q, want ABSENT", v.GetRewrittenSql())
	}
	if v.GetDenyReason() != "" {
		t.Errorf("deny_reason = %q, want the empty proto3 default for an ALLOW", v.GetDenyReason())
	}
	// The Kotlin case's other two assertions: no after-statement commands were invented, and
	// sanitize_diagnostics stays false. A mapper that defaulted either the other way would widen what
	// the proxy does on an ordinary ALLOW — the second would make it withhold diagnostics from every
	// permitted query.
	if len(v.GetAfterStatement()) != 0 {
		t.Errorf("after_statement = %v, want empty when no refetch was requested", v.GetAfterStatement())
	}
	if v.GetSanitizeDiagnostics() {
		t.Error("sanitize_diagnostics = true on a plain ALLOW; the flag must not default on")
	}
}

// TestToWireDecisionMapsATargetedRefetchSchemaAndHash is GrpcMappersTest case 2, which
// TestToWireDecisionCarriesTheVerdictArm only half-covers: it passes a Refetch and checks the SCHEMA
// crossed, but never a non-empty if_hash_differs.
//
// 🔒 if_hash_differs is what makes an after-statement refetch CONDITIONAL. The proxy re-measures only
// when the backend's current schema hash differs from the one quoted here; a mapper that dropped or
// truncated the bytes would turn every targeted refetch into an unconditional one (INV-A10-39's
// inverse — empty means "fetch regardless"), so the field's exact bytes are the behaviour.
//
// KT: GrpcMappersTest.kt#targeted after-statement refetch maps schema and hash
func TestToWireDecisionMapsATargetedRefetchSchemaAndHash(t *testing.T) {
	hash := []byte("h1")
	got := toWireDecision(
		query.DecisionContext{Action: pb.EnfAction_ALLOW},
		1, 9,
		[]*pb.Refetch{{Schema: "app", IfHashDiffers: hash}},
	)

	cmds := got.GetVerdict().GetAfterStatement()
	if len(cmds) != 1 {
		t.Fatalf("after_statement = %v, want exactly one ProxyCommand", cmds)
	}
	cmd := cmds[0].GetRefetch()
	if cmd == nil {
		t.Fatalf("the ProxyCommand is %v, want a Refetch", cmds[0])
	}
	if cmd.GetSchema() != "app" {
		t.Errorf("refetch schema = %q, want app", cmd.GetSchema())
	}
	if string(cmd.GetIfHashDiffers()) != "h1" {
		t.Errorf("if_hash_differs = %q, want the caller's bytes verbatim — a dropped hash turns a "+
			"CONDITIONAL refetch into an unconditional one", cmd.GetIfHashDiffers())
	}
	// The Kotlin asserts the generation on this case too: the same verdict carries the catalog
	// generation the refetch is relative to, so a proxy can tell a stale command from a current one.
	if got.GetVerdict().GetGeneration() != 9 {
		t.Errorf("generation = %d, want 9", got.GetVerdict().GetGeneration())
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
//
// KT: GrpcMappersTest.kt#before-decide is structurally exclusive from verdict
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
