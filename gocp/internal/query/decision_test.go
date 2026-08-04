package query

import (
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The four decision constructors and their EXACT failedStage / structural values —
// 06-query-decision.md §3's "Deny constructors" table.
//
// 🔒 INV-A6-13 — the structural/policy split drives approval eligibility, and `failedStage` is what
// the minting path filters on ("the minting path must refuse rows with failed_stage='admission'").
// Getting either wrong is silent: the decision still denies, and the approval queue quietly changes
// shape. Hence a table test rather than trust.

func stageOf(t *testing.T, d DecisionContext) string {
	t.Helper()
	if d.FailedStage == nil {
		return "<nil>"
	}
	return *d.FailedStage
}

func TestDenyConstructorsCarryTheirExactFailedStageAndStructuralFlag(t *testing.T) {
	for _, tc := range []struct {
		name       string
		got        DecisionContext
		action     pb.EnfAction
		stage      string
		structural bool
	}{
		{"structuralDeny defaults to admission", structuralDeny("r", nil, stageAdmission, nil),
			pb.EnfAction_DENY, "admission", true},
		{"structuralDeny at policy", structuralDeny("r", nil, stagePolicy, nil),
			pb.EnfAction_DENY, "policy", true},
		{"structuralDeny at catalog", structuralDeny("r", nil, stageCatalog, nil),
			pb.EnfAction_DENY, "catalog", true},
		{"structuralDeny at mask-binding", structuralDeny("r", nil, stageMaskBinding, nil),
			pb.EnfAction_DENY, "mask-binding", true},
		{"structuralDeny at explain-masked", structuralDeny("r", nil, stageExplainMasked, nil),
			pb.EnfAction_DENY, "explain-masked", true},
		{"structuralDeny at deprovisioned", structuralDeny("r", nil, stageDeprovisioned, nil),
			pb.EnfAction_DENY, "deprovisioned", true},
		// 🔒 policyDeny is GRANT-OVERRIDABLE — a JIT grant could add the missing role — so structural
		// must be false and the stage must be "policy", never "admission".
		{"policyDeny is policy and non-structural", policyDeny("r", nil, nil),
			pb.EnfAction_DENY, "policy", false},
		// 🔒 wireTaskForbiddenDeny surfaces a forbidden native-wire self-approve as an ORDINARY policy
		// DENY, never a gRPC status, so the client sees the same shape as any other denied statement.
		{"wireTaskForbiddenDeny is an ordinary policy deny", WireTaskForbiddenDeny(nil, nil),
			pb.EnfAction_DENY, "policy", false},
		{"passthroughAllow has no failedStage", passthroughAllow(nil, "d", nil),
			pb.EnfAction_ALLOW, "<nil>", false},
	} {
		if tc.got.Action != tc.action {
			t.Errorf("%s: action = %v, want %v", tc.name, tc.got.Action, tc.action)
		}
		if got := stageOf(t, tc.got); got != tc.stage {
			t.Errorf("%s: failedStage = %q, want %q", tc.name, got, tc.stage)
		}
		if tc.got.Structural != tc.structural {
			t.Errorf("%s: structural = %v, want %v", tc.name, tc.got.Structural, tc.structural)
		}
	}

	// denyReason and detail carry the SAME prose on both deny constructors (Query.kt:743,748).
	d := structuralDeny("because", nil, stageAdmission, nil)
	if d.DenyReason == nil || *d.DenyReason != "because" || d.Detail == nil || *d.Detail != "because" {
		t.Errorf("structuralDeny must set denyReason AND detail to the reason, got %v/%v", d.DenyReason, d.Detail)
	}
	// wireTaskForbiddenDeny's message is the constant, verbatim (F13 — English prose, not localised).
	w := WireTaskForbiddenDeny(nil, nil)
	if w.DenyReason == nil || *w.DenyReason != "automatic task approval is not permitted for this datasource" {
		t.Errorf("wireTaskForbiddenDeny reason = %v", w.DenyReason)
	}
	// passthroughAllow relays: no reason, no masks, passthrough set.
	p := passthroughAllow([]string{"analyst"}, "passthrough (readonly-meta)", []string{"t"})
	if p.DenyReason != nil || len(p.Masks) != 0 || !p.Passthrough {
		t.Errorf("passthroughAllow = %+v", p)
	}
	if p.Detail == nil || *p.Detail != "passthrough (readonly-meta)" {
		t.Errorf("passthroughAllow detail = %v", p.Detail)
	}
}

// grantAction — Query.kt:790-799. The five SQL kinds map; UNSPECIFIED, RESULT_READ and anything
// unrecognised do NOT, which step 15 turns into `policyDeny("statement kind 'other' is not permitted")`.
func TestGrantActionMapsOnlyTheFiveSQLKinds(t *testing.T) {
	for _, tc := range []struct {
		in   probepb.GrantAction
		want authz.AuthzAction
	}{
		{probepb.GrantAction_GRANT_ACTION_SQL_SELECT, authz.ActionSQLSelect},
		{probepb.GrantAction_GRANT_ACTION_SQL_INSERT, authz.ActionSQLInsert},
		{probepb.GrantAction_GRANT_ACTION_SQL_UPDATE, authz.ActionSQLUpdate},
		{probepb.GrantAction_GRANT_ACTION_SQL_DELETE, authz.ActionSQLDelete},
		{probepb.GrantAction_GRANT_ACTION_SQL_DDL, authz.ActionSQLDDL},
	} {
		got, ok := grantAction(tc.in)
		if !ok || got != tc.want {
			t.Errorf("grantAction(%v) = %q/%v, want %q/true", tc.in, got, ok, tc.want)
		}
	}
	for _, in := range []probepb.GrantAction{
		probepb.GrantAction_GRANT_ACTION_UNSPECIFIED,
		probepb.GrantAction_GRANT_ACTION_RESULT_READ,
		probepb.GrantAction(99), // the Go stand-in for Kotlin's UNRECOGNIZED
	} {
		if _, ok := grantAction(in); ok {
			t.Errorf("grantAction(%v) must not map", in)
		}
	}
}

// decisionRecord's shape — Query.kt:823-844. The EnfAction → Decision mapping is FAIL-CLOSED, and
// `maskedColumns` is the mask COLUMN NAMES, not the mask specs.
func TestDecisionRecordShapeAndFailClosedDecisionMapping(t *testing.T) {
	ds := datasource.Datasource{ID: 7, Name: "acme-pg", Engine: datasource.EnginePostgres}
	addr := "1.2.3.4"
	ord0, ord1 := int32(0), int32(1)
	ctx := DecisionContext{
		Action: pb.EnfAction_MASK,
		Masks: []*pb.ColumnMask{
			{Column: "rrn", MaskFn: "last4", Kind: "LAST_N", Ordinal: &ord0},
			{Column: "email", MaskFn: "redact", Kind: "NULL", Ordinal: &ord1},
		},
		PIITouched:     []string{"acme.public.users.rrn"},
		EffectiveRoles: []string{"analyst"},
		FailedStage:    nil,
		Detail:         strptr("synthetic"),
		ContextTags:    []string{"trusted-network"},
	}

	ev := DecisionRecord("analyst@example.com", ds, "SELECT rrn FROM users", &addr, ctx, 42, []string{"public"}, ChannelEditor)

	if ev.Principal != "analyst@example.com" || ev.Datasource != "acme-pg" || ev.Statement != "SELECT rrn FROM users" {
		t.Errorf("identity fields = %+v", ev)
	}
	if ev.Decision != types.DecisionMask {
		t.Errorf("decision = %v, want MASK", ev.Decision)
	}
	if len(ev.MaskedColumns) != 2 || ev.MaskedColumns[0] != "rrn" || ev.MaskedColumns[1] != "email" {
		t.Errorf("maskedColumns = %v, want the mask COLUMN names in order", ev.MaskedColumns)
	}
	if ev.ClientAddr == nil || *ev.ClientAddr != "1.2.3.4" || ev.LatencyMs != 42 {
		t.Errorf("clientAddr/latency = %v/%d", ev.ClientAddr, ev.LatencyMs)
	}
	if ev.Channel == nil || *ev.Channel != "editor" {
		t.Errorf("channel = %v, want \"editor\"", ev.Channel)
	}
	if len(ev.ContextTags) != 1 || ev.ContextTags[0] != "trusted-network" {
		t.Errorf("contextTags = %v — INV-A6-4 requires the derived tags on the row", ev.ContextTags)
	}
	if len(ev.EffectiveNamespace) != 1 || ev.EffectiveNamespace[0] != "public" {
		t.Errorf("effectiveNamespace = %v", ev.EffectiveNamespace)
	}
	if ev.Kind != types.DefaultAuditKind {
		t.Errorf("kind = %q, want %q", ev.Kind, types.DefaultAuditKind)
	}

	// 🔒 The fail-closed mapping. ALLOW and MASK pass; DENY, the proto3 zero AND an unrecognised
	// number all become DENY — never ALLOW.
	for _, tc := range []struct {
		in   pb.EnfAction
		want types.Decision
	}{
		{pb.EnfAction_ALLOW, types.DecisionAllow},
		{pb.EnfAction_MASK, types.DecisionMask},
		{pb.EnfAction_DENY, types.DecisionDeny},
		{pb.EnfAction_ENF_ACTION_UNSPECIFIED, types.DecisionDeny},
		{pb.EnfAction(42), types.DecisionDeny},
	} {
		got := DecisionRecord("p", ds, "s", nil, DecisionContext{Action: tc.in}, 0, nil, ChannelWire)
		if got.Decision != tc.want {
			t.Errorf("DecisionRecord(action=%v).Decision = %v, want %v", tc.in, got.Decision, tc.want)
		}
	}
}

// The channel model — 06-query-decision.md §1.
//
// 🔒 INV-A6-2 — only persistent-connection channels may pass through session statements. MCP is in
// the REFUSING set with the two workflow channels (§8 Q4 asked; step 14 answers yes).
func TestChannelContextValuesAndTheSessionPassthroughSet(t *testing.T) {
	for _, tc := range []struct {
		c     Channel
		value string
		holds bool
	}{
		{ChannelWire, "wire", true},
		{ChannelEditor, "editor", true},
		{ChannelWorkflowExecutor, "workflow-executor", false},
		{ChannelWorkflowViewer, "workflow-viewer", false},
		{ChannelMCP, "mcp", false},
	} {
		if tc.c.ContextValue() != tc.value {
			t.Errorf("%v.ContextValue() = %q, want %q", tc.c, tc.c.ContextValue(), tc.value)
		}
		if tc.c.holdsConnection() != tc.holds {
			t.Errorf("%v.holdsConnection() = %v, want %v", tc.c, tc.c.holdsConnection(), tc.holds)
		}
	}
	// 🔒 The zero Channel is not a channel. An int enum would have made it WIRE — the one channel that
	// MAY relay a session statement — so this asserts the fail-closed direction of the type choice.
	var zero Channel
	if zero.holdsConnection() {
		t.Fatal("the zero Channel must NOT hold a connection")
	}
}

// isMalformedDisposition — Query.kt:718-721, inverted for Go. Only the three declared dispositions are
// well-formed; the proto3 zero and any unrecognised number are malformed and fail closed at step 11.
func TestIsMalformedDispositionAcceptsOnlyTheThreeDeclaredValues(t *testing.T) {
	for _, d := range []probepb.MaskedDisposition{
		probepb.MaskedDisposition_MASKED_DISPOSITION_DENY_STATEMENT,
		probepb.MaskedDisposition_MASKED_DISPOSITION_MASK_OUTPUT,
		probepb.MaskedDisposition_MASKED_DISPOSITION_REDACT_OUTPUT_NULL,
	} {
		if isMalformedDisposition(d) {
			t.Errorf("%v must be well-formed", d)
		}
	}
	for _, d := range []probepb.MaskedDisposition{
		probepb.MaskedDisposition_MASKED_DISPOSITION_UNSPECIFIED,
		probepb.MaskedDisposition(77),
	} {
		if !isMalformedDisposition(d) {
			t.Errorf("%v must be malformed", d)
		}
	}
}
