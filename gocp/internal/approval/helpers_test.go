package approval

import (
	"reflect"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `ApprovalsTest.kt` — 55 LOC, 9 cases, pure unit, no DB (07-tasks-approvals-results.md §10).
//
// ORACLE: Approvals.kt:158-163 and :292-298.
// ---------------------------------------------------------------------------------------------

func denyEvent(principal string) *types.AuditEvent {
	ev := types.NewAuditEvent(principal, "ds", "SELECT 1", types.DecisionDeny)
	return &ev
}

// Case 1 — the requester's OWN DENY is a valid source.
// KT: ApprovalsTest.kt#ValidateApprovalSourceTest.own DENY is OK
func TestValidateApprovalSourceAcceptsAnOwnDeny(t *testing.T) {
	if got := ValidateApprovalSource(denyEvent("alice"), "alice"); got != SourceOK {
		t.Errorf("got %q, want %q", got, SourceOK)
	}
}

// Case 2 — a null source is NOT_FOUND.
// KT: ApprovalsTest.kt#ValidateApprovalSourceTest.null source is NOT_FOUND
func TestValidateApprovalSourceRejectsANullSourceAsNotFound(t *testing.T) {
	if got := ValidateApprovalSource(nil, "alice"); got != SourceNotFound {
		t.Errorf("got %q, want %q", got, SourceNotFound)
	}
}

// 🔒 Case 3 — ANOTHER PRINCIPAL'S DENY IS NOT_FOUND, not a 403.
//
// The distinction is the whole point: a 403 would confirm the decision id EXISTS, letting a caller
// enumerate other principals' decisions. Asserting only "it is refused" would pass for the leaky
// implementation too, so this asserts the exact discriminant.
// KT: ApprovalsTest.kt#ValidateApprovalSourceTest.another principal's DENY is NOT_FOUND
func TestValidateApprovalSourceHidesAnotherPrincipalsDenyAsNotFoundNotForbidden(t *testing.T) {
	got := ValidateApprovalSource(denyEvent("bob"), "alice")
	if got == SourceNotDeny {
		t.Fatal("a not-owned DENY leaked as NOT_DENY — that confirms the decision exists")
	}
	if got != SourceNotFound {
		t.Errorf("got %q, want %q", got, SourceNotFound)
	}
}

// Case 4 — the requester's own NON-deny decisions are NOT_DENY. Every non-DENY value, so a port that
// special-cased only ALLOW is caught.
// KT: ApprovalsTest.kt#ValidateApprovalSourceTest.own non-DENY decisions are NOT_DENY
func TestValidateApprovalSourceRejectsOwnNonDenyDecisions(t *testing.T) {
	for _, decision := range []types.Decision{types.DecisionAllow, types.DecisionMask, types.DecisionError} {
		t.Run(string(decision), func(t *testing.T) {
			ev := types.NewAuditEvent("alice", "ds", "SELECT 1", decision)
			if got := ValidateApprovalSource(&ev, "alice"); got != SourceNotDeny {
				t.Errorf("got %q, want %q", got, SourceNotDeny)
			}
		})
	}
}

// ⚠️ F15 — THE PINNED GAP. `Query.kt:818-820` says the minting path "must refuse rows with
// failed_stage='admission'", and ValidateApprovalSource does not check it. This test asserts the
// BUGGY behaviour on purpose (PORT POLICY: REPRODUCE + PIN), so closing the gap later has to change a
// test that says why it exists rather than silently altering behaviour.
//
// 07-tasks-approvals-results.md §11 Q1 owns the decision; §10 records that ApprovalsTest has no such
// case at all, which is exactly why one is added here.
func TestAnAdmissionStageDenyIsAcceptedAsASourceF15(t *testing.T) {
	ev := types.NewAuditEvent("alice", "ds", "not sql at all", types.DecisionDeny)
	stage := "admission"
	ev.FailedStage = &stage

	if got := ValidateApprovalSource(&ev, "alice"); got != SourceOK {
		t.Fatalf("F15 is REPRODUCE: an admission-stage DENY is still an acceptable source; got %q", got)
	}
}

// Cases 5-9 — validateProactiveCompose. 🔒 The ORDER is the contract: the response names ONE field
// and the console highlights it, so a fully empty form must name `datasourceId`, not `reason`.
//
// KT: ApprovalsTest.kt#ValidateProactiveComposeTest.missing datasource is invalid
// KT: ApprovalsTest.kt#ValidateProactiveComposeTest.blank sql is invalid
// KT: ApprovalsTest.kt#ValidateProactiveComposeTest.blank title is invalid
// KT: ApprovalsTest.kt#ValidateProactiveComposeTest.blank reason is invalid
// KT: ApprovalsTest.kt#ValidateProactiveComposeTest.complete proactive compose input is valid
func TestValidateProactiveComposeNamesTheFirstMissingFieldInOrder(t *testing.T) {
	id := int64(7)
	sql, title, reason := "SELECT 1", "t", "r"
	blank := "   "
	empty := ""

	tests := []struct {
		name               string
		datasourceID       *int64
		sql, title, reason *string
		want               string
	}{
		{"missing datasource", nil, &sql, &title, &reason, "datasourceId"},
		{"blank sql", &id, &blank, &title, &reason, "sql"},
		{"nil sql", &id, nil, &title, &reason, "sql"},
		// The Kotlin's `blank title is invalid` passes WHITESPACE, not "": `isNullOrBlank` covers both and
		// both are asserted here, so a port that only checked for the empty string is caught.
		{"blank title", &id, &sql, &blank, &reason, "title"},
		{"empty title", &id, &sql, &empty, &reason, "title"},
		{"blank reason", &id, &sql, &title, &blank, "reason"},
		{"complete input is valid", &id, &sql, &title, &reason, ""},
		// The ordering claim, stated as its own case: everything missing still names the FIRST field.
		{"everything missing names datasourceId first", nil, nil, nil, nil, "datasourceId"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidateProactiveCompose(test.datasourceID, test.sql, test.title, test.reason); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// `RoleDiscoveryTest.kt` — 86 LOC, 6 cases, unit (07 §10).
//
// ORACLE: Approvals.kt:97-114.
// ---------------------------------------------------------------------------------------------

// maskDecision builds an ALLOW/MASK DecisionContext masking the named output columns.
func maskDecision(columns ...string) query.DecisionContext {
	d := query.DecisionContext{Action: pb.EnfAction_ALLOW}
	for _, c := range columns {
		name := c
		d.Masks = append(d.Masks, &pb.ColumnMask{Column: name, MaskFn: "mask", Kind: "FIXED"})
	}
	if len(d.Masks) > 0 {
		d.Action = pb.EnfAction_MASK
	}
	return d
}

func denyDecision() query.DecisionContext {
	return query.DecisionContext{Action: pb.EnfAction_DENY}
}

// scriptedDecide answers per role-set, and RECORDS every set it was asked about — which is what
// case 6 asserts on.
type scriptedDecide struct {
	byKey map[string]query.DecisionContext
	asked [][]string
}

func (s *scriptedDecide) decide(roles []string) (query.DecisionContext, error) {
	s.asked = append(s.asked, append([]string(nil), roles...))
	key := keyOf(roles)
	if d, ok := s.byKey[key]; ok {
		return d, nil
	}
	return denyDecision(), nil
}

func keyOf(roles []string) string {
	out := ""
	for _, r := range roles {
		out += r + "|"
	}
	return out
}

// Case 1 — a role that unmasks a baseline-masked column is offered, WITH the unmasked column named.
//
// The Kotlin fixture is the THREE-role list (RoleDiscoveryTest.kt:28) and asserts the offer list is
// EXACTLY [pii-reader] — analyst is held, and auditor "still masks it (no improvement)"
// (RoleDiscoveryTest.kt:32) so it must be filtered in the same pass. A single-candidate fixture would
// pass with that filter broken, so the whole list is mirrored here.
// KT: RoleDiscoveryTest.kt#a role that unmasks a baseline-masked column is offered with the unmasked column
func TestARoleThatUnmasksABaselineMaskedColumnIsOffered(t *testing.T) {
	s := &scriptedDecide{byKey: map[string]query.DecisionContext{
		"analyst|":    maskDecision("rrn"), // the baseline: the requester's own role masks rrn
		"pii-reader|": maskDecision(),      // unmasks rrn → an improvement
		"auditor|":    maskDecision("rrn"), // returns the same → NOT an improvement
	}}
	allRoles := []Role{{ID: 1, Name: "analyst"}, {ID: 2, Name: "pii-reader"}, {ID: 3, Name: "auditor"}}
	got, err := DiscoverRoles([]string{"analyst"}, allRoles, s.decide)
	if err != nil {
		t.Fatalf("DiscoverRoles: %v", err)
	}
	if !got.BaselineAllowed {
		t.Error("baselineAllowed: got false, want true (the baseline was a MASK, not a DENY)")
	}
	want := []RoleOption{{RoleID: 2, RoleName: "pii-reader", UnmasksColumns: []string{"rrn"}}}
	if !reflect.DeepEqual(got.Options, want) {
		t.Errorf("options: got %#v, want %#v — only the role that returns MORE is offered", got.Options, want)
	}
}

// Case 2 — a role that returns exactly what the requester already sees is NOISE and is not offered.
// UPSTREAM-DELETED CASE — no traceability marker, deliberately.
//
// This ported `RoleDiscoveryTest`'s "a role that returns the same is not offered". The rebase onto main
// brought that suite's rework and the case is gone; the surviving names describe the OPPOSITE outcome for
// this input ("a role that runs the query but still masks is offered, marked masked"), i.e. a role
// producing the same masked view now appears to be OFFERED and labelled rather than withheld.
//
// 🔒 THE MARKER IS REMOVED RATHER THAN REPOINTED. The checker requires a cited case to exist, and
// repointing this at a case with the inverse expectation would be the WRONG-mapping class — a claim of
// coverage satisfied by a test asserting the opposite, which is worse than an admitted gap. The test
// below still PASSES because it pins the old behaviour; it must be re-derived from the reworked Kotlin,
// and until then this area is knowingly behind main.
func TestARoleThatReturnsTheSameIsNotOffered(t *testing.T) {
	s := &scriptedDecide{byKey: map[string]query.DecisionContext{
		"own|":       maskDecision("rrn"),
		"same-view|": maskDecision("rrn"),
	}}
	got, err := DiscoverRoles([]string{"own"}, []Role{{ID: 6, Name: "same-view"}}, s.decide)
	if err != nil {
		t.Fatalf("DiscoverRoles: %v", err)
	}
	if len(got.Options) != 0 {
		t.Errorf("a role returning the same view must not be offered; got %#v", got.Options)
	}
}

// Case 3 — a role under which Q is DENIED is not offered: R does not even let Q run.
// KT: RoleDiscoveryTest.kt#a role that denies the query is not offered
func TestARoleUnderWhichQIsDeniedIsNotOffered(t *testing.T) {
	s := &scriptedDecide{byKey: map[string]query.DecisionContext{
		"own|": maskDecision("rrn"),
		// "locked-down" is absent from the script ⇒ the default DENY.
	}}
	got, err := DiscoverRoles([]string{"own"}, []Role{{ID: 7, Name: "locked-down"}}, s.decide)
	if err != nil {
		t.Fatalf("DiscoverRoles: %v", err)
	}
	if len(got.Options) != 0 {
		t.Errorf("a role that denies Q must not be offered; got %#v", got.Options)
	}
}

// Case 4 — when the BASELINE is denied, a role that makes Q runnable is offered even though it
// unmasks nothing. `unmasksColumns` is then [], which is why RoleOption normalises nil → [].
// The Kotlin fixture again runs the whole three-role list under `if ("pii-reader" in r) ALLOW else
// DENY` (RoleDiscoveryTest.kt:63) and asserts the offer list is EXACTLY [pii-reader], so auditor —
// which also denies — has to be excluded from the SAME denied-baseline pass, where `baselineDenied`
// alone would otherwise be enough to offer it.
// KT: RoleDiscoveryTest.kt#when baseline is denied, a role that makes Q runnable is offered
func TestWhenTheBaselineIsDeniedARoleThatMakesQRunnableIsOffered(t *testing.T) {
	s := &scriptedDecide{byKey: map[string]query.DecisionContext{
		// analyst| (the baseline) and auditor| are absent ⇒ the default DENY.
		"pii-reader|": maskDecision(),
	}}
	allRoles := []Role{{ID: 1, Name: "analyst"}, {ID: 2, Name: "pii-reader"}, {ID: 3, Name: "auditor"}}
	got, err := DiscoverRoles([]string{"analyst"}, allRoles, s.decide)
	if err != nil {
		t.Fatalf("DiscoverRoles: %v", err)
	}
	if got.BaselineAllowed {
		t.Error("baselineAllowed must be false when the baseline DENIED")
	}
	want := []RoleOption{{RoleID: 2, RoleName: "pii-reader", UnmasksColumns: []string{}}}
	if !reflect.DeepEqual(got.Options, want) {
		t.Errorf("options: got %#v, want %#v", got.Options, want)
	}
}

// Case 5 — a role the requester ALREADY HOLDS is never offered, and — the part worth asserting —
// is never even PREVIEWED, since discovery would otherwise pay a decision per held role.
// KT: RoleDiscoveryTest.kt#a role the requester already holds is never offered
func TestARoleTheRequesterAlreadyHoldsIsNeverOfferedOrPreviewed(t *testing.T) {
	s := &scriptedDecide{byKey: map[string]query.DecisionContext{
		"own|": maskDecision("rrn"),
	}}
	got, err := DiscoverRoles([]string{"own"}, []Role{{ID: 9, Name: "own"}}, s.decide)
	if err != nil {
		t.Fatalf("DiscoverRoles: %v", err)
	}
	if len(got.Options) != 0 {
		t.Errorf("a held role must not be offered; got %#v", got.Options)
	}
	if len(s.asked) != 1 {
		t.Errorf("only the baseline should have been decided; asked %#v", s.asked)
	}
}

// 🔒 Case 6 — INV-A7-12, THE UNION TRAP. A candidate is previewed under R ALONE, never unioned with
// the requester's own roles.
//
// The script makes the two answers DIFFER: `{own, full-reader}` unmasks everything while
// `{full-reader}` alone still masks `rrn`. A union-previewing port therefore OFFERS the role (and
// claims it unmasks rrn), while the correct one does not — so the assertion cannot pass for the wrong
// implementation. Asserting the recorded role sets on top of that pins the mechanism, not just the
// outcome.
// KT: RoleDiscoveryTest.kt#a candidate is previewed under R ALONE, not unioned with the requester's own roles
func TestACandidateIsPreviewedUnderRAloneNotUnionedWithOwnRoles(t *testing.T) {
	s := &scriptedDecide{byKey: map[string]query.DecisionContext{
		"own|":             maskDecision("rrn"),
		"full-reader|":     maskDecision("rrn"), // R alone still masks ⇒ NOT an improvement
		"own|full-reader|": maskDecision(),      // the union would look like one
	}}

	got, err := DiscoverRoles([]string{"own"}, []Role{{ID: 10, Name: "full-reader"}}, s.decide)
	if err != nil {
		t.Fatalf("DiscoverRoles: %v", err)
	}
	if len(got.Options) != 0 {
		t.Fatalf("INV-A7-12: the candidate was previewed as a UNION with the requester's own roles "+
			"and offered a role that DENIES nothing extra under R alone; got %#v", got.Options)
	}
	for _, asked := range s.asked[1:] {
		if len(asked) != 1 || asked[0] != "full-reader" {
			t.Errorf("INV-A7-12: candidate previewed with role set %#v, want exactly [full-reader]", asked)
		}
	}
}

// A DECIDE FAILURE PROPAGATES rather than silently dropping a candidate. Kotlin lets decideQuery
// throw out of the closure, so the route answers 500; a Go port that swallowed the error would turn a
// database outage into a short offer list, which reads as "no roles would help".
func TestADecideFailurePropagatesRatherThanShorteningTheOfferList(t *testing.T) {
	boom := errorString("policy store is down")
	_, err := DiscoverRoles(nil, []Role{{ID: 1, Name: "r"}}, func([]string) (query.DecisionContext, error) {
		return query.DecisionContext{}, boom
	})
	if err == nil {
		t.Fatal("a decide failure must propagate, not be swallowed into an empty offer list")
	}
}
