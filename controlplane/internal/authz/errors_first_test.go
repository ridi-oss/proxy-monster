package authz

import (
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// 🔴 REPRODUCE + PIN — the errors-first mapping (98-cedar-spike-report.md § S4, work item W1).
//
// NO KOTLIN TEST PINS THIS. The spike grepped control-plane/src/test for "authorization engine error",
// "denied by policy" and "no policy permits this action" and found zero hits; the only hits are
// Authz.kt:270 and :276 in main. Under PORT POLICY that makes this a REPRODUCE + PIN item: write the
// assertion the Kotlin suite never had, because getting it backwards is FAIL-OPEN and nothing else
// would catch it.
//
// The fork exists because the two engines have different error models. cedar-java's
// AuthorizationResponse is present-or-absent — an engine error means NO success payload — so "errored"
// and "allowed" are mutually exclusive. cedar-go's Diagnostic.Errors is a separate slice, PER-POLICY and
// NON-FATAL: it can return Allow AND an error at the same time.

// errorsFirstSeed is the shipped self-approval pair: the system:no-self-approval FORBID and the
// system:admin PERMIT, matching migration rows -2 and -3 (and AuthzTest.seedPolicies ids 2 and 3).
var errorsFirstSeed = []PolicySource{
	{ID: -2, Src: `forbid(principal, action == Action::"task.approve", resource) when { principal == resource.requester };`},
	{ID: -3, Src: `permit(principal in Role::"system:admin", action == Action::"task.approve", resource);`},
}

// authorizeRaw drives the engine directly, so a test can construct the entity-marshalling failure the
// port is most likely to introduce — a MISSING or INCOMPLETE resource entity — which AuthorizeAs itself
// can never produce.
func authorizeRaw(t *testing.T, entities types.EntityMap) (types.Decision, types.Diagnostic) {
	t.Helper()
	e, err := NewCedarEngineFromSources(errorsFirstSeed)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	d, diag, err := e.Authorize(
		types.NewEntityUID(typeUser, "alice"),
		types.NewEntityUID(typeAction, "task.approve"),
		types.NewEntityUID(typeRequest, "alice#-"),
		entities,
		AuthzContext{}.ToCedarMap(true),
	)
	if err != nil {
		t.Fatalf("engine error: %v", err)
	}
	return d, diag
}

// alicePrincipal is the User entity carrying system:admin, as principalEntities builds it.
func alicePrincipal() []types.Entity {
	_, principal, roles := principalEntities("alice", []string{"system:admin"})
	return append([]types.Entity{principal}, roles...)
}

// TestErrorsFirst_TheHealthyBaselineDenies is the control: with the Request entity present and complete,
// the FORBID evaluates cleanly and wins. This is AuthzTest case 6's oracle, and it must hold before the
// error cases below mean anything.
func TestErrorsFirst_TheHealthyBaselineDenies(t *testing.T) {
	_, resourceEntities := marshalResource(ResourceApprovalRequest{Requester: "alice"})
	entities := dedupeEntities(alicePrincipal(), resourceEntities)

	d, diag := authorizeRaw(t, entities)
	if d != cedar.Deny {
		t.Fatalf("healthy baseline: decision = %v, want Deny", d)
	}
	if len(diag.Errors) != 0 {
		t.Fatalf("healthy baseline: unexpected errors %v", diag.Errors)
	}
	assertDeny(t, toAuthzDecision(d, diag, nil), "healthy baseline")
}

// TestErrorsFirst_AnErroringForbidMustNotBecomeAnAllow is the whole point.
//
// With the Request entity OMITTED from the batch, the FORBID (-2) errors on `resource.requester`,
// cedar-go DROPS it, and the PERMIT (-3) stands. cedar-go therefore reports:
//
//	decision = Allow, reasons = [policy--3], errors = [policy--2: entity `Request::"alice#-"` does not exist]
//
// A verdict-first mapping would return Allow here — letting a system-admin approve their own request,
// precisely the hole AuthzTest case 6 exists to keep closed. Errors-first returns Deny.
func TestErrorsFirst_AnErroringForbidMustNotBecomeAnAllow(t *testing.T) {
	entities := dedupeEntities(alicePrincipal()) // Request entity deliberately absent

	d, diag := authorizeRaw(t, entities)

	// First pin the PREMISE, so this test still fails loudly if a future cedar-go stops producing the
	// Allow+error state rather than silently passing for the wrong reason.
	if d != cedar.Allow {
		t.Fatalf("premise changed: cedar-go returned %v, expected Allow (the raw verdict the forbid's "+
			"error leaves standing). Re-derive the mapping before trusting this test.", d)
	}
	if len(diag.Errors) == 0 {
		t.Fatal("premise changed: expected a non-empty Diagnostic.Errors from the dropped forbid")
	}

	// Now the mapping itself.
	got := toAuthzDecision(d, diag, nil)
	if got.Allowed {
		t.Fatal("🔴 FAIL-OPEN: errors-first was not applied — a system-admin can self-approve. " +
			"len(Diagnostic.Errors) > 0 MUST deny, before the verdict is read.")
	}
	if !strings.HasPrefix(got.Reason, "authorization engine error: ") {
		t.Errorf("reason = %q, want the Kotlin branch-1 prefix %q", got.Reason, "authorization engine error: ")
	}
}

// TestErrorsFirst_AMissingRequiredAttributeIsAlsoAnError is the second replay from the spike: the
// Request entity is PRESENT but its schema-required `requester` attribute is missing. Same outcome, and
// it is a distinct failure mode from a wholly absent entity.
func TestErrorsFirst_AMissingRequiredAttributeIsAlsoAnError(t *testing.T) {
	reqEuid := types.NewEntityUID(typeRequest, "alice#-")
	entities := dedupeEntities(alicePrincipal(), []types.Entity{{UID: reqEuid}})

	d, diag := authorizeRaw(t, entities)
	if d != cedar.Allow || len(diag.Errors) == 0 {
		t.Fatalf("premise changed: decision=%v errors=%v", d, diag.Errors)
	}
	assertDeny(t, toAuthzDecision(d, diag, nil), "Request present, `requester` missing")
}

// TestErrorsFirst_AppliesAtTheBatchCallSites — W1 requires the mapping at toAuthzDecision AND at all
// five batch call sites (Authz.kt:525, 603, 672, 737, 825), which read the verdict inline rather than
// through toAuthzDecision. allowedByCedar is the single helper all five share, so pinning it pins them.
func TestErrorsFirst_AppliesAtTheBatchCallSites(t *testing.T) {
	entities := dedupeEntities(alicePrincipal())
	d, diag := authorizeRaw(t, entities)

	if allowedByCedar(d, diag, nil) {
		t.Fatal("🔴 FAIL-OPEN: the batch verdict helper let an Allow-with-errors through")
	}
	// And it must not be denying everything — the healthy Allow path still has to work.
	if !allowedByCedar(cedar.Allow, types.Diagnostic{Reasons: []types.DiagnosticReason{{PolicyID: "policy--3"}}}, nil) {
		t.Error("allowedByCedar denied a clean Allow")
	}
}

// TestErrorsFirst_PassOneIsFailClosed — 🔒 INV-A2-13. A tag exists only if a rule PERMITTED it; an
// engine error is a NON-ALLOW, so the tag is ABSENT, never "present on error".
//
// This is the pass-1 analogue of the self-approval replay, and it is built to DISCRIMINATE: an erroring
// rule on its own would deny anyway, so the fixture pairs a clean PERMIT with a FORBID that errors. The
// operator's intent is "grant trusted-network, except under <condition>"; the forbid's condition
// overflows at evaluation, cedar-go drops the forbid, and the permit stands:
//
//	decision=allow  reasons=[policy-1]  errors=[policy-2: integer overflow ...]
//
// Verdict-first would EARN the tag from a policy set whose withholding rule silently failed. Errors-first
// withholds it. The overflow is a synthetic trigger for a real class — the spike found 10 enabled shipped
// rows with an unguarded read of a schema-required attribute, 2 of them FORBIDs.
func TestErrorsFirst_PassOneIsFailClosed(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
		2: `forbid(principal, action == Action::"context.tag::trusted-network", resource) when { 9223372036854775807 + 1 == 0 };`,
	}, nil)

	// Premise: both rules load (they validate), and the permit alone WOULD earn the tag — proven by
	// TestTagResolution_ATagRuleLoadsThoughItsActionIsNotPredefinedAndFires on the same permit.
	got := a.ResolveContextTags("alice", nil, "acme-prod",
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil)
	if len(got) != 0 {
		t.Errorf("🔴 INV-A2-13 violated: pass 1 earned %v while the withholding forbid was erroring. "+
			"A tag must never be present on error.", got)
	}
}

// TestErrorsFirst_BranchesTwoThreeAndFour pins the branches that DO have a state-for-state cedar-java
// counterpart. The spike verified each of these reproduces byte-exact.
func TestErrorsFirst_BranchesTwoThreeAndFour(t *testing.T) {
	// branch 2 — Allow
	if got := toAuthzDecision(cedar.Allow, types.Diagnostic{}, nil); !got.Allowed {
		t.Error("branch 2: a clean Allow must map to Allow")
	}
	// branch 3 — Deny with no reasons
	if got := toAuthzDecision(cedar.Deny, types.Diagnostic{}, nil); got.Reason != "no policy permits this action" {
		t.Errorf("branch 3: reason = %q", got.Reason)
	}
	// branch 4 — Deny carrying the diagnosing policy ids, comma-joined
	got := toAuthzDecision(cedar.Deny, types.Diagnostic{Reasons: []types.DiagnosticReason{
		{PolicyID: "policy--2"}, {PolicyID: "policy--258"},
	}}, nil)
	if got.Reason != "denied by policy: policy--2, policy--258" {
		t.Errorf("branch 4: reason = %q", got.Reason)
	}
}
