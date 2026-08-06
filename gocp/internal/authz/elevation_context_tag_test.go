package authz

import (
	"sync/atomic"
	"testing"
)

// Port of ElevationContextTagTest.kt — 178 LOC, 7 cases, unit. 02-authz.md §10.
// Case names verbatim from the Kotlin. These exercise the FULL two-pass through AuthorizeWithContext.

// ElevationContextTagTest.kt:46-53 — a producer/consumer tag pair.
var elevationTagPair = map[int64]string{
	1: `permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
	2: `permit(principal in Role::"reviewer", action == Action::"task.approve", resource) when { context has tags && context.tags.contains("trusted-network") };`,
}

// 1. `rolesOf` exposes the wired `RoleSource`
//
// No Cedar involved — a pure accessor test.
// KT: ElevationContextTagTest.kt#rolesOf exposes the wired RoleSource
func TestElevation_RolesOfExposesTheWiredRoleSource(t *testing.T) {
	a := authzFor(t, elevationTagPair, map[string][]string{
		"alice": {"analyst", "approver"},
	})
	assertStrings(t, a.RolesOf("alice"), []string{"analyst", "approver"}, "rolesOf(alice)")
	if got := a.RolesOf("nobody"); len(got) != 0 {
		t.Errorf("rolesOf(nobody) = %v, want empty", got)
	}
}

// 2. a `requester_ip`-derived tag gates a `TASK_APPROVE` elevation decision
// KT: ElevationContextTagTest.kt#a requester_ip-derived tag gates a TASK_APPROVE elevation decision (Access-kt Approvals-kt shape)
func TestElevation_ARequesterIPDerivedTagGatesATaskApproveDecision(t *testing.T) {
	a := authzFor(t, elevationTagPair, map[string][]string{"approver": {"reviewer"}})
	resource := ResourceApprovalRequest{Requester: "requester", DatasourceName: ptr("acme-prod")}

	inRange := a.AuthorizeWithContext("approver", ActionTaskApprove, resource,
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, ptr("acme-prod"), nil)
	assertAllow(t, inRange, "requesterIp 100.100.5.5 earns trusted-network")

	outOfRange := a.AuthorizeWithContext("approver", ActionTaskApprove, resource,
		AuthzContext{RequesterIP: ptr("10.0.0.1")}, ptr("acme-prod"), nil)
	assertDeny(t, outOfRange, "requesterIp 10.0.0.1 earns nothing")
}

// 3. 🔒 a null datasource derives no tags — a tag-conditioned permit fails closed (INV-A2-14)
//
// INV-A2-14 half 1: no pseudo-datasource is synthesised. Pass 1 does not run at all, so tags stays
// empty even though the raw signal WOULD have earned the tag.
// KT: ElevationContextTagTest.kt#a null datasource derives no tags — a tag-conditioned permit fails closed
func TestElevation_ANullDatasourceDerivesNoTags(t *testing.T) {
	a := authzFor(t, elevationTagPair, map[string][]string{"approver": {"reviewer"}})
	d := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester"},
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil, nil)
	assertDeny(t, d, "nil datasourceName with an in-range ip")
}

// 4. a null datasource still passes `requester_ip` through to Cedar (INV-A2-14)
//
// INV-A2-14 half 2: raw signals still reach Cedar with no datasource in scope — only `tags` is empty.
// KT: ElevationContextTagTest.kt#a null datasource still passes requester_ip through to Cedar
func TestElevation_ANullDatasourceStillPassesRequesterIPThroughToCedar(t *testing.T) {
	a := authzFor(t, map[int64]string{
		3: `permit(principal in Role::"reviewer", action == Action::"task.approve", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
	}, map[string][]string{"approver": {"reviewer"}})

	d := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester"},
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, nil, nil)
	assertAllow(t, d, "nil datasourceName, ip-conditioned permit")
}

// 5. a datasource-scoped tag rule fires only for the datasource in scope
// KT: ElevationContextTagTest.kt#a datasource-scoped tag rule fires only for the datasource in scope
func TestElevation_ADatasourceScopedTagRuleFiresOnlyForTheDatasourceInScope(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"context.tag::trusted-network", resource == Datasource::"acme-prod") when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`,
		2: `permit(principal in Role::"reviewer", action == Action::"task.approve", resource) when { context has tags && context.tags.contains("trusted-network") };`,
	}, map[string][]string{"approver": {"reviewer"}})

	raw := AuthzContext{RequesterIP: ptr("100.100.5.5")}

	matched := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester", DatasourceName: ptr("acme-prod")},
		raw, ptr("acme-prod"), nil)
	assertAllow(t, matched, "acme-prod is the scoped datasource")

	other := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester", DatasourceName: ptr("other-ds")},
		raw, ptr("other-ds"), nil)
	assertDeny(t, other, "other-ds is out of the rule's scope")
}

// 6. `datasourceTags` reach the tag rule's `Datasource` entity (preset posture)
//
// Pass-1's Datasource entity carries posture Tag parents; INV-A2-7's filter applies there too.
// KT: ElevationContextTagTest.kt#datasourceTags reach the tag rule's Datasource entity (preset posture)
func TestElevation_DatasourceTagsReachTheTagRulesDatasourceEntity(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"context.tag::trusted-network", resource) when { resource in Tag::"system:development" };`,
		2: `permit(principal in Role::"reviewer", action == Action::"task.approve", resource) when { context has tags && context.tags.contains("trusted-network") };`,
	}, map[string][]string{"approver": {"reviewer"}})

	dev := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester", DatasourceName: ptr("acme-dev")},
		AuthzContext{}, ptr("acme-dev"), []string{"system:development"})
	assertAllow(t, dev, "acme-dev tagged system:development")

	prod := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester", DatasourceName: ptr("acme-prod")},
		AuthzContext{}, ptr("acme-prod"), nil)
	assertDeny(t, prod, "acme-prod with no posture tag")
}

// 7. 🔒 tag derivation and final authorization share ONE role snapshot — no second, disagreeing
// resolution (INV-A2-10)
//
// The RoleSource is deliberately FLAKY: it returns {reviewer} on call #1 and {} on every later call. If
// AuthorizeWithContext resolved roles twice, pass 2 would see an empty role set and DENY. Asserting both
// the Allow and the call count is what pins the invariant — the Allow alone would not distinguish a
// second resolution that happened to agree.
// KT: ElevationContextTagTest.kt#tag derivation and final authorization share ONE role snapshot — no second, disagreeing resolution
func TestElevation_TagDerivationAndFinalAuthorizationShareOneRoleSnapshot(t *testing.T) {
	var calls atomic.Int32
	flaky := RoleSourceFunc(func(principal string) []string {
		if calls.Add(1) == 1 {
			return []string{"reviewer"}
		}
		return nil
	})
	a := New(engineFor(t, elevationTagPair), nil, flaky)

	d := a.AuthorizeWithContext("approver", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "requester", DatasourceName: ptr("acme-prod")},
		AuthzContext{RequesterIP: ptr("100.100.5.5")}, ptr("acme-prod"), nil)
	assertAllow(t, d, "one role snapshot threaded through both passes")

	if got := calls.Load(); got != 1 {
		t.Errorf("INV-A2-10: RoleSource invoked %d times, want exactly 1", got)
	}
}
