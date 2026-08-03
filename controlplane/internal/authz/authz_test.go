package authz

import "testing"

// Port of AuthzTest.kt — 278 LOC, 14 cases, unit (in-memory CedarEngine), THE SEED ORACLE.
// 02-authz.md §10. Case names are verbatim from the Kotlin.

// AuthzTest.kt:28-34 — the seed policy set.
var authzTestSeedPolicies = map[int64]string{
	1: `permit(principal in Role::"system:admin", action in [Action::"admin.datasources",Action::"admin.policies",Action::"admin.identity"], resource);`,
	2: `forbid(principal, action == Action::"task.approve", resource) when { principal == resource.requester };`,
	3: `permit(principal in Role::"system:admin", action == Action::"task.approve", resource);`,
	4: `permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };`,
	5: `permit(principal in Role::"auditor", action == Action::"audit.read", resource);`,
}

// AuthzTest.kt:145-154 — a role-scoped approval grant.
var authzTestRoleScopedApproval = map[int64]string{
	1: `permit(principal in Role::"pii-reader", action == Action::"task.approve", resource) when { resource in Role::"pii-reader" };`,
}

// 1. system-admin is allowed on admin actions
func TestAuthz_SystemAdminIsAllowedOnAdminActions(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{"root": {"system:admin"}})
	for _, action := range []AuthzAction{ActionAdminPolicies, ActionAdminDatasources, ActionAdminIdentity} {
		assertAllow(t, a.Authorize("root", action, ResourceSystem{}, AuthzContext{}), string(action))
	}
}

// 2. 🔒 no roles is denied on admin actions — the "admin = any session" hole stays closed
func TestAuthz_NoRolesIsDeniedOnAdminActions(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{})
	d := a.Authorize("nobody", ActionAdminPolicies, ResourceSystem{}, AuthzContext{})
	assertDeny(t, d, "admin.policies with no roles")
	// The Kotlin oracle records the reason as branch 3: reasons are empty, so it is the
	// deny-by-default message rather than "denied by policy: …".
	if d.Reason != "no policy permits this action" {
		t.Errorf("reason = %q, want %q", d.Reason, "no policy permits this action")
	}
	if d.Code != "forbidden" {
		t.Errorf("code = %q, want %q", d.Code, "forbidden")
	}
}

// 3. a role other than system-admin is still denied on admin actions
func TestAuthz_ANonAdminRoleIsStillDeniedOnAdminActions(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{"analyst-alice": {"analyst"}})
	assertDeny(t, a.Authorize("analyst-alice", ActionAdminPolicies, ResourceSystem{}, AuthzContext{}), "analyst on admin.policies")
}

// 4. the audit policies allow own records and grant auditors the whole collection
//
// Pins the `resource is AuditRecord && resource.principal == principal` type-guard + narrowing shape,
// and AuditLog::"all" as a distinct type.
func TestAuthz_AuditPoliciesAllowOwnRecordsAndGrantAuditorsTheWholeCollection(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{
		"alice": {"analyst"},
		"bob":   {"auditor"},
	})
	assertAllow(t, a.Authorize("alice", ActionAuditRead, ResourceAuditRecord{Principal: "alice"}, AuthzContext{}), "alice on her own record")
	assertDeny(t, a.Authorize("alice", ActionAuditRead, ResourceAuditRecord{Principal: "bob"}, AuthzContext{}), "alice on bob's record")
	assertDeny(t, a.Authorize("alice", ActionAuditRead, ResourceAuditLog{}, AuthzContext{}), "alice on the whole log")
	assertAllow(t, a.Authorize("bob", ActionAuditRead, ResourceAuditRecord{Principal: "alice"}, AuthzContext{}), "auditor on alice's record")
	assertAllow(t, a.Authorize("bob", ActionAuditRead, ResourceAuditLog{}, AuthzContext{}), "auditor on the whole log")
}

// 5. an approver may approve someone else's request
//
// EUID is Request::"<requester>#<datasourceName ?: "-">" -> Request::"someone-else#-".
func TestAuthz_AnApproverMayApproveSomeoneElsesRequest(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{"approver1": {"system:admin"}})
	d := a.Authorize("approver1", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "someone-else"}, AuthzContext{})
	assertAllow(t, d, "system-admin approving someone else")
}

// 6. 🔒 ROLE self-approval is denied even for a system-admin — the self-approval hole stays closed
//
// Pins Cedar's forbid-overrides-permit precedence: forbid id 2 beats permit id 3.
//
// This is ALSO the case the errors-first mapping exists to protect (98-cedar-spike-report.md § S4): with
// the Request entity omitted or its `requester` attribute missing, the forbid ERRORS, cedar-go drops it,
// and the permit stands — a verdict-first port would Allow here. See errors_first_test.go.
func TestAuthz_RoleSelfApprovalIsDeniedEvenForASystemAdmin(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{"alice": {"system:admin"}})
	d := a.Authorize("alice", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "alice"}, AuthzContext{})
	assertDeny(t, d, "system-admin self-approval")
}

// 7. 🔒 a non-admin approving someone else's request is still denied — no ambient permit
func TestAuthz_ANonAdminApprovingSomeoneElsesRequestIsStillDenied(t *testing.T) {
	a := authzFor(t, authzTestSeedPolicies, map[string][]string{"bob": {}})
	assertDeny(t, a.Authorize("bob", ActionTaskApprove,
		ResourceApprovalRequest{Requester: "someone-else"}, AuthzContext{}), "non-admin approving")
}

// 8. an approval request scoped to a role is matched via `resource in Role` — Request carries the role
// as a Cedar parent
//
// S6 KEY CASE — this is the dedupeByEuid collision: the Request's Role parent (Role::"pii-reader") is
// the SAME EUID the principal already carries as a parent, so the entity list holds two distinct Entity
// objects for one EntityUID. cedar-java rejects that outright; the test asserts ALLOW, i.e. that
// dedupeByEuid PREVENTED the error. It does NOT assert the error itself.
func TestAuthz_AnApprovalRequestScopedToARoleIsMatchedViaResourceInRole(t *testing.T) {
	a := authzFor(t, authzTestRoleScopedApproval, map[string][]string{"approver1": {"pii-reader"}})
	d := a.Authorize("approver1", ActionTaskApprove, ResourceApprovalRequest{
		Requester: "someone-else",
		RoleName:  ptr("pii-reader"),
	}, AuthzContext{})
	assertAllow(t, d, "role-scoped approval matching the principal's own role")
}

// 9. a request scoped to a DIFFERENT role than the policy grants is denied — the Role parent is the
// request's, not ambient
func TestAuthz_ARequestScopedToADifferentRoleIsDenied(t *testing.T) {
	a := authzFor(t, authzTestRoleScopedApproval, map[string][]string{"approver1": {"pii-reader"}})
	d := a.Authorize("approver1", ActionTaskApprove, ResourceApprovalRequest{
		Requester: "someone-else",
		RoleName:  ptr("other-role"),
	}, AuthzContext{})
	assertDeny(t, d, "request scoped to other-role")
}

// 10. task lifecycle and grant revoke actions validate against the bundled schema
func TestAuthz_TaskLifecycleAndGrantRevokeActionsValidateAgainstTheBundledSchema(t *testing.T) {
	for _, src := range []string{
		`permit(principal, action == Action::"task.request", resource);`,
		`permit(principal, action == Action::"task.approve", resource);`,
		`permit(principal, action == Action::"task.read", resource);`,
		`permit(principal, action == Action::"task.assume", resource);`,
		`permit(principal, action == Action::"task.cancel", resource);`,
		`permit(principal, action == Action::"task.delete", resource);`,
		`permit(principal, action == Action::"grant.revoke", resource);`,
	} {
		assertValid(t, src)
	}
}

// 11. task assume seeds validate and allow only parties or auditor
//
// Pins the `resource has approver` guard and that an admin's task.read does NOT confer task.assume.
func TestAuthz_TaskAssumeSeedsValidateAndAllowOnlyPartiesOrAuditor(t *testing.T) {
	policies := map[int64]string{
		21: `permit(principal, action == Action::"task.assume", resource) when { resource is Request && (resource.requester == principal || (resource has approver && resource.approver == principal)) };`,
		22: `permit(principal in Role::"system:auditor", action == Action::"task.assume", resource) when { resource is Request };`,
		23: `permit(principal in Role::"system:admin", action == Action::"task.read", resource);`,
	}
	assertValid(t, policies[21])
	assertValid(t, policies[22])

	a := authzFor(t, policies, map[string][]string{
		"auditor@example.com": {"system:auditor"},
		"admin@example.com":   {"system:admin"},
	})
	resource := ResourceApprovalRequest{
		Requester:  "requester@example.com",
		Approver:   ptr("approver@example.com"),
		ExecutedBy: ptr("executor@example.com"),
	}
	assertAllow(t, a.Authorize("requester@example.com", ActionTaskAssume, resource, AuthzContext{}), "requester")
	assertAllow(t, a.Authorize("approver@example.com", ActionTaskAssume, resource, AuthzContext{}), "approver")
	assertAllow(t, a.Authorize("auditor@example.com", ActionTaskAssume, resource, AuthzContext{}), "auditor")
	assertDeny(t, a.Authorize("admin@example.com", ActionTaskAssume, resource, AuthzContext{}),
		"admin — task.read is not task.assume")
}

// 12. approval request marshals `executedBy` as a User attribute
//
// approver ABSENT here, executedBy present — pins the optional-attribute marshalling shape (INV-A2-3's
// sibling on Request).
func TestAuthz_ApprovalRequestMarshalsExecutedByAsAUserAttribute(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal, action == Action::"task.assume", resource) when { resource has executedBy && resource.executedBy == principal };`,
	}, map[string][]string{})
	d := a.Authorize("executor@example.com", ActionTaskAssume, ResourceApprovalRequest{
		Requester:  "requester@example.com",
		ExecutedBy: ptr("executor@example.com"),
	}, AuthzContext{})
	assertAllow(t, d, "executedBy match")
}

// 13. retired workflow action ids are rejected by the bundled schema
//
// S1/S2 KEY CASE — the ONLY place cedar-java's REJECT of an undeclared action is pinned at the
// CedarSchema.validate() level. The assertion is only isNotEmpty(): the error MESSAGE TEXT is never
// pinned, so cedar-go's wording is free to differ.
func TestAuthz_RetiredWorkflowActionIDsAreRejectedByTheBundledSchema(t *testing.T) {
	for _, src := range []string{
		`permit(principal, action == Action::"workflow.request", resource);`,
		`permit(principal, action == Action::"workflow.approve", resource);`,
		`permit(principal, action == Action::"workflow.read", resource);`,
		`permit(principal, action == Action::"workflow.readResult", resource);`,
		`permit(principal, action == Action::"workflow.revoke", resource);`,
	} {
		assertInvalid(t, src)
	}
}

// 14. an approval request scoped to a datasource is matched via `resource in Datasource` by NAME
//
// INV-A2-2: the Request EUID embeds the datasource NAME and the Datasource parent is NAME-keyed.
func TestAuthz_AnApprovalRequestScopedToADatasourceIsMatchedByName(t *testing.T) {
	a := authzFor(t, map[int64]string{
		1: `permit(principal in Role::"acme-approver", action == Action::"task.approve", resource) when { resource in Datasource::"acme-mysql" };`,
	}, map[string][]string{"approver1": {"acme-approver"}})

	assertAllow(t, a.Authorize("approver1", ActionTaskApprove, ResourceApprovalRequest{
		Requester:      "someone-else",
		DatasourceName: ptr("acme-mysql"),
	}, AuthzContext{}), "scoped to acme-mysql")

	assertDeny(t, a.Authorize("approver1", ActionTaskApprove, ResourceApprovalRequest{
		Requester:      "someone-else",
		DatasourceName: ptr("some-other-ds"),
	}, AuthzContext{}), "scoped to some-other-ds")
}
