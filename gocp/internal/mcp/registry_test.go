package mcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
)

// ---------------------------------------------------------------------------------------------
// A11 §1 — the catalog and `verify()`.
//
// The Kotlin's only coverage of this file is INDIRECT, through `McpServerDbTest` case 4 ("tool catalog
// is complete, localized, and scope cannot grant a write"), which asserts only that the advertised
// names equal `approvedToolNames`. §9's table records `McpCapabilityRegistry.verify()` as 136 LOC with
// "indirectly, case 4" for coverage. Everything below the first test is therefore NEW, and it exists
// because verify()'s six assertions are a BOOT GATE: a check that never fails in a test is
// indistinguishable from a check that cannot fail.
// ---------------------------------------------------------------------------------------------

func TestTheCatalogIsTheThirtyEightApprovedTools(t *testing.T) {
	if len(Entries) != 38 {
		t.Fatalf("catalog has %d tools, want 38", len(Entries))
	}
	if len(ApprovedToolNames) != 38 {
		t.Fatalf("approved list has %d names, want 38", len(ApprovedToolNames))
	}
	for _, name := range ApprovedToolNames {
		if _, ok := ByName[name]; !ok {
			t.Errorf("approved tool %q is not in the catalog", name)
		}
	}
	for name := range ByName {
		if !slices.Contains(ApprovedToolNames, name) {
			t.Errorf("catalog tool %q is not in the approved list", name)
		}
	}
}

// TestEveryCapabilityMatchesTheKotlinCatalogEntryByEntry is the assertion `McpServerDbTest` case 4
// does NOT make: it pins the ACTION, the SCOPE, the CLASSIFICATION and both annotation hints of all 38
// tools, not just their names.
//
// 🔒 Case 4 would still pass if `delete_policy` silently became `ADMIN_IDENTITY` or `mcp:read`. That is
// exactly the mistake this table catches, and it is the mistake with the largest blast radius in the
// file: the scope is what an OAuth consent grants and the action is what Cedar decides on.
func TestEveryCapabilityMatchesTheKotlinCatalogEntryByEntry(t *testing.T) {
	type want struct {
		action         authz.AuthzAction
		scope          string
		classification Classification
		destructive    bool
	}
	const (
		R = ClassificationRead
		W = ClassificationWrite
	)
	table := map[string]want{
		"list_datasources":            {authz.ActionAdminDatasources, ScopeRead, R, false},
		"get_datasource_liveness":     {authz.ActionAdminDatasources, ScopeRead, R, false},
		"browse_catalog":              {authz.ActionAdminDatasources, ScopeRead, R, false},
		"get_table_detail":            {authz.ActionAdminDatasources, ScopeRead, R, false},
		"list_column_tags":            {authz.ActionAdminDatasources, ScopeRead, R, false},
		"set_column_classification":   {authz.ActionAdminDatasources, ScopeDatasourcesWrite, W, false},
		"clear_column_classification": {authz.ActionAdminDatasources, ScopeDatasourcesWrite, W, true},

		"list_policies":     {authz.ActionAdminPolicies, ScopeRead, R, false},
		"get_policy":        {authz.ActionAdminPolicies, ScopeRead, R, false},
		"validate_policy":   {authz.ActionAdminPolicies, ScopeRead, R, false},
		"get_policy_schema": {authz.ActionAdminPolicies, ScopeRead, R, false},
		"create_policy":     {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"update_policy":     {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"enable_policy":     {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"disable_policy":    {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"delete_policy":     {authz.ActionAdminPolicies, ScopePoliciesWrite, W, true},

		// 🔒 F5, STRENGTHENED AND REPRODUCED: list_roles needs ADMIN_POLICIES here while A9's REST
		// GET /api/roles is gated only requireApi. Same data, two authority levels, by transport.
		"list_roles":            {authz.ActionAdminPolicies, ScopeRead, R, false},
		"create_role":           {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"update_role":           {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"delete_role":           {authz.ActionAdminPolicies, ScopePoliciesWrite, W, true},
		"list_role_assignments": {authz.ActionAdminIdentity, ScopeRead, R, false},
		"assign_role":           {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},
		"unassign_role":         {authz.ActionAdminIdentity, ScopeIdentityWrite, W, true},

		"list_users":          {authz.ActionAdminIdentity, ScopeRead, R, false},
		"create_user":         {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},
		"update_user":         {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},
		"deprovision_user":    {authz.ActionAdminIdentity, ScopeIdentityWrite, W, true},
		"list_groups":         {authz.ActionAdminIdentity, ScopeRead, R, false},
		"create_group":        {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},
		"update_group":        {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},
		"delete_group":        {authz.ActionAdminIdentity, ScopeIdentityWrite, W, true},
		"add_group_member":    {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},
		"remove_group_member": {authz.ActionAdminIdentity, ScopeIdentityWrite, W, true},
		"set_group_roles":     {authz.ActionAdminIdentity, ScopeIdentityWrite, W, false},

		"list_mask_fns":  {authz.ActionAdminPolicies, ScopeRead, R, false},
		"create_mask_fn": {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"update_mask_fn": {authz.ActionAdminPolicies, ScopePoliciesWrite, W, false},
		"delete_mask_fn": {authz.ActionAdminPolicies, ScopePoliciesWrite, W, true},
	}
	if len(table) != len(Entries) {
		t.Fatalf("expectation table has %d rows, catalog has %d", len(table), len(Entries))
	}
	for _, c := range Entries {
		w, ok := table[c.ToolName]
		if !ok {
			t.Errorf("%s: no expectation", c.ToolName)
			continue
		}
		if c.Action != w.action {
			t.Errorf("%s: action = %q, want %q", c.ToolName, c.Action, w.action)
		}
		if c.RequiredScope != w.scope {
			t.Errorf("%s: scope = %q, want %q", c.ToolName, c.RequiredScope, w.scope)
		}
		if c.Classification != w.classification {
			t.Errorf("%s: classification = %q, want %q", c.ToolName, c.Classification, w.classification)
		}
		if c.Annotations.DestructiveHint != w.destructive {
			t.Errorf("%s: destructiveHint = %v, want %v", c.ToolName, c.Annotations.DestructiveHint, w.destructive)
		}
		// readOnlyHint is derived from the constructor, so it must agree with the classification.
		if c.Annotations.ReadOnlyHint != (c.Classification == ClassificationRead) {
			t.Errorf("%s: readOnlyHint = %v but classification is %q",
				c.ToolName, c.Annotations.ReadOnlyHint, c.Classification)
		}
		if _, ok := c.Resource.(authz.ResourceSystem); !ok {
			t.Errorf("%s: resource = %T, want authz.ResourceSystem — every MCP capability is System-scoped",
				c.ToolName, c.Resource)
		}
	}
}

// TestExactlyEightToolsAreDestructive pins the destructive set as a COUNT as well as a list.
//
// ⚠️ 🔴 THE AREA DOC IS WRONG HERE AND THE CODE IS RIGHT. 11-mcp-oauth-management.md:31 says
// "`destructiveHint = true` on the 10 delete/deprovision/remove tools". Counting
// McpCapabilityRegistry.kt's `destructive = true` arguments gives EIGHT:
// clear_column_classification, delete_policy, delete_role, unassign_role, deprovision_user,
// delete_group, remove_group_member, delete_mask_fn. There are no other `delete_*` / `remove_*` /
// `deprovision_*` tools in the 38, so 10 cannot be reached by any reading of the catalog.
//
// Recorded rather than silently matched: the number in the spec is the kind of thing a later reader
// uses to decide the port dropped two tools.
func TestExactlyEightToolsAreDestructive(t *testing.T) {
	got := []string{}
	for _, c := range Entries {
		if c.Annotations.DestructiveHint {
			got = append(got, c.ToolName)
		}
	}
	slices.Sort(got)
	want := []string{
		"clear_column_classification", "delete_group", "delete_mask_fn", "delete_policy", "delete_role",
		"deprovision_user", "remove_group_member", "unassign_role",
	}
	if len(got) != 8 {
		t.Errorf("destructive tools = %v (%d)", got, len(got))
	}
	if !slices.Equal(got, want) {
		t.Errorf("destructive tools = %v, want %v", got, want)
	}
}

func TestTheFourScopesAreAdvertisedSorted(t *testing.T) {
	want := []string{"mcp:datasources:write", "mcp:identity:write", "mcp:policies:write", "mcp:read"}
	if !slices.Equal(SupportedScopes, want) {
		t.Errorf("SupportedScopes = %v, want %v", SupportedScopes, want)
	}
	// Every READ tool takes mcp:read; each WRITE takes its domain's write scope and never mcp:read.
	for _, c := range Entries {
		if c.Classification == ClassificationRead && c.RequiredScope != ScopeRead {
			t.Errorf("%s is READ but requires %q", c.ToolName, c.RequiredScope)
		}
		if c.Classification == ClassificationWrite && c.RequiredScope == ScopeRead {
			t.Errorf("%s is WRITE but requires only mcp:read — a read scope would grant a write", c.ToolName)
		}
	}
}

func TestVerifyPassesOnTheShippedCatalog(t *testing.T) {
	if err := Verify(); err != nil {
		t.Fatalf("Verify() on the shipped catalog: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// verify()'s six assertions, each with a NEGATIVE case.
//
// 🔒 These mutate the package-level catalog and restore it. That is deliberate and it is the only way
// to prove the boot gate BITES: `Verify()` reads package state, so a test that could not perturb that
// state could only ever re-assert that today's catalog is today's catalog.
// ---------------------------------------------------------------------------------------------

// restoreCatalog snapshots every var Verify reads and puts them back.
func restoreCatalog(t *testing.T) {
	t.Helper()
	inScope := slices.Clone(InScopeActions)
	excluded := slices.Clone(ExcludedActions)
	entries := slices.Clone(Entries)
	approved := slices.Clone(ApprovedToolNames)
	byName := ByName
	t.Cleanup(func() {
		InScopeActions, ExcludedActions, Entries, ApprovedToolNames, ByName = inScope, excluded, entries, approved, byName
	})
}

func TestVerifyRejectsOverlappingClassifications(t *testing.T) {
	restoreCatalog(t)
	ExcludedActions = append(slices.Clone(ExcludedActions), authz.ActionAdminPolicies)
	assertVerifyFails(t, "MCP action classifications overlap")
}

// TestVerifyRejectsAnUnclassifiedAuthzAction is 🔒 INV-A11-1 IN ITS ACTUAL FORM.
//
// It removes an action from `excludedActions` — which is EXACTLY what adding a new action to A2's enum
// looks like from `verify()`'s point of view: the union of in-scope and excluded no longer covers
// `AuthzAction.entries`. Boot must fail until someone classifies it.
//
// 🔒 It also fails if internal/authz's AllAuthzActions accessor is removed or narrowed, which is the
// other half of the invariant: the check is only real because it reads A2's enumeration rather than a
// local copy of it.
func TestVerifyRejectsAnUnclassifiedAuthzAction(t *testing.T) {
	restoreCatalog(t)
	dropped := ExcludedActions[len(ExcludedActions)-1]
	ExcludedActions = slices.Clone(ExcludedActions)[:len(ExcludedActions)-1]
	assertVerifyFails(t, "Every AuthzAction must be explicitly MCPA in-scope or deferred")
	if len(authz.AllAuthzActions()) != len(InScopeActions)+len(ExcludedActions)+1 {
		t.Fatalf("the premise broke: dropping %q should leave exactly one action unclassified", dropped)
	}
}

// TestVerifyRejectsAnExtraNameThatIsNotAnAuthzAction is the other direction of assertion 2. A typo in
// the excluded list ("sql.selct") would leave the real action unclassified AND add a phantom, keeping
// the SIZE right — so a size-only check would pass. This proves the membership check runs too.
func TestVerifyRejectsAnExtraNameThatIsNotAnAuthzAction(t *testing.T) {
	restoreCatalog(t)
	swapped := slices.Clone(ExcludedActions)
	swapped[len(swapped)-1] = authz.AuthzAction("sql.selct")
	ExcludedActions = swapped
	assertVerifyFails(t, "Every AuthzAction must be explicitly MCPA in-scope or deferred")
}

func TestVerifyRejectsAnInScopeActionWithNoTool(t *testing.T) {
	restoreCatalog(t)
	kept := []Capability{}
	for _, c := range Entries {
		if c.Action != authz.ActionAdminIdentity {
			kept = append(kept, c)
		}
	}
	Entries = kept
	ByName = buildByName()
	// The approved-set check would also fail; assert the ORDER of assertions puts this one first, which
	// is what makes the boot message name the real problem.
	assertVerifyFails(t, "Every in-scope MCPA action must have at least one tool")
}

func TestVerifyRejectsDuplicateToolNames(t *testing.T) {
	restoreCatalog(t)
	Entries = append(slices.Clone(Entries), Entries[0])
	ByName = buildByName()
	assertVerifyFails(t, "MCP tool names must be unique")
}

func TestVerifyRejectsABlankScope(t *testing.T) {
	restoreCatalog(t)
	mutated := slices.Clone(Entries)
	mutated[0].RequiredScope = "  "
	Entries = mutated
	ByName = buildByName()
	assertVerifyFails(t, "Every MCP tool must declare exactly one scope")
}

// TestVerifyRejectsAToolAddedToTheCatalogButNotReviewed is 🔒 INV-A11-2: `approvedToolNames` is a
// hardcoded duplicate ON PURPOSE and the duplication IS the review gate.
//
// 🔴 If someone ever "DRYs" ApprovedToolNames into a derivation of Entries, this test still passes
// while the gate is gone — so the assertion below ALSO checks that the two are independent, by adding
// a tool to Entries only and requiring boot to fail.
func TestVerifyRejectsAToolAddedToTheCatalogButNotReviewed(t *testing.T) {
	restoreCatalog(t)
	Entries = append(slices.Clone(Entries),
		write("drop_all_policies", authz.ActionAdminPolicies, ScopePoliciesWrite, true))
	ByName = buildByName()
	assertVerifyFails(t, "MCP tool catalog differs from the approved set")
}

func TestVerifyRejectsAnApprovedNameWithNoTool(t *testing.T) {
	restoreCatalog(t)
	ApprovedToolNames = append(slices.Clone(ApprovedToolNames), "a_tool_that_was_removed")
	assertVerifyFails(t, "MCP tool catalog differs from the approved set")
}

func assertVerifyFails(t *testing.T, wantContains string) {
	t.Helper()
	err := Verify()
	if err == nil {
		t.Fatalf("Verify() returned nil; want a failure containing %q", wantContains)
	}
	if !strings.Contains(err.Error(), wantContains) {
		t.Fatalf("Verify() = %q, want it to contain %q", err.Error(), wantContains)
	}
}

// TestNewRefusesToBootOnACatalogMismatch closes the loop from [Verify] to the boot path: the check is
// worthless if the constructor does not call it.
//
//	🔒 internal/app MUST treat this error as FATAL.
func TestNewRefusesToBootOnACatalogMismatch(t *testing.T) {
	restoreCatalog(t)
	ApprovedToolNames = slices.Clone(ApprovedToolNames)[:10]
	if _, err := New(Options{}); err == nil {
		t.Fatal("New() booted with a catalog that does not match the approved set")
	}
}
