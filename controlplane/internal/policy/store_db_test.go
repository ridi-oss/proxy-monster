package policy

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A9's DB-backed suite. 🔴 EVERY CASE HERE IS NEW.
//
// 09-policies.md §4 / 00-INDEX.md F10: there is NO Kotlin test to port. No test file HTTP-calls
// /api/roles, /api/role-assignments or /api/mask-fns, and there is no PolicyStoreTest — PolicyStore
// appears in ~36 Kotlin suites *exclusively as a fixture*. So the usual method (1:1 migration) has
// nothing to migrate, the area doc is the sole specification, and these tests are written against
// §1-§3 of it.
//
// §4.3 asks Step 3 for four things on the store side, and they are the four this file leads with:
// the CRUD, isSystemRole against a SYSTEM-sourced group, the ON CONFLICT idempotency of
// createAssignment, and — F34 — the six SYSTEM groups no Kotlin test ever names.
// ---------------------------------------------------------------------------------------------

type policyFixture struct {
	t     testing.TB
	ctx   context.Context
	db    *store.Db
	store *PolicyStore
}

func newPolicyFixture(t testing.TB) *policyFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &policyFixture{t: t, ctx: context.Background(), db: db, store: NewPolicyStore(db.Pool)}
}

func (f *policyFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (f *policyFixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}

// mustCreateRole is CreateRole with the error fataled.
func (f *policyFixture) mustCreateRole(name string, description *string) Role {
	f.t.Helper()
	role, err := f.store.CreateRole(f.ctx, RoleInput{Name: name, Description: description})
	if err != nil {
		f.t.Fatalf("createRole %s: %v", name, err)
	}
	return role
}

// sameRole compares two Roles by VALUE. Role.Description is a *string (Kotlin's `String? = null`
// under explicitNulls = false), so `==` would compare pointer identity and two reads of the same row
// would never be equal.
func sameRole(a, b Role) bool {
	if a.ID != b.ID || a.Name != b.Name {
		return false
	}
	if (a.Description == nil) != (b.Description == nil) {
		return false
	}
	return a.Description == nil || *a.Description == *b.Description
}

// showRole renders a Role with its description dereferenced, so a failure message is readable.
func showRole(r *Role) string {
	if r == nil {
		return "<nil>"
	}
	desc := "<nil>"
	if r.Description != nil {
		desc = strconv.Quote(*r.Description)
	}
	return fmt.Sprintf("{ID:%d Name:%q Description:%s}", r.ID, r.Name, desc)
}

// systemGroup inserts an `app_group` with source='SYSTEM' — the only thing isSystemRole keys on.
//
// dbtest.Seed.Group() takes the column default (LOCAL), and deliberately so: a fixture that could
// mint a SYSTEM group casually is a fixture that hides which tests are actually about the guard.
func (f *policyFixture) systemGroup(name string) int64 {
	f.t.Helper()
	return f.scalarInt64(`INSERT INTO app_group (name, source) VALUES ($1, 'SYSTEM') RETURNING id`, name)
}

// ---- Roles -----------------------------------------------------------------------------------

// The migration seeds twelve roles (V8__seed.sql:27-39) and every one of them is visible to
// listRoles: A9's store applies no filter of any kind, so a "system" role is an ordinary row here.
func TestPolicyStore_ListRolesIsOrderedByNameAndHidesNothing(t *testing.T) {
	f := newPolicyFixture(t)

	f.mustCreateRole("zulu", nil)
	f.mustCreateRole("alpha", nil)

	roles, err := f.store.ListRoles(f.ctx)
	if err != nil {
		t.Fatalf("listRoles: %v", err)
	}
	if len(roles) != 14 {
		t.Errorf("listRoles returned %d roles, want 14 (12 seeded + 2 created)", len(roles))
	}

	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	if !slices.IsSorted(names) {
		t.Errorf("listRoles is not ORDER BY name: %v", names)
	}
	// INV-A3-14's rule reaches here too: web/ renders this list directly, so the order is contractual.
	if names[0] != "alpha" {
		t.Errorf("listRoles[0] = %q, want alpha", names[0])
	}
	if !slices.Contains(names, "system:admin") {
		t.Error("listRoles omitted system:admin: the store applies no filter, system roles included")
	}
}

func TestPolicyStore_RoleCRUDRoundTrip(t *testing.T) {
	f := newPolicyFixture(t)

	created := f.mustCreateRole("analyst", types.Ptr("reads the warehouse"))
	if created.ID == 0 || created.Name != "analyst" ||
		created.Description == nil || *created.Description != "reads the warehouse" {
		t.Fatalf("createRole returned %+v, want the re-read row", created)
	}

	byID, err := f.store.GetRole(f.ctx, created.ID)
	if err != nil {
		t.Fatalf("getRole: %v", err)
	}
	if byID == nil || !sameRole(*byID, created) {
		t.Errorf("getRole(%d) = %s, want %s", created.ID, showRole(byID), showRole(&created))
	}

	byName, err := f.store.GetRoleByName(f.ctx, "analyst")
	if err != nil {
		t.Fatalf("getRoleByName: %v", err)
	}
	if byName == nil || !sameRole(*byName, created) {
		t.Errorf("getRoleByName(analyst) = %s, want %s", showRole(byName), showRole(&created))
	}

	// A null description round-trips as nil, not "".
	noDesc := f.mustCreateRole("bare", nil)
	if noDesc.Description != nil {
		t.Errorf("createRole with no description = %+v, want Description nil", noDesc)
	}

	// updateRole rewrites BOTH columns and re-reads — including clearing the description.
	updated, err := f.store.UpdateRole(f.ctx, created.ID, RoleInput{Name: "analyst-2"})
	if err != nil {
		t.Fatalf("updateRole: %v", err)
	}
	if updated == nil || updated.Name != "analyst-2" || updated.Description != nil {
		t.Errorf("updateRole = %+v, want name analyst-2 and a cleared description", updated)
	}
	if updated.ID != created.ID {
		t.Errorf("updateRole changed the id: %d → %d", created.ID, updated.ID)
	}

	deleted, err := f.store.DeleteRole(f.ctx, created.ID)
	if err != nil {
		t.Fatalf("deleteRole: %v", err)
	}
	if !deleted {
		t.Error("deleteRole = false for a row that existed, want true")
	}
	gone, err := f.store.GetRole(f.ctx, created.ID)
	if err != nil {
		t.Fatalf("getRole after delete: %v", err)
	}
	if gone != nil {
		t.Errorf("getRole after delete = %+v, want nil", gone)
	}
}

// The absent-id answers are the ones A11 turns into 404 / "no change", so they are contractual:
// getRole nil, getRoleByName nil, updateRole nil (NOT an error, and no UPDATE runs), deleteRole false.
func TestPolicyStore_RoleAbsentIDAnswers(t *testing.T) {
	f := newPolicyFixture(t)

	const missing = int64(999_999)

	if got, err := f.store.GetRole(f.ctx, missing); err != nil || got != nil {
		t.Errorf("getRole(absent) = %+v, %v; want nil, nil", got, err)
	}
	if got, err := f.store.GetRoleByName(f.ctx, "no-such-role"); err != nil || got != nil {
		t.Errorf("getRoleByName(absent) = %+v, %v; want nil, nil", got, err)
	}
	if got, err := f.store.UpdateRole(f.ctx, missing, RoleInput{Name: "x"}); err != nil || got != nil {
		t.Errorf("updateRole(absent) = %+v, %v; want nil, nil", got, err)
	}
	if got, err := f.store.DeleteRole(f.ctx, missing); err != nil || got {
		t.Errorf("deleteRole(absent) = %v, %v; want false, nil", got, err)
	}
}

// ---- isSystemRole — INV-A9-1 and F34 ---------------------------------------------------------

// TestPolicyStore_IsSystemRoleIsDerivedNotStored is 🔒 INV-A9-1.
//
// A role is a system role IFF at least one group with source='SYSTEM' grants it. There is no
// `app_role.is_system` column, and the consequence — which is the whole reason the invariant is
// flagged — is that the answer MOVES as group_role mappings change. A port that added a stored flag
// would pass the first two assertions here and fail the last two.
func TestPolicyStore_IsSystemRoleIsDerivedNotStored(t *testing.T) {
	f := newPolicyFixture(t)

	role := f.mustCreateRole("toggles", nil)
	isSystem := func() bool {
		t.Helper()
		got, err := f.store.IsSystemRole(f.ctx, role.ID)
		if err != nil {
			t.Fatalf("isSystemRole: %v", err)
		}
		return got
	}

	if isSystem() {
		t.Error("a role granted by no group at all is a system role, want false")
	}

	// A LOCAL group granting it changes nothing — the predicate is on g.source, not on the link.
	localGroup := f.scalarInt64(`INSERT INTO app_group (name) VALUES ('local-team') RETURNING id`)
	f.exec(`INSERT INTO group_role (group_id, role_id) VALUES ($1, $2)`, localGroup, role.ID)
	if isSystem() {
		t.Error("a role granted only by a source=LOCAL group is a system role, want false")
	}

	// Add a SYSTEM group and it becomes one.
	sysGroup := f.systemGroup("system:toggle-owner")
	f.exec(`INSERT INTO group_role (group_id, role_id) VALUES ($1, $2)`, sysGroup, role.ID)
	if !isSystem() {
		t.Error("a role granted by a source=SYSTEM group is not a system role, want true")
	}

	// Remove that one link and it stops being one — derived, not stored.
	f.exec(`DELETE FROM group_role WHERE group_id = $1 AND role_id = $2`, sysGroup, role.ID)
	if isSystem() {
		t.Error("the role stayed a system role after its only SYSTEM group_role link was removed: " +
			"INV-A9-1 says the answer is DERIVED from group mappings")
	}
}

// TestPolicyStore_IsSystemRoleCoversAllSevenSeededSystemGroups is ⚠️ F34.
//
// V8__seed.sql:48-58 installs EIGHT app_group rows: `query-approvers` (source=LOCAL) plus SEVEN with
// source=SYSTEM — system:admin, system:developer and five system:production-*. Every SYSTEM-
// immutability guard in the codebase keys on the COLUMN, so all seven behave identically; but every
// Kotlin test names only `system:admin`. A Go port that special-cased that string would leave six
// production-capability groups' roles freely mutable through the admin API and SCIM.
//
// So this asserts the derived predicate for all ELEVEN roles the seven groups grant, and — the other
// half of the same point — that `system:auditor` is NOT a system role despite the `system:` prefix,
// because no group grants it. The name is never the test.
func TestPolicyStore_IsSystemRoleCoversAllSevenSeededSystemGroups(t *testing.T) {
	f := newPolicyFixture(t)

	// From V8__seed.sql:62-74. system:developer aggregates the five development roles; each
	// production group is 1:1 with its role.
	systemGroups := map[string][]string{
		"system:admin": {"system:admin"},
		"system:developer": {
			"system:development-viewer", "system:development-pii-accessor", "system:development-updater",
			"system:development-deleter", "system:development-architect",
		},
		"system:production-viewer":       {"system:production-viewer"},
		"system:production-pii-accessor": {"system:production-pii-accessor"},
		"system:production-updater":      {"system:production-updater"},
		"system:production-deleter":      {"system:production-deleter"},
		"system:production-architect":    {"system:production-architect"},
	}

	// Assert the seed rather than trusting the table above: an eighth SYSTEM group in a later
	// migration must fail here, not silently escape the sweep.
	if n := f.scalarInt64(`SELECT count(*) FROM app_group WHERE source = 'SYSTEM'`); n != int64(len(systemGroups)) {
		t.Fatalf("app_group has %d source=SYSTEM rows, want %d — F34's table is stale", n, len(systemGroups))
	}

	for group, roles := range systemGroups {
		for _, roleName := range roles {
			role, err := f.store.GetRoleByName(f.ctx, roleName)
			if err != nil {
				t.Fatalf("getRoleByName %s: %v", roleName, err)
			}
			if role == nil {
				t.Fatalf("seeded role %s is missing", roleName)
			}
			got, err := f.store.IsSystemRole(f.ctx, role.ID)
			if err != nil {
				t.Fatalf("isSystemRole %s: %v", roleName, err)
			}
			if !got {
				t.Errorf("isSystemRole(%q) = false, want true — it is granted by the source=SYSTEM "+
					"group %q (F34: the guard keys on the COLUMN, and all seven groups count)",
					roleName, group)
			}
		}
	}

	// `system:auditor` is seeded, is `system:`-prefixed, and NO group grants it.
	auditor, err := f.store.GetRoleByName(f.ctx, "system:auditor")
	if err != nil || auditor == nil {
		t.Fatalf("getRoleByName system:auditor = %+v, %v", auditor, err)
	}
	got, err := f.store.IsSystemRole(f.ctx, auditor.ID)
	if err != nil {
		t.Fatalf("isSystemRole system:auditor: %v", err)
	}
	if got {
		t.Error("isSystemRole(system:auditor) = true, want false: no group grants it, and the " +
			"`system:` NAME is not what the predicate reads (INV-A9-1)")
	}

	// A role that does not exist at all is not a system role — EXISTS over an empty join, no error.
	if got, err := f.store.IsSystemRole(f.ctx, 999_999); err != nil || got {
		t.Errorf("isSystemRole(absent) = %v, %v; want false, nil", got, err)
	}
}

// ---- Assignments -----------------------------------------------------------------------------

// TestPolicyStore_CreateAssignmentIsIdempotentOnConflict is 🔒 INV-A9-2.
//
// `ON CONFLICT (principal, role_id) DO UPDATE SET principal=EXCLUDED.principal RETURNING id` is a
// deliberate NO-OP write — setting principal to the value it already has — whose only purpose is to
// make RETURNING fire on conflict. A plain DO NOTHING returns no row, which would leave
// createAssignment with no id to look up and nothing to return.
//
// So the observable contract is: re-assigning an existing (principal, role) pair SUCCEEDS and
// returns the EXISTING id, and no second row appears.
func TestPolicyStore_CreateAssignmentIsIdempotentOnConflict(t *testing.T) {
	f := newPolicyFixture(t)
	role := f.mustCreateRole("analyst", nil)

	first, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: "a@example.com", RoleID: role.ID})
	if err != nil {
		t.Fatalf("createAssignment: %v", err)
	}
	second, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: "a@example.com", RoleID: role.ID})
	if err != nil {
		t.Fatalf("createAssignment (repeat): %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("re-assigning returned id %d, want the existing %d — the upsert exists so RETURNING "+
			"fires on conflict (INV-A9-2)", second.ID, first.ID)
	}
	if second != first {
		t.Errorf("re-assigning returned %+v, want the identical row %+v", second, first)
	}
	if n := f.scalarInt64(`SELECT count(*) FROM principal_role`); n != 1 {
		t.Errorf("principal_role holds %d rows after two identical creates, want 1", n)
	}

	// The denormalized roleName comes from the join, not from the row.
	if first.RoleName != "analyst" {
		t.Errorf("roleName = %q, want analyst (denormalized from app_role)", first.RoleName)
	}
}

// TestPolicyStore_CreateAssignmentFindsItsRowThroughAFullScan is ⚠️ F8 — reproduced, and asserted
// only for its OBSERVABLE half.
//
// Policies.kt:98 locates the row it just inserted with `listAssignments(null, null, c).first { it.id
// == id }`: a full read of `principal_role` to find one row, when `getAssignment(id, c)` is exact and
// one line away. 00-INDEX.md:375 dispositions this REPRODUCE — inefficiency is named in the port
// policy as *not* grounds for OMIT — so this test does not try to detect the scan. It pins the thing
// a later swap must keep true: with many rows present, and with the returned row NOT the first in
// `ORDER BY pr.principal, r.name`, the right one still comes back.
func TestPolicyStore_CreateAssignmentFindsItsRowThroughAFullScan(t *testing.T) {
	f := newPolicyFixture(t)
	role := f.mustCreateRole("analyst", nil)

	// Fill the table, and make sure the row under test sorts LAST — so a scan that returned the
	// first row, or the wrong row, is visible.
	for _, p := range []string{"aaa@example.com", "bbb@example.com", "ccc@example.com"} {
		if _, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: p, RoleID: role.ID}); err != nil {
			t.Fatalf("seed assignment %s: %v", p, err)
		}
	}

	got, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: "zzz@example.com", RoleID: role.ID})
	if err != nil {
		t.Fatalf("createAssignment: %v", err)
	}
	if got.Principal != "zzz@example.com" || got.RoleID != role.ID || got.RoleName != "analyst" {
		t.Errorf("createAssignment returned %+v, want the zzz@example.com row", got)
	}

	// The exact path agrees with the scanning one — which is what makes F8's fix a safe swap later.
	exact, err := f.store.GetAssignment(f.ctx, got.ID)
	if err != nil {
		t.Fatalf("getAssignment: %v", err)
	}
	if exact == nil || *exact != got {
		t.Errorf("getAssignment(%d) = %+v, want %+v", got.ID, exact, got)
	}
}

// TestPolicyStore_ListAssignmentsFiltersAndOrdering exercises the dynamic WHERE.
//
// ⚠️ The roleId-ONLY case is the one that matters. In JDBC the placeholders are positional and the
// Kotlin can append clauses freely; in pgx they are NUMBERED, so with `principal` absent the roleId
// binds to $1, not $2. A mis-numbered argument there is a silent wrong-value bug, not a compile
// error — it is the single most dangerous mechanical hazard in this package.
func TestPolicyStore_ListAssignmentsFiltersAndOrdering(t *testing.T) {
	f := newPolicyFixture(t)
	analyst := f.mustCreateRole("analyst", nil)
	auditor := f.mustCreateRole("auditor", nil)

	for _, a := range []RoleAssignmentInput{
		{Principal: "bob@example.com", RoleID: auditor.ID},
		{Principal: "bob@example.com", RoleID: analyst.ID},
		{Principal: "alice@example.com", RoleID: auditor.ID},
		{Principal: "alice@example.com", RoleID: analyst.ID},
	} {
		if _, err := f.store.CreateAssignment(f.ctx, a); err != nil {
			t.Fatalf("seed assignment: %v", err)
		}
	}

	list := func(principal *string, roleID *int64) []RoleAssignment {
		t.Helper()
		got, err := f.store.ListAssignments(f.ctx, principal, roleID)
		if err != nil {
			t.Fatalf("listAssignments(%v, %v): %v", principal, roleID, err)
		}
		return got
	}

	// No filter: everything, ORDER BY pr.principal, r.name.
	all := list(nil, nil)
	wantOrder := []string{
		"alice@example.com/analyst", "alice@example.com/auditor",
		"bob@example.com/analyst", "bob@example.com/auditor",
	}
	gotOrder := make([]string, len(all))
	for i, a := range all {
		gotOrder[i] = a.Principal + "/" + a.RoleName
	}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Errorf("listAssignments order = %v, want %v (ORDER BY pr.principal, r.name)", gotOrder, wantOrder)
	}

	// principal only — binds to $1.
	if got := list(types.Ptr("alice@example.com"), nil); len(got) != 2 {
		t.Errorf("listAssignments(alice, nil) returned %d rows, want 2: %+v", len(got), got)
	}

	// ⚠️ roleId only — ALSO binds to $1, because principal is absent.
	byRole := list(nil, &analyst.ID)
	if len(byRole) != 2 {
		t.Fatalf("listAssignments(nil, analyst) returned %d rows, want 2: %+v", len(byRole), byRole)
	}
	for _, a := range byRole {
		if a.RoleID != analyst.ID {
			t.Errorf("listAssignments(nil, analyst) returned a %s row — the roleId bound to the wrong "+
				"placeholder", a.RoleName)
		}
	}

	// Both — $1 and $2.
	both := list(types.Ptr("alice@example.com"), &analyst.ID)
	if len(both) != 1 || both[0].Principal != "alice@example.com" || both[0].RoleID != analyst.ID {
		t.Errorf("listAssignments(alice, analyst) = %+v, want exactly the one row", both)
	}

	// A filter that matches nothing is an empty list, not an error.
	if got := list(types.Ptr("nobody@example.com"), nil); len(got) != 0 {
		t.Errorf("listAssignments(nobody, nil) = %+v, want empty", got)
	}
}

func TestPolicyStore_GetAndDeleteAssignment(t *testing.T) {
	f := newPolicyFixture(t)
	role := f.mustCreateRole("analyst", nil)

	created, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: "a@example.com", RoleID: role.ID})
	if err != nil {
		t.Fatalf("createAssignment: %v", err)
	}

	if got, err := f.store.GetAssignment(f.ctx, 999_999); err != nil || got != nil {
		t.Errorf("getAssignment(absent) = %+v, %v; want nil, nil", got, err)
	}

	// deleteAssignment(id).
	ok, err := f.store.DeleteAssignment(f.ctx, created.ID)
	if err != nil {
		t.Fatalf("deleteAssignment: %v", err)
	}
	if !ok {
		t.Error("deleteAssignment = false for an existing row, want true")
	}
	if ok, err := f.store.DeleteAssignment(f.ctx, created.ID); err != nil || ok {
		t.Errorf("deleteAssignment (repeat) = %v, %v; want false, nil", ok, err)
	}

	// deleteAssignment(principal, roleId, c) — connection-form ONLY in the Kotlin, so it is called
	// on a handle here too. A11's replaceDirectRoles runs it under the per-principal advisory lock.
	again, err := f.store.CreateAssignment(f.ctx, RoleAssignmentInput{Principal: "a@example.com", RoleID: role.ID})
	if err != nil {
		t.Fatalf("createAssignment (again): %v", err)
	}
	ok, err = f.store.DeleteAssignmentByPrincipalRoleOn(f.ctx, f.db.Pool, "a@example.com", role.ID)
	if err != nil {
		t.Fatalf("deleteAssignmentByPrincipalRole: %v", err)
	}
	if !ok {
		t.Error("deleteAssignmentByPrincipalRole = false for an existing row, want true")
	}
	if got, err := f.store.GetAssignment(f.ctx, again.ID); err != nil || got != nil {
		t.Errorf("getAssignment after delete = %+v, %v; want nil, nil", got, err)
	}
	if ok, err := f.store.DeleteAssignmentByPrincipalRoleOn(f.ctx, f.db.Pool, "a@example.com", role.ID); err != nil || ok {
		t.Errorf("deleteAssignmentByPrincipalRole (repeat) = %v, %v; want false, nil", ok, err)
	}
}

// ---- Mask functions --------------------------------------------------------------------------

// The mask-fn surface is the same shape as roles: ORDER BY name, RETURNING id, update nil when
// absent, delete reports whether a row matched. `kind` is free-form at this layer and NOTHING
// validates it — 09-policies.md Q4 is open on whether anything anywhere does. That is asserted, not
// worked around: an admin really can create a mask fn the engine cannot apply.
func TestPolicyStore_MaskFnCRUD(t *testing.T) {
	f := newPolicyFixture(t)

	created, err := f.store.CreateMaskFn(f.ctx, MaskFnInput{Name: "rrn-last4", Kind: "LAST_N"})
	if err != nil {
		t.Fatalf("createMaskFn: %v", err)
	}
	if created.ID == 0 || created.Name != "rrn-last4" || created.Kind != "LAST_N" {
		t.Fatalf("createMaskFn = %+v, want the re-read row", created)
	}

	byID, err := f.store.GetMaskFn(f.ctx, created.ID)
	if err != nil || byID == nil || *byID != created {
		t.Errorf("getMaskFn = %+v, %v; want %+v", byID, err, created)
	}
	byName, err := f.store.GetMaskFnByName(f.ctx, "rrn-last4")
	if err != nil || byName == nil || *byName != created {
		t.Errorf("getMaskFnByName = %+v, %v; want %+v", byName, err, created)
	}

	if _, err := f.store.CreateMaskFn(f.ctx, MaskFnInput{Name: "email-fixed", Kind: "FIXED"}); err != nil {
		t.Fatalf("createMaskFn: %v", err)
	}
	list, err := f.store.ListMaskFns(f.ctx)
	if err != nil {
		t.Fatalf("listMaskFns: %v", err)
	}
	if len(list) != 2 || list[0].Name != "email-fixed" || list[1].Name != "rrn-last4" {
		t.Errorf("listMaskFns = %+v, want [email-fixed rrn-last4] (ORDER BY name)", list)
	}

	// 09-policies.md Q4: `kind` is free-form TEXT with no CHECK and no validation here.
	odd, err := f.store.CreateMaskFn(f.ctx, MaskFnInput{Name: "nonsense", Kind: "NOT_A_REAL_KIND"})
	if err != nil {
		t.Fatalf("createMaskFn with an unknown kind: %v — nothing at this layer validates `kind` "+
			"(09-policies.md Q4); if this ever starts failing, the validation was ADDED", err)
	}
	if odd.Kind != "NOT_A_REAL_KIND" {
		t.Errorf("kind = %q, want it stored verbatim", odd.Kind)
	}

	updated, err := f.store.UpdateMaskFn(f.ctx, created.ID, MaskFnInput{Name: "rrn-last2", Kind: "LAST_N"})
	if err != nil {
		t.Fatalf("updateMaskFn: %v", err)
	}
	if updated == nil || updated.Name != "rrn-last2" || updated.ID != created.ID {
		t.Errorf("updateMaskFn = %+v, want the re-read row named rrn-last2", updated)
	}
	if got, err := f.store.UpdateMaskFn(f.ctx, 999_999, MaskFnInput{Name: "x", Kind: "FIXED"}); err != nil || got != nil {
		t.Errorf("updateMaskFn(absent) = %+v, %v; want nil, nil", got, err)
	}

	ok, err := f.store.DeleteMaskFn(f.ctx, created.ID)
	if err != nil || !ok {
		t.Errorf("deleteMaskFn = %v, %v; want true, nil", ok, err)
	}
	if ok, err := f.store.DeleteMaskFn(f.ctx, created.ID); err != nil || ok {
		t.Errorf("deleteMaskFn (repeat) = %v, %v; want false, nil", ok, err)
	}
	if got, err := f.store.GetMaskFnByName(f.ctx, "no-such-fn"); err != nil || got != nil {
		t.Errorf("getMaskFnByName(absent) = %+v, %v; want nil, nil", got, err)
	}
}

// ---- The method pair -------------------------------------------------------------------------

// TestPolicyStore_ConnectionFormComposesIntoTheCallersTransaction is why 09-policies.md §2 says to
// keep the pair. The `On` form runs on the CALLER's handle, so a policy write and whatever else that
// transaction is doing commit — or roll back — together. That is the same property INV-A3-6 rests on
// for the credential-teardown paths: never a follow-up transaction a crash could skip.
func TestPolicyStore_ConnectionFormComposesIntoTheCallersTransaction(t *testing.T) {
	f := newPolicyFixture(t)

	// Rolled back: nothing survives.
	tx, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rolled, err := f.store.CreateRoleOn(f.ctx, tx, RoleInput{Name: "doomed"})
	if err != nil {
		t.Fatalf("createRoleOn: %v", err)
	}
	inTx, err := f.store.GetRoleOn(f.ctx, tx, rolled.ID)
	if err != nil || inTx == nil {
		t.Fatalf("getRoleOn(tx) = %+v, %v; want the uncommitted row", inTx, err)
	}
	outside, err := f.store.GetRole(f.ctx, rolled.ID)
	if err != nil {
		t.Fatalf("getRole(pool): %v", err)
	}
	if outside != nil {
		t.Error("getRole on the store's own handle saw another transaction's uncommitted row")
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got, err := f.store.GetRole(f.ctx, rolled.ID); err != nil || got != nil {
		t.Errorf("getRole after rollback = %+v, %v; want nil, nil", got, err)
	}

	// Committed through store.InTx: the role AND its assignment land atomically.
	err = store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		role, err := f.store.CreateRoleOn(ctx, tx, RoleInput{Name: "kept"})
		if err != nil {
			return err
		}
		_, err = f.store.CreateAssignmentOn(ctx, tx, RoleAssignmentInput{Principal: "a@example.com", RoleID: role.ID})
		return err
	})
	if err != nil {
		t.Fatalf("InTxDo: %v", err)
	}
	kept, err := f.store.GetRoleByName(f.ctx, "kept")
	if err != nil || kept == nil {
		t.Fatalf("getRoleByName(kept) = %+v, %v; want the committed row", kept, err)
	}
	assignments, err := f.store.ListAssignments(f.ctx, types.Ptr("a@example.com"), nil)
	if err != nil {
		t.Fatalf("listAssignments: %v", err)
	}
	if len(assignments) != 1 || assignments[0].RoleName != "kept" {
		t.Errorf("listAssignments = %+v, want the one assignment committed with the role", assignments)
	}
}
