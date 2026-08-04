package management

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// 🔴 EVERY CASE IN THIS PACKAGE IS NEW.
//
// 00-INDEX.md F19 / 11-mcp-oauth-management.md §9: `ManagementServices.kt` is 732 LOC with ZERO
// dedicated Kotlin tests — "the largest untested surface in the control-plane", and unlike the other
// untested surfaces it contains security guards. There is nothing to migrate 1:1, so the area doc's
// §8 is the whole specification and these suites are written against it.
//
// The area doc lists what nothing tested. Each bullet is a suite here:
//
//   - replaceDirectRoles' four invariants, "including the ADVISORY-LOCK CONCURRENCY property, which
//     is exactly the kind of thing that passes single-threaded and corrupts under load" →
//     policy_management_db_test.go.
//   - isSystemRole enforcement on updateRole/deleteRole (INV-A11-30) → policy_management_db_test.go,
//     all four call sites.
//   - rejectSystem / lockMutableGroup / setGroupRoles' three different SYSTEM guards (INV-A11-32) →
//     identity_db_test.go.
//   - INV-A11-28's reserved-tag WRITE rejection (only the marshalling half is tested, in A2) →
//     datasource_db_test.go.
//   - unique's SQLSTATE-23505 mapping and setGroupRoles' diff semantics → both files.
//
// The stores are REAL, over a migrated Postgres. Every claim here is about what a guard let through
// or refused, and that is only observable in the rows.
// ---------------------------------------------------------------------------------------------

type fixture struct {
	t   testing.TB
	ctx context.Context
	db  *store.Db

	seed        *dbtest.Seed
	policyStore *policy.PolicyStore
	cedarStore  *policy.CedarPolicyStore
	userStore   *identity.UserGroupStore

	identities *IdentityService
	policies   *PolicyService
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	policyStore := policy.NewPolicyStore(db.Pool)
	cedarStore := policy.NewCedarPolicyStore(db.Pool)
	userStore := identity.NewUserGroupStore(db.Pool)
	return &fixture{
		t:           t,
		ctx:         context.Background(),
		db:          db,
		seed:        dbtest.NewSeed(t, db),
		policyStore: policyStore,
		cedarStore:  cedarStore,
		userStore:   userStore,
		// ⚠️ credentials is nil, and that is a DELIBERATE narrowing of what this package's suites
		// claim. The group surface — where all three INV-A11-32 guards live — never touches it, and
		// the user surface's teardown ORDERING is A3's property, asserted against real token/grant/
		// session rows in internal/identity's usergroupwrites_db_test.go. A fake here would prove
		// only that a nil-guard fired.
		identities: NewIdentityService(db.Pool, userStore, policyStore, nil),
		policies:   NewPolicyService(cedarStore, policyStore),
	}
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (f *fixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}

// systemGroup seeds a `source = 'SYSTEM'` group directly, because no API path can create one — which
// is the entire point of INV-A11-32. dbtest.Seed.Group writes source='LOCAL'.
//
// 🔒 F34 — the guards key on the COLUMN, never on the `system:` name prefix, so these fixtures
// deliberately use names that do NOT start with `system:`. A guard that passed only because of the
// name would fail here.
func (f *fixture) systemGroup(name string) int64 {
	f.t.Helper()
	return f.scalarInt64(`INSERT INTO app_group (name, source) VALUES ($1, 'SYSTEM') RETURNING id`, name)
}

// groupRoleNames reads `group_role` straight from the table, so an assertion about what a diff did is
// never mediated by the code under test.
func (f *fixture) groupRoleNames(groupID int64) []string {
	f.t.Helper()
	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT r.name FROM group_role gr JOIN app_role r ON r.id = gr.role_id
		  WHERE gr.group_id = $1 ORDER BY r.name`, groupID)
	if err != nil {
		f.t.Fatalf("group roles: %v", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			f.t.Fatalf("group roles scan: %v", err)
		}
		out = append(out, name)
	}
	return out
}

// directRoleNames reads `principal_role` straight from the table.
func (f *fixture) directRoleNames(principal string) []string {
	f.t.Helper()
	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT r.name FROM principal_role pr JOIN app_role r ON r.id = pr.role_id
		  WHERE pr.principal = $1 ORDER BY r.name`, principal)
	if err != nil {
		f.t.Fatalf("direct roles: %v", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			f.t.Fatalf("direct roles scan: %v", err)
		}
		out = append(out, name)
	}
	return out
}

// ---- assertions ---------------------------------------------------------------------------------

// assertManagementCode unwraps a [Error] and asserts its code, returning the ApiError so a caller can
// go on to check the params.
//
// 🔒 It uses errors.As with `*Error`, which is `*policy.ManagementError`. A test that passed here
// while the route layer's own `errors.As(err, &me)` failed would mean the alias had been replaced by
// a second struct — so this assertion is also the cross-package identity check.
func assertManagementCode(t testing.TB, err error, want string, context string) types.ApiError {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want management failure %q", context, want)
	}
	var me *Error
	if !errors.As(err, &me) {
		t.Fatalf("%s: got %T (%v), want *management.Error with code %q", context, err, err, want)
	}
	if me.Err.Code != want {
		t.Fatalf("%s: got code %q, want %q (params %v)", context, me.Err.Code, want, me.Err.Params)
	}
	return me.Err
}

func assertParam(t testing.TB, e types.ApiError, key, want, context string) {
	t.Helper()
	if got := e.Params[key]; got != want {
		t.Errorf("%s: params[%q] = %q, want %q", context, key, got, want)
	}
}

func assertNoError(t testing.TB, err error, context string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", context, err)
	}
}

func assertStrings(t testing.TB, got, want []string, context string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", context, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", context, got, want)
		}
	}
}

// assertJSON marshals v and compares the bytes. Used for the INV-A1-4 shape assertions, where the
// question is literally which keys are present and whether an empty list is `[]` or `null`.
func assertJSON(t testing.TB, v any, want, context string) {
	t.Helper()
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", context, err)
	}
	if string(got) != want {
		t.Errorf("%s:\n got %s\nwant %s", context, got, want)
	}
}

func ptr[T any](v T) *T { return &v }
