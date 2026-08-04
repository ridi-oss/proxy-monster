package identity

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// The DB-backed support for this package's suites. It leans on internal/dbtest for the shared
// container and the fresh, migrated database (see that package's doc.go for the three rules); what
// lives here is only what A3's own tests need on top.

// fixture is a migrated control-plane store with the three A3 objects wired over it, exactly as
// ControlPlaneCore.kt:31 wires them: one UserGroupStore, one RoleResolver, both over the same pool.
type fixture struct {
	t        testing.TB
	ctx      context.Context
	db       *store.Db
	seed     *dbtest.Seed
	users    *UserGroupStore
	resolver *RoleResolver
	grants   *testAccessGrants
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	users := NewUserGroupStore(db.Pool)
	grants := &testAccessGrants{db: db.Pool}
	return &fixture{
		t:        t,
		ctx:      context.Background(),
		db:       db,
		seed:     dbtest.NewSeed(t, db),
		users:    users,
		resolver: NewRoleResolver(db.Pool, users, grants),
		grants:   grants,
	}
}

// exec runs a literal statement. The ported Kotlin suites drive their state transitions with raw SQL
// (ReadinessDiagnosticDbTest's `execute` helper), and keeping that shape makes the two readable
// side by side.
func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// scalarInt64 reads one bigint — the port of ReadinessDiagnosticDbTest's `scalarLong`.
func (f *fixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}

// roleID looks up a seeded role by name.
func (f *fixture) roleID(name string) int64 {
	f.t.Helper()
	return f.scalarInt64(`SELECT id FROM app_role WHERE name = $1`, name)
}

// groupID looks up a seeded group by name.
func (f *fixture) groupID(name string) int64 {
	f.t.Helper()
	return f.scalarInt64(`SELECT id FROM app_group WHERE name = $1`, name)
}

// resolve is Resolve with the error already fataled — every call site in these suites treats an
// error as a broken fixture, not as an outcome under test.
func (f *fixture) resolve(principal string) []string {
	f.t.Helper()
	roles, err := f.resolver.Resolve(f.ctx, principal)
	if err != nil {
		f.t.Fatalf("resolve %s: %v", principal, err)
	}
	return roles
}

// hasActiveAssignee is HasActiveAssignee with the error fataled.
func (f *fixture) hasActiveAssignee(roleName string) bool {
	f.t.Helper()
	got, err := f.resolver.HasActiveAssignee(f.ctx, roleName)
	if err != nil {
		f.t.Fatalf("hasActiveAssignee %s: %v", roleName, err)
	}
	return got
}

// isDeactivated is IsDeactivated with the error fataled.
func (f *fixture) isDeactivated(principal string) bool {
	f.t.Helper()
	got, err := f.users.IsDeactivated(f.ctx, principal)
	if err != nil {
		f.t.Fatalf("isDeactivated %s: %v", principal, err)
	}
	return got
}

// grant inserts an `access_grant` row directly.
//
// ⚠️ TODO(A6): the Kotlin suites mint grants through the real path —
// `accessStore.createRequest(...)` then `accessStore.approve(id, durationSec, decidedBy)`, which
// computes `expires_at = now() + durationSec` (ResolveRolesTest.kt:59-60,72-73,87). AccessStore is
// not ported, so this writes the row the approve path would have written. Re-point it at
// AccessStore.approve when A6 lands: a fixture with its own INSERT is a second definition of what a
// valid grant looks like, and the two will disagree exactly where it matters.
//
// expiresAt is a Postgres interval expression relative to now(), or "" for a NULL expiry (a grant
// that never lapses — which activeOnly counts as ACTIVE).
func (f *fixture) grant(principal string, roleID int64, expiresAt string) int64 {
	f.t.Helper()
	sql := `INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
	        VALUES ($1, $2, 'approver@example.com', NULL) RETURNING id`
	if expiresAt != "" {
		sql = `INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
		       VALUES ($1, $2, 'approver@example.com', now() + interval '` + expiresAt + `') RETURNING id`
	}
	return f.scalarInt64(sql, principal, roleID)
}

// testAccessGrants is the DB-backed stand-in for A6's AccessStore, satisfying [AccessGrants].
//
// ⚠️ TODO(A6): DELETE this and wire the production AccessStore. It reproduces
// `AccessStore.listGrants(principal, activeOnly).map { it.roleName }` (Access.kt:486-495 and
// GRANT_SELECT at :558) statement-for-statement — the same `WHERE 1=1` + conditional-append shape,
// the same activeOnly predicate, the same `ORDER BY ag.granted_at DESC`, and the same join to
// `app_role` for the name. It is written out in full rather than simplified precisely so that when
// the real store arrives, the diff between them is the thing to look at.
//
// The one part deliberately NOT reproduced is the `principal == null` arm: [RoleResolver] always
// passes a principal, and a fixture that supports a call shape production never makes is a fixture
// that can pass for the wrong reason.
type testAccessGrants struct {
	db store.Queryer
}

func (g *testAccessGrants) ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
	sql := `SELECT r.name
	          FROM access_grant ag JOIN app_role r ON r.id = ag.role_id
	         WHERE 1=1 AND ag.principal = $1`
	if activeOnly {
		sql += ` AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())`
	}
	sql += ` ORDER BY ag.granted_at DESC`

	rows, err := g.db.Query(ctx, sql, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// assertResolves compares Resolve's output against an expected set (membership, no duplicates).
func (f *fixture) assertResolves(principal string, want ...string) {
	f.t.Helper()
	assertRoleSet(f.t, f.resolve(principal), want...)
}
