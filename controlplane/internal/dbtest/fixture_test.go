package dbtest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
)

// TestEnforcementFixture proves the fixture itself is wired, on BOTH target engines. It is not an
// enforcement test — decideQuery is not ported — but it pins the four things every enforcement suite
// will assume, so a fixture regression fails here rather than as an inexplicable DENY three areas
// away.
//
// The four: (1) the target really holds the seeded rows, (2) the catalog and classification landed
// with the engine-correct namespace, (3) roles resolve server-side from the store, and (4) a REAL
// Cedar engine over the seeded policy rows reaches the "read table except pii" verdicts.
func TestEnforcementFixture(t *testing.T) {
	for _, engine := range []string{EnginePostgres, EngineMySQL} {
		t.Run(engine, func(t *testing.T) {
			f := NewEnforcementFixture(t, engine)

			// (1) The target holds the seeded cleartext.
			rows := f.ExecOnTarget(`SELECT id, email, rrn, region FROM users ORDER BY id`)
			if len(rows.Rows) != 2 {
				t.Fatalf("users has %d rows, want 2", len(rows.Rows))
			}
			rrn, ok := rows.Values("rrn")
			if !ok {
				t.Fatalf("no rrn column in %v", rows.Columns)
			}
			for i, v := range rrn {
				if v == nil || *v != FixtureCleartextRRN[i] {
					t.Errorf("users.rrn[%d] = %s, want %q", i, Cell(v), FixtureCleartextRRN[i])
				}
			}
			// The ungranted table exists too — deny-by-default is only provable if there is something
			// to deny.
			if got := f.ExecOnTarget(`SELECT id, amount FROM orders ORDER BY id`); len(got.Rows) != 2 {
				t.Errorf("orders has %d rows, want 2", len(got.Rows))
			}

			// (2) The catalog landed under the engine-correct schema, and rrn is classified pii+last4.
			ctx := context.Background()
			var cols int
			if err := f.Store.Pool.QueryRow(ctx,
				`SELECT count(*) FROM catalog_column
				  WHERE datasource_id = $1 AND schema_name = $2 AND table_name = 'users'`,
				f.DatasourceID, f.Schema).Scan(&cols); err != nil {
				t.Fatalf("count catalog columns: %v", err)
			}
			if cols != 4 {
				t.Errorf("catalog has %d users columns under schema %q, want 4", cols, f.Schema)
			}

			var tags []string
			var maskKind string
			err := f.Store.Pool.QueryRow(ctx,
				`SELECT cc.tags, mf.kind
				   FROM column_classification cc JOIN mask_fn mf ON mf.id = cc.mask_fn_id
				  WHERE cc.datasource_id = $1 AND cc.table_name = 'users' AND cc.column_name = 'rrn'`,
				f.DatasourceID).Scan(&tags, &maskKind)
			if err != nil {
				t.Fatalf("read users.rrn classification: %v", err)
			}
			if len(tags) != 1 || tags[0] != "pii" || maskKind != "LAST_N" {
				t.Errorf("users.rrn classified as tags=%v mask=%q, want [pii] LAST_N", tags, maskKind)
			}

			// The static namespace metadata a catalog push captures.
			var schemas []string
			var engineVersion *string
			if err := f.Store.Pool.QueryRow(ctx,
				`SELECT default_schemas, engine_version FROM datasource WHERE id = $1`,
				f.DatasourceID).Scan(&schemas, &engineVersion); err != nil {
				t.Fatalf("read datasource namespace: %v", err)
			}
			if len(schemas) == 0 {
				t.Error("default_schemas is empty — bare-name resolution would be unsafe")
			}
			if engineVersion == nil || *engineVersion == "" {
				t.Error("engine_version is unset — system classification resolves its manifest off it")
			}
			// MySQL's @@lower_case_table_names decides identifier-case behaviour and is NULL until read.
			var lct *int
			if err := f.Store.Pool.QueryRow(ctx,
				`SELECT mysql_lower_case_table_names FROM datasource WHERE id = $1`,
				f.DatasourceID).Scan(&lct); err != nil {
				t.Fatalf("read lower_case_table_names: %v", err)
			}
			if engine == EngineMySQL && lct == nil {
				t.Error("MySQL datasource has a NULL mysql_lower_case_table_names")
			}
			if engine == EnginePostgres && lct != nil {
				t.Errorf("Postgres datasource has mysql_lower_case_table_names = %d, want NULL", *lct)
			}

			// (3) Roles resolve server-side, from the store, for each seeded principal.
			for principal, want := range map[string]string{
				FixturePrincipal:          FixtureRole,
				FixtureNoConnectPrincipal: "no-connect-reader",
				FixtureDDLPrincipal:       "ddl-writer",
				FixtureInsertPrincipal:    "insert-writer",
			} {
				got := f.Authz.RolesOf(principal)
				if len(got) != 1 || got[0] != want {
					t.Errorf("RolesOf(%s) = %v, want [%s]", principal, got, want)
				}
			}
			if got := f.Authz.RolesOf("nobody@example.com"); len(got) != 0 {
				t.Errorf("RolesOf(nobody) = %v, want none — no roles are invented", got)
			}

			// (4) A real Cedar engine over the seeded rows reaches the "read table except pii"
			// verdicts: cleartext on a non-pii column, masked on the pii one, and DENIED on the
			// ungranted table — which is deny-by-default, not a fall-through to cleartext.
			cases := []struct {
				table, column string
				tags          []string
				want          authz.ColumnVerdict
			}{
				{"users", "region", nil, authz.ColumnUnmasked},
				{"users", "rrn", []string{"pii"}, authz.ColumnMasked},
				{"orders", "amount", nil, authz.ColumnDenied},
			}
			refs := make([]authz.ColumnRef, 0, len(cases))
			for _, c := range cases {
				refs = append(refs, authz.ColumnRef{
					Key:     c.table + "." + c.column,
					Catalog: f.Catalog,
					Schema:  f.Schema,
					Table:   c.table,
					Column:  c.column,
					Tags:    c.tags,
				})
			}
			verdicts := f.Authz.AuthorizeColumns(
				FixturePrincipal, f.Authz.RolesOf(FixturePrincipal), f.DatasourceName,
				refs, authz.AuthzContext{}, nil, nil)
			for _, c := range cases {
				key := c.table + "." + c.column
				if got := verdicts[key]; got != c.want {
					t.Errorf("column %s: verdict %v, want %v", key, got, c.want)
				}
			}

			// The datasource-level gates the fixture also seeds: analyst may connect, reader may not.
			// AuthorizeDatasourceAction, not Authorize — there is no AuthzResource.Datasource (F1), and
			// the datasource EUID is keyed off its NAME (INV-A2-2).
			connect := func(principal string) authz.AuthzDecision {
				return f.Authz.AuthorizeDatasourceAction(principal, f.Authz.RolesOf(principal),
					authz.ActionDatasourceConnect, f.DatasourceName, authz.AuthzContext{}, nil)
			}
			if d := connect(FixturePrincipal); !d.Allowed {
				t.Errorf("analyst datasource.connect denied: %s", d.Reason)
			}
			if d := connect(FixtureNoConnectPrincipal); d.Allowed {
				t.Error("no-connect-reader was allowed datasource.connect — the connect gate is the " +
					"one the fixture exists to prove runs first")
			}
		})
	}
}

// TestEnforcementFixture_TargetQueryErrorIsNotADeny pins the distinction EnforcementHarness.kt:34
// exists for: a broken target query must surface as a TargetQueryError, never as something a suite
// could mistake for a policy DENY.
func TestEnforcementFixture_TargetQueryErrorIsNotADeny(t *testing.T) {
	f := NewEnforcementFixture(t, EnginePostgres)
	_, err := ExecOnTarget(f.Target, `SELECT * FROM no_such_table`, 100)
	if err == nil {
		t.Fatal("a query against a nonexistent table returned no error")
	}
	var tqe *TargetQueryError
	if !errors.As(err, &tqe) {
		t.Fatalf("error is %T, want *TargetQueryError", err)
	}
	if !strings.Contains(tqe.Error(), "no_such_table") {
		t.Errorf("error %q does not name the failing relation", tqe.Error())
	}
	// Unwrap keeps the driver error reachable, so a suite can still match a specific SQLSTATE through
	// the wrapper rather than parsing the message.
	if tqe.Unwrap() == nil {
		t.Error("TargetQueryError.Unwrap() is nil — the driver error is unreachable")
	}
}

// TestSeedGroupRoleResolvesServerSide covers the group -> role path the direct principal_role
// assignments in the fixture do not: the IdP never mints a role, its group claim provisions local
// app_group membership, and `group_role` is what turns a group into roles (V1__identity.sql).
func TestSeedGroupRoleResolvesServerSide(t *testing.T) {
	db, _ := MigratedStore(t)
	s := NewSeed(t, db)
	roles := NewDBRoleSource(t, db.Pool)

	roleID := s.Role("data-reader")
	groupID := s.Group("analytics")
	s.GroupRole(groupID, roleID)

	// A principal with no app_user row and no direct assignment has nothing.
	if got := roles.RolesOf("member@example.com"); len(got) != 0 {
		t.Fatalf("RolesOf(unprovisioned) = %v, want none", got)
	}

	userID := s.User("member@example.com")
	s.GroupMember(groupID, userID)
	got := roles.RolesOf("member@example.com")
	if len(got) != 1 || got[0] != "data-reader" {
		t.Errorf("RolesOf(group member) = %v, want [data-reader]", got)
	}

	// Direct ∪ group, deduped: the same role from both sources resolves once.
	s.AssignRole("member@example.com", roleID)
	if got := roles.RolesOf("member@example.com"); len(got) != 1 {
		t.Errorf("RolesOf(direct + group, same role) = %v, want one entry", got)
	}
}

// TestMySQLAuthPlugin pins that the harness names a plugin the RUNNING series can actually create an
// account with — mysql_native_password is disabled on 8.4 and available on 8.0, and a fixture that
// hardcoded either would fail on exactly one matrix leg.
func TestMySQLAuthPlugin(t *testing.T) {
	got := MySQLAuthPlugin(t)
	if got != "mysql_native_password" && got != "caching_sha2_password" {
		t.Fatalf("MySQLAuthPlugin() = %q, want one of the two MySQL ships", got)
	}
	// Prove the answer is not a constant: it must match what this server reports.
	db := OpenMySQL(t, "")
	var status string
	err := db.QueryRow(
		`SELECT plugin_status FROM information_schema.plugins WHERE plugin_name = 'mysql_native_password'`,
	).Scan(&status)
	active := err == nil && strings.EqualFold(status, "ACTIVE")
	if active && got != "mysql_native_password" {
		t.Errorf("mysql_native_password is ACTIVE but the harness chose %q", got)
	}
	if !active && got != "caching_sha2_password" {
		t.Errorf("mysql_native_password is not ACTIVE (%q) but the harness chose %q", status, got)
	}
	t.Logf("series %s -> auth plugin %s", MySQL(t).Series(t), got)
}

// TestFreshDatabasesDoNotCollide pins the one place the Go harness cannot copy the Kotlin: the
// container is REUSED across runs, so a per-process counter would collide with the previous run's
// databases. See runToken in freshdb.go.
func TestFreshDatabasesDoNotCollide(t *testing.T) {
	a := FreshPostgresDatabase(t, "pm_collide")
	b := FreshPostgresDatabase(t, "pm_collide")
	if a == b {
		t.Fatalf("two fresh databases got the same name %q", a)
	}
	if !strings.Contains(a, runToken) {
		t.Errorf("fresh name %q carries no run token — it would collide with the previous run", a)
	}
}
