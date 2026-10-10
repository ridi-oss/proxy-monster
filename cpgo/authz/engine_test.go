package authz

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
)

func TestSchemaMatchesKotlin(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	kotlin, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../control-plane/src/main/resources/authz/schema.cedarschema"))
	if err != nil {
		t.Fatal(err)
	}
	if string(kotlin) != schemaText {
		t.Fatal("cpgo/authz/schema.cedarschema differs from the control plane's; copy it over")
	}
}

func TestSeededPoliciesValidate(t *testing.T) {
	st := dbtest.Open(t)
	rows, err := st.Pool.Query(context.Background(), `SELECT id, cedar_src FROM policy WHERE deleted_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var (
			id  int64
			src string
		)
		_ = rows.Scan(&id, &src)
		if errs := Validate(src); len(errs) != 0 {
			t.Errorf("seeded policy %d: %v", id, errs)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no seeded policies")
	}
}

func TestValidateRejects(t *testing.T) {
	for _, src := range []string{
		``,
		`not cedar`,
		`permit(principal, action == Action::"audit.write", resource);`,
		`permit(principal, action == Action::"audit.read", resource) when { context.nope == 1 };`,
		`@cap("5M") permit(principal, action == Action::"result.cap", resource);`,
		`@cap("1/32d") permit(principal, action == Action::"result.cap", resource);`,
		`@cap("10/1x") permit(principal, action == Action::"result.cap", resource);`,
		`@cap("5") permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource);`,
		`permit(principal, action == Action::"result.read.unmasked", resource == Utility::"ds/SHOW_GRANTS");`,
		`permit(principal, action == Action::"audit.read", resource) when { datetime("2026-01-01") == datetime("2026-01-01") };`,
		`permit(principal, action == Action::"audit.read", resource) when { duration("1h") == duration("1h") };`,
		`@cap("9223372036854775808") permit(principal, action == Action::"result.cap", resource);`,
	} {
		if errs := Validate(src); len(errs) == 0 {
			t.Errorf("accepted %q", src)
		}
	}
	for _, src := range []string{
		`permit(principal, action == Action::"audit.read", resource);`,
		`@cap("2000, 3MB, 100KB/10m, 7GB/31d") permit(principal in Role::"analyst", action == Action::"result.cap", resource);`,
		`permit(principal, action == Action::"context.tag::office", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };`,
	} {
		if errs := Validate(src); len(errs) != 0 {
			t.Errorf("rejected %q: %v", src, errs)
		}
	}
}

func TestDecisionsUnderShippedPolicies(t *testing.T) {
	st := dbtest.Open(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO principal_role (principal, role_id) SELECT 'auditor', id FROM app_role WHERE name = 'system:admin'`)
	exec(`INSERT INTO app_role (name) VALUES ('ip-auditor')`)
	exec(`INSERT INTO principal_role (principal, role_id) SELECT 'edge', id FROM app_role WHERE name = 'ip-auditor'`)
	exec(`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('ip-gated', 'permit(principal in Role::"ip-auditor", action == Action::"audit.read", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };', true, 'USER')`)
	exec(`INSERT INTO datasource (name, host, port, db_name, tags) VALUES ('gated', 'h', 1, 'd', '["prod"]')`)
	exec(`INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('connect', 'permit(principal == User::"connector", action == Action::"datasource.connect", resource == Datasource::"gated");', true, 'USER')`)
	exec(`INSERT INTO app_user (principal, active) VALUES ('gone', false)`)
	exec(`INSERT INTO principal_role (principal, role_id) SELECT 'gone', id FROM app_role WHERE name = 'system:admin'`)

	l := Local{Engine: New(st.Pool)}
	allow := func(principal, action string, r bridge.Resource, ip string) bool {
		t.Helper()
		ok, _, err := l.Authorize(ctx, principal, action, r, ip)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	ds := "gated"
	role := "analyst"
	for _, tc := range []struct {
		name      string
		principal string
		action    string
		resource  bridge.Resource
		ip        string
		want      bool
	}{
		{"own audit record", "alice", "audit.read", bridge.AuditRecord("alice"), "", true},
		{"another's audit record", "alice", "audit.read", bridge.AuditRecord("bob"), "", false},
		{"whole log without a grant", "alice", "audit.read", bridge.AuditLog, "", false},
		{"admin reads the log", "auditor", "audit.read", bridge.AuditLog, "", true},
		{"admin admin.policies", "auditor", "admin.policies", bridge.System, "", true},
		{"plain admin.policies", "alice", "admin.policies", bridge.System, "", false},
		{"ip-gated in range", "edge", "audit.read", bridge.AuditLog, "203.0.113.10", true},
		{"ip-gated out of range", "edge", "audit.read", bridge.AuditLog, "198.51.100.10", false},
		{"ip-gated without an address", "edge", "audit.read", bridge.AuditLog, "", false},
		{"ip-gated garbage address", "edge", "audit.read", bridge.AuditLog, "not-an-ip", false},
		{"own request", "alice", "task.read", bridge.Resource{Type: "ApprovalRequest", Principal: "alice", DatasourceName: &ds, RoleName: &role}, "", true},
		{"another's request", "bob", "task.read", bridge.Resource{Type: "ApprovalRequest", Principal: "alice"}, "", false},
		{"own grant", "alice", "task.read", bridge.Resource{Type: "AccessGrant", Principal: "alice", ID: 1, RoleName: &role}, "", true},
		{"deactivated admin", "gone", "admin.policies", bridge.System, "", false},
	} {
		if got := allow(tc.principal, tc.action, tc.resource, tc.ip); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}

	var id int64
	_ = st.Pool.QueryRow(ctx, `SELECT id FROM datasource WHERE name = 'gated'`).Scan(&id)
	for principal, want := range map[string]bool{"connector": true, "stranger": false} {
		got, err := l.MayConnect(ctx, principal, []int64{id, 999999}, "")
		if err != nil || len(got) != 2 || got[0] != want || got[1] {
			t.Errorf("may-connect %s: %v %v", principal, got, err)
		}
	}

	ok, reason, _ := l.Authorize(ctx, "alice", "admin.policies", bridge.System, "")
	if ok || reason != "no policy permits this action" {
		t.Errorf("deny reason %q", reason)
	}
}

func TestPoliciesReloadWhenTheStoreChanges(t *testing.T) {
	st := dbtest.Open(t)
	ctx := context.Background()
	l := Local{Engine: New(st.Pool)}
	ask := func() bool {
		ok, _, err := l.Authorize(ctx, "late", "audit.read", bridge.AuditLog, "")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if ask() {
		t.Fatal("allowed before the grant")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('late', 'permit(principal == User::"late", action == Action::"audit.read", resource);', true, 'USER')`); err != nil {
		t.Fatal(err)
	}
	if !ask() {
		t.Fatal("a policy written by another process must apply without a signal")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('newer', 'permit(principal == User::"x", action == Action::"audit.read", resource);', true, 'USER')`); err != nil {
		t.Fatal(err)
	}
	if !ask() {
		t.Fatal("still allowed")
	}
	// An edit committed by a transaction that started before the newest policy was written.
	if _, err := st.Pool.Exec(ctx, `UPDATE policy SET cedar_src = 'forbid(principal == User::"late", action == Action::"audit.read", resource);',
		updated_at = updated_at + interval '1 microsecond' WHERE name = 'late'`); err != nil {
		t.Fatal(err)
	}
	if ask() {
		t.Fatal("an older-timestamped edit must apply")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE policy SET deleted_at = now() WHERE name = 'late'`); err != nil {
		t.Fatal(err)
	}
	if ask() {
		t.Fatal("a deleted policy must stop applying")
	}
}

func TestSameReason(t *testing.T) {
	if !SameReason("denied by policy: policy-2, policy-1", "denied by policy: policy-1, policy-2") || SameReason("a", "b") {
		t.Fatal(strings.Repeat("x", 0))
	}
}
