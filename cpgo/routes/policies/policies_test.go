package policies_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestAdminLists(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	admin := e.St.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.St.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.Authz.Allow = map[string]bool{
		"admin@example.com admin.identity System:": true,
		"admin@example.com admin.policies System:": true,
	}
	var roleID int64
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO app_role (name) VALUES ('zz-analyst') RETURNING id`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO principal_role (principal, role_id) VALUES ('bob@example.com', $1), ('amy@example.com', $1)`, roleID); err != nil {
		t.Fatal(err)
	}

	status, body := e.Do(t, http.MethodGet, "/api/roles", "", plain)
	if status != http.StatusOK || !strings.Contains(body, `{"id":`+strconv.FormatInt(roleID, 10)+`,"name":"zz-analyst"}`) {
		t.Fatalf("roles for any session: %d %s", status, body)
	}

	status, body = e.Do(t, http.MethodGet, "/api/role-assignments", "", plain)
	if status != http.StatusForbidden || body != `{"code":"common.forbidden","params":{"detail":"no permit for admin.identity"}}` {
		t.Fatalf("non-admin: %d %s", status, body)
	}
	_, body = e.Do(t, http.MethodGet, "/api/role-assignments?roleId="+strconv.FormatInt(roleID, 10), "", admin)
	want := `[{"id":%d,"principal":"amy@example.com","roleId":%d,"roleName":"zz-analyst"},{"id":%d,"principal":"bob@example.com","roleId":%d,"roleName":"zz-analyst"}]`
	var amy, bob int64
	_ = e.St.Pool.QueryRow(ctx, `SELECT id FROM principal_role WHERE principal = 'amy@example.com'`).Scan(&amy)
	_ = e.St.Pool.QueryRow(ctx, `SELECT id FROM principal_role WHERE principal = 'bob@example.com'`).Scan(&bob)
	if body != fmt.Sprintf(want, amy, roleID, bob, roleID) {
		t.Fatalf("by role: %s", body)
	}
	if _, body = e.Do(t, http.MethodGet, "/api/role-assignments?principal=bob@example.com&roleId="+strconv.FormatInt(roleID, 10), "", admin); strings.Count(body, `"principal"`) != 1 {
		t.Fatalf("by principal and role: %s", body)
	}
	if _, body = e.Do(t, http.MethodGet, "/api/role-assignments?roleId=abc", "", admin); body != "[]" {
		t.Fatalf("non-numeric roleId: %s", body)
	}

	for _, path := range []string{"/api/mask-fns", "/api/policies"} {
		e.Authz.Asked = nil
		status, body = e.Do(t, http.MethodGet, path, "", plain)
		if status != http.StatusForbidden || body != `{"code":"common.forbidden","params":{"detail":"no permit for admin.policies"}}` ||
			len(e.Authz.Asked) != 1 || e.Authz.Asked[0] != "plain@example.com admin.policies System: @127.0.0.1" {
			t.Fatalf("%s for a non-admin: %d %s asked %v", path, status, body, e.Authz.Asked)
		}
	}

	var live int64
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO mask_fn (name, kind) VALUES ('zz-live', 'HASH') RETURNING id`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO mask_fn (name, kind, deleted_at) VALUES ('zz-gone', 'HASH', now())`); err != nil {
		t.Fatal(err)
	}
	status, body = e.Do(t, http.MethodGet, "/api/mask-fns", "", admin)
	if status != http.StatusOK || !strings.HasSuffix(body, fmt.Sprintf(`{"id":%d,"name":"zz-live","kind":"HASH"}]`, live)) || strings.Contains(body, "zz-gone") {
		t.Fatalf("mask fns: %d %s", status, body)
	}
	status, body = e.Do(t, http.MethodGet, "/api/policies", "", admin)
	var ps []map[string]any
	if err := json.Unmarshal([]byte(body), &ps); err != nil || status != http.StatusOK || len(ps) == 0 {
		t.Fatalf("policies: %d %s", status, body)
	}
	var seed map[string]any
	for _, p := range ps {
		if p["id"] == float64(-1) {
			seed = p
		}
	}
	if seed["origin"] != "SYSTEM" || seed["systemKey"] != "bootstrap.pm-admin" || seed["name"] != "system:admin" {
		t.Fatalf("the seeded system policy carries its provenance: %v", seed)
	}
	if _, ok := ps[0]["updatedAt"].(string); !ok || ps[0]["cedarSrc"] == nil {
		t.Fatalf("policy shape: %v", ps[0])
	}
}

func TestMePermissions(t *testing.T) {
	e := routetest.Setup(t)
	for _, tc := range []struct {
		principal string
		allow     []string
		want      string
	}{
		{"roleless@example.com", nil, `{"isAdmin":false,"canReadAllAudit":false,"canApprove":false}`},
		{"policy@example.com", []string{"admin.policies System:"}, `{"isAdmin":true,"canReadAllAudit":false,"canApprove":true}`},
		{"datasources@example.com", []string{"admin.datasources System:"}, `{"isAdmin":true,"canReadAllAudit":false,"canApprove":true}`},
		{"identity@example.com", []string{"admin.identity System:"}, `{"isAdmin":true,"canReadAllAudit":false,"canApprove":true}`},
		{"auditor@example.com", []string{"audit.read AuditLog:"}, `{"isAdmin":false,"canReadAllAudit":true,"canApprove":false}`},
	} {
		e.Authz.Allow = map[string]bool{}
		for _, a := range tc.allow {
			e.Authz.Allow[tc.principal+" "+a] = true
		}
		c := e.St.WebSession(t, tc.principal, "k-"+tc.principal, "dev-1")
		if status, body := e.Do(t, http.MethodGet, "/api/me/permissions", "", c); status != http.StatusOK || body != tc.want {
			t.Fatalf("%s: %d %s", tc.principal, status, body)
		}
	}
}

func TestMePermissionsRequesterIP(t *testing.T) {
	const gated = `permit(principal in Role::"edge-admin", action == Action::"admin.datasources", resource)
		when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`
	seed := func(e *routetest.Env) []*http.Cookie {
		e.Exec(t, `INSERT INTO app_role (name) VALUES ('edge-admin')`)
		e.Exec(t, `INSERT INTO principal_role (principal, role_id) SELECT 'edge@example.com', id FROM app_role WHERE name = 'edge-admin'`)
		e.Exec(t, `INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('ip-gated-admin', $1, true, 'USER')`, gated)
		return e.St.WebSession(t, "edge@example.com", "k-edge", "dev-1")
	}
	isAdmin := func(e *routetest.Env, c []*http.Cookie, xff string) bool {
		t.Helper()
		status, body := e.DoHeader(t, http.MethodGet, "/api/me/permissions", "", c, "X-Forwarded-For", xff)
		var p struct{ IsAdmin bool }
		if err := json.Unmarshal([]byte(body), &p); status != http.StatusOK || err != nil {
			t.Fatalf("permissions: %d %s", status, body)
		}
		return p.IsAdmin
	}

	trusted := routetest.SetupConfig(t, routetest.Config{Local: true, Edges: []string{"127.0.0.1"}})
	c := seed(trusted)
	if !isAdmin(trusted, c, "203.0.113.10") || isAdmin(trusted, c, "198.51.100.10") {
		t.Fatal("a trusted edge's forwarded requester IP must decide the IP-gated admin permit")
	}
	untrusted := routetest.SetupConfig(t, routetest.Config{Local: true})
	if isAdmin(untrusted, seed(untrusted), "203.0.113.10") {
		t.Fatal("an untrusted peer spoofed requester_ip through X-Forwarded-For")
	}

	for _, tc := range []struct {
		edges []string
		want  string
	}{{[]string{"127.0.0.1"}, "@203.0.113.10"}, {nil, "@127.0.0.1"}} {
		e := routetest.SetupConfig(t, routetest.Config{Edges: tc.edges})
		c := e.St.WebSession(t, "edge@example.com", "k-edge", "dev-1")
		e.DoHeader(t, http.MethodGet, "/api/me/permissions", "", c, "X-Forwarded-For", "203.0.113.10")
		for _, asked := range e.Authz.Asked {
			if !strings.HasSuffix(asked, " "+tc.want) {
				t.Fatalf("edges %v: asked %v, want every decision %s", tc.edges, e.Authz.Asked, tc.want)
			}
		}
		if len(e.Authz.Asked) != 4 {
			t.Fatalf("edges %v: asked %v", tc.edges, e.Authz.Asked)
		}
	}
}

func TestPolicyCapAnnotations(t *testing.T) {
	e := routetest.SetupConfig(t, routetest.Config{Local: true})
	e.Exec(t, `INSERT INTO principal_role (principal, role_id) SELECT 'boss@example.com', id FROM app_role WHERE name = 'system:admin'`)
	boss := e.St.WebSession(t, "boss@example.com", "k-boss", "dev-1")
	analyst := e.St.WebSession(t, "analyst@example.com", "k-analyst", "dev-2")
	save := func(c []*http.Cookie, name, src string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": name, "cedarSrc": src})
		return e.Do(t, http.MethodPost, "/api/policies", string(body), c)
	}
	for i, bad := range []string{
		`@cap("5M") permit(principal, action == Action::"result.cap", resource);`,
		`@cap("1/32d") permit(principal, action == Action::"result.cap", resource);`,
		`@cap("10/1x") permit(principal, action == Action::"result.cap", resource);`,
		`@cap("5") permit(principal in Role::"analyst", action == Action::"result.read.unmasked", resource);`,
	} {
		status, body := save(boss, fmt.Sprintf("cap-%d", i), bad)
		if status != http.StatusBadRequest || !strings.Contains(body, `"errors"`) || !(strings.Contains(body, "@cap") || strings.Contains(body, "result.cap")) {
			t.Errorf("%s: %d %s", bad, status, body)
		}
	}
	if status, body := save(boss, "cap-ok", `@cap("2000, 3MB, 100KB/10m, 7GB/31d") permit(principal in Role::"analyst", action == Action::"result.cap", resource);`); status != http.StatusCreated {
		t.Fatalf("valid cap: %d %s", status, body)
	}
	if status, body := save(analyst, "cap-nope", `@cap("1") permit(principal, action == Action::"result.cap", resource);`); status != http.StatusForbidden {
		t.Fatalf("non-admin save: %d %s", status, body)
	}
	if e.Authz.Changed != 1 {
		t.Fatalf("%d policy change signals, want 1", e.Authz.Changed)
	}
}
