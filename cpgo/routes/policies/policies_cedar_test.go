package policies_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestCedarPolicyWrites(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	admin := e.St.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	e.Authz.Allow = map[string]bool{"admin@example.com admin.policies System:": true}
	snapshot := func() string {
		var s string
		_ = e.St.Pool.QueryRow(ctx, `SELECT string_agg(id || ':' || name || ':' || enabled || ':' || (deleted_at IS NULL), ',' ORDER BY id) FROM policy`).Scan(&s)
		return s
	}
	e.Authz.AtSignal = snapshot
	// do also checks the request signals Kotlin exactly signals times, after its change is visible to
	// another connection, i.e. after commit.
	do := func(method, path, body string, want int, signals ...int) string {
		t.Helper()
		before := e.Authz.Changed
		status, resp := e.Do(t, method, path, body, admin)
		if status != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, want)
		}
		wantSignals := 0
		if len(signals) > 0 {
			wantSignals = signals[0]
		}
		if got := e.Authz.Changed - before; got != wantSignals {
			t.Fatalf("%s %s: %d signals, want %d", method, path, got, wantSignals)
		}
		if wantSignals > 0 && e.Authz.Seen[len(e.Authz.Seen)-1] != snapshot() {
			t.Fatalf("%s %s: signalled before the change was committed", method, path)
		}
		return resp
	}
	src := `permit(principal, action == Action::\"audit.read\", resource);`

	created := do(http.MethodPost, "/api/policies", `{"name":"p1","cedarSrc":"`+src+`","enabled":false}`, http.StatusCreated, 1)
	var id int64
	_, _ = fmt.Sscanf(created, `{"id":%d`, &id)
	if !strings.Contains(created, `"origin":"USER","name":"p1",`) || !strings.Contains(created, `"enabled":false,"updatedBy":"admin@example.com","updatedAt":"`) {
		t.Fatalf("created %s", created)
	}
	if body := do(http.MethodPost, "/api/policies", `{"name":"p1","cedarSrc":"`+src+`"}`, http.StatusBadRequest); body != `{"code":"common.already_exists","params":{"resource":"policy"}}` {
		t.Fatalf("duplicate: %s", body)
	}
	if body := do(http.MethodPost, "/api/policies", `{"name":"p2","cedarSrc":"BAD"}`, http.StatusBadRequest); body != "{\"errors\":[\"unrecognized action `BAD`\"]}" {
		t.Fatalf("invalid: %s", body)
	}
	if body := do(http.MethodPost, "/api/policies", `{"name":"system:x","cedarSrc":"`+src+`"}`, http.StatusBadRequest); body != `{"code":"policy.reserved_name","params":{}}` {
		t.Fatalf("reserved: %s", body)
	}
	if body := do(http.MethodPut, fmt.Sprintf("/api/policies/%d", id), `{"name":"system:renamed","cedarSrc":"`+src+`"}`, http.StatusBadRequest); body != `{"code":"policy.reserved_name","params":{}}` {
		t.Fatalf("reserved rename: %s", body)
	}
	var name string
	if _ = e.St.Pool.QueryRow(ctx, `SELECT name FROM policy WHERE id = $1`, id).Scan(&name); name != "p1" {
		t.Fatalf("a refused rename changed the name to %q", name)
	}
	do(http.MethodPut, fmt.Sprintf("/api/policies/%d", id), `{"name":"p1-renamed","cedarSrc":"`+src+`"}`, http.StatusOK, 1)
	do(http.MethodPut, "/api/policies/999999", `{"name":"x","cedarSrc":"`+src+`"}`, http.StatusNotFound)
	system := func() string {
		var row string
		_ = e.St.Pool.QueryRow(ctx, `SELECT to_jsonb(p)::text FROM policy p WHERE id = -1`).Scan(&row)
		return row
	}
	before := system()
	if body := do(http.MethodPut, "/api/policies/-1", `{"name":"system:rewritten","cedarSrc":"not cedar","enabled":false}`, http.StatusConflict); body != `{"code":"policy.system_immutable","params":{}}` {
		t.Fatalf("system update: %s", body)
	}
	if body := do(http.MethodDelete, "/api/policies/-1", "", http.StatusConflict); body != `{"code":"policy.system_immutable","params":{}}` {
		t.Fatalf("system delete: %s", body)
	}
	if after := system(); before == "" || after != before {
		t.Fatalf("system policy changed:\n%s\n%s", before, after)
	}

	if _, err := e.St.Pool.Exec(ctx, `UPDATE policy SET cedar_src = 'BAD stored' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if body := do(http.MethodPost, fmt.Sprintf("/api/policies/%d/enable", id), "", http.StatusBadRequest); body != "{\"errors\":[\"unrecognized action `BAD`\"]}" {
		t.Fatalf("enabling an invalid stored source: %s", body)
	}
	do(http.MethodPost, fmt.Sprintf("/api/policies/%d/disable", id), "", http.StatusOK, 1)
	if body := do(http.MethodPost, "/api/policies/-1/disable", "", http.StatusOK, 1); !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("disable: %s", body)
	}
	if body := do(http.MethodPost, "/api/policies/-1/enable", "", http.StatusOK, 1); !strings.Contains(body, `"enabled":true`) {
		t.Fatalf("enable: %s", body)
	}
	var enabled bool
	if _ = e.St.Pool.QueryRow(ctx, `SELECT enabled FROM policy WHERE id = -1`).Scan(&enabled); !enabled {
		t.Fatal("the system policy is left disabled")
	}

	do(http.MethodDelete, fmt.Sprintf("/api/policies/%d", id), "", http.StatusNoContent, 1)
	do(http.MethodDelete, fmt.Sprintf("/api/policies/%d", id), "", http.StatusNotFound)

	if body := do(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"BAD"}`, http.StatusOK); body != "{\"valid\":false,\"errors\":[\"unrecognized action `BAD`\"]}" {
		t.Fatalf("validate bad: %s", body)
	}
	if body := do(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"`+src+`"}`, http.StatusOK); body != `{"valid":true,"errors":[]}` {
		t.Fatalf("validate good: %s", body)
	}

	var row string
	_ = e.St.Pool.QueryRow(ctx, `SELECT kind || '|' || principal || '|' || resource || '|' || channel || '|' || coalesce(client_addr, '')
		FROM audit_event WHERE statement = $1`, "disable policy 'system:admin'").Scan(&row)
	if row != `admin|admin@example.com|Policy::"-1"|console|127.0.0.1` {
		t.Fatalf("policy audit row: %s", row)
	}
	rows, _ := e.St.Pool.Query(ctx, `SELECT statement FROM audit_event WHERE action = 'admin.policies' ORDER BY id`)
	var got []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		got = append(got, s)
	}
	want := "create policy 'p1'|update policy 'p1' -> 'p1-renamed'|disable policy 'p1-renamed'|disable policy 'system:admin'|enable policy 'system:admin'|delete policy 'p1-renamed'"
	if strings.Join(got, "|") != want {
		t.Fatalf("audit:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
}
