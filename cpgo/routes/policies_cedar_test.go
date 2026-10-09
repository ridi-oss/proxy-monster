package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCedarPolicyWrites(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.st.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	e.authz.allow = map[string]bool{"admin@example.com admin.policies System:": true}
	do := func(method, path, body string, want int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, admin)
		if status != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, want)
		}
		return resp
	}
	src := `permit(principal, action == Action::\"audit.read\", resource);`

	created := do(http.MethodPost, "/api/policies", `{"name":"p1","cedarSrc":"`+src+`","enabled":false}`, http.StatusCreated)
	var id int64
	_, _ = fmt.Sscanf(created, `{"id":%d`, &id)
	if !strings.Contains(created, `"origin":"USER","name":"p1",`) || !strings.Contains(created, `"enabled":false,"updatedBy":"admin@example.com","updatedAt":"`) || e.authz.changed != 1 {
		t.Fatalf("created %s changed=%d", created, e.authz.changed)
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
	do(http.MethodPut, fmt.Sprintf("/api/policies/%d", id), `{"name":"p1-renamed","cedarSrc":"`+src+`"}`, http.StatusOK)
	do(http.MethodPut, "/api/policies/999999", `{"name":"x","cedarSrc":"`+src+`"}`, http.StatusNotFound)
	if body := do(http.MethodPut, "/api/policies/-1", `{"name":"x","cedarSrc":"`+src+`"}`, http.StatusConflict); body != `{"code":"policy.system_immutable","params":{}}` {
		t.Fatalf("system update: %s", body)
	}
	do(http.MethodDelete, "/api/policies/-1", "", http.StatusConflict)

	if _, err := e.st.Pool.Exec(ctx, `UPDATE policy SET cedar_src = 'BAD stored' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	do(http.MethodPost, fmt.Sprintf("/api/policies/%d/enable", id), "", http.StatusBadRequest)
	do(http.MethodPost, fmt.Sprintf("/api/policies/%d/disable", id), "", http.StatusOK)
	do(http.MethodPost, "/api/policies/-1/disable", "", http.StatusOK)
	do(http.MethodPost, "/api/policies/-1/enable", "", http.StatusOK)

	before := e.authz.changed
	do(http.MethodDelete, fmt.Sprintf("/api/policies/%d", id), "", http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/policies/%d", id), "", http.StatusNotFound)
	if e.authz.changed != before+1 {
		t.Fatalf("delete signals once: %d -> %d", before, e.authz.changed)
	}

	if body := do(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"BAD"}`, http.StatusOK); body != "{\"valid\":false,\"errors\":[\"unrecognized action `BAD`\"]}" {
		t.Fatalf("validate bad: %s", body)
	}
	if body := do(http.MethodPost, "/api/policies/validate", `{"cedarSrc":"`+src+`"}`, http.StatusOK); body != `{"valid":true,"errors":[]}` {
		t.Fatalf("validate good: %s", body)
	}

	rows, _ := e.st.Pool.Query(ctx, `SELECT statement FROM audit_event WHERE action = 'admin.policies' ORDER BY id`)
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
