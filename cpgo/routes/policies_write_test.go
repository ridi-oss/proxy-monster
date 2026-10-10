package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestPolicyWrites(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.st.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.st.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.authz.allow = map[string]bool{
		"admin@example.com admin.policies System:": true,
		"admin@example.com admin.identity System:": true,
	}
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, c)
		if status != wantStatus {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, wantStatus)
		}
		return resp
	}

	do(http.MethodPost, "/api/roles", `{"name":"analyst"}`, plain, http.StatusForbidden)
	created := do(http.MethodPost, "/api/roles", `{"name":"analyst","description":"reads <stuff>"}`, admin, http.StatusCreated)
	var id int64
	if _, err := fmt.Sscanf(created, `{"id":%d`, &id); err != nil || !strings.HasSuffix(created, `,"name":"analyst","description":"reads <stuff>"}`) {
		t.Fatalf("created %s", created)
	}
	if body := do(http.MethodPost, "/api/roles", `{"name":"analyst"}`, admin, http.StatusBadRequest); body != `{"code":"common.already_exists","params":{"resource":"role","name":"analyst"}}` {
		t.Fatalf("duplicate: %s", body)
	}
	for _, junk := range []string{`{"name":"trailing"} garbage`, `{"name":"two"}{"name":"three"}`, `not json`} {
		do(http.MethodPost, "/api/roles", junk, admin, http.StatusBadRequest)
	}
	if body := do(http.MethodPost, "/api/roles", `{"name":"  "}`, admin, http.StatusBadRequest); body != `{"code":"common.field_required","params":{"fields":"name"}}` {
		t.Fatalf("blank: %s", body)
	}
	do(http.MethodPut, fmt.Sprintf("/api/roles/%d", id), `{"name":"analyst-2"}`, admin, http.StatusOK)
	do(http.MethodPut, "/api/roles/99999", `{"name":"x"}`, admin, http.StatusNotFound)
	do(http.MethodPut, "/api/roles/abc", `{"name":"x"}`, admin, http.StatusBadRequest)

	assigned := do(http.MethodPost, "/api/role-assignments", fmt.Sprintf(`{"principal":"bob@example.com","roleId":%d}`, id), admin, http.StatusCreated)
	do(http.MethodPost, "/api/role-assignments", fmt.Sprintf(`{"principal":"bob@example.com","roleId":%d}`, id), admin, http.StatusCreated)
	var assignment int64
	_, _ = fmt.Sscanf(assigned, `{"id":%d`, &assignment)
	if !strings.HasSuffix(assigned, fmt.Sprintf(`,"principal":"bob@example.com","roleId":%d,"roleName":"analyst-2"}`, id)) {
		t.Fatalf("assigned %s", assigned)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/role-assignments/%d", assignment), "", admin, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/role-assignments/%d", assignment), "", admin, http.StatusNotFound)

	mf := do(http.MethodPost, "/api/mask-fns", `{"name":"hash-it","kind":"HASH"}`, admin, http.StatusCreated)
	var mfID int64
	_, _ = fmt.Sscanf(mf, `{"id":%d`, &mfID)
	do(http.MethodPost, "/api/mask-fns", `{"name":"x","kind":""}`, admin, http.StatusBadRequest)
	if updated := do(http.MethodPut, fmt.Sprintf("/api/mask-fns/%d", mfID), `{"name":"hash-it","kind":"FIXED"}`, admin, http.StatusOK); updated != fmt.Sprintf(`{"id":%d,"name":"hash-it","kind":"FIXED"}`, mfID) {
		t.Fatalf("mask fn update: %s", updated)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/mask-fns/%d", mfID), "", admin, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/mask-fns/%d", mfID), "", admin, http.StatusNotFound)

	var system int64
	if err := e.st.Pool.QueryRow(ctx, `SELECT gr.role_id FROM group_role gr JOIN app_group g ON g.id = gr.group_id WHERE g.source = 'SYSTEM' LIMIT 1`).Scan(&system); err != nil {
		t.Fatal(err)
	}
	do(http.MethodPut, fmt.Sprintf("/api/roles/%d", system), `{"name":"renamed-admin"}`, admin, http.StatusConflict)
	if body := do(http.MethodDelete, fmt.Sprintf("/api/roles/%d", system), "", admin, http.StatusConflict); body != `{"code":"role.system_immutable","params":{}}` {
		t.Fatalf("system role: %s", body)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/roles/%d", id), "", admin, http.StatusNoContent)

	want := []string{
		"admin|admin@example.com|admin.policies|Role::\"analyst\"|create role 'analyst'|127.0.0.1|console",
		"admin|admin@example.com|admin.policies|Role::\"analyst-2\"|update role 'analyst' -> 'analyst-2'|127.0.0.1|console",
		"admin|admin@example.com|admin.identity|Role::\"analyst-2\"|assign role 'analyst-2' to 'bob@example.com'|127.0.0.1|console",
		"admin|admin@example.com|admin.identity|Role::\"analyst-2\"|unassign role 'analyst-2' from 'bob@example.com'|127.0.0.1|console",
		"admin|admin@example.com|admin.policies|MaskFn::\"hash-it\"|create mask function 'hash-it'|127.0.0.1|console",
		"admin|admin@example.com|admin.policies|MaskFn::\"hash-it\"|update mask function 'hash-it'|127.0.0.1|console",
		"admin|admin@example.com|admin.policies|MaskFn::\"hash-it\"|delete mask function 'hash-it'|127.0.0.1|console",
		"admin|admin@example.com|admin.policies|Role::\"analyst-2\"|delete role 'analyst-2'|127.0.0.1|console",
	}
	if got := auditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	verifyChain(t, e)
}
