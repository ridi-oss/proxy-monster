package datasources_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestDatasourceDelete(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	admin := e.St.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.St.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.Authz.Allow = map[string]bool{"admin@example.com admin.datasources System:": true}
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.Do(t, method, path, body, c)
		if status != wantStatus {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, wantStatus)
		}
		return resp
	}

	var id int64
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO datasource (name, engine, target_info) VALUES ('orders', 'mysql', 'db:3306') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	row := func() string {
		t.Helper()
		var r string
		if err := e.St.Pool.QueryRow(ctx, `SELECT to_jsonb(d)::text FROM datasource d WHERE id = $1`, id).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := row()
	if body := do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", plain, http.StatusForbidden); body != `{"code":"common.forbidden","params":{"detail":"no permit for admin.datasources"}}` {
		t.Fatalf("delete by a non-admin: %s", body)
	}
	if row() != before || len(e.Authz.Deleted) != 0 {
		t.Fatalf("a refused delete changed the datasource: %s", row())
	}

	e.Authz.Attached = []string{"orders"}
	if body := do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusConflict); body != `{"code":"datasource.in_use_proxy_attached","params":{}}` {
		t.Fatalf("attached: %s", body)
	}
	e.Authz.Attached = nil
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO app_role (name) VALUES ('r')`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.St.Pool.Exec(ctx, `INSERT INTO access_request (principal, role_id, datasource_id, creator_kind) SELECT 'p', id, $1, 'WORKFLOW' FROM app_role WHERE name = 'r'`, id); err != nil {
		t.Fatal(err)
	}
	if body := do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusConflict); body != `{"code":"datasource.in_use_active_requests","params":{}}` {
		t.Fatalf("active requests: %s", body)
	}
	if _, err := e.St.Pool.Exec(ctx, `UPDATE access_request SET status = 'REJECTED' WHERE datasource_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"PENDING", "EXECUTING"} {
		if _, err := e.St.Pool.Exec(ctx, `INSERT INTO access_request (principal, kind, datasource_id, status, creator_kind) VALUES ('p', 'QUERY', $1, $2, 'WORKFLOW')`, id, status); err != nil {
			t.Fatal(err)
		}
		do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusConflict)
		if _, err := e.St.Pool.Exec(ctx, `UPDATE access_request SET status = 'EXECUTED' WHERE datasource_id = $1 AND kind = 'QUERY'`, id); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Authz.Deleted) != 0 {
		t.Fatalf("a refused delete signalled Kotlin: %v", e.Authz.Deleted)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusNotFound)
	if strings.Join(e.Authz.Deleted, ",") != "orders" {
		t.Fatalf("deleted signals %v", e.Authz.Deleted)
	}

	a := func(resource, summary string) string {
		return "admin|admin@example.com|admin.datasources|" + resource + "|" + summary + "|127.0.0.1|console"
	}
	want := []string{
		a(`Datasource::"orders"`, "delete datasource 'orders'"),
	}
	if got := routetest.AuditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e)
}
