package datasources_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestDatasourceWrites(t *testing.T) {
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

	do(http.MethodPost, "/api/datasources", `{"name":"orders"}`, plain, http.StatusForbidden)
	if body := do(http.MethodPost, "/api/datasources", `{"name":"x","engine":"oracle"}`, admin, http.StatusBadRequest); body != `{"code":"datasource.invalid_engine","params":{"engine":"oracle"}}` {
		t.Fatalf("invalid engine: %s", body)
	}
	if body := do(http.MethodPost, "/api/datasources", `{"name":" "}`, admin, http.StatusBadRequest); body != `{"code":"common.field_required","params":{"fields":"name"}}` {
		t.Fatalf("blank name: %s", body)
	}
	created := do(http.MethodPost, "/api/datasources", `{"name":"orders","engine":"MySQL","host":"db","port":3306,"dbName":"app"}`, admin, http.StatusCreated)
	var id int64
	if _, err := fmt.Sscanf(created, `{"id":%d`, &id); err != nil || created != fmt.Sprintf(`{"id":%d,"name":"orders","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"`+"`"+`"}`, id) {
		t.Fatalf("created %s", created)
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
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if body := do(method, fmt.Sprintf("/api/datasources/%d", id), `{"name":"orders"}`, plain, http.StatusForbidden); body != `{"code":"common.forbidden","params":{"detail":"no permit for admin.datasources"}}` {
			t.Fatalf("%s by a non-admin: %s", method, body)
		}
	}
	if row() != before || len(e.Authz.Deleted) != 0 {
		t.Fatalf("a refused write changed the datasource: %s", row())
	}
	if _, err := e.St.Pool.Exec(ctx, `UPDATE datasource SET catalog = '\x01', current_catalog_name = 'def', catalog_synced_at = now(),
		default_schemas = '["app"]', mysql_lower_case_table_names = 1 WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	catalogKept := func() int {
		t.Helper()
		var n int
		if err := e.St.Pool.QueryRow(ctx, `SELECT (catalog IS NOT NULL)::int + (current_catalog_name IS NOT NULL)::int + (catalog_synced_at IS NOT NULL)::int
			+ (default_schemas <> '[]'::jsonb)::int + (mysql_lower_case_table_names IS NOT NULL)::int FROM datasource WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if body := do(http.MethodPut, fmt.Sprintf("/api/datasources/%d", id), `{"name":"orders","engine":"postgres"}`, admin, http.StatusConflict); body != `{"code":"datasource.engine_immutable","params":{}}` {
		t.Fatalf("engine change: %s", body)
	}
	kept := do(http.MethodPut, fmt.Sprintf("/api/datasources/%d", id), `{"name":"orders-2","engine":"mysql","host":"db2","port":3307,"dbName":"app"}`, admin, http.StatusOK)
	if !strings.Contains(kept, `"name":"orders-2","engine":"mysql","host":"db2","port":3307,"dbName":"app","tags":[],"defaultSchemas":["app"],"mysqlLowerCaseTableNames":1,"catalogSyncedAt":`) || catalogKept() != 5 {
		t.Fatalf("same db_name must keep the catalog: %s", kept)
	}
	moved := do(http.MethodPut, fmt.Sprintf("/api/datasources/%d", id), `{"name":"orders-2","engine":"mysql","host":"db2","port":3307,"dbName":"other"}`, admin, http.StatusOK)
	if moved != fmt.Sprintf(`{"id":%d,"name":"orders-2","engine":"mysql","host":"db2","port":3307,"dbName":"other","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true,"identifierQuote":"`+"`"+`"}`, id) || catalogKept() != 0 {
		t.Fatalf("a db_name change must drop the catalog: %s", moved)
	}
	do(http.MethodPut, "/api/datasources/999999", `{"name":"x"}`, admin, http.StatusNotFound)

	e.Authz.Attached = []string{"orders-2"}
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
	if strings.Join(e.Authz.Deleted, ",") != "orders-2" {
		t.Fatalf("deleted signals %v", e.Authz.Deleted)
	}

	a := func(resource, summary string) string {
		return "admin|admin@example.com|admin.datasources|" + resource + "|" + summary + "|127.0.0.1|console"
	}
	want := []string{
		a(`Datasource::"orders"`, "create datasource 'orders'"),
		a(`Datasource::"orders-2"`, "update datasource 'orders' -> 'orders-2'"),
		a(`Datasource::"orders-2"`, "update datasource 'orders-2'"),
		a(`Datasource::"orders-2"`, "delete datasource 'orders-2'"),
	}
	if got := routetest.AuditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e)
}
