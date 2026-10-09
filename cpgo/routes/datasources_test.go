package routes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDatasourceDetailAndWireCert(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	const chain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	var gated, bare, other int64
	if err := e.st.Pool.QueryRow(ctx, `INSERT INTO datasource (name, host, port, db_name, advertise_addr, advertise_cert_chain)
		VALUES ('gated', 'h', 1, 'd', 'proxy:3306', $1) RETURNING id`, chain).Scan(&gated); err != nil {
		t.Fatal(err)
	}
	_ = e.st.Pool.QueryRow(ctx, `INSERT INTO datasource (name, host, port, db_name) VALUES ('bare', 'h', 1, 'd') RETURNING id`).Scan(&bare)
	_ = e.st.Pool.QueryRow(ctx, `INSERT INTO datasource (name, host, port, db_name, advertise_cert_chain) VALUES ('other', 'h', 1, 'd', $1) RETURNING id`, chain).Scan(&other)
	e.authz.allow = map[string]bool{
		fmt.Sprintf("connector@example.com datasource.connect %d", gated): true,
		fmt.Sprintf("connector@example.com datasource.connect %d", bare):  true,
	}
	connector := e.st.WebSession(t, "connector@example.com", "k-c", "dev-c")
	stranger := e.st.WebSession(t, "stranger@example.com", "k-s", "dev-s")
	const token = "wire-token-for-connector"
	sum := sha256.Sum256([]byte(token))
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO proxy_token (token_hash, principal, kind, expires_at) VALUES ($1, 'connector@example.com', 'USER', now() + interval '1 hour')`,
		hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	get := func(path string, cookies []*http.Cookie, bearer string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	expect := func(path string, cookies []*http.Cookie, bearer string, status int, body string) {
		t.Helper()
		resp, got := get(path, cookies, bearer)
		if resp.StatusCode != status || (body != "" && got != body) || (status != http.StatusOK && strings.Contains(got, "BEGIN CERTIFICATE")) {
			t.Fatalf("GET %s: %d %s, want %d %s", path, resp.StatusCode, got, status, body)
		}
	}
	row, cert := fmt.Sprintf("/api/datasources/%d", gated), fmt.Sprintf("/api/datasources/%d/wire-cert", gated)

	for _, path := range []string{row, cert} {
		expect(path, nil, "", http.StatusUnauthorized, `{"code":"common.unauthenticated","params":{}}`)
		expect(path, stranger, "", http.StatusForbidden, `{"code":"datasource.not_connectable","params":{}}`)
	}
	for _, path := range []string{fmt.Sprintf("/api/datasources/%d", other), fmt.Sprintf("/api/datasources/%d/wire-cert", other)} {
		expect(path, connector, "", http.StatusForbidden, `{"code":"datasource.not_connectable","params":{}}`)
		expect(path, nil, token, http.StatusForbidden, `{"code":"datasource.not_connectable","params":{}}`)
	}
	expect("/api/datasources/999999", connector, "", http.StatusNotFound, `{"code":"common.not_found","params":{"resource":"datasource"}}`)
	expect("/api/datasources/x", connector, "", http.StatusBadRequest, `{"code":"common.bad_id","params":{}}`)
	expect(fmt.Sprintf("/api/datasources/%d/wire-cert", bare), connector, "", http.StatusNotFound, `{"code":"datasource.no_wire_cert","params":{}}`)

	for _, c := range []struct {
		cookies []*http.Cookie
		bearer  string
	}{{connector, ""}, {nil, token}} {
		if _, body := get(row, c.cookies, c.bearer); !strings.Contains(body, `"advertiseAddr":"proxy:3306","advertiseCertChain":"-----BEGIN CERTIFICATE-----\nMIIB`) {
			t.Fatalf("row %s", body)
		}
		resp, body := get(cert, c.cookies, c.bearer)
		if resp.StatusCode != http.StatusOK || body != chain || resp.Header.Get("Content-Type") != "application/x-pem-file" ||
			resp.Header.Get("Content-Disposition") != fmt.Sprintf(`attachment; filename="datasource-%d-wire-cert.pem"`, gated) {
			t.Fatalf("wire cert: %d %v %q", resp.StatusCode, resp.Header, body)
		}
	}
}

func TestDatasourceWrites(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.st.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.st.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.authz.allow = map[string]bool{"admin@example.com admin.datasources System:": true}
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, c)
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
	if _, err := fmt.Sscanf(created, `{"id":%d`, &id); err != nil || !strings.Contains(created, `"name":"orders","engine":"mysql","host":"db","port":3306,"dbName":"app","tags":[],"defaultSchemas":[],"advertiseWireTls":false,"description":"","defaultSchemaSettable":true}`) {
		t.Fatalf("created %s", created)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE datasource SET catalog = '\x01', current_catalog_name = 'def', catalog_synced_at = now(),
		default_schemas = '["app"]', mysql_lower_case_table_names = 1 WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	catalogKept := func() int {
		t.Helper()
		var n int
		if err := e.st.Pool.QueryRow(ctx, `SELECT (catalog IS NOT NULL)::int + (current_catalog_name IS NOT NULL)::int + (catalog_synced_at IS NOT NULL)::int
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
	if !strings.Contains(moved, `"dbName":"other","tags":[],"defaultSchemas":[],"advertiseWireTls"`) || catalogKept() != 0 {
		t.Fatalf("a db_name change must drop the catalog: %s", moved)
	}
	do(http.MethodPut, "/api/datasources/999999", `{"name":"x"}`, admin, http.StatusNotFound)

	e.kotlin.attached = []string{"orders-2"}
	if body := do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusConflict); body != `{"code":"datasource.in_use_proxy_attached","params":{}}` {
		t.Fatalf("attached: %s", body)
	}
	e.kotlin.attached = nil
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO app_role (name) VALUES ('r')`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO access_request (principal, role_id, datasource_id) SELECT 'p', id, $1 FROM app_role WHERE name = 'r'`, id); err != nil {
		t.Fatal(err)
	}
	if body := do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusConflict); body != `{"code":"datasource.in_use_active_requests","params":{}}` {
		t.Fatalf("active requests: %s", body)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE access_request SET status = 'REJECTED' WHERE datasource_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"PENDING", "EXECUTING"} {
		if _, err := e.st.Pool.Exec(ctx, `INSERT INTO access_request (principal, kind, datasource_id, status) VALUES ('p', 'QUERY', $1, $2)`, id, status); err != nil {
			t.Fatal(err)
		}
		do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusConflict)
		if _, err := e.st.Pool.Exec(ctx, `UPDATE access_request SET status = 'EXECUTED' WHERE datasource_id = $1 AND kind = 'QUERY'`, id); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.kotlin.deleted) != 0 {
		t.Fatalf("a refused delete signalled Kotlin: %v", e.kotlin.deleted)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusNoContent)
	do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d", id), "", admin, http.StatusNotFound)
	if strings.Join(e.kotlin.deleted, ",") != "orders-2" {
		t.Fatalf("deleted signals %v", e.kotlin.deleted)
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
	if got := auditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}
