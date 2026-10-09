package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestClassificationWrites(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.st.WebSession(t, "admin@example.com", "k-admin", "dev-1")
	plain := e.st.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	e.authz.allow = map[string]bool{"admin@example.com admin.datasources System:": true}
	var orders, bare, pg, hash int64
	scan := func(dst *int64, sql string) {
		t.Helper()
		if err := e.st.Pool.QueryRow(ctx, sql).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	scan(&orders, `INSERT INTO datasource (name, engine, host, port, db_name, default_schemas) VALUES ('orders', 'mysql', 'h', 1, 'app', '["information_schema", "app"]') RETURNING id`)
	scan(&bare, `INSERT INTO datasource (name, engine, host, port, db_name) VALUES ('bare', 'mysql', 'h', 1, 'app') RETURNING id`)
	scan(&pg, `INSERT INTO datasource (name, engine, host, port, db_name, default_schemas) VALUES ('pg', 'postgres', 'h', 1, 'shop', '["pg_catalog", "public"]') RETURNING id`)
	scan(&hash, `INSERT INTO mask_fn (name, kind) VALUES ('hash-it', 'HASH') RETURNING id`)
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, c)
		if status != wantStatus {
			t.Fatalf("%s %s %s: %d %s, want %d", method, path, body, status, resp, wantStatus)
		}
		return resp
	}
	put := func(id int64, body string, c []*http.Cookie, want int) string {
		t.Helper()
		return do(http.MethodPut, fmt.Sprintf("/api/datasources/%d/classification", id), body, c, want)
	}

	put(orders, `{"table":"users","column":"email","catalog":"def"}`, plain, http.StatusForbidden)
	put(orders, `{"table":"users","column":"email"}`, admin, http.StatusBadRequest)
	if body := put(orders, `{"table":" ","column":"email","catalog":"def"}`, admin, http.StatusBadRequest); body != `{"code":"common.field_required","params":{"fields":"table"}}` {
		t.Fatalf("blank table: %s", body)
	}
	put(999999, `{"table":"users","column":"email","catalog":"def"}`, admin, http.StatusNotFound)
	if body := put(bare, `{"table":"users","column":"email","catalog":"def"}`, admin, http.StatusBadRequest); body != `{"code":"datasource.schema_required","params":{}}` {
		t.Fatalf("no schema: %s", body)
	}
	if body := put(orders, `{"table":"users","column":"email","tags":["pii","system:whatever"],"catalog":"def"}`, admin, http.StatusBadRequest); body != `{"code":"datasource.reserved_tag","params":{"tag":"system:whatever"}}` {
		t.Fatalf("reserved tag: %s", body)
	}
	if body := put(orders, `{"table":"users","column":"email","catalog":"app"}`, admin, http.StatusBadRequest); body != `{"code":"datasource.invalid_catalog","params":{}}` {
		t.Fatalf("wrong catalog: %s", body)
	}
	tagged := put(orders, fmt.Sprintf(`{"table":"users","column":"email","tags":["pii","system:critical"],"maskFnId":%d,"catalog":"def"}`, hash), admin, http.StatusOK)
	if tagged != fmt.Sprintf(`{"schema":"app","table":"users","column":"email","tags":["pii","system:critical"],"maskFnId":%d,"maskFnName":"hash-it","catalog":"def"}`, hash) {
		t.Fatalf("tagged %s", tagged)
	}
	if retagged := put(orders, `{"schema":"crm","table":"users","column":"email","tags":["pii"],"catalog":"def"}`, admin, http.StatusOK); retagged != `{"schema":"crm","table":"users","column":"email","tags":["pii"],"catalog":"def"}` {
		t.Fatalf("explicit schema %s", retagged)
	}
	if got := put(orders, `{"schema":" ","table":"users","column":"email","tags":["pii"],"catalog":"def"}`, admin, http.StatusOK); !strings.HasPrefix(got, `{"schema":"app",`) {
		t.Fatalf("a blank schema must mean the default schema: %s", got)
	}
	put(orders, `{"table":"users","column":"email","tags":["pii"],"catalog":"def"}`, admin, http.StatusOK)
	put(orders, `{"table":"users","column":"email","tags":null,"catalog":"def"}`, admin, http.StatusBadRequest)
	put(orders, `{"table":"users","column":"email","tags":["system:Production"],"catalog":"def"}`, admin, http.StatusBadRequest)
	put(orders, `{"table":"shipped","column":"c","tags":["system:production","system:development","system:data-leak","system:activity","system:catalog"],"catalog":"def"}`, admin, http.StatusOK)
	put(orders, `{"table":"users","column":"email","tags":[null],"catalog":"def"}`, admin, http.StatusBadRequest)
	if got := put(pg, `{"table":"t","column":"c","tags":["pii"],"catalog":"shop"}`, admin, http.StatusOK); !strings.HasPrefix(got, `{"schema":"public",`) {
		t.Fatalf("postgres default schema: %s", got)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE datasource SET current_catalog_name = 'Shop' WHERE id = $1`, pg); err != nil {
		t.Fatal(err)
	}
	put(pg, `{"table":"t","column":"c","tags":["pii"],"catalog":"shop"}`, admin, http.StatusBadRequest)
	put(pg, `{"table":"t","column":"c","tags":["pii"],"catalog":"Shop"}`, admin, http.StatusOK)
	var rows int
	_ = e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM column_classification WHERE datasource_id = $1 AND schema_name = 'app' AND tags = '["pii"]'::jsonb AND mask_fn_id IS NULL`, orders).Scan(&rows)
	if rows != 1 {
		t.Fatalf("%d replaced rows", rows)
	}

	clear := fmt.Sprintf("/api/datasources/%d/classification", orders)
	do(http.MethodDelete, clear, `{"table":"users","column":"email","catalog":"nope"}`, admin, http.StatusBadRequest)
	do(http.MethodDelete, clear, `{"table":"users","column":"email","catalog":"def"}`, admin, http.StatusNoContent)
	do(http.MethodDelete, clear, `{"table":"users","column":"email","catalog":"def"}`, admin, http.StatusNoContent)
	var left string
	_ = e.st.Pool.QueryRow(ctx, `SELECT string_agg(schema_name || '.' || table_name || '.' || column_name, ',') FROM column_classification WHERE datasource_id = $1`, orders).Scan(&left)
	if left != "app.shipped.c,crm.users.email" && left != "crm.users.email,app.shipped.c" {
		t.Fatalf("after clearing app.users.email, left %q", left)
	}
	do(http.MethodDelete, fmt.Sprintf("/api/datasources/%d/classification", bare), `{"table":"users","column":"email","catalog":"def"}`, admin, http.StatusBadRequest)

	a := func(resource, summary string) string {
		return "admin|admin@example.com|admin.datasources|" + resource + "|" + summary + "|127.0.0.1|console"
	}
	want := []string{
		a(`Datasource::"orders" col app.users.email`, "tag orders.app.users.email [pii, system:critical]"),
		a(`Datasource::"orders" col crm.users.email`, "tag orders.crm.users.email [pii]"),
		a(`Datasource::"orders" col app.users.email`, "tag orders.app.users.email [pii]"),
		a(`Datasource::"orders" col app.users.email`, "tag orders.app.users.email [pii]"),
		a(`Datasource::"orders" col app.shipped.c`, "tag orders.app.shipped.c [system:production, system:development, system:data-leak, system:activity, system:catalog]"),
		a(`Datasource::"pg" col public.t.c`, "tag pg.public.t.c [pii]"),
		a(`Datasource::"pg" col public.t.c`, "tag pg.public.t.c [pii]"),
		a(`Datasource::"orders" col app.users.email`, "clear tags on orders.app.users.email"),
	}
	if got := auditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}
