package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/authz"
)

func auditRows(t *testing.T, e *env) []string {
	t.Helper()
	rows, err := e.st.Pool.Query(context.Background(), `SELECT kind || '|' || principal || '|' || action || '|' || resource || '|' || statement || '|' || coalesce(client_addr, '') || '|' || channel
		FROM audit_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func verifyChain(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	dsn := strings.Replace(strings.TrimPrefix(e.st.JDBCURL, "jdbc:"), "postgresql://", "postgresql://"+e.st.User+":"+e.st.Password+"@", 1)
	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil); err != nil || finding != nil {
		t.Fatalf("chain: %+v %v", finding, err)
	}
}

func TestAccessWrites(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	alice := e.st.WebSession(t, "alice@example.com", "k-alice", "dev-1")
	bob := e.st.WebSession(t, "bob@example.com", "k-bob", "dev-2")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	scalar := func(sql string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := e.st.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.do(t, method, path, body, c)
		if status != wantStatus {
			t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, wantStatus)
		}
		return resp
	}
	exec(`INSERT INTO app_role (name) VALUES ('analyst')`)
	role := scalar(`SELECT id FROM app_role WHERE name = 'analyst'`)
	exec(`INSERT INTO datasource (name, host, port, db_name, tags) VALUES ('orders', 'h', 1, 'd', '["prod"]'), ('gone', 'h', 1, 'd', '[]')`)
	orders := scalar(`SELECT id FROM datasource WHERE name = 'orders'`)
	gone := scalar(`SELECT id FROM datasource WHERE name = 'gone'`)
	exec(`UPDATE datasource SET deleted_at = now() WHERE id = $1`, gone)

	do(http.MethodPost, "/api/access-requests", `{"datasourceId":1}`, alice, http.StatusBadRequest)
	if body := do(http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d,"datasourceId":%d}`, role, gone), alice, http.StatusNotFound); body != `{"code":"common.not_found","params":{"resource":"datasource"}}` {
		t.Fatalf("tombstoned: %s", body)
	}
	if body := do(http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d,"datasourceId":%d}`, role, orders), alice, http.StatusForbidden); body != `{"code":"approval.request_not_permitted","params":{}}` {
		t.Fatalf("not permitted: %s", body)
	}
	e.authz.allow = map[string]bool{
		fmt.Sprintf("alice@example.com task.request %d", orders):         true,
		"bob@example.com task.approve ApprovalRequest:alice@example.com": true,
		"bob@example.com admin.identity System:":                         true,
	}
	created := do(http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d,"datasourceId":%d,"reason":"triage"}`, role, orders), alice, http.StatusCreated)
	var request int64
	if _, err := fmt.Sscanf(created, `{"id":%d`, &request); err != nil ||
		!strings.Contains(created, fmt.Sprintf(`"principal":"alice@example.com","roleId":%d,"roleName":"analyst","datasourceId":%d,"datasourceName":"orders","reason":"triage","requestedDurationSec":3600,"status":"PENDING"`, role, orders)) {
		t.Fatalf("created %s", created)
	}

	if body := do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", request), "", alice, http.StatusForbidden); body != `{"code":"approval.not_approver","params":{}}` {
		t.Fatalf("self approve: %s", body)
	}
	do(http.MethodPost, "/api/access-requests/99999/approve", "", bob, http.StatusNotFound)
	do(http.MethodPost, "/api/access-requests/x/approve", "", bob, http.StatusBadRequest)
	before := time.Now()
	approved := do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", request), `{"durationSec":600}`, bob, http.StatusOK)
	if !strings.Contains(approved, `"status":"APPROVED","decidedBy":"bob@example.com"`) {
		t.Fatalf("approved %s", approved)
	}
	last := e.authz.scopes[len(e.authz.scopes)-1]
	if last.Channel != "workflow-viewer" || last.Datasource == nil || *last.Datasource != "orders" || strings.Join(last.DatasourceTags, ",") != "prod" {
		t.Fatalf("approve scope %+v", last)
	}
	var expires time.Time
	var grant int64
	if err := e.st.Pool.QueryRow(ctx, `SELECT id, expires_at FROM access_grant WHERE request_id = $1`, request).Scan(&grant, &expires); err != nil {
		t.Fatal(err)
	}
	if d := expires.Sub(before); d < 590*time.Second || d > 610*time.Second {
		t.Fatalf("grant lasts %v", d)
	}
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", request), "", bob, http.StatusOK)
	if n := scalar(`SELECT count(*) FROM access_grant WHERE request_id = $1`, request); n != 1 {
		t.Fatalf("%d grants after a second approve", n)
	}

	do(http.MethodPost, "/api/access-requests/rate-reset", `{"reason":" "}`, alice, http.StatusBadRequest)
	reset := do(http.MethodPost, "/api/access-requests/rate-reset", `{"reason":"false positive","denyReason":"rate spent"}`, alice, http.StatusCreated)
	var resetReq int64
	_, _ = fmt.Sscanf(reset, `{"id":%d`, &resetReq)
	if !strings.Contains(reset, `"kind":"RATE_RESET"`) || !strings.Contains(reset, `"denyReason":"rate spent"`) {
		t.Fatalf("rate reset request %s", reset)
	}
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", resetReq), "", bob, http.StatusOK)
	if n := scalar(`SELECT count(*) FROM result_rate_reset WHERE principal = 'alice@example.com' AND reason = 'false positive' AND reset_by = 'bob@example.com'`); n != 1 {
		t.Fatalf("%d reset markers", n)
	}

	second := do(http.MethodPost, "/api/access-requests/rate-reset", `{"reason":"again"}`, alice, http.StatusCreated)
	var secondReq int64
	_, _ = fmt.Sscanf(second, `{"id":%d`, &secondReq)
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", secondReq), "", alice, http.StatusForbidden)
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", secondReq), "", bob, http.StatusBadRequest)
	if rejected := do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", secondReq), `{"reason":"no"}`, bob, http.StatusOK); !strings.Contains(rejected, `"status":"REJECTED","decidedBy":"bob@example.com"`) || !strings.Contains(rejected, `"rejectionReason":"no"`) {
		t.Fatalf("rejected %s", rejected)
	}

	if status, body := e.do(t, http.MethodPost, "/api/access-grants/99999/revoke", "", nil); status != http.StatusNotFound || body != `{"code":"common.not_found","params":{"resource":"access grant"}}` {
		t.Fatalf("missing grant unauthenticated: %d %s", status, body)
	}
	if status, _ := e.do(t, http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", nil); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revoke: %d", status)
	}
	if body := do(http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", bob, http.StatusForbidden); body != `{"code":"common.forbidden","params":{"detail":"no permit for grant.revoke"}}` {
		t.Fatalf("revoke denied: %s", body)
	}
	e.authz.allow["bob@example.com grant.revoke AccessGrant:alice@example.com"] = true
	do(http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", bob, http.StatusNoContent)
	do(http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", bob, http.StatusNotFound)

	do(http.MethodGet, "/api/access/principals/carol@example.com/rate-reset", "", bob, http.StatusNoContent)
	do(http.MethodPost, "/api/access/principals/carol@example.com/rate-reset", `{"reason":"r"}`, alice, http.StatusForbidden)
	if body := do(http.MethodPost, "/api/access/principals/carol@example.com/rate-reset", `{"reason":""}`, bob, http.StatusBadRequest); body != `{"code":"common.field_required","params":{"fields":"reason"}}` {
		t.Fatalf("blank reset: %s", body)
	}
	direct := do(http.MethodPost, "/api/access/principals/carol@example.com/rate-reset", `{"reason":"ops"}`, bob, http.StatusOK)
	if !strings.HasPrefix(direct, `{"principal":"carol@example.com","resetAt":"`) || !strings.HasSuffix(direct, `","resetBy":"bob@example.com","reason":"ops"}`) {
		t.Fatalf("direct reset %s", direct)
	}
	if got := do(http.MethodGet, "/api/access/principals/carol@example.com/rate-reset", "", bob, http.StatusOK); got != direct {
		t.Fatalf("last reset %s, want %s", got, direct)
	}

	ids := func(n int64) string { return fmt.Sprint(n) }
	want := []string{
		"admin|alice@example.com|task.request|AccessRequest::\"" + ids(request) + "\"|open access request #" + ids(request) + " for role 'analyst'|127.0.0.1|console",
		"admin|bob@example.com|task.approve|AccessGrant::\"" + ids(grant) + "\"|approve access request #" + ids(request) + ": grant role 'analyst' to 'alice@example.com' for 600s|127.0.0.1|console",
		"admin|alice@example.com|task.request|AccessRequest::\"" + ids(resetReq) + "\"|open rate reset request #" + ids(resetReq) + "|127.0.0.1|console",
		"admin|bob@example.com|task.approve|AccessRequest::\"" + ids(resetReq) + "\"|approve rate reset request #" + ids(resetReq) + ": reset spent rates of 'alice@example.com'|127.0.0.1|console",
		"admin|alice@example.com|task.request|AccessRequest::\"" + ids(secondReq) + "\"|open rate reset request #" + ids(secondReq) + "|127.0.0.1|console",
		"admin|bob@example.com|task.approve|AccessRequest::\"" + ids(secondReq) + "\"|reject access request #" + ids(secondReq) + " from 'alice@example.com'|127.0.0.1|console",
		"admin|bob@example.com|grant.revoke|AccessGrant::\"" + ids(grant) + "\"|revoke access grant #" + ids(grant) + " (role 'analyst' from 'alice@example.com')|127.0.0.1|console",
		"admin|bob@example.com|admin.identity|User::\"carol@example.com\"|reset spent result rates of 'carol@example.com': ops|127.0.0.1|console",
	}
	if got := auditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	verifyChain(t, e)
}

func TestApprovalUnderShippedPolicies(t *testing.T) {
	e := setupWith(t, func(pool *pgxpool.Pool) api.Authorizer { return authz.Local{Engine: authz.New(pool)} })
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO principal_role (principal, role_id) SELECT 'boss@example.com', id FROM app_role WHERE name = 'system:admin'`)
	exec(`INSERT INTO app_role (name) VALUES ('analyst')`)
	exec(`INSERT INTO datasource (name, host, port, db_name) VALUES ('orders', 'h', 1, 'd')`)
	boss := e.st.WebSession(t, "boss@example.com", "k-boss", "dev-1")
	alice := e.st.WebSession(t, "alice@example.com", "k-alice", "dev-2")
	var role, ds int64
	_ = e.st.Pool.QueryRow(ctx, `SELECT id FROM app_role WHERE name = 'analyst'`).Scan(&role)
	_ = e.st.Pool.QueryRow(ctx, `SELECT id FROM datasource WHERE name = 'orders'`).Scan(&ds)
	idOf := func(body string) int64 {
		var id int64
		if _, err := fmt.Sscanf(body, `{"id":%d`, &id); err != nil {
			t.Fatalf("no id in %s", body)
		}
		return id
	}
	expect := func(method, path, body string, c []*http.Cookie, want int, wantBody string) {
		t.Helper()
		status, got := e.do(t, method, path, body, c)
		if status != want || (wantBody != "" && got != wantBody) {
			t.Fatalf("%s %s: %d %s, want %d %s", method, path, status, got, want, wantBody)
		}
	}

	_, own := e.do(t, http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d}`, role), boss)
	_, ownReset := e.do(t, http.MethodPost, "/api/access-requests/rate-reset", `{"reason":"mine"}`, boss)
	for _, id := range []int64{idOf(own), idOf(ownReset)} {
		expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", id), "", boss, http.StatusForbidden, `{"code":"approval.not_approver","params":{}}`)
		expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", id), `{"reason":"x"}`, boss, http.StatusForbidden, `{"code":"approval.not_approver","params":{}}`)
	}
	_, theirs := e.do(t, http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d}`, role), alice)
	expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", idOf(theirs)), "", alice, http.StatusForbidden, "")
	expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", idOf(theirs)), "", boss, http.StatusOK, "")

	var query int64
	if err := e.st.Pool.QueryRow(ctx, `INSERT INTO access_request (principal, kind, role_id, datasource_id, status)
		VALUES ('alice@example.com', 'QUERY', $1, $2, 'PENDING') RETURNING id`, role, ds).Scan(&query); err != nil {
		t.Fatal(err)
	}
	before := len(auditRows(t, e))
	for _, action := range []string{"approve", "reject"} {
		expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/%s", query, action), `{"reason":"x"}`, boss, http.StatusBadRequest,
			`{"code":"approval.use_query_approval_endpoint","params":{}}`)
	}
	var status string
	var grants int
	_ = e.st.Pool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM access_grant WHERE request_id = $1) FROM access_request WHERE id = $1`, query).Scan(&status, &grants)
	if status != "PENDING" || grants != 0 || len(auditRows(t, e)) != before {
		t.Fatalf("a QUERY request changed through the access routes: %s, %d grants", status, grants)
	}
}
