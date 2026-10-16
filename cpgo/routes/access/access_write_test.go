package access_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

func TestAccessWrites(t *testing.T) {
	e := routetest.Setup(t)
	ctx := context.Background()
	alice := e.St.WebSession(t, "alice@example.com", "k-alice", "dev-1")
	bob := e.St.WebSession(t, "bob@example.com", "k-bob", "dev-2")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.St.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	scalar := func(sql string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := e.St.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	do := func(method, path, body string, c []*http.Cookie, wantStatus int) string {
		t.Helper()
		status, resp := e.Do(t, method, path, body, c)
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
	e.Authz.Allow = map[string]bool{
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
	last := e.Authz.Scopes[len(e.Authz.Scopes)-1]
	if last.Channel != "workflow-viewer" || last.Datasource == nil || *last.Datasource != "orders" || strings.Join(last.DatasourceTags, ",") != "prod" {
		t.Fatalf("approve scope %+v", last)
	}
	var expires time.Time
	var grant int64
	if err := e.St.Pool.QueryRow(ctx, `SELECT id, expires_at FROM access_grant WHERE request_id = $1`, request).Scan(&grant, &expires); err != nil {
		t.Fatal(err)
	}
	if d := expires.Sub(before); d < 590*time.Second || d > 610*time.Second {
		t.Fatalf("grant lasts %v", d)
	}
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", request), "", bob, http.StatusOK)
	if n := scalar(`SELECT count(*) FROM access_grant WHERE request_id = $1`, request); n != 1 {
		t.Fatalf("%d grants after a second approve", n)
	}

	second := do(http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d,"reason":"again"}`, role), alice, http.StatusCreated)
	var secondReq int64
	_, _ = fmt.Sscanf(second, `{"id":%d`, &secondReq)
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", secondReq), "", alice, http.StatusForbidden)
	do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", secondReq), "", bob, http.StatusBadRequest)
	if rejected := do(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", secondReq), `{"reason":"no"}`, bob, http.StatusOK); !strings.Contains(rejected, `"status":"REJECTED","decidedBy":"bob@example.com"`) || !strings.Contains(rejected, `"rejectionReason":"no"`) {
		t.Fatalf("rejected %s", rejected)
	}

	if status, body := e.Do(t, http.MethodPost, "/api/access-grants/99999/revoke", "", nil); status != http.StatusNotFound || body != `{"code":"common.not_found","params":{"resource":"access grant"}}` {
		t.Fatalf("missing grant unauthenticated: %d %s", status, body)
	}
	if status, _ := e.Do(t, http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", nil); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revoke: %d", status)
	}
	if body := do(http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", bob, http.StatusForbidden); body != `{"code":"common.forbidden","params":{"detail":"no permit for grant.revoke"}}` {
		t.Fatalf("revoke denied: %s", body)
	}
	e.Authz.Allow["bob@example.com grant.revoke AccessGrant:alice@example.com"] = true
	do(http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", bob, http.StatusNoContent)
	do(http.MethodPost, fmt.Sprintf("/api/access-grants/%d/revoke", grant), "", bob, http.StatusNotFound)

	ids := func(n int64) string { return fmt.Sprint(n) }
	want := []string{
		"admin|alice@example.com|task.request|AccessRequest::\"" + ids(request) + "\"|open access request #" + ids(request) + " for role 'analyst'|127.0.0.1|console",
		"admin|bob@example.com|task.approve|AccessGrant::\"" + ids(grant) + "\"|approve access request #" + ids(request) + ": grant role 'analyst' to 'alice@example.com' for 600s|127.0.0.1|console",
		"admin|alice@example.com|task.request|AccessRequest::\"" + ids(secondReq) + "\"|open access request #" + ids(secondReq) + " for role 'analyst'|127.0.0.1|console",
		"admin|bob@example.com|task.approve|AccessRequest::\"" + ids(secondReq) + "\"|reject access request #" + ids(secondReq) + " from 'alice@example.com'|127.0.0.1|console",
		"admin|bob@example.com|grant.revoke|AccessGrant::\"" + ids(grant) + "\"|revoke access grant #" + ids(grant) + " (role 'analyst' from 'alice@example.com')|127.0.0.1|console",
	}
	if got := routetest.AuditRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e)

	rows, err := e.St.Pool.Query(context.Background(), `SELECT request_id, kind, coalesce(actor, ''), origin, coalesce(body, '')
		FROM request_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var timeline []string
	for rows.Next() {
		var id int64
		var kind, actor, origin, body string
		if err := rows.Scan(&id, &kind, &actor, &origin, &body); err != nil {
			t.Fatal(err)
		}
		timeline = append(timeline, fmt.Sprintf("%d|%s|%s|%s|%s", id, kind, actor, origin, body))
	}
	wantTimeline := []string{
		ids(request) + "|requested|alice@example.com|console|", ids(request) + "|approved|bob@example.com|console|",
		ids(secondReq) + "|requested|alice@example.com|console|", ids(secondReq) + "|rejected|bob@example.com|console|no",
	}
	if strings.Join(timeline, "\n") != strings.Join(wantTimeline, "\n") {
		t.Fatalf("timeline, one row per transition and none for the repeated approve:\n%s\nwant:\n%s", strings.Join(timeline, "\n"), strings.Join(wantTimeline, "\n"))
	}
	var approvers []string
	prows, err := e.St.Pool.Query(context.Background(), `SELECT request_id || ':' || principal FROM request_participant WHERE kind = 'approver' ORDER BY request_id`)
	if err != nil {
		t.Fatal(err)
	}
	for prows.Next() {
		var p string
		if err := prows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		approvers = append(approvers, p)
	}
	if want := []string{ids(request) + ":bob@example.com", ids(secondReq) + ":bob@example.com"}; strings.Join(approvers, ",") != strings.Join(want, ",") {
		t.Fatalf("approver participants %v, want %v", approvers, want)
	}
	wantNotified := []string{ids(request) + ":requested", ids(request) + ":decided", ids(secondReq) + ":requested", ids(secondReq) + ":decided"}
	if strings.Join(e.Authz.Notified, ",") != strings.Join(wantNotified, ",") {
		t.Fatalf("notifications %v, want %v", e.Authz.Notified, wantNotified)
	}
}

func TestApprovalUnderShippedPolicies(t *testing.T) {
	e := routetest.SetupConfig(t, routetest.Config{Cedar: true})
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.St.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO principal_role (principal, role_id) SELECT 'boss@example.com', id FROM app_role WHERE name = 'system:admin'`)
	exec(`INSERT INTO app_role (name) VALUES ('analyst')`)
	exec(`INSERT INTO datasource (name, host, port, db_name) VALUES ('orders', 'h', 1, 'd')`)
	boss := e.St.WebSession(t, "boss@example.com", "k-boss", "dev-1")
	alice := e.St.WebSession(t, "alice@example.com", "k-alice", "dev-2")
	var role, ds int64
	_ = e.St.Pool.QueryRow(ctx, `SELECT id FROM app_role WHERE name = 'analyst'`).Scan(&role)
	_ = e.St.Pool.QueryRow(ctx, `SELECT id FROM datasource WHERE name = 'orders'`).Scan(&ds)
	idOf := func(body string) int64 {
		var id int64
		if _, err := fmt.Sscanf(body, `{"id":%d`, &id); err != nil {
			t.Fatalf("no id in %s", body)
		}
		return id
	}
	expect := func(method, path, body string, c []*http.Cookie, want int, wantBody string) {
		t.Helper()
		status, got := e.Do(t, method, path, body, c)
		if status != want || (wantBody != "" && got != wantBody) {
			t.Fatalf("%s %s: %d %s, want %d %s", method, path, status, got, want, wantBody)
		}
	}

	_, own := e.Do(t, http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d}`, role), boss)
	for _, id := range []int64{idOf(own)} {
		expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", id), "", boss, http.StatusForbidden, `{"code":"approval.not_approver","params":{}}`)
		expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/reject", id), `{"reason":"x"}`, boss, http.StatusForbidden, `{"code":"approval.not_approver","params":{}}`)
	}
	_, theirs := e.Do(t, http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d}`, role), alice)
	expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", idOf(theirs)), "", alice, http.StatusForbidden, "")
	expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", idOf(theirs)), "", boss, http.StatusOK, "")

	var query int64
	if err := e.St.Pool.QueryRow(ctx, `INSERT INTO access_request (principal, kind, role_id, datasource_id, status, creator_kind)
		VALUES ('alice@example.com', 'QUERY', $1, $2, 'PENDING', 'WORKFLOW') RETURNING id`, role, ds).Scan(&query); err != nil {
		t.Fatal(err)
	}
	before := len(routetest.AuditRows(t, e))
	for _, action := range []string{"approve", "reject"} {
		expect(http.MethodPost, fmt.Sprintf("/api/access-requests/%d/%s", query, action), `{"reason":"x"}`, boss, http.StatusBadRequest,
			`{"code":"approval.use_query_approval_endpoint","params":{}}`)
	}
	var status string
	var grants int
	_ = e.St.Pool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM access_grant WHERE request_id = $1) FROM access_request WHERE id = $1`, query).Scan(&status, &grants)
	if status != "PENDING" || grants != 0 || len(routetest.AuditRows(t, e)) != before {
		t.Fatalf("a QUERY request changed through the access routes: %s, %d grants", status, grants)
	}
}

func TestAccessRequestBodies(t *testing.T) {
	e := routetest.Setup(t)
	e.Exec(t, `INSERT INTO app_role (name) VALUES ('analyst')`)
	role := e.Count(t, `SELECT id FROM app_role WHERE name = 'analyst'`)
	alice := e.St.WebSession(t, "alice@example.com", "k-alice", "dev-1")
	bob := e.St.WebSession(t, "bob@example.com", "k-bob", "dev-2")
	e.Authz.Allow = map[string]bool{"bob@example.com task.approve ApprovalRequest:alice@example.com": true}
	body := func(raw string, volatile ...string) string {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
		for _, k := range volatile {
			if _, ok := m[k].(string); !ok {
				t.Fatalf("%s missing from %s", k, raw)
			}
			delete(m, k)
		}
		delete(m, "id")
		out, _ := json.Marshal(m)
		return string(out)
	}

	status, created := e.Do(t, http.MethodPost, "/api/access-requests", fmt.Sprintf(`{"roleId":%d,"reason":"parity"}`, role), alice)
	want := fmt.Sprintf(`{"ccs":[],"creatorKind":"WORKFLOW","executeAs":[],"forceRun":false,"kind":"ROLE","principal":"alice@example.com","reason":"parity",`+
		`"requestedDurationSec":3600,"revision":1,"roleId":%d,"roleName":"analyst","source":"console","statementCount":0,"status":"PENDING"}`, role)
	if got := body(created, "createdAt"); status != http.StatusCreated || got != want {
		t.Fatalf("created %d\n got %s\nwant %s", status, got, want)
	}
	var id int64
	_, _ = fmt.Sscanf(created, `{"id":%d`, &id)
	status, approved := e.Do(t, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", id), "", bob)
	want = strings.Replace(want, `"status":"PENDING"`, `"status":"APPROVED"`, 1)
	want = strings.Replace(want, `"executeAs"`, `"decidedBy":"bob@example.com","executeAs"`, 1)
	if got := body(approved, "createdAt", "decidedAt"); status != http.StatusOK || got != want {
		t.Fatalf("approved %d\n got %s\nwant %s", status, got, want)
	}
}

func TestApprovalThroughTrustedEdge(t *testing.T) {
	const (
		trustedNetwork = `permit(principal, action == Action::"context.tag::trusted-network", resource)
			when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };`
		tagGatedApprove = `permit(principal in Role::"reviewer", action in [Action::"task.approve", Action::"task.run"], resource)
			when { context has tags && context.tags.contains("trusted-network") };`
	)
	e := routetest.SetupConfig(t, routetest.Config{Cedar: true, Edges: []string{"127.0.0.1"}})
	e.Exec(t, `INSERT INTO app_role (name) VALUES ('reviewer'), ('target-role')`)
	e.Exec(t, `INSERT INTO principal_role (principal, role_id) SELECT 'approver@example.com', id FROM app_role WHERE name = 'reviewer'`)
	e.Exec(t, `INSERT INTO datasource (name, host, port, db_name) VALUES ('elev-ds', 'localhost', 5432, 'app')`)
	e.Exec(t, `INSERT INTO policy (name, cedar_src, enabled, origin) VALUES ('elev-tag', $1, true, 'USER'), ('elev-approve', $2, true, 'USER')`, trustedNetwork, tagGatedApprove)
	approver := e.St.WebSession(t, "approver@example.com", "k-approver", "dev-1")
	request := func() int {
		t.Helper()
		return e.Count(t, `INSERT INTO access_request (principal, role_id, datasource_id, reason, requested_duration_sec, status, creator_kind)
			SELECT 'requester@example.com', r.id, d.id, 'need the role', 3600, 'PENDING', 'WORKFLOW' FROM app_role r, datasource d
			WHERE r.name = 'target-role' AND d.name = 'elev-ds' RETURNING id`)
	}
	denied := request()
	if status, body := e.Do(t, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", denied), "", approver); status != http.StatusForbidden {
		t.Fatalf("no forwarded requester IP: %d %s", status, body)
	}
	approved := request()
	if status, body := e.DoHeader(t, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", approved), "", approver, "X-Forwarded-For", "100.100.5.5"); status != http.StatusOK {
		t.Fatalf("trusted edge's requester IP: %d %s", status, body)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE kind = 'admin' AND statement LIKE $1 AND client_addr = '100.100.5.5'`,
		fmt.Sprintf("approve access request #%d:%%", approved)); n != 1 {
		t.Fatalf("%d approve audit rows from the forwarded IP", n)
	}

	fake := routetest.SetupConfig(t, routetest.Config{Edges: []string{"127.0.0.1"}})
	fake.Exec(t, `INSERT INTO app_role (name) VALUES ('target-role')`)
	fake.Exec(t, `INSERT INTO datasource (name, host, port, db_name) VALUES ('elev-ds', 'localhost', 5432, 'app')`)
	fake.Authz.Allow = map[string]bool{"approver@example.com task.approve ApprovalRequest:requester@example.com": true}
	id := fake.Count(t, `INSERT INTO access_request (principal, role_id, datasource_id, requested_duration_sec, status, creator_kind)
		SELECT 'requester@example.com', r.id, d.id, 3600, 'PENDING', 'WORKFLOW' FROM app_role r, datasource d RETURNING id`)
	c := fake.St.WebSession(t, "approver@example.com", "k-approver", "dev-1")
	if status, body := fake.DoHeader(t, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", id), "", c, "X-Forwarded-For", "100.100.5.5"); status != http.StatusOK {
		t.Fatalf("approve: %d %s", status, body)
	}
	if last := fake.Authz.Asked[len(fake.Authz.Asked)-1]; last != "approver@example.com task.approve ApprovalRequest:requester@example.com @100.100.5.5" || len(fake.Authz.Scopes) != 1 {
		t.Fatalf("AuthorizeIn asked %v scopes %v", fake.Authz.Asked, fake.Authz.Scopes)
	}
}
