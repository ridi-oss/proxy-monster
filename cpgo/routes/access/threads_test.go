package access_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
)

const (
	requester = "alice@example.com"
	approver  = "bob@example.com"
	ccUser    = "cc@example.com"
)

type threadEnv struct {
	*routetest.Env
	t *testing.T
}

func (e threadEnv) id(sql string, args ...any) int64 {
	e.t.Helper()
	var id int64
	if err := e.St.Pool.QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e threadEnv) do(method, path, body string, c []*http.Cookie, wantStatus int) string {
	e.t.Helper()
	status, resp := e.Do(e.t, method, path, body, c)
	if status != wantStatus {
		e.t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, wantStatus)
	}
	return resp
}

func (e threadEnv) kinds(request int64) []string {
	e.t.Helper()
	rows, err := e.St.Pool.Query(context.Background(), `SELECT kind || ':' || coalesce(actor, '') || ':' || coalesce(body, '')
		FROM request_event WHERE request_id = $1 ORDER BY id`, request)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func setupThreads(t *testing.T) threadEnv {
	e := threadEnv{routetest.Setup(t), t}
	e.Exec(t, `INSERT INTO app_user (principal, email) VALUES ($1, 'alice@example.com'), ($2, 'CC-Mail@Example.com'),
		('twin-a', 'twin@example.com'), ('twin-b', 'twin@example.com')`, requester, ccUser)
	return e
}

func (e threadEnv) roleRequest(status string) int64 {
	return e.id(`INSERT INTO access_request (principal, role_id, status, creator_kind)
		VALUES ($1, (SELECT id FROM app_role WHERE name = 'system:admin'), $2, 'WORKFLOW') RETURNING id`, requester, status)
}

func (e threadEnv) queryRequest(principal, status, creator, source string, ds int64, protected *bool) int64 {
	id := e.id(`INSERT INTO access_request (principal, kind, datasource_id, status, creator_kind, source,
		statement_carries_protected_literal) VALUES ($1, 'QUERY', $2, $3, $4, $5, $6) RETURNING id`,
		principal, ds, status, creator, source, protected)
	e.Exec(e.t, `INSERT INTO query_result (task_id, ordinal, sql) VALUES ($1, 0, 'select email from users')`, id)
	return id
}

func TestRequestThread(t *testing.T) {
	e := setupThreads(t)
	alice := e.St.WebSession(t, requester, "k-alice", "dev-1")
	bob := e.St.WebSession(t, approver, "k-bob", "dev-2")
	gone := e.id(`INSERT INTO datasource (name, host, port, db_name, tags) VALUES ('gone', 'h', 1, 'd', '["pii"]') RETURNING id`)
	e.Exec(t, `UPDATE datasource SET deleted_at = now() WHERE id = $1`, gone)
	role := e.roleRequest("PENDING")
	query := e.queryRequest(requester, "APPROVED", "WORKFLOW", "console", gone, nil)
	editor := e.queryRequest(requester, "PENDING", "EDITOR", "console", gone, nil)

	if body := e.do(http.MethodGet, "/api/requests/x/thread", "", alice, http.StatusBadRequest); body != `{"code":"common.bad_id","params":{}}` {
		t.Fatalf("bad id: %s", body)
	}
	e.do(http.MethodGet, fmt.Sprintf("/api/requests/%d/thread", role), "", nil, http.StatusUnauthorized)
	notFound := `{"code":"common.not_found","params":{"resource":"request"}}`
	for _, id := range []int64{editor, 99999} {
		if body := e.do(http.MethodGet, fmt.Sprintf("/api/requests/%d/thread", id), "", alice, http.StatusNotFound); body != notFound {
			t.Fatalf("thread of %d: %s", id, body)
		}
	}
	if body := e.do(http.MethodGet, fmt.Sprintf("/api/requests/%d/thread", role), "", bob, http.StatusNotFound); body != notFound {
		t.Fatalf("task.read denied: %s", body)
	}

	allow := func(actions ...string) {
		e.Authz.Allow = map[string]bool{}
		for _, a := range actions {
			e.Authz.Allow[requester+" "+a+" ApprovalRequest:"+requester] = true
		}
	}
	allow("task.read", "task.comment", "task.cc", "task.cancel", "task.approve")
	e.Exec(t, `UPDATE app_user SET display_name = 'Alice Kim' WHERE principal = $1`, requester)
	e.Authz.Asked = nil
	body := e.do(http.MethodGet, fmt.Sprintf("/api/requests/%d/thread", role), "", alice, http.StatusOK)
	if want := fmt.Sprintf(`{"requestId":%d,"ccs":[],"participants":[],"timeline":[],"canComment":true,"canCc":true,"canClose":true,"canDecide":true,"people":{"alice@example.com":{"name":"Alice Kim","email":"alice@example.com"}}}`, role); body != want {
		t.Fatalf("thread:\n%s\nwant\n%s", body, want)
	}
	var asked []string
	for _, a := range e.Authz.Asked {
		asked = append(asked, strings.Fields(a)[1])
	}
	if strings.Join(asked, ",") != "task.read,task.comment,task.cc,task.cancel,task.approve" {
		t.Fatalf("asked %v", e.Authz.Asked)
	}

	allow("task.read")
	e.Authz.Asked, e.Authz.Scopes = nil, nil
	body = e.do(http.MethodGet, fmt.Sprintf("/api/requests/%d/thread", query), "", alice, http.StatusOK)
	if want := fmt.Sprintf(`{"requestId":%d,"ccs":[],"participants":[],"timeline":[],"canComment":false,"canCc":false,"canClose":false,"canDecide":false,"people":{"alice@example.com":{"name":"Alice Kim","email":"alice@example.com"}}}`, query); body != want {
		t.Fatalf("approved query thread: %s", body)
	}
	if len(e.Authz.Asked) != 4 {
		t.Fatalf("an approved request asks no task.approve: %v", e.Authz.Asked)
	}
	if s := e.Authz.Scopes[0]; s.Channel != "workflow-viewer" || s.Datasource == nil || *s.Datasource != "gone" || strings.Join(s.DatasourceTags, ",") != "pii" {
		t.Fatalf("a deleted datasource still scopes the decision: %+v", s)
	}
}

func TestRequestComments(t *testing.T) {
	e := setupThreads(t)
	alice := e.St.WebSession(t, requester, "k-alice", "dev-1")
	bob := e.St.WebSession(t, approver, "k-bob", "dev-2")
	role := e.roleRequest("PENDING")
	path := fmt.Sprintf("/api/requests/%d/comments", role)

	required := `{"code":"common.field_required","params":{"fields":"body"}}`
	for _, in := range []string{`{}`, `{"body":"   "}`} {
		if body := e.do(http.MethodPost, path, in, alice, http.StatusBadRequest); body != required {
			t.Fatalf("%s: %s", in, body)
		}
	}
	tooLong := `{"code":"approval.comment_too_long","params":{"max":"4000"}}`
	for _, text := range []string{strings.Repeat("a", 4001), strings.Repeat("😀", 2001)} {
		if body := e.do(http.MethodPost, path, `{"body":"`+text+`"}`, alice, http.StatusBadRequest); body != tooLong {
			t.Fatalf("too long: %s", body)
		}
	}
	if body := e.do(http.MethodPost, "/api/requests/99999/comments", `{"body":"hi"}`, alice, http.StatusNotFound); body != `{"code":"common.not_found","params":{"resource":"request"}}` {
		t.Fatalf("missing: %s", body)
	}
	if body := e.do(http.MethodPost, path, `{"body":"hi"}`, bob, http.StatusForbidden); body != `{"code":"approval.comment_forbidden","params":{}}` {
		t.Fatalf("denied: %s", body)
	}
	if len(e.Authz.Notified) != 0 || len(e.kinds(role)) != 0 {
		t.Fatalf("a refused comment wrote or signaled: %v %v", e.Authz.Notified, e.kinds(role))
	}

	e.Authz.Allow = map[string]bool{"bob@example.com task.comment ApprovalRequest:" + requester: true}
	body := e.do(http.MethodPost, path, `{"body":"  `+strings.Repeat("😀", 2000)+`  "}`, bob, http.StatusCreated)
	var ev struct {
		ID       int64
		Kind     string
		Actor    string
		Body     string
		Revision int
		Origin   string
	}
	if err := json.Unmarshal([]byte(body), &ev); err != nil || ev.Kind != "comment" || ev.Actor != approver ||
		ev.Body != strings.Repeat("😀", 2000) || ev.Revision != 1 || ev.Origin != "console" ||
		!strings.HasPrefix(body, fmt.Sprintf(`{"id":%d,"kind":"comment","actor":"bob@example.com","body":"😀`, ev.ID)) ||
		!strings.HasSuffix(body, `Z","deleted":false}`) || strings.Contains(body, "editedAt") {
		t.Fatalf("comment: %s", body)
	}
	lgtm := e.do(http.MethodPost, path, `{"lgtm":true}`, bob, http.StatusCreated)
	if !strings.Contains(lgtm, `"kind":"lgtm","actor":"bob@example.com","revision":1,"origin":"console","createdAt":"`) {
		t.Fatalf("lgtm: %s", lgtm)
	}
	want := []string{"comment:bob@example.com:" + strings.Repeat("😀", 2000), "lgtm:bob@example.com:"}
	if got := e.kinds(role); !slices.Equal(got, want) {
		t.Fatalf("timeline %v", got)
	}
	if n := e.Count(t, `SELECT count(*) FROM request_participant WHERE request_id = $1`, role); n != 0 {
		t.Fatalf("commenting made %d participants", n)
	}
	if n := e.Count(t, `SELECT count(*) FROM access_request WHERE id = $1 AND status = 'PENDING'`, role); n != 1 {
		t.Fatal("an LGTM never changes the status")
	}
	signal := fmt.Sprintf("%d:commented", role)
	if !slices.Equal(e.Authz.Notified, []string{signal, signal}) {
		t.Fatalf("notified %v", e.Authz.Notified)
	}
}

func TestRequestCCs(t *testing.T) {
	e := setupThreads(t)
	alice := e.St.WebSession(t, requester, "k-alice", "dev-1")
	bob := e.St.WebSession(t, approver, "k-bob", "dev-2")
	role := e.roleRequest("PENDING")
	path := fmt.Sprintf("/api/requests/%d/ccs", role)

	if body := e.do(http.MethodPost, path, `{"principal":"cc@example.com"}`, bob, http.StatusForbidden); body != `{"code":"approval.cc_forbidden","params":{}}` {
		t.Fatalf("denied: %s", body)
	}
	e.Authz.Allow = map[string]bool{
		requester + " task.cc ApprovalRequest:" + requester: true,
		approver + " task.cc ApprovalRequest:" + requester:  true,
	}
	unknown := `{"code":"approval.unknown_user","params":{}}`
	for _, who := range []string{"nobody@example.com", "twin@example.com"} {
		if body := e.do(http.MethodPost, path, `{"principal":"`+who+`"}`, alice, http.StatusBadRequest); body != unknown {
			t.Fatalf("%s: %s", who, body)
		}
	}
	if body := e.do(http.MethodPost, path, `{"principal":" alice@example.com "}`, bob, http.StatusBadRequest); body != `{"code":"approval.cc_requester","params":{}}` {
		t.Fatalf("cc requester: %s", body)
	}

	added := e.do(http.MethodPost, path, `{"principal":" cc-mail@example.COM "}`, alice, http.StatusOK)
	if !strings.HasPrefix(added, fmt.Sprintf(`{"id":%d,"principal":"alice@example.com",`, role)) || !strings.HasSuffix(added, `"ccs":["cc@example.com"]}`) {
		t.Fatalf("added: %s", added)
	}
	e.do(http.MethodPost, path, `{"principal":"cc@example.com"}`, bob, http.StatusOK)
	if want := []string{fmt.Sprintf("%d:cc-added:cc@example.com", role)}; !slices.Equal(e.Authz.Notified, want) {
		t.Fatalf("notified %v", e.Authz.Notified)
	}

	e.Authz.Allow[requester+" task.read ApprovalRequest:"+requester] = true
	thread := e.do(http.MethodGet, fmt.Sprintf("/api/requests/%d/thread", role), "", alice, http.StatusOK)
	if !strings.HasPrefix(thread, fmt.Sprintf(`{"requestId":%d,"ccs":["cc@example.com"],"participants":["cc@example.com"],"timeline":[{"id":`, role)) ||
		!strings.Contains(thread, `"kind":"cc_added","actor":"alice@example.com","body":"cc@example.com","revision":1,"origin":"console"`) {
		t.Fatalf("thread: %s", thread)
	}

	removed := e.do(http.MethodDelete, path+"/cc@example.com", "", bob, http.StatusOK)
	if !strings.HasSuffix(removed, `"ccs":[]}`) {
		t.Fatalf("removed: %s", removed)
	}
	e.do(http.MethodDelete, path+"/cc@example.com", "", bob, http.StatusOK)
	e.do(http.MethodDelete, path+"/ghost", "", bob, http.StatusOK)
	if body := e.do(http.MethodDelete, "/api/requests/x/ccs/cc@example.com", "", bob, http.StatusBadRequest); body != `{"code":"common.bad_id","params":{}}` {
		t.Fatalf("bad id: %s", body)
	}
	want := []string{"cc_added:alice@example.com:cc@example.com", "cc_removed:bob@example.com:cc@example.com"}
	if got := e.kinds(role); !slices.Equal(got, want) {
		t.Fatalf("timeline %v", got)
	}
	if len(e.Authz.Notified) != 1 {
		t.Fatalf("a removal or a repeat add signaled: %v", e.Authz.Notified)
	}
	if n := e.Count(t, `SELECT count(*) FROM request_participant WHERE request_id = $1`, role); n != 0 {
		t.Fatalf("%d participants left", n)
	}
}

func TestRequestClose(t *testing.T) {
	e := setupThreads(t)
	alice := e.St.WebSession(t, requester, "k-alice", "dev-1")
	bob := e.St.WebSession(t, approver, "k-bob", "dev-2")
	ds := e.id(`INSERT INTO datasource (name, host, port, db_name) VALUES ('orders', 'h', 1, 'd') RETURNING id`)
	pending := e.roleRequest("PENDING")
	grantedRole := e.roleRequest("APPROVED")
	approvedQuery := e.queryRequest(requester, "APPROVED", "WORKFLOW", "console", ds, nil)
	fromPR := e.queryRequest(requester, "PENDING", "WORKFLOW", "github", ds, nil)
	closePath := func(id int64) string { return fmt.Sprintf("/api/requests/%d/close", id) }

	if body := e.do(http.MethodPost, closePath(pending), "", bob, http.StatusForbidden); body != `{"code":"approval.cancel_forbidden","params":{}}` {
		t.Fatalf("denied: %s", body)
	}
	e.Authz.Allow = map[string]bool{requester + " task.cancel ApprovalRequest:" + requester: true}
	notCancelable := `{"code":"approval.not_cancelable","params":{}}`
	for _, id := range []int64{grantedRole, fromPR} {
		if body := e.do(http.MethodPost, closePath(id), "", alice, http.StatusConflict); body != notCancelable {
			t.Fatalf("close %d: %s", id, body)
		}
	}
	for _, id := range []int64{pending, approvedQuery} {
		if body := e.do(http.MethodPost, closePath(id), "", alice, http.StatusOK); !strings.Contains(body, fmt.Sprintf(`{"id":%d,"principal":"alice@example.com",`, id)) ||
			!strings.Contains(body, `"status":"CANCELLED"`) {
			t.Fatalf("closed %d: %s", id, body)
		}
	}
	if body := e.do(http.MethodPost, closePath(pending), "", alice, http.StatusConflict); body != notCancelable {
		t.Fatalf("close twice: %s", body)
	}
	for _, id := range []int64{pending, approvedQuery} {
		if got := e.kinds(id); !slices.Equal(got, []string{"closed:alice@example.com:"}) {
			t.Fatalf("timeline of %d: %v", id, got)
		}
	}
	if want := []string{fmt.Sprintf("%d:cancelled", pending), fmt.Sprintf("%d:cancelled", approvedQuery)}; !slices.Equal(e.Authz.Notified, want) {
		t.Fatalf("notified %v", e.Authz.Notified)
	}
	var want []string
	for _, id := range []int64{pending, approvedQuery} {
		want = append(want, fmt.Sprintf(`admin|alice@example.com|task.cancel|AccessRequest::"%d"|close request #%d|127.0.0.1|console`, id, id))
	}
	if got := routetest.AuditRows(t, e.Env); !slices.Equal(got, want) {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	routetest.VerifyChain(t, e.Env)
}

func TestRequestsInvolved(t *testing.T) {
	e := setupThreads(t)
	ds := e.id(`INSERT INTO datasource (name, host, port, db_name) VALUES ('orders', 'h', 1, 'd') RETURNING id`)
	yes, no := true, false
	flagged := e.queryRequest(requester, "PENDING", "WORKFLOW", "console", ds, &yes)
	cleared := e.queryRequest(requester, "PENDING", "WORKFLOW", "console", ds, &no)
	unknown := e.queryRequest(requester, "PENDING", "WORKFLOW", "console", ds, nil)
	editor := e.queryRequest(requester, "PENDING", "EDITOR", "console", ds, nil)
	e.Exec(t, `INSERT INTO request_participant (request_id, principal, kind) VALUES ($1, 'appr@example.com', 'approver'),
		($1, 'notified@example.com', 'approver'), ($2, 'cc@example.com', 'cc'), ($3, 'appr@example.com', 'approver'), ($4, 'appr@example.com', 'approver')`,
		flagged, cleared, unknown, editor)

	involved := func(principal string) map[int64]*string {
		t.Helper()
		body := e.do(http.MethodGet, "/api/requests/involved", "", e.St.WebSession(t, principal, "k-"+principal, "d-"+principal), http.StatusOK)
		var rows []struct {
			ID  int64
			SQL *string
		}
		if err := json.Unmarshal([]byte(body), &rows); err != nil {
			t.Fatal(err)
		}
		out := map[int64]*string{}
		var order []int64
		for _, r := range rows {
			out[r.ID] = r.SQL
			order = append(order, r.ID)
		}
		if !slices.IsSortedFunc(order, func(a, b int64) int { return int(b - a) }) {
			t.Fatalf("not newest first: %v", order)
		}
		return out
	}
	keys := func(m map[int64]*string) []int64 {
		var k []int64
		for id := range m {
			k = append(k, id)
		}
		slices.Sort(k)
		return k
	}
	asApprover := involved("appr@example.com")
	if !slices.Equal(keys(asApprover), []int64{flagged, unknown}) || asApprover[flagged] != nil || asApprover[unknown] != nil {
		t.Fatalf("approver: %v", asApprover)
	}
	if got := involved("notified@example.com"); !slices.Equal(keys(got), []int64{flagged}) {
		t.Fatalf("notified: %v", got)
	}
	if got := involved(ccUser); !slices.Equal(keys(got), []int64{cleared}) || got[cleared] == nil || *got[cleared] != "select email from users" {
		t.Fatalf("cc sees a statement with no protected literal: %v", got)
	}
	asRequester := involved(requester)
	if !slices.Equal(keys(asRequester), []int64{flagged, cleared, unknown}) || asRequester[flagged] == nil {
		t.Fatalf("requester: %v", asRequester)
	}
	if got := involved("out@example.com"); len(got) != 0 {
		t.Fatalf("outsider: %v", got)
	}
	if status, _ := e.Do(t, http.MethodGet, "/api/requests/involved", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", status)
	}
}
