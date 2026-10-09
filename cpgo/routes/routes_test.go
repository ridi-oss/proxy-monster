package routes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

type env struct {
	st        dbtest.Store
	srv       *httptest.Server
	forwarded []string
	ended     []string
	authz     fakeAuthz
}

// fakeAuthz allows what allow lists and records every decision asked for.
type fakeAuthz struct {
	allow map[string]bool
	asked []string
}

func (f *fakeAuthz) Authorize(_ context.Context, principal, action string, resource bridge.Resource, ip string) (bool, error) {
	key := principal + " " + action + " " + resource.Type + ":" + resource.Principal
	f.asked = append(f.asked, key+" @"+ip)
	return f.allow[key], nil
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{st: dbtest.Open(t)}
	forward := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.forwarded = append(e.forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})
	mux := http.NewServeMux()
	Register(mux, e.st.Pool, api.Gate{
		Sessions:      session.NewResolver(e.st.Pool, dbtest.Secret),
		EndMismatched: func(r *http.Request) { e.ended = append(e.ended, r.Header.Get("Cookie")) },
		AuthDebug:     true,
	}, &e.authz)
	e.srv = httptest.NewServer(front.Route(mux, forward))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(t *testing.T, method, path, body string, cookies []*http.Cookie) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func TestUnauthenticated(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/api/query-history", "/api/audit", "/api/audit/1"} {
		status, body := e.do(t, http.MethodGet, path, "", nil)
		if status != http.StatusUnauthorized || body != `{"code":"common.unauthenticated","params":{}}` {
			t.Fatalf("%s: %d %s", path, status, body)
		}
	}
}

func TestDeviceMismatchIsEndedByKotlin(t *testing.T) {
	e := setup(t)
	c := e.st.WebSession(t, "alice@example.com", "k1", "dev-1")
	status, body := e.do(t, http.MethodGet, "/api/query-history", "", []*http.Cookie{c[0], {Name: "pm_did", Value: "dev-2"}})
	if status != http.StatusUnauthorized || body != `{"code":"common.unauthenticated","params":{}}` {
		t.Fatalf("status %d %s", status, body)
	}
	if len(e.ended) != 1 || !strings.Contains(e.ended[0], "pm_did=dev-2") || len(e.forwarded) != 0 {
		t.Fatalf("ended %v forwarded %v", e.ended, e.forwarded)
	}
}

func TestUnportedRequestsAreForwarded(t *testing.T) {
	e := setup(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/query-history"},
		{http.MethodGet, "/api/me/locale"},
		{http.MethodGet, "/api//query-history"},
		{http.MethodGet, "/api/query-history/"},
		{http.MethodHead, "/api/query-history"},
		{http.MethodGet, "/api/datasources"},
	} {
		if status, _ := e.do(t, tc.method, tc.path, "", nil); status != http.StatusTeapot {
			t.Fatalf("%s %s: status %d, want forwarded", tc.method, tc.path, status)
		}
	}
}

func TestLocale(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO app_user (principal) VALUES ('alice@example.com')`); err != nil {
		t.Fatal(err)
	}
	c := e.st.WebSession(t, "alice@example.com", "k1", "dev-1")

	if status, _ := e.do(t, http.MethodPut, "/api/me/locale", `{"locale":" KO "}`, c); status != http.StatusNoContent {
		t.Fatalf("status %d", status)
	}
	var locale string
	_ = e.st.Pool.QueryRow(ctx, `SELECT locale FROM app_user WHERE principal = 'alice@example.com'`).Scan(&locale)
	if locale != "ko" {
		t.Fatalf("locale %q", locale)
	}
	for _, body := range []string{`{"locale":"fr"}`, `not json`} {
		status, resp := e.do(t, http.MethodPut, "/api/me/locale", body, c)
		if status != http.StatusBadRequest || resp != `{"code":"common.invalid_value","params":{"field":"locale"}}` {
			t.Fatalf("%s: %d %s", body, status, resp)
		}
	}
}

func TestQueryHistory(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.st.WebSession(t, "alice@example.com", "k1", "dev-1")
	for _, row := range []struct {
		principal, sql string
		ds             any
		ago            string
	}{
		{"alice@example.com", "SELECT 1", int64(7), "3 minutes"},
		{"alice@example.com", "SELECT 2", nil, "2 minutes"},
		{"alice@example.com", "SELECT 1", int64(8), "1 minute"},
		{"bob@example.com", "SELECT secret", nil, "1 minute"},
	} {
		if _, err := e.st.Pool.Exec(ctx, `INSERT INTO query_history (principal, datasource_id, sql, created_at)
			VALUES ($1, $2, $3, now() - $4::interval)`, row.principal, row.ds, row.sql, row.ago); err != nil {
			t.Fatal(err)
		}
	}

	status, body := e.do(t, http.MethodGet, "/api/query-history", "", c)
	if status != http.StatusOK {
		t.Fatalf("status %d %s", status, body)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["sql"] != "SELECT 1" || got[0]["datasourceId"] != float64(8) || got[1]["sql"] != "SELECT 2" {
		t.Fatalf("history %s", body)
	}
	if _, present := got[1]["datasourceId"]; present {
		t.Fatalf("null datasourceId must be omitted: %s", body)
	}
	if _, err := time.Parse(time.RFC3339Nano, got[0]["ranAt"].(string)); err != nil {
		t.Fatalf("ranAt %v", got[0]["ranAt"])
	}

	if _, body := e.do(t, http.MethodGet, "/api/query-history?limit=1", "", c); strings.Count(body, `"sql"`) != 1 {
		t.Fatalf("limit=1: %s", body)
	}

	if status, _ := e.do(t, http.MethodDelete, "/api/query-history", "", c); status != http.StatusNoContent {
		t.Fatalf("delete status %d", status)
	}
	var left int
	_ = e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM query_history`).Scan(&left)
	if left != 1 {
		t.Fatalf("%d rows left, want only bob's", left)
	}
}

func TestJavaInstant(t *testing.T) {
	for in, want := range map[string]string{
		"2026-10-09T03:10:45Z":           "2026-10-09T03:10:45Z",
		"2026-10-09T03:10:45.12Z":        "2026-10-09T03:10:45.120Z",
		"2026-10-09T03:10:45.123456Z":    "2026-10-09T03:10:45.123456Z",
		"2026-10-09T03:10:45.000100Z":    "2026-10-09T03:10:45.000100Z",
		"2026-10-09T12:10:45.5+09:00":    "2026-10-09T03:10:45.500Z",
		"2026-10-09T03:10:45.123456789Z": "2026-10-09T03:10:45.123456789Z",
	} {
		ts, _ := time.Parse(time.RFC3339Nano, in)
		if got := javaInstant(ts); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestAudit(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	ids := map[string]int64{}
	for i, row := range []struct{ principal, statement string }{
		{"alice@example.com", "select a1"},
		{"bob@example.com", "select b1"},
		{"alice@example.com", "select a2"},
	} {
		id := int64(100 + i)
		ids[row.statement] = id
		if _, err := e.st.Pool.Exec(ctx, `INSERT INTO audit_event (id, ts, principal, datasource, statement, decision)
			VALUES ($1, now() - make_interval(mins => $2), $3, 'acme', $4, 'ALLOW')`, id, 10-i, row.principal, row.statement); err != nil {
			t.Fatal(err)
		}
	}
	alice := e.st.WebSession(t, "alice@example.com", "k-a", "dev-a")
	auditor := e.st.WebSession(t, "auditor@example.com", "k-x", "dev-x")
	e.authz.allow = map[string]bool{
		"auditor@example.com audit.read AuditLog:":                   true,
		"auditor@example.com audit.read AuditRecord:bob@example.com": true,
		"alice@example.com audit.read AuditRecord:alice@example.com": true,
	}

	statements := func(body string) []string {
		var got []struct{ Statement string }
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("%v: %s", err, body)
		}
		out := []string{}
		for _, g := range got {
			out = append(out, g.Statement)
		}
		return out
	}

	_, body := e.do(t, http.MethodGet, "/api/audit", "", alice)
	if got := statements(body); strings.Join(got, ",") != "select a2,select a1" {
		t.Fatalf("alice sees %v", got)
	}
	_, body = e.do(t, http.MethodGet, "/api/audit?limit=2", "", auditor)
	if got := statements(body); strings.Join(got, ",") != "select a2,select b1" {
		t.Fatalf("auditor sees %v", got)
	}

	status, body := e.do(t, http.MethodGet, "/api/audit/"+strconv.FormatInt(ids["select a1"], 10), "", alice)
	if status != http.StatusOK || !strings.Contains(body, `"statement":"select a1"`) || !strings.Contains(body, `"roles":[]`) || strings.Contains(body, "clientAddr") {
		t.Fatalf("own record: %d %s", status, body)
	}
	hiddenStatus, hidden := e.do(t, http.MethodGet, "/api/audit/"+strconv.FormatInt(ids["select b1"], 10), "", alice)
	e.authz.asked = nil
	missingStatus, missing := e.do(t, http.MethodGet, "/api/audit/999999", "", alice)
	if hiddenStatus != http.StatusNotFound || missingStatus != http.StatusNotFound || hidden != missing ||
		missing != `{"code":"common.not_found","params":{"resource":"audit record"}}` {
		t.Fatalf("hidden %d %s / missing %d %s", hiddenStatus, hidden, missingStatus, missing)
	}
	if len(e.authz.asked) != 0 {
		t.Fatalf("a missing record must not reach Cedar: %v", e.authz.asked)
	}
	if status, body := e.do(t, http.MethodGet, "/api/audit/not-a-number", "", alice); status != http.StatusBadRequest ||
		body != `{"code":"common.bad_id","params":{}}` {
		t.Fatalf("bad id: %d %s", status, body)
	}
}

func TestAuditDecisionCarriesRequesterIP(t *testing.T) {
	e := setup(t)
	alice := e.st.WebSession(t, "alice@example.com", "k-a", "dev-a")
	e.do(t, http.MethodGet, "/api/audit", "", alice)
	if len(e.authz.asked) != 1 || e.authz.asked[0] != "alice@example.com audit.read AuditLog: @127.0.0.1" {
		t.Fatalf("asked %v", e.authz.asked)
	}

	e.authz.asked = nil
	if _, err := e.st.Pool.Exec(context.Background(), `UPDATE principal_session SET debug_requester_ip = '203.0.113.9' WHERE session_key = 'k-a'`); err != nil {
		t.Fatal(err)
	}
	e.do(t, http.MethodGet, "/api/audit", "", alice)
	if len(e.authz.asked) != 1 || !strings.HasSuffix(e.authz.asked[0], "@203.0.113.9") {
		t.Fatalf("under auth debug the session's chosen address wins: %v", e.authz.asked)
	}
}
