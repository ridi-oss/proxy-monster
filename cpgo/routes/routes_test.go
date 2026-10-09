package routes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

type env struct {
	st        dbtest.Store
	srv       *httptest.Server
	forwarded []string
	ended     []string
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
	})
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
	for _, path := range []string{"/api/query-history"} {
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
