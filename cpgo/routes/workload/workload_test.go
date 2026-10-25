package workload_test

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/workload"
)

const path = "/api/workload/token"

var tokenBody = regexp.MustCompile(`^\{"token":"pmw_[A-Za-z0-9_-]{43}","id":(\d+),"kind":"WORKLOAD","expiresAt":"[^"]+"\}$`)

func setup(t *testing.T, v *workload.Verifier) *routetest.Env {
	t.Helper()
	return routetest.SetupConfig(t, routetest.Config{Workload: v})
}

func exchange(t *testing.T, e *routetest.Env, jwt string) (int, string) {
	t.Helper()
	return e.Do(t, http.MethodPost, path, `{"token":"`+jwt+`"}`, nil)
}

// workloadRows is each proxy_token WORKLOAD row as `principal roles name claims ttl`.
func workloadRows(t *testing.T, e *routetest.Env) []string {
	t.Helper()
	rows, err := e.St.Pool.Query(context.Background(), `SELECT principal || ' ' || roles::text || ' ' || coalesce(name, '-') || ' ' ||
		claims::text || ' ' || extract(epoch FROM expires_at - created_at)::bigint FROM proxy_token WHERE kind = 'WORKLOAD' ORDER BY id`)
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

// detailRows is each auth.workload.exchange row as `outcome principal resource client_addr | statement | detail`.
func detailRows(t *testing.T, e *routetest.Env) []string {
	t.Helper()
	rows, err := e.St.Pool.Query(context.Background(), `SELECT outcome || ' ' || principal || ' ' || resource || ' ' || coalesce(client_addr, '') ||
		' | ' || statement || ' | ' || coalesce(detail, 'NULL') FROM audit_event WHERE action = 'auth.workload.exchange' ORDER BY id`)
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

func TestExchangeMintsAWorkloadTokenWithTheKeptClaims(t *testing.T) {
	ti := newIssuer(t)
	e := setup(t, ti.verifier())
	status, body := exchange(t, e, ti.sign(ti.claims(func(c map[string]any) { c["base_ref"] = "main"; c["actor"] = "octocat" })))
	if status != http.StatusOK || !tokenBody.MatchString(body) {
		t.Fatalf("%d %s", status, body)
	}
	if got := strings.Join(workloadRows(t, e), "\n"); got !=
		`workload:github [] - {"ref": "refs/heads/main", "actor": "octocat", "base_ref": "main", "event_name": "push", "repository": "acme/shop"} 900` {
		t.Errorf("token rows:\n%s", got)
	}
	if got := strings.Join(detailRows(t, e), "\n"); got != "SUCCESS workload:github Workload::\"github\" 127.0.0.1 | "+
		"Exchanged a CI OIDC token for a workload token | repository=acme/shop ref=refs/heads/main base_ref=main event_name=push actor=octocat" {
		t.Errorf("audit rows:\n%s", got)
	}
	var expires time.Time
	if err := e.St.Pool.QueryRow(context.Background(), `SELECT expires_at FROM proxy_token WHERE kind = 'WORKLOAD'`).Scan(&expires); err != nil ||
		time.Until(expires) > 15*time.Minute+time.Minute {
		t.Errorf("expires %v %v", expires, err)
	}
	routetest.VerifyChain(t, e)
}

func TestExchangeRejectsAndAuditsUnattributed(t *testing.T) {
	ti := newIssuer(t)
	e := setup(t, ti.verifier())
	long := "https://ci.example.com/" + strings.Repeat("x", 300)
	for _, tc := range []struct {
		jwt    string
		status int
		body   string
	}{
		{"not-a-jwt", 401, `{"code":"common.invalid_token","params":{"kind":"ci_oidc"}}`},
		{ti.sign(ti.claims(func(c map[string]any) { c["iss"] = long })), 401, `{"code":"workload.issuer_not_trusted","params":{}}`},
		{signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid"}, ti.claims(nil), rsaKey(t)), 401, `{"code":"common.invalid_token","params":{"kind":"ci_oidc"}}`},
	} {
		if status, body := exchange(t, e, tc.jwt); status != tc.status || body != tc.body {
			t.Errorf("%.20s: %d %s, want %d %s", tc.jwt, status, body, tc.status, tc.body)
		}
	}
	want := []string{
		`FAILURE unknown Workload::"-" 127.0.0.1 | CI OIDC token rejected | malformed`,
		`FAILURE unknown Workload::"` + long[:200] + `" 127.0.0.1 | CI OIDC token from an untrusted issuer | NULL`,
		`FAILURE unknown Workload::"github" 127.0.0.1 | CI OIDC token rejected | Signed JWT rejected: Invalid signature`,
	}
	if got := detailRows(t, e); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if rows := workloadRows(t, e); len(rows) != 0 {
		t.Errorf("minted %v", rows)
	}
	routetest.VerifyChain(t, e)
}

func TestExchangeNeedsAToken(t *testing.T) {
	ti := newIssuer(t)
	e := setup(t, ti.verifier())
	const required = `{"code":"common.field_required","params":{"fields":"token"}}`
	for _, body := range []string{"", "{", `{}`, `{"token":null}`, `{"token":5}`, `{"token":""}`, `{"token":" \t"}`, `{"token":"a"} {}`} {
		if status, got := e.Do(t, http.MethodPost, path, body, nil); status != http.StatusBadRequest || got != required {
			t.Errorf("%q: %d %s", body, status, got)
		}
	}
	if status, got := e.DoHeader(t, http.MethodPost, path, `{"token":"x"}`, nil, "Content-Type", "text/plain"); status != http.StatusBadRequest || got != required {
		t.Errorf("text/plain: %d %s", status, got)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.workload.exchange'`); n != 0 {
		t.Errorf("%d audit rows", n)
	}
}

func TestExchangeIsNotFoundWithoutIssuers(t *testing.T) {
	ti := newIssuer(t)
	for _, v := range []*workload.Verifier{nil, workload.NewVerifier(nil, http.DefaultClient)} {
		e := setup(t, v)
		if status, body := exchange(t, e, ti.sign(ti.claims(nil))); status != http.StatusNotFound || body != `{"code":"workload.not_configured","params":{}}` {
			t.Errorf("%d %s", status, body)
		}
		if status, body := exchange(t, e, ""); status != http.StatusBadRequest || body != `{"code":"common.field_required","params":{"fields":"token"}}` {
			t.Errorf("blank: %d %s", status, body)
		}
	}
}

func TestExchangeAnswers500WhenDiscoveryFails(t *testing.T) {
	ti := newIssuer(t)
	cfg := ti.config()
	cfg.URL = ti.srv.URL + "/missing"
	e := setup(t, workload.NewVerifier([]workload.Issuer{cfg}, http.DefaultClient))
	status, body := exchange(t, e, ti.sign(ti.claims(func(c map[string]any) { c["iss"] = cfg.URL })))
	if status != http.StatusInternalServerError || body != `{"code":"common.fallback","params":{}}` {
		t.Errorf("%d %s", status, body)
	}
	if n := e.Count(t, `SELECT count(*) FROM audit_event`); n != 0 {
		t.Errorf("%d audit rows", n)
	}
}

func TestExchangeAuditsTheDebugSessionsRequesterIP(t *testing.T) {
	ti := newIssuer(t)
	e := setup(t, ti.verifier())
	b := e.Browser(t)
	b.Expect(http.MethodPost, "/auth/debug", `{"principal":"ci-user@example.com","requesterIp":"198.51.100.7"}`, http.StatusOK, "")
	if resp, body := b.Do(http.MethodPost, path, `{"token":"`+ti.sign(ti.claims(nil))+`"}`, "X-Forwarded-For", "203.0.113.9"); resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if got := detailRows(t, e); len(got) != 1 || !strings.Contains(got[0], " 198.51.100.7 | ") {
		t.Errorf("audit rows %v", got)
	}
}
