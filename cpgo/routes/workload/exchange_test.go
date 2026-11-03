package workload_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/internal/routetest"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/workload"
)

const (
	exchangePath = "/api/workload/exchange"
	bindingsPath = "/api/workload-bindings"
	role         = "arn:aws:iam::111122223333:role/batch-settlement"
)

type awsIssuer struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
	n   int
}

func newAWSIssuer(t *testing.T) *awsIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ai := &awsIssuer{key: key}
	ai.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": ai.srv.URL, "jwks_uri": ai.srv.URL + "/.well-known/jwks.json",
				"id_token_signing_alg_values_supported": []string{"RS256", "ES384"}})
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "EC", "kid": "EC384_4", "use": "sig", "alg": "ES384", "crv": "P-384",
				"x": b64(pad(key.X.Bytes())), "y": b64(pad(key.Y.Bytes())),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ai.srv.Close)
	return ai
}

func pad(b []byte) []byte {
	out := make([]byte, 48)
	copy(out[48-len(b):], b)
	return out
}

func (ai *awsIssuer) issuer() workload.Issuer {
	return workload.Issuer{Name: "aws-prod", URL: ai.srv.URL, Audience: audience, Kind: workload.KindAWSSTS}
}

func (ai *awsIssuer) token(t *testing.T, sub string, edit func(ns map[string]any)) string {
	t.Helper()
	ai.n++
	now := time.Now().Unix()
	ns := map[string]any{"aws_account": "111122223333", "org_id": "o-abc1234567", "ou_path": []string{"o-abc1234567/r-ab12/ou-ab12-1/"},
		"principal_id": sub, "source_region": "ap-northeast-2", "principal_tags": map[string]string{"team": "data"}}
	if edit != nil {
		edit(ns)
	}
	claims := map[string]any{"iss": ai.srv.URL, "aud": audience, "sub": sub, "exp": now + 300, "iat": now,
		"jti": "jti-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+ai.n)), "https://sts.amazonaws.com/": ns}
	input := part(map[string]any{"alg": "ES384", "kid": "EC384_4", "typ": "JWT"}) + "." + part(claims)
	digest := sha512.Sum384([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, ai.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(append(pad(r.Bytes()), pad(s.Bytes())...))
}

type harness struct {
	t     *testing.T
	e     *routetest.Env
	admin []*http.Cookie
}

func newHarness(t *testing.T, issuers ...workload.Issuer) *harness {
	t.Helper()
	e := routetest.SetupConfig(t, routetest.Config{Workload: workload.NewVerifier(issuers, http.DefaultClient)})
	e.Authz.Allow = map[string]bool{"admin@example.com admin.identity System:": true}
	return &harness{t: t, e: e, admin: e.St.WebSession(t, "admin@example.com", "k-admin", "dev-1")}
}

func (h *harness) do(method, path, body string, cookies []*http.Cookie, want int) string {
	h.t.Helper()
	status, resp := h.e.Do(h.t, method, path, body, cookies)
	if status != want {
		h.t.Fatalf("%s %s: %d %s, want %d", method, path, status, resp, want)
	}
	return resp
}

func (h *harness) bind(body string) int64 {
	h.t.Helper()
	var b workload.Binding
	if err := json.Unmarshal([]byte(h.do(http.MethodPost, bindingsPath, body, h.admin, http.StatusCreated)), &b); err != nil {
		h.t.Fatal(err)
	}
	return b.ID
}

func (h *harness) exchange(jwt, purpose, extra string, want int) string {
	h.t.Helper()
	return h.do(http.MethodPost, exchangePath, `{"token":"`+jwt+`","purpose":"`+purpose+`"`+extra+`}`, nil, want)
}

var serviceBody = regexp.MustCompile(`^\{"token":"pms_[A-Za-z0-9_-]{43}","id":\d+,"kind":"SERVICE","name":"batch-settlement","expiresAt":"[^"]+","principal":"svc:batch-settlement"\}$`)

func TestAWSTokenExchangesForAServiceWireTokenOnce(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	h.bind(`{"name":"batch-settlement","issuer":"aws-prod","subject":"` + role + `","conditions":{"aws_account":"111122223333"},
		"purposes":["wire"],"ttlSeconds":600}`)
	jwt := ai.token(t, role, nil)
	if body := h.exchange(jwt, "wire", "", http.StatusOK); !serviceBody.MatchString(body) {
		t.Fatalf("body %s", body)
	}
	var principal, claims string
	var ttl int
	if err := h.e.St.Pool.QueryRow(t.Context(), `SELECT principal, claims::text, extract(epoch FROM expires_at - created_at)::int
		FROM proxy_token WHERE kind = 'SERVICE'`).Scan(&principal, &claims, &ttl); err != nil {
		t.Fatal(err)
	}
	if principal != "svc:batch-settlement" || !strings.Contains(claims, `"aws_account": ["111122223333"]`) ||
		!strings.Contains(claims, `"principal_tags.team": ["data"]`) || ttl < 599 || ttl > 601 {
		t.Errorf("row %s %s %d", principal, claims, ttl)
	}
	if body := h.exchange(jwt, "wire", "", http.StatusUnauthorized); body != `{"code":"workload.token_replayed","params":{}}` {
		t.Errorf("replay %s", body)
	}
	h.exchange(ai.token(t, role, nil), "wire", "", http.StatusOK)
	if n := h.e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.workload.bind' AND outcome = 'SUCCESS'
		AND principal = 'svc:batch-settlement' AND detail LIKE '%aws_account=111122223333%'`); n != 2 {
		t.Errorf("%d success audit rows", n)
	}
	routetest.VerifyChain(t, h.e)
}

func TestBindingConditionsPinAPodIdentityServiceAccount(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	h.bind(`{"name":"batch-settlement","issuer":"aws-prod","subject":"` + role + `",
		"conditions":{"principal_tags.kubernetes-namespace":"batch","principal_tags.kubernetes-service-account":["settle","settle-*"]},
		"purposes":["wire"]}`)
	tags := func(ns, sa string) func(map[string]any) {
		return func(c map[string]any) {
			c["principal_tags"] = map[string]string{"kubernetes-namespace": ns, "kubernetes-service-account": sa}
		}
	}
	h.exchange(ai.token(t, role, tags("batch", "settle-nightly")), "wire", "", http.StatusOK)
	for _, tc := range []string{
		ai.token(t, role, tags("other", "settle")),
		ai.token(t, role, tags("batch", "api")),
		ai.token(t, role, nil),
		ai.token(t, role+"-other", tags("batch", "settle")),
	} {
		if body := h.exchange(tc, "wire", "", http.StatusForbidden); body != `{"code":"workload.no_binding","params":{}}` {
			t.Errorf("unbound: %s", body)
		}
	}
}

func TestMCPPurposeMintsAnAccessTokenWithinTheBindingScopes(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	h.bind(`{"name":"tf-pmon","issuer":"aws-prod","subject":"` + role + `","purposes":["mcp"],"mcpScopes":["mcp:read","mcp:policies:write"]}`)
	body := h.exchange(ai.token(t, role, nil), "mcp", `,"scopes":["mcp:read"]`, http.StatusOK)
	if !regexp.MustCompile(`^\{"accessToken":"pma_[A-Za-z0-9_-]+","expiresAt":"[^"]+","scope":"mcp:read"\}$`).MatchString(body) {
		t.Fatalf("body %s", body)
	}
	if n := h.e.Count(t, `SELECT count(*) FROM proxy_token t JOIN oauth_consent c ON c.id = t.consent_id
		WHERE t.kind = 'MCP_ACCESS' AND t.principal = 'svc:tf-pmon' AND c.client_id = 'workload:tf-pmon' AND t.workload_binding_id IS NOT NULL`); n != 1 {
		t.Errorf("%d mcp tokens", n)
	}
	h.exchange(ai.token(t, role, nil), "mcp", "", http.StatusOK)
	if n := h.e.Count(t, `SELECT count(*) FROM proxy_token WHERE kind = 'MCP_ACCESS' AND scope = 'mcp:policies:write mcp:read'`); n != 1 {
		t.Errorf("%d tokens with every binding scope", n)
	}
	var minted struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.Unmarshal([]byte(body), &minted)
	if status, got := h.e.DoHeader(t, http.MethodPost, "/oauth/revoke", "token="+minted.AccessToken, nil,
		"Content-Type", "application/x-www-form-urlencoded"); status != http.StatusOK {
		t.Fatalf("revoke %d %s", status, got)
	}
	if n := h.e.Count(t, `SELECT count(*) FROM proxy_token WHERE kind = 'MCP_ACCESS' AND scope = 'mcp:read' AND revoked_at IS NOT NULL`); n != 1 {
		t.Errorf("RFC 7009 revoke left the workload access token live (%d revoked)", n)
	}
	if body := h.exchange(ai.token(t, role, nil), "mcp", `,"scopes":["mcp:identity:write"]`, http.StatusForbidden); body !=
		`{"code":"workload.scope_not_allowed","params":{}}` {
		t.Errorf("scope %s", body)
	}
	if body := h.exchange(ai.token(t, role, nil), "wire", "", http.StatusForbidden); body != `{"code":"workload.purpose_not_allowed","params":{}}` {
		t.Errorf("purpose %s", body)
	}
}

func TestTwoMatchingBindingsRefuseTheExchange(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	h.bind(`{"name":"one","issuer":"aws-prod","subject":"` + role + `","purposes":["wire"]}`)
	h.bind(`{"name":"two","issuer":"aws-prod","subject":"arn:aws:iam::111122223333:role/*","purposes":["wire"]}`)
	if body := h.exchange(ai.token(t, role, nil), "wire", "", http.StatusForbidden); body != `{"code":"workload.ambiguous_binding","params":{}}` {
		t.Errorf("%s", body)
	}
}

func TestExchangeValidatesThePurpose(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	for _, purpose := range []string{"", "admin"} {
		if body := h.exchange(ai.token(t, role, nil), purpose, "", http.StatusBadRequest); body != `{"code":"common.invalid_value","params":{"field":"purpose"}}` {
			t.Errorf("%q: %s", purpose, body)
		}
	}
}

func TestDisablingOrDeletingABindingRevokesWhatItMinted(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	body := `{"name":"batch-settlement","issuer":"aws-prod","subject":"` + role + `","purposes":["wire","mcp"],"mcpScopes":["mcp:read"]%s}`
	id := h.bind(strings.Replace(body, "%s", "", 1))
	path := bindingsPath + "/" + itoa(id)
	live := func() int {
		return h.e.Count(t, `SELECT count(*) FROM proxy_token WHERE workload_binding_id IS NOT NULL AND revoked_at IS NULL`)
	}
	h.exchange(ai.token(t, role, nil), "wire", "", http.StatusOK)
	h.exchange(ai.token(t, role, nil), "mcp", "", http.StatusOK)
	h.do(http.MethodPut, path, strings.Replace(body, "%s", `,"description":"nightly"`, 1), h.admin, http.StatusOK)
	if n := live(); n != 2 {
		t.Fatalf("a widening edit revoked: %d live", n)
	}
	h.do(http.MethodPut, path, strings.Replace(body, "%s", `,"enabled":false`, 1), h.admin, http.StatusOK)
	if n := live(); n != 0 {
		t.Fatalf("disable left %d live", n)
	}
	if body := h.exchange(ai.token(t, role, nil), "wire", "", http.StatusForbidden); body != `{"code":"workload.no_binding","params":{}}` {
		t.Errorf("disabled binding still binds: %s", body)
	}
	h.do(http.MethodPut, path, strings.Replace(body, "%s", "", 1), h.admin, http.StatusOK)
	h.exchange(ai.token(t, role, nil), "wire", "", http.StatusOK)
	h.do(http.MethodDelete, path, "", h.admin, http.StatusNoContent)
	if n := live(); n != 0 {
		t.Fatalf("delete left %d live", n)
	}
	if n := h.e.Count(t, `SELECT count(*) FROM oauth_consent WHERE client_id = 'workload:batch-settlement' AND revoked_at IS NULL`); n != 0 {
		t.Errorf("%d live consents", n)
	}
	if got := h.do(http.MethodGet, bindingsPath, "", h.admin, http.StatusOK); got != "[]" {
		t.Errorf("list %s", got)
	}
	routetest.VerifyChain(t, h.e)
}

func TestBindingWritesAreValidatedAndAdminOnly(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	plain := h.e.St.WebSession(t, "plain@example.com", "k-plain", "dev-2")
	h.do(http.MethodGet, bindingsPath, "", plain, http.StatusForbidden)
	h.do(http.MethodPost, bindingsPath, `{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"]}`, plain, http.StatusForbidden)
	for _, tc := range []struct{ body, want string }{
		{`{"issuer":"aws-prod","subject":"s","purposes":["wire"]}`, `{"code":"common.field_required","params":{"fields":"name"}}`},
		{`{"name":"Bad Name","issuer":"aws-prod","subject":"s","purposes":["wire"]}`, `{"code":"common.invalid_value","params":{"field":"name"}}`},
		{`{"name":"x","issuer":"gitlab","subject":"s","purposes":["wire"]}`, `{"code":"common.invalid_value","params":{"field":"issuer"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"*","purposes":["wire"]}`, `{"code":"common.invalid_value","params":{"field":"subject"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":[]}`, `{"code":"common.field_required","params":{"fields":"purposes"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["admin"]}`, `{"code":"common.invalid_value","params":{"field":"purposes"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["mcp"]}`, `{"code":"common.invalid_value","params":{"field":"mcpScopes"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"],"mcpScopes":["mcp:read"]}`, `{"code":"common.invalid_value","params":{"field":"mcpScopes"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["mcp"],"mcpScopes":["mcp:root"]}`, `{"code":"common.invalid_value","params":{"field":"mcpScopes"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"],"principal":"alice@example.com"}`, `{"code":"common.invalid_value","params":{"field":"principal"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"],"conditions":{"a":5}}`, `{"code":"common.invalid_value","params":{"field":"conditions"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"],"conditions":{"a":"*"}}`, `{"code":"common.invalid_value","params":{"field":"conditions"}}`},
		{`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"],"ttlSeconds":30}`, `{"code":"common.invalid_value","params":{"field":"ttlSeconds"}}`},
	} {
		if got := h.do(http.MethodPost, bindingsPath, tc.body, h.admin, http.StatusBadRequest); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.body, got, tc.want)
		}
	}
	h.bind(`{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"]}`)
	if got := h.do(http.MethodPost, bindingsPath, `{"name":"x","issuer":"aws-prod","subject":"s","purposes":["wire"]}`, h.admin, http.StatusBadRequest); got !=
		`{"code":"common.already_exists","params":{"resource":"workload_binding","name":"x"}}` {
		t.Errorf("duplicate %s", got)
	}
	if got := h.do(http.MethodGet, "/api/workload-issuers", "", h.admin, http.StatusOK); got !=
		`[{"name":"aws-prod","kind":"aws-sts","url":"`+ai.srv.URL+`"}]` {
		t.Errorf("issuers %s", got)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestAnExchangeRacingADisableMintsNothing(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	id := h.bind(`{"name":"batch-settlement","issuer":"aws-prod","subject":"` + role + `","purposes":["wire"]}`)
	tx, err := h.e.St.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `UPDATE workload_binding SET enabled = false, updated_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE proxy_token SET revoked_at = now() WHERE workload_binding_id = $1 AND revoked_at IS NULL`, id); err != nil {
		t.Fatal(err)
	}
	type result struct {
		status int
		body   string
	}
	done := make(chan result, 1)
	jwt := ai.token(t, role, nil)
	go func() {
		status, body := h.e.Do(t, http.MethodPost, exchangePath, `{"token":"`+jwt+`","purpose":"wire"}`, nil)
		done <- result{status, body}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for h.e.Count(t, `SELECT count(*) FROM pg_locks WHERE NOT granted`) == 0 && len(done) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.status != http.StatusForbidden || got.body != `{"code":"workload.no_binding","params":{}}` {
		t.Errorf("exchange racing a disable: %d %s", got.status, got.body)
	}
	if n := h.e.Count(t, `SELECT count(*) FROM proxy_token WHERE workload_binding_id = $1 AND revoked_at IS NULL`, id); n != 0 {
		t.Errorf("%d live tokens for a disabled binding", n)
	}
}

func TestAServiceTokenRevokesItself(t *testing.T) {
	ai := newAWSIssuer(t)
	h := newHarness(t, ai.issuer())
	h.bind(`{"name":"batch-settlement","issuer":"aws-prod","subject":"` + role + `","purposes":["wire"]}`)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(h.exchange(ai.token(t, role, nil), "wire", "", http.StatusOK)), &issued); err != nil {
		t.Fatal(err)
	}
	if status, body := h.e.Do(t, http.MethodPost, "/api/workload/revoke", "", nil); status != http.StatusUnauthorized {
		t.Errorf("no bearer: %d %s", status, body)
	}
	for range 2 {
		if status, body := h.e.DoHeader(t, http.MethodPost, "/api/workload/revoke", "", nil, "Authorization", "Bearer "+issued.Token); status != http.StatusNoContent {
			t.Fatalf("revoke: %d %s", status, body)
		}
	}
	if n := h.e.Count(t, `SELECT count(*) FROM proxy_token WHERE kind = 'SERVICE' AND revoked_at IS NULL`); n != 0 {
		t.Errorf("%d live SERVICE tokens", n)
	}
	if n := h.e.Count(t, `SELECT count(*) FROM audit_event WHERE action = 'auth.workload.revoke' AND principal = 'svc:batch-settlement'`); n != 1 {
		t.Errorf("%d revoke audit rows", n)
	}
	routetest.VerifyChain(t, h.e)
}
