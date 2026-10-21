package workload_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/routes/workload"
)

func TestVerifyAcceptsAValidTokenAndSurfacesItsClaims(t *testing.T) {
	ti := newIssuer(t)
	v := ti.verifier()
	for _, edit := range []func(map[string]any){nil, func(c map[string]any) { c["base_ref"] = "main" }} {
		issuer, claims, err := v.Verify(context.Background(), ti.sign(ti.claims(edit)))
		if err != nil {
			t.Fatal(err)
		}
		if issuer != ti.config() || claims["repository"] != "acme/shop" {
			t.Errorf("issuer %+v claims %v", issuer, claims)
		}
	}
	if n := ti.jwksCalls.Load(); n != 1 {
		t.Errorf("JWKS fetched %d times, want once", n)
	}
}

func TestVerifyRejects(t *testing.T) {
	ti := newIssuer(t)
	v := ti.verifier()
	now := time.Now().Unix()
	for _, tc := range []struct {
		name, jwt, want string
	}{
		{"malformed", "not-a-jwt", "malformed"},
		{"payload not an object", part(map[string]string{"alg": "RS256"}) + "." + b64([]byte("[1]")) + ".c", "malformed"},
		{"alg none", part(map[string]string{"alg": "none"}) + "." + part(ti.claims(nil)) + ".", "malformed"},
		{"exp a string", ti.sign(ti.claims(func(c map[string]any) { c["exp"] = "soon" })), "malformed"},
		{"untrusted issuer", ti.sign(ti.claims(func(c map[string]any) { c["iss"] = "https://ci.example.com" })), "untrusted issuer"},
		{"no issuer", ti.sign(ti.claims(func(c map[string]any) { delete(c, "iss") })), "untrusted issuer"},
		{"wrong audience", ti.sign(ti.claims(func(c map[string]any) { c["aud"] = "https://other.example.com" })), "JWT aud claim rejected"},
		{"no audience", ti.sign(ti.claims(func(c map[string]any) { delete(c, "aud") })), "JWT missing required aud claim"},
		{"expired", ti.sign(ti.claims(func(c map[string]any) { c["exp"], c["iat"] = now-120, now-600 })), "Expired JWT"},
		{"not yet valid", ti.sign(ti.claims(func(c map[string]any) { c["nbf"] = now + 300 })), "JWT before use time"},
		{"iat in the future", ti.sign(ti.claims(func(c map[string]any) { c["iat"] = now + 300 })), "iat in the future"},
		{"no sub", ti.sign(ti.claims(func(c map[string]any) { delete(c, "sub") })), "JWT missing required claims: [sub]"},
		{"no exp or iat", ti.sign(ti.claims(func(c map[string]any) { delete(c, "exp"); delete(c, "iat") })), "JWT missing required claims: [exp, iat]"},
		{"impostor key under the published kid", signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid"}, ti.claims(nil), rsaKey(t)),
			"Signed JWT rejected: Invalid signature"},
		{"forged and expired", signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid"}, ti.claims(func(c map[string]any) { c["exp"] = now - 120 }), rsaKey(t)),
			"Signed JWT rejected: Invalid signature"},
		{"unknown kid", signRS256(map[string]any{"alg": "RS256", "kid": "other"}, ti.claims(nil), ti.key),
			"Signed JWT rejected: Another algorithm expected, or no matching key(s) found"},
		{"HS256", signHS256(ti.claims(nil)), "Signed JWT rejected: Another algorithm expected, or no matching key(s) found"},
		{"critical header", signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid", "crit": []string{"future"}, "future": true}, ti.claims(nil), ti.key),
			"Signed JWT rejected: Invalid signature"},
		{"typ at+jwt", signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid", "typ": "at+jwt"}, ti.claims(nil), ti.key),
			"JOSE header typ (type) at+jwt not allowed"},
	} {
		if _, _, err := v.Verify(context.Background(), tc.jwt); err == nil || err.Error() != tc.want {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestVerifyAcceptsSkewsAndAudienceLists(t *testing.T) {
	ti := newIssuer(t)
	v := ti.verifier()
	now := time.Now().Unix()
	for name, jwt := range map[string]string{
		"expired within skew": ti.sign(ti.claims(func(c map[string]any) { c["exp"], c["iat"] = now-30, now-600 })),
		"iat within skew":     ti.sign(ti.claims(func(c map[string]any) { c["iat"] = now + 30 })),
		"nbf within skew":     ti.sign(ti.claims(func(c map[string]any) { c["nbf"] = now + 30 })),
		"audience list":       ti.sign(ti.claims(func(c map[string]any) { c["aud"] = []string{"https://other.example.com", audience} })),
		"no kid":              signRS256(map[string]any{"alg": "RS256"}, ti.claims(nil), ti.key),
		"fractional exp":      ti.sign(ti.claims(func(c map[string]any) { c["exp"] = float64(now) + 300.5 })),
		"lowercase typ":       signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid", "typ": "jwt"}, ti.claims(nil), ti.key),
	} {
		if _, _, err := v.Verify(context.Background(), jwt); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyFailsOnABrokenDiscoveryDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://elsewhere.example.com","jwks_uri":"https://elsewhere.example.com/jwks"}`))
	}))
	t.Cleanup(srv.Close)
	ti := newIssuer(t)
	v := workload.NewVerifier([]workload.Issuer{{Name: "github", URL: srv.URL, Audience: audience}}, http.DefaultClient)
	_, _, err := v.Verify(context.Background(), ti.sign(ti.claims(func(c map[string]any) { c["iss"] = srv.URL })))
	if err == nil || !strings.Contains(err.Error(), "discovery issuer mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestParseIssuers(t *testing.T) {
	got, err := workload.ParseIssuers("github=https://token.actions.githubusercontent.com, gitlab=https://gitlab.com,", "aud", false)
	want := []workload.Issuer{{"github", "https://token.actions.githubusercontent.com", "aud"}, {"gitlab", "https://gitlab.com", "aud"}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %+v %v", got, err)
	}
	if got, err := workload.ParseIssuers("", "aud", false); err != nil || got != nil {
		t.Errorf("empty: %+v %v", got, err)
	}
	if got, err := workload.ParseIssuers("local=http://127.0.0.1:1", "aud", true); err != nil || len(got) != 1 {
		t.Errorf("http under PM_AUTH_DEBUG: %+v %v", got, err)
	}
	for _, raw := range []string{
		"github=http://token.actions.githubusercontent.com",
		"github=",
		"GitHub=https://token.actions.githubusercontent.com",
		"https://token.actions.githubusercontent.com",
		"a=https://a.example.com,a=https://b.example.com",
		"a=https://a.example.com?x=1",
		"a=https://user@a.example.com",
	} {
		if _, err := workload.ParseIssuers(raw, "aud", false); err == nil {
			t.Errorf("%q parsed", raw)
		}
	}
}
