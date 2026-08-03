package oidc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Port of OidcDiscoveryTest.kt — 4 cases, plus the INV-A14-1 and failure-semantics cases the Kotlin
// suite leaves uncovered (14-auth.md's "Failure semantics to preserve").
//
// ORACLE: control-plane/src/test/kotlin/.../OidcDiscoveryTest.kt, read this session.

// discardLogger silences the validator's INV-A14-29 warn line in tests that deliberately fail
// closed. It is NOT used where the log line itself is the behaviour under test.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- Case 1 · `document parses every field, required and optional`
func TestDiscoveryDocument_ParsesEveryField(t *testing.T) {
	idp := newFakeIdP(t, "discovery-kid")
	d := NewDiscovery(NewHTTPClient(), idp.issuer())

	doc, err := d.Document(context.Background())
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if doc.Issuer != idp.issuer() {
		t.Errorf("issuer = %q, want %q", doc.Issuer, idp.issuer())
	}
	if doc.AuthorizationEndpoint != idp.issuer()+"/authorize" {
		t.Errorf("authorization_endpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != idp.issuer()+"/token" {
		t.Errorf("token_endpoint = %q", doc.TokenEndpoint)
	}
	if doc.UserinfoEndpoint == nil || *doc.UserinfoEndpoint != idp.issuer()+"/userinfo" {
		t.Errorf("userinfo_endpoint = %v", doc.UserinfoEndpoint)
	}
	if doc.JwksURI != idp.issuer()+"/jwks" {
		t.Errorf("jwks_uri = %q", doc.JwksURI)
	}
	if doc.DeviceAuthorizationEndpoint == nil || *doc.DeviceAuthorizationEndpoint != idp.issuer()+"/device/authorize" {
		t.Errorf("device_authorization_endpoint = %v", doc.DeviceAuthorizationEndpoint)
	}
}

// --- Case 2 · `optional fields default to null when the IdP omits them`
func TestDiscoveryDocument_OptionalFieldsDefaultToNil(t *testing.T) {
	srv := minimalIdP(t)
	d := NewDiscovery(NewHTTPClient(), srv.URL+"/minimal")

	doc, err := d.Document(context.Background())
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if doc.UserinfoEndpoint != nil {
		t.Errorf("userinfo_endpoint = %q, want nil", *doc.UserinfoEndpoint)
	}
	if doc.DeviceAuthorizationEndpoint != nil {
		t.Errorf("device_authorization_endpoint = %q, want nil", *doc.DeviceAuthorizationEndpoint)
	}
}

// --- Case 3 · `a trailing slash on the configured issuer is tolerated`
//
// Both SIDES are normalised: the discovery URL is built off a trimmed issuer, and INV-A14-27's
// comparison trims both. IdPs are inconsistent about the trailing slash, which is why.
func TestDiscoveryDocument_TrailingSlashOnConfiguredIssuerIsTolerated(t *testing.T) {
	idp := newFakeIdP(t, "discovery-kid")
	d := NewDiscovery(NewHTTPClient(), idp.issuer()+"/")

	doc, err := d.Document(context.Background())
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if doc.Issuer != idp.issuer() {
		t.Errorf("issuer = %q, want %q", doc.Issuer, idp.issuer())
	}
	if got, want := d.URL(), idp.issuer()+WellKnownPath; got != want {
		t.Errorf("URL() = %q, want %q — a doubled slash would 404 on some IdPs", got, want)
	}
}

// --- Case 4 · `the document is fetched once and cached across repeated calls`
func TestDiscoveryDocument_FetchedOnceAndCached(t *testing.T) {
	idp := newFakeIdP(t, "discovery-kid")
	d := NewDiscovery(NewHTTPClient(), idp.issuer())

	for i := 0; i < 3; i++ {
		if _, err := d.Document(context.Background()); err != nil {
			t.Fatalf("Document #%d: %v", i, err)
		}
	}
	if got := idp.discoveryHits.Load(); got != 1 {
		t.Errorf("discovery fetched %d times, want exactly 1 — repeated Document() calls must not re-fetch", got)
	}
}

// --- Extra 🔒 INV-A14-27 · a document whose `issuer` disagrees with the configured one is REFUSED.
//
// The document dictates token_endpoint and jwks_uri; without this check a hijacked discovery URL would
// point signature verification at attacker-controlled keys. Not covered by the Kotlin suite.
func TestDiscoveryDocument_IssuerMismatchIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"https://attacker.example",
			"authorization_endpoint":"https://attacker.example/authorize",
			"token_endpoint":"https://attacker.example/token",
			"jwks_uri":"https://attacker.example/jwks"}`)
	}))
	t.Cleanup(srv.Close)

	d := NewDiscovery(NewHTTPClient(), srv.URL)
	_, err := d.Document(context.Background())
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("Document error = %v, want ErrIssuerMismatch", err)
	}
}

// --- Extra 🔒 INV-A14-1 · each of the four required fields is a hard requirement.
//
// kotlinx throws MissingFieldException; Go's encoding/json would zero-fill instead, so a document
// missing `jwks_uri` would reach signature verification with an empty URL. Fail-closed here.
func TestDiscoveryDocument_RequiredFieldsAreEnforced(t *testing.T) {
	full := map[string]string{
		"issuer":                 "ISSUER",
		"authorization_endpoint": "ISSUER/authorize",
		"token_endpoint":         "ISSUER/token",
		"jwks_uri":               "ISSUER/jwks",
	}
	for _, omit := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		t.Run("omit_"+omit, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				parts := make([]string, 0, 4)
				for k, v := range full {
					if k == omit {
						continue
					}
					parts = append(parts, `"`+k+`":"`+strings.ReplaceAll(v, "ISSUER", srv.URL)+`"`)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, "{"+strings.Join(parts, ",")+"}")
			}))
			t.Cleanup(srv.Close)

			d := NewDiscovery(NewHTTPClient(), srv.URL)
			_, err := d.Document(context.Background())
			if err == nil {
				t.Fatalf("a document with no %q must fail the parse", omit)
			}
			if !strings.Contains(err.Error(), omit) {
				t.Errorf("error %q should name the missing field %q", err, omit)
			}
		})
	}
}

// --- Extra 🔒 · the three failure modes leave the cache EMPTY, so the next call RETRIES.
//
// 14-auth.md INV-A14-28's Go half: "A sync.Once-based Go port would cache the FAILURE and never
// retry, which is a different product: it converts a transient IdP blip into a login outage that
// survives until restart." This test is the mutation guard for exactly that refactor.
func TestDiscoveryDocument_TransientFailureIsNotCached(t *testing.T) {
	failing := true
	hits := 0
	// The success body must name the server's own URL, which only exists after Start — hence the
	// unstarted server plus an explicit Start rather than httptest.NewServer.
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if failing {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"`+srv.URL+`","authorization_endpoint":"`+srv.URL+
			`/a","token_endpoint":"`+srv.URL+`/t","jwks_uri":"`+srv.URL+`/j"}`)
	})
	srv.Start()
	t.Cleanup(srv.Close)

	d := NewDiscovery(NewHTTPClient(), srv.URL)
	if _, err := d.Document(context.Background()); err == nil {
		t.Fatal("a 503 must surface as an error (ktor's expectSuccess = true)")
	}
	var status *StatusError
	if _, err := d.Document(context.Background()); !errors.As(err, &status) || status.IsClientError() {
		t.Fatalf("second call error = %v, want a 5xx StatusError — the failure must NOT be cached", err)
	}

	failing = false
	doc, err := d.Document(context.Background())
	if err != nil {
		t.Fatalf("the third call must succeed once the IdP recovers, got %v", err)
	}
	if doc.Issuer != srv.URL {
		t.Errorf("issuer = %q, want %q", doc.Issuer, srv.URL)
	}
	if hits < 3 {
		t.Errorf("the IdP saw %d requests, want at least 3 — each failure must retry", hits)
	}
}

// minimalIdP serves a document with only the four required fields, at a SUB-PATH issuer — the Kotlin
// suite's `/minimal` route, which also proves the discovery URL is built from the configured issuer
// rather than from its origin.
func minimalIdP(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("GET /minimal"+WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"`+srv.URL+`/minimal","authorization_endpoint":"`+srv.URL+
			`/authorize","token_endpoint":"`+srv.URL+`/token","jwks_uri":"`+srv.URL+`/jwks"}`)
	})
	return srv
}
