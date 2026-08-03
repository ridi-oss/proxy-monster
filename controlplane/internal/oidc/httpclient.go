package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxResponseBytes caps what a helper will read from the IdP before giving up.
//
// ⚠️ DEVIATION, not a port. `oidcHttpClient()` has no size limit of its own; ktor-client-cio streams
// whatever arrives and kotlinx decodes it. Go's io.ReadAll on an http.Response.Body is unbounded, and
// an unbounded read on an outbound call to a third party is a memory-exhaustion primitive an attacker
// controls. The cap is far above any real discovery document, JWKS or token response (Okta's JWKS with
// four 4096-bit keys is ~4 KB), so no legitimate response is affected — but the divergence is recorded
// rather than hidden, because a deployment with a genuinely enormous JWKS would fail here and not in
// the Kotlin. See the deviations list in the increment return.
const maxResponseBytes = 1 << 20

// NewHTTPClient is `fun oidcHttpClient(): HttpClient` (auth/Oidc.kt:96-101).
//
// The Kotlin installs exactly two things: `expectSuccess = true` and a JSON content negotiator with
// `ignoreUnknownKeys = true`. Both map onto stdlib behaviour rather than configuration —
// [StatusError] reproduces expectSuccess at each call site, and encoding/json ignores unknown keys by
// default — so this constructor's whole job is to be the ONE place that says what is deliberately
// absent.
//
// ⚠️ F38 — no timeout, no retry, no connection limit, no proxy or TLS configuration. `Timeout: 0` is
// therefore load-bearing, not an oversight: a hung IdP stalls whatever is fetching discovery or the
// token endpoint, exactly as it does today. Every call in this package takes its deadline from the
// caller's context.Context instead, which is the ONLY reason that is survivable — 14-auth.md's
// INV-A14-29b makes the same point from the Kotlin side ("validate performs a synchronous outbound
// HTTP request and needs a context deadline").
func NewHTTPClient() *http.Client { return &http.Client{Timeout: 0} }

// StatusError is the port of ktor's `expectSuccess = true` behaviour: a non-2xx response becomes an
// error rather than a value.
//
// The 4xx/5xx SPLIT is contractual, not cosmetic. Ktor raises `ClientRequestException` for 4xx and
// `ServerResponseException` for 5xx, and [RefreshGrant] branches on exactly that distinction
// (INV-A4-40): only a 4xx body carrying `invalid_grant` may revoke a session; a 5xx is transient.
// Collapsing the two mass-logs-out a fleet during an IdP incident.
type StatusError struct {
	StatusCode int
	// Body is the response body, truncated at maxResponseBytes. RefreshGrant parses it for the
	// OAuth error code; nothing else reads it.
	Body []byte
	// URL is included for the log line only. It carries no secret: every URL this package fetches
	// is a discovery/JWKS/token endpoint, and secrets travel in POST bodies.
	URL string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("oidc: %s returned HTTP %d", e.URL, e.StatusCode)
}

// IsClientError reports a 4xx. See the type doc for why the split matters.
func (e *StatusError) IsClientError() bool { return e.StatusCode >= 400 && e.StatusCode < 500 }

// getJSON is `http.get(url).body<T>()` under `expectSuccess = true` + `ignoreUnknownKeys = true`.
//
// out must be a pointer. A non-2xx yields a [StatusError] BEFORE any decoding is attempted, which is
// what stops an IdP's HTML error page from being decoded into a half-populated document.
func getJSON(ctx context.Context, hc *http.Client, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("oidc: build GET %s: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")
	return doJSON(hc, req, out)
}

// postFormJSON is ktor's `http.submitForm(url, formParameters).body<T>()` — an
// application/x-www-form-urlencoded POST whose response is JSON, under the same expectSuccess rule.
//
// Both OAuth grants this package performs (authorization_code in the callback, refresh_token in the
// liveness sweep) are this shape.
func postFormJSON(ctx context.Context, hc *http.Client, rawURL string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("oidc: build POST %s: %w", rawURL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return doJSON(hc, req, out)
}

// doJSON runs req, enforces expectSuccess, and decodes the body when out is non-nil.
func doJSON(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: %s %s: %w", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{StatusCode: resp.StatusCode, Body: body, URL: req.URL.String()}
	}
	if readErr != nil {
		return fmt.Errorf("oidc: read %s: %w", req.URL, readErr)
	}
	if out == nil {
		return nil
	}
	// ignoreUnknownKeys = true is encoding/json's DEFAULT, so there is nothing to configure and
	// nothing to disable — a provider's extra discovery fields are dropped rather than failing the
	// fetch. DisallowUnknownFields would be the bug.
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("oidc: decode %s: %w", req.URL, err)
	}
	return nil
}
