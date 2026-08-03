package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// WellKnownPath is the ONE discovery path this package knows.
//
// 🔒 docs/auth-model.md: "resolve endpoints from OIDC discovery instead of hardcoding
// provider-specific paths". Nothing in this package may ever grow an Okta/Entra/Keycloak-shaped
// fallback URL — the whole point is that the deployment's IdP is unknown at build time.
const WellKnownPath = "/.well-known/openid-configuration"

// DiscoveryDocument is `@Serializable data class OidcDiscoveryDocument` (auth/Oidc.kt:25-33).
//
// INBOUND ONLY: parsed FROM the IdP, never written by the control plane, so the snake_case names are
// OIDC Discovery 1.0's own and need no rename layer. (The Kotlin's OidcCallbackTest does respond with
// one from its fake-IdP double, which is why the json tags are declared in both directions.)
//
// 🔒 INV-A14-1 — the four non-pointer fields are HARD REQUIREMENTS. kotlinx throws
// MissingFieldException when any is absent, which propagates out of Document and fails the login.
// Fail-closed on purpose: a partially-parsed document with an empty jwks_uri would otherwise NPE deep
// inside signature verification, where the cause is unrecoverable from the log. Go's encoding/json
// silently zero-fills instead, so [Discovery.Document] enforces the requirement explicitly — see
// discoveryWire.
type DiscoveryDocument struct {
	Issuer                      string  `json:"issuer"`
	AuthorizationEndpoint       string  `json:"authorization_endpoint"`
	TokenEndpoint               string  `json:"token_endpoint"`
	UserinfoEndpoint            *string `json:"userinfo_endpoint,omitempty"`
	JwksURI                     string  `json:"jwks_uri"`
	DeviceAuthorizationEndpoint *string `json:"device_authorization_endpoint,omitempty"`
}

// discoveryWire decodes with EVERY field optional so "absent" can be told apart from "present and
// empty".
//
// That distinction is the whole reason this shadow type exists. kotlinx rejects an ABSENT
// non-nullable field and accepts an explicitly-empty one (`"jwks_uri": ""` parses fine). A Go check
// written as `if doc.JwksURI == ""` would reject both, which is stricter than the Kotlin — a
// divergence in the fail-closed direction, but still a divergence, and on a login path. Pointers
// reproduce the Kotlin exactly.
type discoveryWire struct {
	Issuer                      *string `json:"issuer"`
	AuthorizationEndpoint       *string `json:"authorization_endpoint"`
	TokenEndpoint               *string `json:"token_endpoint"`
	UserinfoEndpoint            *string `json:"userinfo_endpoint"`
	JwksURI                     *string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint *string `json:"device_authorization_endpoint"`
}

// ErrIssuerMismatch is the port of
// `require(document.issuer.trimEnd('/') == issuer.trimEnd('/')) { "OIDC discovery issuer mismatch" }`
// (auth/Oidc.kt:44).
//
// 🔒 INV-A14-27 — the discovered issuer must match the configured one. The document dictates
// token_endpoint and jwks_uri; without this check a hijacked or misconfigured discovery URL would
// point signature verification at attacker-controlled keys. Trailing slashes are normalised on BOTH
// sides because IdPs are inconsistent about them — and note this is the ONLY place the port
// normalises an issuer. [IDTokenValidator] must NOT, per INV-A14-30's exact-match `iss` rule.
var ErrIssuerMismatch = errors.New("OIDC discovery issuer mismatch")

// Discovery is `class OidcDiscovery(private val http: HttpClient, private val issuer: String)`
// (auth/Oidc.kt:35-51).
//
// ⚠️ F35 — the cache has NO lifetime and NO invalidation. A change to the LOCATION of jwks_uri is
// never picked up without a process restart. Key ROTATION is still handled, because the JWKS itself
// is re-fetched on every validation (F36) — but that is a property of [IDTokenValidator], not of this
// cache. Reproduce both; adding a TTL here changes which failures a deployment sees.
type Discovery struct {
	http   *http.Client
	issuer string

	// mu + cached are Kotlin's `Mutex()` + `@Volatile var cached`, and the double-check inside
	// Document is required.
	//
	// 🔒 INV-A14-28 (Go half) — a plain sync.Once is NOT a valid substitute, and the reason is a
	// product difference rather than a style one: all three failure modes below leave cached nil so
	// the NEXT call retries. sync.Once caches the FAILURE, converting a transient IdP blip into a
	// login outage that survives until restart. There is no negative caching, no timeout, no retry
	// and no backoff at this layer, and each of those absences is deliberate.
	mu     sync.Mutex
	cached atomic.Pointer[DiscoveryDocument]
}

// NewDiscovery builds the (uncached) discovery client for one issuer.
func NewDiscovery(hc *http.Client, issuer string) *Discovery {
	return &Discovery{http: hc, issuer: issuer}
}

// URL is `private fun discoveryUrl()` (auth/Oidc.kt:50).
//
// Kotlin's `trimEnd('/')` strips EVERY trailing slash, not just one; strings.TrimRight does the same.
// OidcDiscoveryTest case 3 ("a trailing slash on the configured issuer is tolerated") pins it.
func (d *Discovery) URL() string { return strings.TrimRight(d.issuer, "/") + WellKnownPath }

// Document is `suspend fun document(): OidcDiscoveryDocument` (auth/Oidc.kt:38-48).
//
//  1. Lock-free fast path on the cached pointer.
//  2. Under the mutex, RE-CHECK (double-checked locking).
//  3. GET the discovery URL; a non-2xx is a [StatusError] (ktor's expectSuccess).
//  4. Enforce INV-A14-1's four required fields, then INV-A14-27's issuer match.
//  5. Cache and return.
//
// ⚠️ None of the three call sites in the Kotlin wraps this (04-auth-session-tokens.md quotes the grep:
// GET /auth/oidc/login, the callback's token exchange, and daemon liveness). A misconfigured
// PM_OIDC_ISSUER therefore surfaces as a 500 on the login redirect, NOT as
// `common.oidc_not_configured`. [Routes.Login] reproduces that.
func (d *Discovery) Document(ctx context.Context) (*DiscoveryDocument, error) {
	if doc := d.cached.Load(); doc != nil {
		return doc, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if doc := d.cached.Load(); doc != nil {
		return doc, nil
	}

	var wire discoveryWire
	if err := getJSON(ctx, d.http, d.URL(), &wire); err != nil {
		return nil, err
	}
	doc, err := wire.required()
	if err != nil {
		return nil, err
	}
	// The Kotlin's `require` throws INSIDE withLock and `cached = document` at :45 is never reached;
	// withLock releases in a finally, so the lock is not leaked. The deferred Unlock plus this early
	// return is the same shape.
	if strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(d.issuer, "/") {
		return nil, fmt.Errorf("%w: document says %q, configured %q", ErrIssuerMismatch, doc.Issuer, d.issuer)
	}
	d.cached.Store(doc)
	return doc, nil
}

// required enforces INV-A14-1: the four non-nullable fields must be PRESENT (an explicit empty string
// is accepted, exactly as kotlinx accepts it).
func (w discoveryWire) required() (*DiscoveryDocument, error) {
	missing := make([]string, 0, 4)
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"issuer", w.Issuer},
		{"authorization_endpoint", w.AuthorizationEndpoint},
		{"token_endpoint", w.TokenEndpoint},
		{"jwks_uri", w.JwksURI},
	} {
		if f.val == nil {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		// The message names every missing field at once. kotlinx's MissingFieldException does the
		// same, and an operator debugging a non-compliant IdP wants the whole list, not the first.
		return nil, fmt.Errorf("oidc: discovery document is missing required field(s): %s", strings.Join(missing, ", "))
	}
	return &DiscoveryDocument{
		Issuer:                      *w.Issuer,
		AuthorizationEndpoint:       *w.AuthorizationEndpoint,
		TokenEndpoint:               *w.TokenEndpoint,
		UserinfoEndpoint:            w.UserinfoEndpoint,
		JwksURI:                     *w.JwksURI,
		DeviceAuthorizationEndpoint: w.DeviceAuthorizationEndpoint,
	}, nil
}
