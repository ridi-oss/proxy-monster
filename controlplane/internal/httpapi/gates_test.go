package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The three session-based gates — 02-authz.md §6 (requireAdmin/requireAuthz) and
// 05-datasources-catalog.md §"Route-file gates and helpers" (requireApi).
//
// 🔒 The invariant this file exists to pin is INV-A2-16: THE DEV BYPASS NEVER SKIPS CEDAR, IT
// PREVENTS CEDAR FROM BEING REACHED. Every case that turns AuthDebug on asserts that the Cedar engine
// was never CALLED, not merely that the answer was Allow — because a port that "implemented" the
// bypass inside Authz would pass an answer-only assertion while leaving the hole open on the query
// path, the MCP tools and the gRPC decide surface.

// countingAuthz records whether Cedar was reached, which is the observable INV-A2-16 is about.
type countingAuthz struct {
	calls    int
	decision authz.AuthzDecision
}

func (c *countingAuthz) Authorize(string, authz.AuthzAction, authz.AuthzResource, authz.AuthzContext) authz.AuthzDecision {
	c.calls++
	return c.decision
}

// gatesWith builds Gates whose Cedar decision is fixed, over a session that resolves (or does not).
func gatesWith(t *testing.T, authDebug bool, principal string, decision authz.AuthzDecision) (*Gates, *countingAuthz, *http.Request) {
	t.Helper()

	storage := newFakeStorage()
	resolver := newFakeResolver()
	sessions := testSessions(storage, resolver)

	r := requestWithIdentity(http.MethodGet, "/probe")
	if principal != "" {
		resolver.rows[7] = &session.WebRow{ID: 7, Principal: principal, Now: time.Now()}
		r.AddCookie(loginCookie(t, sessions, storage, 7))
	}

	cfg := gateConfig()
	cfg.AuthDebug = authDebug
	counting := &countingAuthz{decision: decision}
	g := &Gates{Config: cfg, Sessions: sessions, Authz: AuthorizeFunc(counting.Authorize)}
	return g, counting, r
}

// ---------------------------------------------------------------------------------------------
// requireApi — Datasources.kt:699
// ---------------------------------------------------------------------------------------------

func TestRequireAPIRejectsAnUnauthenticatedRequestWithCommonUnauthenticated(t *testing.T) {
	g, _, r := gatesWith(t, false, "", authz.Allow)
	rec := httptest.NewRecorder()

	if g.RequireAPI(rec, r) {
		t.Fatal("requireApi must reject a request with no session when authDebug is off")
	}
	assertStatus(t, rec, http.StatusUnauthorized, "no session")

	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.unauthenticated" {
		t.Errorf("code: got %q, want \"common.unauthenticated\"", body.Code)
	}
	// 🔒 INV-A1-13 — params is always present, as {} at minimum (encodeDefaults=true).
	if body.Params == nil || len(body.Params) != 0 {
		t.Errorf("params: got %v, want an empty map", body.Params)
	}
}

func TestRequireAPIAdmitsALiveSession(t *testing.T) {
	g, _, r := gatesWith(t, false, "alice@example.com", authz.Allow)
	rec := httptest.NewRecorder()

	if !g.RequireAPI(rec, r) {
		t.Fatalf("requireApi must admit a live session (body: %s)", rec.Body.String())
	}
}

// 🔒 The short-circuit is BEFORE the session read, so a route behind requireApi gets no principal in
// debug mode and falls back to "debug-user" at its own call site. Observable here as: no resolver
// round trip at all.
func TestRequireAPIUnderAuthDebugNeverReadsTheSession(t *testing.T) {
	storage := newFakeStorage()
	resolver := newFakeResolver()
	sessions := testSessions(storage, resolver)
	cfg := gateConfig()
	cfg.AuthDebug = true
	g := &Gates{Config: cfg, Sessions: sessions}

	rec := httptest.NewRecorder()
	if !g.RequireAPI(rec, requestWithIdentity(http.MethodGet, "/probe")) {
		t.Fatal("authDebug must admit every caller")
	}
	if resolver.resolveCalls != 0 {
		t.Errorf("the session was resolved %d times under authDebug; the bypass precedes the read",
			resolver.resolveCalls)
	}
}

// A store failure mid-resolution is an EXCEPTION in the Kotlin and reaches StatusPages, so the body
// is the catch-all's, not a 401. Answering 401 would tell a caller "you are not signed in" when the
// truth is "we could not tell", and would send them re-authenticating against a dead database.
func TestRequireAPIAnswersTheFallbackWhenTheStoreFails(t *testing.T) {
	storage := newFakeStorage()
	resolver := newFakeResolver()
	resolver.resolveErr = errStoreDown
	sessions := testSessions(storage, resolver)

	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	g := &Gates{Config: gateConfig(), Sessions: sessions}
	rec := httptest.NewRecorder()

	if g.RequireAPI(rec, r) {
		t.Fatal("a resolver failure must not admit the request")
	}
	assertStatus(t, rec, http.StatusInternalServerError, "store down")

	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.fallback" {
		t.Errorf("code: got %q, want \"common.fallback\" — the same body StatusPages would produce", body.Code)
	}
}

// ---------------------------------------------------------------------------------------------
// requireAdmin / requireAuthz — Authz.kt:881, :896
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A2-16, step 1. Cedar is NOT REACHED.
func TestRequireAuthzUnderAuthDebugPreventsCedarFromBeingReached(t *testing.T) {
	// The Cedar decision is a DENY, so a bypass implemented inside Authz would still deny here and
	// the case would fail. The only way to pass is for the gate to return before calling it.
	g, counting, r := gatesWith(t, true, "", authz.Deny("policy says no"))
	rec := httptest.NewRecorder()

	if !g.RequireAdmin(rec, r, authz.ActionAdminIdentity) {
		t.Fatalf("authDebug must admit before Cedar is consulted (body: %s)", rec.Body.String())
	}
	if counting.calls != 0 {
		t.Errorf("Cedar was called %d times under authDebug — the bypass must PREVENT Cedar from being "+
			"reached, never ask Cedar to allow everything (INV-A2-16)", counting.calls)
	}
}

// 🔒 INV-A2-16, step 2. With the bypass off, an unauthenticated caller is 401 common.unauthenticated
// and Cedar is still not reached — there is no principal to authorize.
func TestRequireAuthzWithNoSessionIs401AndDoesNotReachCedar(t *testing.T) {
	g, counting, r := gatesWith(t, false, "", authz.Allow)
	rec := httptest.NewRecorder()

	if g.RequireAdmin(rec, r, authz.ActionAdminPolicies) {
		t.Fatal("no session must not pass the admin gate")
	}
	assertStatus(t, rec, http.StatusUnauthorized, "no session")

	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.unauthenticated" {
		t.Errorf("code: got %q, want \"common.unauthenticated\"", body.Code)
	}
	if counting.calls != 0 {
		t.Errorf("Cedar was consulted %d times with no principal", counting.calls)
	}
}

// 🔒 INV-A2-16, step 3 — this is the case that matters: once authDebug is off, a MERE SESSION IS NOT
// ADMIN. The whole point of the gate is that an authenticated non-admin gets 403, not 200.
func TestRequireAuthzWithASessionButACedarDenyIs403WithTheReasonAsDetail(t *testing.T) {
	g, counting, r := gatesWith(t, false, "mallory@example.com",
		authz.Deny("no policy permits admin.identity"))
	rec := httptest.NewRecorder()

	if g.RequireAdmin(rec, r, authz.ActionAdminIdentity) {
		t.Fatal("an authenticated non-admin must not pass the admin gate")
	}
	assertStatus(t, rec, http.StatusForbidden, "cedar deny")
	if counting.calls != 1 {
		t.Errorf("Cedar was called %d times, want exactly 1", counting.calls)
	}

	var body types.ApiError
	decodeBody(t, rec, &body)
	if body.Code != "common.forbidden" {
		t.Errorf("code: got %q, want \"common.forbidden\"", body.Code)
	}
	// `mapOf("detail" to decision.reason)` — Cedar's OWN reason, verbatim. The console shows it, and
	// dropping it turns every 403 into an unexplained one.
	if body.Params["detail"] != "no policy permits admin.identity" {
		t.Errorf("detail: got %q, want Cedar's reason verbatim", body.Params["detail"])
	}
}

func TestRequireAuthzWithACedarAllowAdmits(t *testing.T) {
	g, counting, r := gatesWith(t, false, "root@example.com", authz.Allow)
	rec := httptest.NewRecorder()

	if !g.RequireAdmin(rec, r, authz.ActionAdminDatasources) {
		t.Fatalf("a Cedar Allow must admit (body: %s)", rec.Body.String())
	}
	if counting.calls != 1 {
		t.Errorf("Cedar was called %d times, want exactly 1", counting.calls)
	}
}

// requireAdmin is the System-resource ALIAS and nothing else — 02-authz.md:349, "both share one
// body". A port that gave it its own body is how the two drift.
func TestRequireAdminIsRequireAuthzOverResourceSystem(t *testing.T) {
	var seen authz.AuthzResource
	storage, resolver := newFakeStorage(), newFakeResolver()
	sessions := testSessions(storage, resolver)
	resolver.rows[7] = &session.WebRow{ID: 7, Principal: "root@example.com"}
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	g := &Gates{Config: gateConfig(), Sessions: sessions,
		Authz: AuthorizeFunc(func(_ string, _ authz.AuthzAction, resource authz.AuthzResource, _ authz.AuthzContext) authz.AuthzDecision {
			seen = resource
			return authz.Allow
		})}

	g.RequireAdmin(httptest.NewRecorder(), r, authz.ActionAdminPolicies)
	if _, ok := seen.(authz.ResourceSystem); !ok {
		t.Errorf("requireAdmin authorized against %T, want authz.ResourceSystem", seen)
	}
}

// The resource is threaded through unchanged, which is what lets a call site build it from the
// caller's own principal (`Token(owner)`) — the requireAuthz half of the pair.
func TestRequireAuthzThreadsTheGivenResource(t *testing.T) {
	var seen authz.AuthzResource
	storage, resolver := newFakeStorage(), newFakeResolver()
	sessions := testSessions(storage, resolver)
	resolver.rows[7] = &session.WebRow{ID: 7, Principal: "alice@example.com"}
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))

	g := &Gates{Config: gateConfig(), Sessions: sessions,
		Authz: AuthorizeFunc(func(_ string, _ authz.AuthzAction, resource authz.AuthzResource, _ authz.AuthzContext) authz.AuthzDecision {
			seen = resource
			return authz.Allow
		})}

	want := authz.ResourceToken{Owner: "alice@example.com"}
	g.RequireAuthz(httptest.NewRecorder(), r, authz.ActionTokenRevoke, want)
	got, ok := seen.(authz.ResourceToken)
	if !ok || got != want {
		t.Errorf("authorized against %#v, want %#v", seen, want)
	}
}

// The principal handed to Cedar is the SESSION's, never a header or a body field.
func TestRequireAuthzAuthorizesTheSessionPrincipal(t *testing.T) {
	var seen string
	storage, resolver := newFakeStorage(), newFakeResolver()
	sessions := testSessions(storage, resolver)
	resolver.rows[7] = &session.WebRow{ID: 7, Principal: "alice@example.com"}
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	r.Header.Set("X-Principal", "root@example.com")

	g := &Gates{Config: gateConfig(), Sessions: sessions,
		Authz: AuthorizeFunc(func(principal string, _ authz.AuthzAction, _ authz.AuthzResource, _ authz.AuthzContext) authz.AuthzDecision {
			seen = principal
			return authz.Allow
		})}

	g.RequireAdmin(httptest.NewRecorder(), r, authz.ActionAdminIdentity)
	if seen != "alice@example.com" {
		t.Errorf("Cedar saw principal %q, want the session's", seen)
	}
}

// 🔴 The A12 gap, made visible rather than left implicit. [Gates.Context] defaults to an EMPTY
// AuthzContext because httpAuthzContext is unported, so `requester_ip` is absent from every gate
// decision. Absence is fail-closed (INV-A2-8), but it IS a divergence, and this case is what a later
// A12 increment flips.
func TestGateContextDefaultsToAnEmptyContextUntilA12Lands(t *testing.T) {
	var seen authz.AuthzContext
	storage, resolver := newFakeStorage(), newFakeResolver()
	sessions := testSessions(storage, resolver)
	resolver.rows[7] = &session.WebRow{ID: 7, Principal: "alice@example.com"}
	r := requestWithIdentity(http.MethodGet, "/probe")
	r.AddCookie(loginCookie(t, sessions, storage, 7))
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	g := &Gates{Config: gateConfig(), Sessions: sessions,
		Authz: AuthorizeFunc(func(_ string, _ authz.AuthzAction, _ authz.AuthzResource, ctx authz.AuthzContext) authz.AuthzDecision {
			seen = ctx
			return authz.Allow
		})}

	g.RequireAdmin(httptest.NewRecorder(), r, authz.ActionAdminIdentity)
	if seen.RequesterIP != nil {
		t.Errorf("requester_ip = %q — A12 has landed; wire Gates.Context and update this case", *seen.RequesterIP)
	}
	if seen.Channel != nil {
		t.Errorf("channel = %q, want nil — INV-A2-15: these routes have no query-decision channel and "+
			"inventing one would be dishonest", *seen.Channel)
	}
	if len(seen.Tags) != 0 {
		t.Errorf("tags = %v, want empty — INV-A2-14: tags derive only when a datasource is in scope", seen.Tags)
	}

	// And the seam works when supplied, so A12 is a one-field change.
	ip := "203.0.113.9"
	g.Context = func(*http.Request) authz.AuthzContext { return authz.AuthzContext{RequesterIP: &ip} }
	g.RequireAdmin(httptest.NewRecorder(), r, authz.ActionAdminIdentity)
	if seen.RequesterIP == nil || *seen.RequesterIP != ip {
		t.Errorf("the Context seam did not reach Cedar: %+v", seen)
	}
}
