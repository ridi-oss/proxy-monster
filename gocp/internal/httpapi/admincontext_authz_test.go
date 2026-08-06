package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// ---------------------------------------------------------------------------------------------
// PORT of AdminContextAuthzTest.kt — 161 LOC, 3 cases. 02-authz.md §6 / docs/authz-context.md.
//
// WHAT THE KOTLIN SUITE IS FOR, from its kdoc: requireAdmin "is the single choke point every admin
// route funnels through — proving `requester_ip` reaches Cedar HERE, once, stands in for all ~35 admin
// call sites […] with zero call-site churn". Plus the anti-spoof invariant end to end: "an arbitrary
// caller supplying `X-Forwarded-For` gains NOTHING unless the socket peer […] is itself a configured
// trusted proxy."
//
// So the subject is [Gates.RequireAdmin] threading [Gates.authzContext] into the Cedar call — which is
// why these cases run against the REAL Cedar engine (an ip-gated admin permit) rather than the
// counting fake the rest of gates_test.go uses. Delete `g.authzContext(r)` from RequireAdmin's
// Authorize call and case 2's ALLOW half goes red; nothing else in this package notices.
//
// NO STUB AND NO DEVIATION. While A12 was unported these cases derived `requester_ip` through a
// test-local `trustedEdgeContext` plugged into [Gates.Context]. A12 has landed, so the field is left
// NIL — the production shape — and the derivation under test is the real [Gates.HTTPAuthzContext].
//
// 🔒 That removal is what makes case 2's marker honest. With an injected context, case 2 proved only
// that RequireAdmin threads whatever context it is handed; the resolution from socket peer plus
// X-Forwarded-For was the fixture's own work. Now the whole chain — [RequestPeer], [LastHeader],
// [ResolveHTTPRequesterIP], Cedar validation, the gate — is production code, and case 1's
// untrusted-peer half is a real anti-spoof assertion rather than a restatement of the fixture.
//
// The Kotlin reaches a real Postgres only to MINT a web session (PrincipalSessionStore over a migrated
// database); the session seam is faked here exactly as it is for every other case in this package —
// internal/session's own DB suites prove the SQL behind it. Nothing about requester_ip or the gate is
// weakened by that.
// ---------------------------------------------------------------------------------------------

// ipGatedAdminPolicy is AdminContextAuthzTest.kt:69-71 verbatim: admin.datasources gated on a
// requester_ip inside the RFC 5737 documentation range 203.0.113.0/24.
const ipGatedAdminPolicy = `permit(
        principal in Role::"system:admin", action == Action::"admin.datasources", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };`

// adminContextTestPeer is the socket peer httptest.NewRequest reports. It stands in for the literal
// "localhost" Ktor's test host reports and that the Kotlin's `trustedProxies = setOf("localhost")`
// trusts — same posture: the peer is trusted in one case and not the other, and nothing else moves.
const adminContextTestPeer = "192.0.2.1"

// adminContextGates builds the Kotlin's `installAdminTestApp` shape: the real ip-gated engine, a
// principal that holds system:admin, and the configured trusted-proxy set.
func adminContextGates(t *testing.T, trustedProxies []string, principal string) (http.Handler, *http.Cookie) {
	t.Helper()

	engine, err := authz.NewCedarEngineFromSources([]authz.PolicySource{{ID: 1, Src: ipGatedAdminPolicy}})
	if err != nil {
		t.Fatalf("CedarEngine construction failed: %v", err)
	}
	a := authz.New(engine, nil, authz.RoleSourceFunc(func(p string) []string {
		if p == "admin@example.com" {
			return []string{"system:admin"}
		}
		return nil
	}))

	cfg := gateConfig()
	cfg.TrustedProxies = map[string]struct{}{}
	for _, p := range trustedProxies {
		cfg.TrustedProxies[p] = struct{}{}
	}

	storage, resolver := newFakeStorage(), newFakeResolver()
	sessions := testSessions(storage, resolver)

	var cookie *http.Cookie
	if principal != "" {
		resolver.rows[7] = &session.WebRow{ID: 7, Principal: principal, Now: time.Now()}
		cookie = loginCookie(t, sessions, storage, 7)
	}

	g := &Gates{
		Config:   cfg,
		Sessions: sessions,
		Authz:    AuthorizeFunc(a.Authorize),
	}

	// `get("/admin/datasources") { if (!call.requireAdmin(...)) return@get; call.respond(OK) }`.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.RequireAdmin(w, r, authz.ActionAdminDatasources) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return handler, cookie
}

// adminContextGet is `client.get("/admin/datasources") { header("X-Forwarded-For", xff) }`.
func adminContextGet(h http.Handler, cookie *http.Cookie, xff string) *httptest.ResponseRecorder {
	r := requestWithIdentity(http.MethodGet, "/admin/datasources")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// 1. 🔒 an admin session with no trusted edge is denied even though the policy would allow with the
// right ip
//
// THE ANTI-SPOOF CASE. No trusted proxy is configured, so the X-Forwarded-For is never honored,
// requester_ip is absent, and the ip-gated permit cannot fire — 403 even though the very same header
// value ALLOWS in case 2. The pair is what makes each half informative: this one alone would also pass
// if requester_ip were never derived at all.
// KT: AdminContextAuthzTest.kt#an admin session with no trusted edge is denied even though the policy would allow with the right ip
func TestAdminContext_AnAdminSessionWithNoTrustedEdgeIsDenied(t *testing.T) {
	h, cookie := adminContextGates(t, nil, "admin@example.com")
	rec := adminContextGet(h, cookie, "203.0.113.10")
	assertStatus(t, rec, http.StatusForbidden,
		"an untrusted caller cannot spoof requester_ip via X-Forwarded-For")
}

// 2. a trusted edge's forwarded ip reaches Cedar and satisfies the ip-gated admin policy
//
// The ALLOW half is the load-bearing one: it fails if RequireAdmin stops passing the request context
// into Cedar (INV-A2-16's "threading it HERE fixes requester_ip for ~35 admin call sites"). The
// out-of-range half proves the permit is really evaluating the ip rather than the mere presence of a
// trusted edge.
// KT: AdminContextAuthzTest.kt#a trusted edge's forwarded ip reaches Cedar and satisfies the ip-gated admin policy
func TestAdminContext_ATrustedEdgesForwardedIPReachesCedar(t *testing.T) {
	h, cookie := adminContextGates(t, []string{adminContextTestPeer}, "admin@example.com")

	allowed := adminContextGet(h, cookie, "203.0.113.10")
	assertStatus(t, allowed, http.StatusOK,
		"requester_ip from the trusted edge's XFF must satisfy the ip-gated permit")

	outsideRange := adminContextGet(h, cookie, "198.51.100.10")
	assertStatus(t, outsideRange, http.StatusForbidden,
		"an ip outside the granted range must still deny")
}

// 3. no session is unauthenticated regardless of ip
//
// 401, not 403: step 1 of the gate answers "is there a session" before Cedar is consulted, so a
// trusted in-range ip does not upgrade an anonymous caller.
// KT: AdminContextAuthzTest.kt#no session is unauthenticated regardless of ip
func TestAdminContext_NoSessionIsUnauthenticatedRegardlessOfIP(t *testing.T) {
	h, _ := adminContextGates(t, []string{adminContextTestPeer}, "")
	rec := adminContextGet(h, nil, "203.0.113.10")
	assertStatus(t, rec, http.StatusUnauthorized, "no session, trusted in-range ip")
}
