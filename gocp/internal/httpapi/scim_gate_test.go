package httpapi

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Port of ScimAuthTest.kt (121 LOC, 6 cases) and ScimTlsGateTest.kt (7 cases) — 03-identity-scim.md
// §"Scim.kt" and its test inventory at :1179 and :1160.
//
// 🔒 EVERY CASE RUNS WITH AuthDebug = true, because that is what makes this suite the proof of
// INV-A3-38 / F33: `requireScimAuth` has NO PM_AUTH_DEBUG bypass, while `AGENTS.md` and
// `docs/authz-model.md:363` both claim "PM_AUTH_DEBUG short-circuits all four". THE CODE IS RIGHT AND
// THE DOCS ARE WRONG (ScimAuthTest.kt:106,111 sets authDebug = true and still expects 501/403/401).
// A port that implements the documentation makes a dev-mode control plane accept unauthenticated
// directory writes over plaintext, so this is REPRODUCE + PIN.

// A var, not a const, because the fixture takes *string — Config.scimToken is nullable.
var scimToken = "s3cret-scim-token"

// probe stands in for scimRoutes, exactly as ScimAuthTest's `/probe` route does: this file is about
// the GATE, not the store-backed routes.
func scimProbe(cfg func() (gates *Gates)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g := cfg()
		if !g.RequireScimAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// scimRequest builds the request each case sends. `tls` chooses whether the connection itself is
// HTTPS (Ktor's `request.origin.scheme`), `peer` is the socket peer, and the headers are verbatim.
func scimRequest(tlsConn bool, peer string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/probe", nil)
	r.RemoteAddr = peer
	if tlsConn {
		r.TLS = &tls.ConnectionState{}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func runScimGate(t *testing.T, cfg func() *Gates, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	scimProbe(cfg)(rec, r)
	return rec
}

func scimGates(token *string, trustedProxies ...string) func() *Gates {
	return func() *Gates {
		return &Gates{Config: testScimConfig(token, trustedProxies...), Sessions: testSessions(newFakeStorage(), newFakeResolver())}
	}
}

// ScimAuthTest case 1 — 🔒 INV-A3-37.
// KT: ScimAuthTest.kt#plaintext request is rejected regardless of the bearer token
func TestScimPlaintextRequestIsRejectedRegardlessOfTheBearerToken(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken),
		scimRequest(false, "203.0.113.9:5555", map[string]string{"Authorization": "Bearer " + scimToken}))

	assertStatus(t, rec, http.StatusForbidden, "plaintext with the correct bearer")

	var body ScimError
	decodeBody(t, rec, &body)
	if body.Detail == nil || *body.Detail != scimRequiresTLSDetail {
		t.Errorf("expected the TLS detail, got %+v — the bearer must not be compared over plaintext", body.Detail)
	}

	// ⚠️ THIS CASE DOES NOT, ON ITS OWN, PIN THE ORDERING. With the CORRECT bearer a gate that
	// compared the secret first would pass that check and then fail the TLS one, answering 403 with
	// this same detail. Verified by mutation: swapping the two checks leaves this case green.
	// TestScimPlaintextWithAWrongBearerIsRejectedForTLSNotForTheBearer is what actually pins it.
}

// 🔒 INV-A3-37, THE CASE THAT ACTUALLY DISTINGUISHES THE TWO ORDERINGS — and a HARDENING test, not a
// port: the Kotlin suite does not have it either. 03-identity-scim.md:930 records that "ScimAuthTest
// cases 1 and 2 assert 403 with the correct bearer", and with a correct bearer both orderings answer
// 403, so the invariant the spec marks 🔒 ("reordering these two is a real regression, not a style
// change") is unpinned on both sides.
//
// The observable difference is plaintext + a WRONG bearer:
//
//	TLS first (correct):   403 "SCIM requires TLS"  — rejected BEFORE the secret is compared
//	bearer first (broken): 401 "invalid bearer token" — the comparison HAPPENED, and the answer now
//	                        tells a plaintext caller whether their guess was right, over the wire
//
// That 401 is the leak: it turns the gate into an oracle a passive observer can use, on a standing
// secret that is never rotated.
func TestScimPlaintextWithAWrongBearerIsRejectedForTLSNotForTheBearer(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken),
		scimRequest(false, "203.0.113.9:5555", map[string]string{"Authorization": "Bearer wrong-token"}))

	assertStatus(t, rec, http.StatusForbidden, "plaintext with a wrong bearer")

	var body ScimError
	decodeBody(t, rec, &body)
	if body.Detail == nil || *body.Detail != scimRequiresTLSDetail {
		t.Fatalf("detail = %v, want %q — a 401 here means the secret was compared over plaintext, "+
			"which is exactly the ordering INV-A3-37 forbids", body.Detail, scimRequiresTLSDetail)
	}
	if body.Status != "403" {
		t.Errorf("status = %q, want \"403\"", body.Status)
	}
}

// The same ordering claim one step earlier: an UNCONFIGURED token wins over both later checks, so a
// deployment that never set PM_SCIM_TOKEN answers 501 even over plaintext with a wrong bearer. 501,
// not 403 and not 401 — INV-A3-36's "no provisioning surface at all, not an open one".
func TestScimUnconfiguredTokenOutranksBothTheTLSAndBearerChecks(t *testing.T) {
	rec := runScimGate(t, scimGates(nil),
		scimRequest(false, "203.0.113.9:5555", map[string]string{"Authorization": "Bearer wrong-token"}))

	assertStatus(t, rec, http.StatusNotImplemented, "unconfigured token over plaintext")
	var body ScimError
	decodeBody(t, rec, &body)
	if body.Detail == nil || *body.Detail != scimNotConfiguredDetail {
		t.Errorf("detail = %v, want %q", body.Detail, scimNotConfiguredDetail)
	}
}

// ScimAuthTest case 2 — 🔒 INV-A3-39, the spoof path end to end.
// KT: ScimAuthTest.kt#forwarded proto from an untrusted peer does not satisfy the TLS gate
func TestScimForwardedProtoFromAnUntrustedPeerDoesNotSatisfyTheTLSGate(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken), scimRequest(false, "203.0.113.9:5555", map[string]string{
		"X-Forwarded-Proto": "https",
		"Authorization":     "Bearer " + scimToken,
	}))

	assertStatus(t, rec, http.StatusForbidden,
		"an untrusted peer must not assert its own transport — even with the correct bearer")
}

// ScimAuthTest case 3.
// KT: ScimAuthTest.kt#https-asserted request with the wrong bearer is unauthorized
func TestScimHTTPSAssertedRequestWithTheWrongBearerIsUnauthorized(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken, "10.0.0.1"), scimRequest(false, "10.0.0.1:5555", map[string]string{
		"X-Forwarded-Proto": "https",
		"Authorization":     "Bearer wrong-token",
	}))

	assertStatus(t, rec, http.StatusUnauthorized, "wrong bearer from a trusted edge")
}

// ScimAuthTest case 4.
// KT: ScimAuthTest.kt#https-asserted request with no bearer header is unauthorized
func TestScimHTTPSAssertedRequestWithNoBearerHeaderIsUnauthorized(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken, "10.0.0.1"), scimRequest(false, "10.0.0.1:5555", map[string]string{
		"X-Forwarded-Proto": "https",
	}))

	assertStatus(t, rec, http.StatusUnauthorized, "no Authorization header")
}

// ScimAuthTest case 5.
// KT: ScimAuthTest.kt#https-asserted request with the correct bearer succeeds
func TestScimHTTPSAssertedRequestWithTheCorrectBearerSucceeds(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken, "10.0.0.1"), scimRequest(false, "10.0.0.1:5555", map[string]string{
		"X-Forwarded-Proto": "https",
		"Authorization":     "Bearer " + scimToken,
	}))

	assertStatus(t, rec, http.StatusOK, "correct bearer from a trusted edge")
}

// ScimAuthTest case 6 — 🔒 INV-A3-36: an unconfigured token means NO provisioning surface at all,
// not an open one.
// KT: ScimAuthTest.kt#an unconfigured SCIM token disables the endpoint fail-closed
func TestScimAnUnconfiguredSCIMTokenDisablesTheEndpointFailClosed(t *testing.T) {
	rec := runScimGate(t, scimGates(nil), scimRequest(false, "10.0.0.1:5555", map[string]string{
		"X-Forwarded-Proto": "https",
		"Authorization":     "Bearer " + scimToken,
	}))

	assertStatus(t, rec, http.StatusNotImplemented, "PM_SCIM_TOKEN unset")

	var body ScimError
	decodeBody(t, rec, &body)
	if body.Status != "501" {
		t.Errorf("SCIM body status: got %q, want \"501\"", body.Status)
	}
	if body.Detail == nil || *body.Detail != scimNotConfiguredDetail {
		t.Errorf("detail: got %v, want %q", body.Detail, scimNotConfiguredDetail)
	}
}

// 🔒 F33 / INV-A3-38 — THE PIN. Every case above already runs with AuthDebug = true; this one says so
// out loud, and fails the moment someone "fixes the inconsistency" the docs describe.
//
// A port that added the bypass would make ALL THREE of these 200.
func TestRequireScimAuthHasNoAuthDebugBypass(t *testing.T) {
	cfg := testScimConfig(&scimToken, "10.0.0.1")
	if !cfg.AuthDebug {
		t.Fatal("the fixture must have AuthDebug on — that is the whole point of this suite")
	}

	cases := []struct {
		name string
		req  *http.Request
		cfg  scimFixture
		want int
	}{
		{
			name: "unconfigured token still 501s under authDebug",
			req:  scimRequest(false, "10.0.0.1:5555", map[string]string{"X-Forwarded-Proto": "https"}),
			cfg:  scimFixture{token: nil, edges: []string{"10.0.0.1"}},
			want: http.StatusNotImplemented,
		},
		{
			name: "plaintext still 403s under authDebug",
			req:  scimRequest(false, "203.0.113.9:5555", map[string]string{"Authorization": "Bearer " + scimToken}),
			cfg:  scimFixture{token: &scimToken},
			want: http.StatusForbidden,
		},
		{
			name: "a wrong bearer still 401s under authDebug",
			req:  scimRequest(true, "203.0.113.9:5555", map[string]string{"Authorization": "Bearer nope"}),
			cfg:  scimFixture{token: &scimToken},
			want: http.StatusUnauthorized,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := runScimGate(t, scimGates(tc.cfg.token, tc.cfg.edges...), tc.req)
			assertStatus(t, rec, tc.want,
				"PM_AUTH_DEBUG must NOT short-circuit requireScimAuth (F33: the docs are wrong, the code is right)")
		})
	}
}

// scimFixture is a two-field local so the table above reads without four positional arguments. It is
// NOT named `config` because this package imports config.
type scimFixture struct {
	token *string
	edges []string
}

// 🔒 INV-A1-13's ONE EXEMPTION, observable: the gate's bodies are SCIM-shaped, never ApiError-shaped.
// An IdP parses `{"schemas":[…],"status":"403","detail":…}` and has no schema for `{"code":…}`.
func TestScimGateBodiesAreScimShapedNotApiError(t *testing.T) {
	rec := runScimGate(t, scimGates(&scimToken), scimRequest(false, "203.0.113.9:5555", nil))

	var apiErr types.ApiError
	if err := apiErr.UnmarshalJSON(rec.Body.Bytes()); err == nil {
		t.Fatalf("the SCIM gate answered an ApiError envelope: %s", rec.Body.String())
	}

	var body ScimError
	decodeBody(t, rec, &body)
	if len(body.Schemas) != 1 || body.Schemas[0] != ScimErrorSchema {
		t.Errorf("schemas: got %v, want [%s] — encodeDefaults=true always emits the default", body.Schemas, ScimErrorSchema)
	}
	if body.ScimType != nil {
		t.Errorf("scimType must be ABSENT on a gate rejection, got %q", *body.ScimType)
	}
}

// ⚠️ `removePrefix("Bearer ")` is CASE-SENSITIVE while RFC 7235 declares the scheme
// case-insensitive, so a client sending `bearer <tok>` gets 401. Untested in the Kotlin
// (03-identity-scim.md calls it "F33-adjacent"); REPRODUCE + PIN, because it is the difference
// between an IdP that provisions and one that silently 401s forever.
func TestScimBearerPrefixIsCaseSensitive(t *testing.T) {
	for _, header := range []string{"bearer " + scimToken, "BEARER " + scimToken, "Basic " + scimToken} {
		t.Run(header[:strings.IndexByte(header, ' ')], func(t *testing.T) {
			rec := runScimGate(t, scimGates(&scimToken, "10.0.0.1"), scimRequest(false, "10.0.0.1:5555", map[string]string{
				"X-Forwarded-Proto": "https",
				"Authorization":     header,
			}))
			assertStatus(t, rec, http.StatusUnauthorized,
				"only the exact `Bearer ` prefix is stripped — reproduced, not fixed")
		})
	}

	// The trim IS honoured, though, which is what makes a double space work.
	rec := runScimGate(t, scimGates(&scimToken, "10.0.0.1"), scimRequest(false, "10.0.0.1:5555", map[string]string{
		"X-Forwarded-Proto": "https",
		"Authorization":     "Bearer  " + scimToken + " ",
	}))
	assertStatus(t, rec, http.StatusOK, "`.trim()` after removePrefix")
}

// ---------------------------------------------------------------------------------------------
// ScimTlsGateTest.kt — the resolver, unit
// ---------------------------------------------------------------------------------------------

func edgeSet(entries ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, e := range entries {
		m[e] = struct{}{}
	}
	return m
}

// ScimTlsGateTest case 1.
// KT: ScimTlsGateTest.kt#direct https is TLS regardless of the trusted-edge set
func TestResolveScimTLSDirectHTTPSIsTLSRegardlessOfTheTrustedEdgeSet(t *testing.T) {
	if !ResolveScimTLS("https", "203.0.113.9", true, nil, edgeSet()) {
		t.Error("direct https must be TLS")
	}
	if !ResolveScimTLS("HTTPS", "", false, nil, edgeSet()) {
		t.Error("scheme compare is case-insensitive")
	}
}

// ScimTlsGateTest case 2.
// KT: ScimTlsGateTest.kt#direct http with no forwarded header is not TLS
func TestResolveScimTLSDirectHTTPWithNoForwardedHeaderIsNotTLS(t *testing.T) {
	if ResolveScimTLS("http", "10.0.0.1", true, nil, edgeSet("10.0.0.1")) {
		t.Error("plaintext with no header is not TLS")
	}
}

// ScimTlsGateTest case 3.
// KT: ScimTlsGateTest.kt#forwarded proto from a trusted edge is honored
func TestResolveScimTLSForwardedProtoFromATrustedEdgeIsHonored(t *testing.T) {
	https := "https"
	if !ResolveScimTLS("http", "10.0.0.1", true, &https, edgeSet("10.0.0.1")) {
		t.Error("a trusted edge may assert the transport")
	}
	upper := "HTTPS"
	if !ResolveScimTLS("http", "10.0.0.1", true, &upper, edgeSet("10.0.0.1")) {
		t.Error("header compare is case-insensitive")
	}
}

// ScimTlsGateTest case 4 — 🔒 the vulnerability this gate exists to close.
// KT: ScimTlsGateTest.kt#forwardedProtoFromUntrustedPeerIsIgnored
func TestResolveScimTLSForwardedProtoFromUntrustedPeerIsIgnored(t *testing.T) {
	https := "https"
	if ResolveScimTLS("http", "203.0.113.9", true, &https, edgeSet("10.0.0.1")) {
		t.Error("a direct plaintext caller must not pass the gate by setting its own X-Forwarded-Proto")
	}
}

// ScimTlsGateTest case 5.
// KT: ScimTlsGateTest.kt#an empty trusted-edge set trusts no peer
func TestResolveScimTLSAnEmptyTrustedEdgeSetTrustsNoPeer(t *testing.T) {
	https := "https"
	if ResolveScimTLS("http", "10.0.0.1", true, &https, edgeSet()) {
		t.Error("PM_TRUSTED_PROXIES unset means no edge may assert the transport (fail-closed)")
	}
}

// ScimTlsGateTest case 6 — 🔒 INV-A3-40, the rightmost entry.
// KT: ScimTlsGateTest.kt#a multi-hop value takes the rightmost entry
func TestResolveScimTLSAMultiHopValueTakesTheRightmostEntry(t *testing.T) {
	edge := edgeSet("10.0.0.1")
	httpThenHTTPS := "http, https"
	if !ResolveScimTLS("http", "10.0.0.1", true, &httpThenHTTPS, edge) {
		t.Error("the edge appended https, so the request is TLS")
	}
	httpsThenHTTP := "https, http"
	if ResolveScimTLS("http", "10.0.0.1", true, &httpsThenHTTP, edge) {
		t.Error("a client-supplied leading https must not override the edge's own http")
	}
}

// ScimTlsGateTest case 7.
// KT: ScimTlsGateTest.kt#absent or blank forwarded proto is not TLS
func TestResolveScimTLSAbsentOrBlankForwardedProtoIsNotTLS(t *testing.T) {
	edge := edgeSet("10.0.0.1")
	blank, spaces := "", "   "
	for name, v := range map[string]*string{"absent": nil, "empty": &blank, "spaces": &spaces} {
		if ResolveScimTLS("http", "10.0.0.1", true, v, edge) {
			t.Errorf("%s forwarded proto must not be TLS", name)
		}
	}
}

// ScimTlsGateTest case 8.
// KT: ScimTlsGateTest.kt#a null peer never passes on a header alone
func TestResolveScimTLSANullPeerNeverPassesOnAHeaderAlone(t *testing.T) {
	https := "https"
	if ResolveScimTLS("http", "", false, &https, edgeSet("10.0.0.1")) {
		t.Error("no socket peer means no trusted edge")
	}
}

// IsTrustedEdge's CIDR half — the deployment shape (autoscaled LB, k8s ingress) literal entries
// cannot express. Not a Kotlin test case; it covers the branch requireScimAuth reaches through
// isTrustedEdge, which the ScimTlsGateTest cases only exercise literally.
func TestIsTrustedEdgeCIDRBlocks(t *testing.T) {
	cases := []struct {
		peer  string
		block string
		want  bool
	}{
		{"10.10.4.7", "10.10.0.0/16", true},
		{"10.11.4.7", "10.10.0.0/16", false},
		{"10.10.4.7", "10.10.0.0/32", false},
		{"10.10.0.0", "10.10.0.0/32", true},
		{"192.168.1.130", "192.168.1.128/25", true},
		{"192.168.1.127", "192.168.1.128/25", false},
		{"2001:db8::1", "2001:db8::/32", true},
		{"2001:db9::1", "2001:db8::/32", false},
		// 🔒 A family mismatch is NEVER a match: the two address spaces are compared, never coerced.
		// net.ParseIP alone would normalise the v4 peer to a v4-in-v6 form and make this true.
		{"10.10.4.7", "::/0", false},
		// A malformed entry matches nothing rather than everything — a typo must fail closed.
		{"10.10.4.7", "10.10.0.0/notanumber", false},
		{"10.10.4.7", "10.10.0.0/33", false},
		{"10.10.4.7", "not-an-address/16", false},
	}
	for _, tc := range cases {
		if got := IsTrustedEdge(tc.peer, true, edgeSet(tc.block)); got != tc.want {
			t.Errorf("IsTrustedEdge(%q, {%q}) = %v, want %v", tc.peer, tc.block, got, tc.want)
		}
	}

	// The literal match comes first, so a NON-PARSEABLE entry still matches an identical peer
	// string — which is what Ktor's test host relies on when it reports its peer as "localhost".
	if !IsTrustedEdge("localhost", true, edgeSet("localhost")) {
		t.Error("a literal entry must match verbatim before any parsing is attempted")
	}
}

// RequestPeer strips the port Go carries and Ktor does not, and keeps a port-less value verbatim.
func TestRequestPeerStripsThePortButKeepsAPortlessValue(t *testing.T) {
	cases := map[string]struct {
		remote string
		want   string
		ok     bool
	}{
		"ipv4 with port": {"10.0.0.1:5555", "10.0.0.1", true},
		"ipv6 with port": {"[2001:db8::1]:5555", "2001:db8::1", true},
		"no port":        {"localhost", "localhost", true},
		"absent":         {"", "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/probe", nil)
			r.RemoteAddr = tc.remote
			got, ok := RequestPeer(r)
			if got != tc.want || ok != tc.ok {
				t.Errorf("RequestPeer(%q) = (%q, %v), want (%q, %v)", tc.remote, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// ⚠️ Two levels of "rightmost", and this is the outer one: the LAST HEADER INSTANCE, not the first.
// Go's Header.Get returns the first and would honour a value an upstream hop set.
func TestLastHeaderTakesTheLastInstance(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/probe", nil)
	r.Header.Add("X-Forwarded-Proto", "https")
	r.Header.Add("X-Forwarded-Proto", "http")

	got := LastHeader(r, "X-Forwarded-Proto")
	if got == nil || *got != "http" {
		t.Fatalf("LastHeader = %v, want \"http\" — getAll(...).lastOrNull(), not the first instance", got)
	}
	if LastHeader(r, "X-Absent") != nil {
		t.Error("an absent header must be nil, distinct from an empty value")
	}
}
