package mcp

import (
	"net/url"
	"slices"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §2's pure functions. `ForwardedAuthorityTest.kt` (A12) covers `resolveForwardedAuthority` cases
// 1-8 on the Kotlin side; the origin comparison, the audit-record shape and the detail builder have no
// Kotlin unit tests at all.
// ---------------------------------------------------------------------------------------------

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestSameOriginIsStrictInBothDirections is 🔒 INV-A11-6.
func TestSameOriginIsStrictInBothDirections(t *testing.T) {
	resource := mustURL(t, "https://console.example.com/mcp")
	cases := []struct {
		origin string
		want   bool
		why    string
	}{
		{"https://console.example.com", true, "the bare matching origin"},
		{"HTTPS://CONSOLE.EXAMPLE.COM", true, "scheme and host compare case-insensitively"},
		{"https://console.example.com:443", true, "the explicit default port is the default port"},
		{"http://console.example.com", false, "scheme must match"},
		{"https://evil.example.com", false, "host must match"},
		{"https://console.example.com:8443", false, "🔒 the PORT is enforced here even though gate 1 ignores it"},
		{"https://user@console.example.com", false, "userInfo must be absent"},
		{"https://console.example.com/", false, "a trailing slash is a PATH; a browser never sends one"},
		{"https://console.example.com/mcp", false, "a path must be absent"},
		{"https://console.example.com?q=1", false, "a query must be absent"},
		{"https://console.example.com#f", false, "a fragment must be absent"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			if got := sameOrigin(mustURL(t, c.origin), resource); got != c.want {
				t.Errorf("sameOrigin(%q) = %v, want %v", c.origin, got, c.want)
			}
		})
	}

	// The http default is 80, and the `else 80` arm is unconditional — a non-http scheme with no port
	// also defaults to 80. Unreachable for a browser Origin, reproduced anyway.
	plain := mustURL(t, "http://localhost/mcp")
	if !sameOrigin(mustURL(t, "http://localhost:80"), plain) {
		t.Error("http://localhost:80 should match an http resource on the default port")
	}
	if effectivePort(mustURL(t, "ws://x")) != "80" {
		t.Error("effectivePort's unconditional `else 80` arm was not reproduced")
	}
}

// TestResolveForwardedAuthority is A12's function, exercised through A11's only call site.
//
// 🔒 INV-A12-1 — an X-Forwarded-Host is honored ONLY from a peer in PM_TRUSTED_PROXIES, so a direct
// caller cannot assert its way past the host gate.
// 🔒 INV-A12-8 — HOST ONLY, never a port.
// 🔒 INV-A12-9 — the fallback is directHost, not nil.
//
// All EIGHT of ForwardedAuthorityTest.kt's ForwardedAuthorityTest cases land in this one table, each on
// the row named below; the markers sit here rather than beside the rows because the rows are data and
// `go test -run` addresses the subtests by their table names. The suite's second class,
// TrustedEdgeCidrTest, is ported in internal/httpapi/requesterip_test.go.
//
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.with no trusted edge the direct host is used — row "an empty trusted set trusts nobody"
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.forwardedHostFromAnUntrustedPeerIsIgnored — row "an untrusted peer's header is ignored"; the DNS-rebinding case
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.a trusted edge's forwarded host supersedes the proxy's own authority — row "a trusted peer's header supersedes the direct host"
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.an edge that preserves the client host needs no forwarded header — row "INV-A12-9: a trusted peer with NO header falls back to the direct host"
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.aPortIsNeverPartOfTheResolvedHost — rows "INV-A12-8: a port is stripped, not compared" (8443) and "…the default 443 port is stripped the same way", the Kotlin's two assertions
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.the rightmost entry of a multi-hop forwarded host is taken — row "the RIGHTMOST entry wins"
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.a bracketed IPv6 authority is unwrapped without being split at its own colons — rows "an IPv6 literal is unbracketed" and "…with a port keeps the address"
// KT: ForwardedAuthorityTest.kt#ForwardedAuthorityTest.a blank or non-numeric-port forwarded host falls back rather than resolving a partial authority — rows "a blank header falls back too" and "a non-numeric suffix is not a port"
func TestResolveForwardedAuthority(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.1": {}}
	cases := []struct {
		name      string
		direct    string
		peer      string
		present   bool
		forwarded *string
		trusted   map[string]struct{}
		want      string
	}{
		{"an untrusted peer's header is ignored", "backend.internal", "203.0.113.9", true,
			strp("console.example.com"), trusted, "backend.internal"},
		{"no peer at all is never trusted", "backend.internal", "", false,
			strp("console.example.com"), trusted, "backend.internal"},
		{"a trusted peer's header supersedes the direct host", "backend.internal", "10.0.0.1", true,
			strp("console.example.com"), trusted, "console.example.com"},
		{"INV-A12-9: a trusted peer with NO header falls back to the direct host", "backend.internal", "10.0.0.1", true,
			nil, trusted, "backend.internal"},
		{"a blank header falls back too", "backend.internal", "10.0.0.1", true,
			strp("   "), trusted, "backend.internal"},
		{"the RIGHTMOST entry wins", "backend.internal", "10.0.0.1", true,
			strp("spoofed.example, console.example.com"), trusted, "console.example.com"},
		{"INV-A12-8: a port is stripped, not compared", "backend.internal", "10.0.0.1", true,
			strp("console.example.com:8443"), trusted, "console.example.com"},
		// aPortIsNeverPartOfTheResolvedHost asserts the DEFAULT https port too — 443 is stripped by the
		// same all-digits rule as 8443, with no default-port special case anywhere in the path.
		{"INV-A12-8: the default 443 port is stripped the same way", "backend.internal", "10.0.0.1", true,
			strp("console.example.com:443"), trusted, "console.example.com"},
		{"an IPv6 literal is unbracketed", "backend.internal", "10.0.0.1", true,
			strp("[::1]"), trusted, "::1"},
		{"an IPv6 literal with a port keeps the address", "backend.internal", "10.0.0.1", true,
			strp("[::1]:8443"), trusted, "::1"},
		// 🔴 REPRODUCED DEFECT, PINNED. An UNBRACKETED IPv6 literal IS shredded. RequesterIp.kt's
		// port test is `lastColon > lastIndexOf(']')` — with no bracket at all that is `1 > -1`, and
		// `"::1".drop(2)` is the all-digit `"1"`, so `::1` parses as host `:` port `1`. The bracket
		// guard only protects a BRACKETED literal. Harmless in practice (a conforming edge brackets
		// what it appends, and gate 1 then fails closed on the mismatch) but it is observable
		// behaviour, so it is reproduced rather than "fixed" — see 00-INDEX.md's PORT POLICY.
		{"an unbracketed IPv6 literal is shredded at its last colon (reproduced defect)",
			"backend.internal", "10.0.0.1", true, strp("::1"), trusted, ":"},
		{"a trailing colon is not a port", "backend.internal", "10.0.0.1", true,
			strp("console.example.com:"), trusted, "console.example.com:"},
		{"a non-numeric suffix is not a port", "backend.internal", "10.0.0.1", true,
			strp("console.example.com:abc"), trusted, "console.example.com:abc"},
		{"an empty trusted set trusts nobody", "backend.internal", "10.0.0.1", true,
			strp("console.example.com"), map[string]struct{}{}, "backend.internal"},
		{"a CIDR entry matches", "backend.internal", "10.0.0.7", true,
			strp("console.example.com"), map[string]struct{}{"10.0.0.0/24": {}}, "console.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveForwardedAuthority(c.direct, c.peer, c.present, c.forwarded, c.trusted)
			if got != c.want {
				t.Errorf("resolveForwardedAuthority = %q, want %q", got, c.want)
			}
		})
	}
}

// TestDirectHostParsesIPv6Correctly is the 🔴 DELIBERATE, RECORDED DIVERGENCE.
//
// Ktor's `host()` splits a direct `Host: [::1]` at the literal's FIRST colon and yields `[`, so on the
// JVM an IPv6-literal PM_MCP_RESOURCE is reachable only behind a trusted edge — KNOWN_LIMITATIONS.md:
// 265-271, attributed there to Ktor rather than to proxy-monster. The port uses the same bracket-aware
// parse as the forwarded path, which makes that limitation disappear.
//
// It is NOT a widening of authority: gate 1 still demands equality with the CONFIGURED resource host.
// It only stops rejecting the host the operator configured.
func TestDirectHostParsesIPv6Correctly(t *testing.T) {
	cases := map[string]string{
		"console.example.com":      "console.example.com",
		"console.example.com:8443": "console.example.com",
		"[::1]":                    "::1",
		"[::1]:8443":               "::1",
		"[2001:db8::1]:443":        "2001:db8::1",
		"localhost":                "localhost",
	}
	for in, want := range cases {
		if got := directHost(in); got != want {
			t.Errorf("directHost(%q) = %q, want %q", in, got, want)
		}
	}
	// The behaviour the Kotlin has and this does not, stated as an assertion so the divergence is
	// visible in the suite rather than only in a comment.
	if directHost("[::1]") == "[" {
		t.Error("the port reproduced Ktor's first-colon shred; see this test's doc comment")
	}
}

func TestUnbracketOnlyStripsAMatchedPair(t *testing.T) {
	cases := map[string]string{
		"[::1]": "::1",
		"[::1":  "[::1",
		"::1]":  "::1]",
		"::1":   "::1",
		"[]":    "",
		"":      "",
	}
	for in, want := range cases {
		if got := unbracket(in); got != want {
			t.Errorf("unbracket(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProtectedResourceMetadataURIKeepsTheResourcePort(t *testing.T) {
	cases := map[string]string{
		"https://console.example.com/mcp":      "https://console.example.com/.well-known/oauth-protected-resource/mcp",
		"https://console.example.com:8443/mcp": "https://console.example.com:8443/.well-known/oauth-protected-resource/mcp",
		"http://localhost/mcp":                 "http://localhost/.well-known/oauth-protected-resource/mcp",
		"http://[::1]/mcp":                     "http://[::1]/.well-known/oauth-protected-resource/mcp",
		// Query and fragment on the resource are dropped.
		"https://console.example.com/mcp?x=1#f": "https://console.example.com/.well-known/oauth-protected-resource/mcp",
	}
	for in, want := range cases {
		if got := protectedResourceMetadataURI(mustURL(t, in)); got != want {
			t.Errorf("protectedResourceMetadataURI(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMutationDetailIsAFixedKeyListWithNoTrailingSpace pins the audit `detail` builder.
//
// 🔒 The fixed key list is a data-exposure boundary: `cedarSrc`, `email` and `displayName` are NOT on
// it, so a policy body or an email address cannot reach the audit trail through this path.
func TestMutationDetailIsAFixedKeyListWithNoTrailingSpace(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args string
		want string
	}{
		{
			// ⚠️ joinToString's `prefix = " "` is applied BEFORE isNotBlank, so an argument-less call
			// produces the bare tool name — no trailing space. A naive `tool + " " + joined` would
			// emit one.
			"no target keys means the bare tool name",
			"list_roles", `{}`, "list_roles",
		},
		{
			"one target key",
			"create_role", `{"name":"analyst"}`, "create_role name=analyst",
		},
		{
			"keys appear in the FIXED list's order, not the argument's",
			"set_column_classification",
			`{"column":"rrn","table":"users","datasource":"warehouse"}`,
			"set_column_classification datasource=warehouse,table=users,column=rrn",
		},
		{
			"🔒 cedarSrc is NOT a target key and never reaches the trail",
			"create_policy",
			`{"name":"p","cedarSrc":"permit(principal, action, resource);"}`,
			"create_policy name=p",
		},
		{
			"🔒 email and displayName are NOT target keys",
			"create_user",
			`{"principal":"a@b.c","email":"secret@example.com","displayName":"Real Name"}`,
			"create_user principal=a@b.c",
		},
		{
			"a non-string value is skipped, not rendered",
			"set_column_classification",
			`{"datasource":{"invalid":true},"table":"users","column":"rrn"}`,
			"set_column_classification table=users,column=rrn",
		},
		{
			"an empty string IS a value",
			"create_role", `{"name":""}`, "create_role name=",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mutationDetail(c.tool, mustArgs(t, c.args)); got != c.want {
				t.Errorf("mutationDetail = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSafeDatasourceNamesTheRealDatasourceForExactlyTwoTools is the audit-scoping guard.
//
// 🔒 `audit_event.datasource` is a scoping column the console filters on. Letting any tool set it from
// an argument would let a caller choose whose datasource trail their action appears in.
func TestSafeDatasourceNamesTheRealDatasourceForExactlyTwoTools(t *testing.T) {
	withDS := mustArgs(t, `{"datasource":"warehouse"}`)
	for _, c := range Entries {
		got := safeDatasource(c, withDS)
		want := "control-plane"
		if c.ToolName == "set_column_classification" || c.ToolName == "clear_column_classification" {
			want = "warehouse"
		}
		if got != want {
			t.Errorf("%s: safeDatasource = %q, want %q", c.ToolName, got, want)
		}
	}
	// A blank or non-string datasource falls back rather than writing an empty scope.
	set := ByName["set_column_classification"]
	for _, raw := range []string{`{}`, `{"datasource":""}`, `{"datasource":"  "}`, `{"datasource":7}`} {
		if got := safeDatasource(set, mustArgs(t, raw)); got != "control-plane" {
			t.Errorf("safeDatasource(%s) = %q, want control-plane", raw, got)
		}
	}
}

// TestTheAuditRecordShapeIsTheOneMcpServerDbTestQueriesBy pins every field the Kotlin suite selects on.
func TestTheAuditRecordShapeIsTheOneMcpServerDbTestQueriesBy(t *testing.T) {
	ip := "203.0.113.9"
	rc := RequestContext{Principal: "a@b.c", ClientID: "https://client.example/mcp.json", RequesterIP: &ip}
	rec := auditRecord(rc, ByName["create_role"], []string{"zeta", "alpha"},
		"control-plane", "create_role name=r", types.DecisionAllow, "ALLOW")

	if rec.Statement != "[MCP create_role]" {
		t.Errorf("statement = %q, want [MCP create_role] — the suites select MCP rows by this literal", rec.Statement)
	}
	if rec.Channel == nil || *rec.Channel != "mcp" {
		t.Errorf("channel = %v, want mcp", rec.Channel)
	}
	if rec.AuthzAction == nil || *rec.AuthzAction != "admin.policies" {
		t.Errorf("authzAction = %v, want admin.policies", rec.AuthzAction)
	}
	if rec.AuthzResource == nil || *rec.AuthzResource != `System::"system"` {
		t.Errorf("authzResource = %v, want System::\"system\"", rec.AuthzResource)
	}
	if rec.Outcome == nil || *rec.Outcome != "ALLOW" {
		t.Errorf("outcome = %v", rec.Outcome)
	}
	if rec.ClientAddr == nil || *rec.ClientAddr != ip {
		t.Errorf("clientAddr = %v, want %q", rec.ClientAddr, ip)
	}
	// 🔒 roles.sorted() — the row is byte-stable across runs, which the A8 hash chain needs.
	if !slices.Equal(rec.Roles, []string{"alpha", "zeta"}) {
		t.Errorf("roles = %v, want them SORTED", rec.Roles)
	}
	if rec.Kind != types.DefaultAuditKind {
		t.Errorf("kind = %q, want %q", rec.Kind, types.DefaultAuditKind)
	}
	// The five list fields default to [] rather than nil, so the row marshals as the Kotlin's.
	if rec.EffectiveNamespace == nil || rec.MaskedColumns == nil || rec.PIITouched == nil || rec.ContextTags == nil {
		t.Error("a list field is nil; NewAuditEvent should have materialised all of them as []")
	}
	// An empty role set stays empty rather than becoming nil.
	empty := auditRecord(rc, ByName["create_role"], nil, "control-plane", "d", types.DecisionDeny, "x")
	if empty.Roles == nil || len(empty.Roles) != 0 {
		t.Errorf("roles for an unresolved denial = %v, want an empty slice (INV-A11-9)", empty.Roles)
	}
}

// TestTheAdvisoryLockSeparatorIsTheSixCharacterLiteralNotANulByte is 🔴 F20.
//
// A one-character "tidy" of the double backslash changes which calls serialize against each other,
// silently, across a rolling cutover. No other test in this package would notice.
func TestTheAdvisoryLockSeparatorIsTheSixCharacterLiteralNotANulByte(t *testing.T) {
	if len(advisoryLockSeparator) != 6 {
		t.Fatalf("separator is %d bytes (%q); F20 says it is the six-character literal",
			len(advisoryLockSeparator), advisoryLockSeparator)
	}
	if advisoryLockSeparator != "\\u0000" {
		t.Errorf("separator = %q, want the six characters backslash-u-0000", advisoryLockSeparator)
	}
	if strings_Contains(advisoryLockSeparator, "\x00") {
		t.Error("the separator contains a real NUL byte — F20 says it must NOT")
	}
}

func strings_Contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

// TestBearerTokenParsing pins the three reproduced details of the Authorization header split.
func TestBearerTokenParsing(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc", // RFC 6750: the scheme is case-insensitive
		"BEARER abc":  "abc",
		"Bearer  abc": " abc", // split at the FIRST space; the extra one is carried, and will not match
		"Bearer ":     "",     // blank remainder is NO token, not a lookup of ""
		"Bearer    ":  "",
		"Basic abc":   "",
		"abc":         "",
		"":            "",
		"Bearer a b":  "a b",
		"Bearer\tabc": "", // a tab is not the space the scheme test requires
	}
	for header, want := range cases {
		r := newRequest(header)
		if got := bearerToken(r); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}

// TestTheAuthorizerNeverConsultsCedarWhenTheScopeIsMissing is 🔒 INV-A11-7's ORDERING half and
// INV-A11-9's empty-role-set half, without a database.
func TestTheAuthorizerNeverConsultsCedarWhenTheScopeIsMissing(t *testing.T) {
	asked := false
	rolesResolved := false
	a := NewAuthorizer(false,
		rolesFunc(func(string) ([]string, error) { rolesResolved = true; return []string{"system:admin"}, nil }),
		cedarFunc(func(string, []string, authz.AuthzAction, authz.AuthzResource, authz.AuthzContext) authz.AuthzDecision {
			asked = true
			return authz.AuthzDecision{Allowed: true}
		}))

	rc := RequestContext{Principal: "a@b.c", Scopes: []string{ScopeRead}}
	_, err := a.Authorize(t.Context(), rc, ByName["create_role"])

	var authErr *authorizationError
	if !asError(err, &authErr) {
		t.Fatalf("Authorize = %v, want an authorizationError", err)
	}
	if authErr.err.Code != "mcp.insufficient_scope" {
		t.Errorf("code = %q, want mcp.insufficient_scope", authErr.err.Code)
	}
	if authErr.err.Params["scope"] != ScopePoliciesWrite {
		t.Errorf("params = %v, want scope=%s", authErr.err.Params, ScopePoliciesWrite)
	}
	// 🔒 INV-A11-9 — the roles are EMPTY because they were never resolved, and the audit row must be
	// honest about that.
	if len(authErr.roles) != 0 {
		t.Errorf("roles = %v, want empty", authErr.roles)
	}
	if rolesResolved {
		t.Error("roles were resolved for a request that failed the scope check")
	}
	if asked {
		t.Error("🔒 Cedar was consulted for a request that failed the scope check")
	}
}

// TestABroadScopeCannotWidenCedarAuthority is 🔒 INV-A11-7's SUFFICIENCY half: holding the write scope
// gets you to Cedar and no further.
func TestABroadScopeCannotWidenCedarAuthority(t *testing.T) {
	a := NewAuthorizer(false,
		rolesFunc(func(string) ([]string, error) { return []string{"reader"}, nil }),
		cedarFunc(func(string, []string, authz.AuthzAction, authz.AuthzResource, authz.AuthzContext) authz.AuthzDecision {
			return authz.Deny("no matching permit")
		}))
	rc := RequestContext{Principal: "a@b.c", Scopes: []string{ScopeRead, ScopePoliciesWrite, ScopeIdentityWrite}}
	_, err := a.Authorize(t.Context(), rc, ByName["create_role"])

	var authErr *authorizationError
	if !asError(err, &authErr) {
		t.Fatalf("Authorize = %v, want an authorizationError", err)
	}
	if authErr.err.Code != "common.forbidden" {
		t.Errorf("code = %q, want common.forbidden", authErr.err.Code)
	}
	if authErr.err.Params["detail"] != "no matching permit" {
		t.Errorf("detail = %q, want Cedar's reason verbatim", authErr.err.Params["detail"])
	}
	// 🔒 The RESOLVED roles ride along, unlike the scope failure's empty set.
	if !slices.Equal(authErr.roles, []string{"reader"}) {
		t.Errorf("roles = %v, want [reader]", authErr.roles)
	}
}

// TestTheAuthorizerBuildsAnMcpChannelContextWithNoTags pins A11 §3's flagged consequence.
//
// 🔒 MCP IS A TAG-FREE CHANNEL: `authorizeAs` is called with a hand-built context, so no context.tags
// are derived and a tag-conditioned policy never fires here. §11 Q1.
func TestTheAuthorizerBuildsAnMcpChannelContextWithNoTags(t *testing.T) {
	var seen authz.AuthzContext
	ip := "198.51.100.4"
	a := NewAuthorizer(false,
		rolesFunc(func(string) ([]string, error) { return []string{"admin"}, nil }),
		cedarFunc(func(_ string, _ []string, _ authz.AuthzAction, _ authz.AuthzResource, c authz.AuthzContext) authz.AuthzDecision {
			seen = c
			return authz.AuthzDecision{Allowed: true}
		}))
	rc := RequestContext{Principal: "a@b.c", Scopes: []string{ScopeRead}, RequesterIP: &ip}
	if _, err := a.Authorize(t.Context(), rc, ByName["list_roles"]); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if seen.Channel == nil || *seen.Channel != "mcp" {
		t.Errorf("channel = %v, want mcp", seen.Channel)
	}
	if seen.RequesterIP == nil || *seen.RequesterIP != ip {
		t.Errorf("requesterIp = %v, want %q", seen.RequesterIP, ip)
	}
	if len(seen.Tags) != 0 {
		t.Errorf("tags = %v; MCP is a tag-free channel (§11 Q1)", seen.Tags)
	}
	if len(seen.NetworkZones) != 0 {
		t.Errorf("networkZones = %v, want none", seen.NetworkZones)
	}
}

// TestAuthDebugSkipsCedarButStillEnforcesTheScope is INV-A2-16's shape on this surface: the dev bypass
// prevents Cedar from being REACHED, and it does not turn the OAuth scope check off.
func TestAuthDebugSkipsCedarButStillEnforcesTheScope(t *testing.T) {
	asked := false
	a := NewAuthorizer(true,
		rolesFunc(func(string) ([]string, error) { return []string{"whoever"}, nil }),
		cedarFunc(func(string, []string, authz.AuthzAction, authz.AuthzResource, authz.AuthzContext) authz.AuthzDecision {
			asked = true
			return authz.Deny("would have denied")
		}))
	rc := RequestContext{Principal: "a@b.c", Scopes: []string{ScopePoliciesWrite}}
	roles, err := a.Authorize(t.Context(), rc, ByName["create_role"])
	if err != nil {
		t.Fatalf("authDebug should allow: %v", err)
	}
	if asked {
		t.Error("Cedar was reached under authDebug")
	}
	if !slices.Equal(roles, []string{"whoever"}) {
		t.Errorf("roles = %v; they are still resolved under authDebug (they go on the audit row)", roles)
	}
	// The scope check still bites.
	if _, err := a.Authorize(t.Context(), RequestContext{Principal: "a@b.c"}, ByName["create_role"]); err == nil {
		t.Error("authDebug turned off the OAuth scope check")
	}
}
