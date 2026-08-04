package httpapi

// HttpRequesterIpResolutionTest.kt — 11 cases — and ForwardedAuthorityTest.kt's second class,
// TrustedEdgeCidrTest — 7 cases.
//
// Both suites had NOTHING to map to before this file, because the functions under test were the
// unported half of RequesterIp.kt (trustededge.go's TODO(A12) listed them by name). requesterip.go is
// that port; this is its suite.
//
// The core invariant across both is the anti-spoof one (docs/authz-context.md, "server-attested, never
// client-asserted"): `X-Forwarded-For` speaks for the client ONLY behind a configured trusted edge, and
// even then only its RIGHTMOST entry — never falling back to the edge's own address.
//
// ---------------------------------------------------------------------------------------------
// WHERE THE DebugRequesterIpDbTest CONSUMPTION CASES LIVE NOW.
//
// [RequestRequesterIP] is only the peer/header half of Kotlin's `ApplicationCall.httpRequesterIp`. Its
// FIRST act — under PM_AUTH_DEBUG a web session's stored `debug_requester_ip` REPLACES the observed
// peer — needs a session read, so it is [Gates.HTTPRequesterIP] rather than a free function, and the
// two cases that assert through it are in internal/app where `/auth/debug` can actually mint the row:
// TestADebugLoginsSimulatedAddressReplacesTheObservedPeer and
// TestTheStoredSimulatedAddressIsInertOnceTheBypassIsOff. Both were KT-DEFER here until A12 landed.
//
// They deliberately observe at the RESOLVER, which is the Kotlin's own stated requirement: the
// assertions read "the ONE resolver every HTTP-path decision goes through … rather than an inner
// helper — the substitution is only worth anything if it reaches that resolver, and a helper-level test
// would stay green if the wiring into it were deleted."
//
// Also covered: the STORAGE and read-back of the simulated address (internal/app
// TestADebugLoginStoresAndReportsAValidSimulatedAddress), the 400 rejection and its "leaves nothing
// behind" ordering (TestARefusedSimulatedAddressLeavesNothingBehind), and the full sixteen-literal
// accept/reject corpus (storableip_test.go + internal/authz/ip_test.go).
//
// KT-DEFER: DebugRequesterIpDbTest.kt#a simulated address changes a real Cedar decision through the derived tag — the one still open. httpAuthzContext now exists and internal/access/elevationcontext_db_test.go already drives real two-pass tag derivation over Cedar, so this is no longer BLOCKED, only unwritten: it needs a debug-login-minted simulated address carried into a tag-gated Cedar decision, which crosses internal/app's `/auth/debug` fixture and internal/access's policy fixture. Deferred as fixture work, not as a missing production path.
// ---------------------------------------------------------------------------------------------

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// kotlinTrustedEdge is the Kotlin's `private val trustedEdge = setOf("10.0.0.9")`.
func kotlinTrustedEdge() map[string]struct{} { return edgeSet("10.0.0.9") }

// resolved renders the resolver's answer so an absent value is distinguishable from "" in a failure
// message — the distinction INV-A2-8 makes load-bearing.
func resolved(peer string, xff *string, trusted map[string]struct{}) string {
	got := ResolveHTTPRequesterIP(peer, true, xff, trusted)
	if got == nil {
		return "<nil>"
	}
	return *got
}

// resolvedNoPeer is the Kotlin's `peerAddress = null` arm.
func resolvedNoPeer(xff *string, trusted map[string]struct{}) string {
	got := ResolveHTTPRequesterIP("", false, xff, trusted)
	if got == nil {
		return "<nil>"
	}
	return *got
}

func xffOf(v string) *string { return &v }

// ---------------------------------------------------------------------------------------------
// HttpRequesterIpResolutionTest
// ---------------------------------------------------------------------------------------------

// TestAnUntrustedPeersXFFIsIgnoredEntirely is case 1, and it is THE security case of the suite.
//
// 🔒 Both halves matter. With NO trusted proxies configured the header is never honored — that is the
// default posture, so a fresh deployment cannot be spoofed. With a trusted edge configured but a
// DIFFERENT peer connecting, the header is still ignored: being on the list is what buys the header,
// not the existence of a list.
//
// KT: HttpRequesterIpResolutionTest.kt#an untrusted peer's X-Forwarded-For is ignored entirely — the peer itself is used
func TestAnUntrustedPeersXFFIsIgnoredEntirely(t *testing.T) {
	xff := xffOf("203.0.113.5")
	if got := resolved("192.0.2.10", xff, edgeSet()); got != "192.0.2.10" {
		t.Errorf("no trusted proxies configured: got %q, want the PEER 192.0.2.10 — the XFF must never be honored", got)
	}
	if got := resolved("192.0.2.10", xff, kotlinTrustedEdge()); got != "192.0.2.10" {
		t.Errorf("peer not in trustedProxies: got %q, want the PEER 192.0.2.10", got)
	}
}

// TestATrustedPeersRightmostXFFEntryIsHonored is case 2 — the deployment the whole mechanism exists
// for: behind an edge the socket peer is the load balancer, and only the header carries the client.
//
// KT: HttpRequesterIpResolutionTest.kt#a trusted peer's rightmost XFF entry is honored
func TestATrustedPeersRightmostXFFEntryIsHonored(t *testing.T) {
	if got := resolved("10.0.0.9", xffOf("203.0.113.5"), kotlinTrustedEdge()); got != "203.0.113.5" {
		t.Errorf("got %q, want 203.0.113.5", got)
	}
}

// TestMultiHopXFFTakesTheRightmostEntry is case 3.
//
// 🔒 THE RIGHTMOST, NOT THE LEFTMOST. Everything left of the rightmost entry was supplied by whatever
// sits upstream of the trusted edge — the client, or another untrusted hop — and is not attested here.
// Taking the leftmost is the classic X-Forwarded-For bug: it hands the client full control of the value
// while still looking like it "reads the client IP".
//
// KT: HttpRequesterIpResolutionTest.kt#multi-hop XFF takes the RIGHTMOST entry — the one the trusted edge itself appended
func TestMultiHopXFFTakesTheRightmostEntry(t *testing.T) {
	got := resolved("10.0.0.9", xffOf("203.0.113.5, 198.51.100.7"), kotlinTrustedEdge())
	if got != "198.51.100.7" {
		t.Errorf("got %q, want the RIGHTMOST entry 198.51.100.7 (the leftmost, 203.0.113.5, is client-supplied)", got)
	}
}

// TestWhitespaceAroundAMultiHopXFFEntryIsTrimmed is case 4. Real proxies write `a, b` and some write
// `a ,  b  `; an untrimmed entry fails Cedar's parse and the address would go absent for a purely
// cosmetic reason.
//
// KT: HttpRequesterIpResolutionTest.kt#whitespace around a multi-hop XFF entry is trimmed
func TestWhitespaceAroundAMultiHopXFFEntryIsTrimmed(t *testing.T) {
	got := resolved("10.0.0.9", xffOf("203.0.113.5 ,  198.51.100.7  "), kotlinTrustedEdge())
	if got != "198.51.100.7" {
		t.Errorf("got %q, want 198.51.100.7", got)
	}
}

// TestAnInvalidRightmostXFFEntryNeverFallsBackToTheEdge is case 5.
//
// 🔒 THE MOST TEMPTING WRONG FIX IN THE AREA. "The header was garbage, so use the peer" attributes the
// request to the LOAD BALANCER — whose address sits inside any plausible trusted CIDR, so a
// network-gated policy would fire for every request behind the edge. Absent is the only safe answer.
//
// The second row is the sharper one: a WELL-FORMED entry to the left does not rescue a broken
// rightmost. A resolver that scanned for "the first parseable entry" would return 203.0.113.5 here and
// let a client choose its own requester_ip by appending garbage.
//
// KT: HttpRequesterIpResolutionTest.kt#an invalid rightmost XFF entry from a trusted peer resolves to null — never falls back to the edge's own IP
func TestAnInvalidRightmostXFFEntryNeverFallsBackToTheEdge(t *testing.T) {
	for _, xff := range []string{"not-an-ip", "203.0.113.5, garbage"} {
		if got := resolved("10.0.0.9", xffOf(xff), kotlinTrustedEdge()); got != "<nil>" {
			t.Errorf("xff %q resolved to %q, want <nil> — the edge is not the requester and a left-hand "+
				"entry must not be salvaged", xff, got)
		}
	}
}

// TestAMalformedRightmostXFFEntryIsNotSalvaged is case 6 — the STRICT stripper, and the reason
// [StripToBareIP] exists separately from query.ParseRequesterIp.
//
// ⚠️ Every one of these five would be SALVAGED into a valid-looking IP by the permissive wire-path
// stripper. That one parses Netty's always-well-formed SocketAddress.toString(); an XFF entry is
// attacker-adjacent, so truncating `[203.0.113.5]junk` to `203.0.113.5` would let a client smuggle a
// chosen address past a shape check. The two strippers must not be unified.
//
// KT: HttpRequesterIpResolutionTest.kt#a malformed rightmost XFF entry is not salvaged into a valid IP — it resolves to null
func TestAMalformedRightmostXFFEntryIsNotSalvaged(t *testing.T) {
	cases := map[string]string{
		"[203.0.113.5":           "unclosed bracket",
		"[203.0.113.5]junk":      "trailing garbage after the closing bracket",
		"203.0.113.5:not-a-port": "non-numeric port",
		"203.0.113.5:":           "empty port",
		"[2001:db8::1]:junk":     "non-numeric port on a bracketed v6",
	}
	for xff, why := range cases {
		if got := resolved("10.0.0.9", xffOf(xff), kotlinTrustedEdge()); got != "<nil>" {
			t.Errorf("%s: xff %q resolved to %q, want <nil> — a malformed entry must not be salvaged", why, xff, got)
		}
	}
}

// TestABlankOrAbsentXFFFromATrustedPeerResolvesToNil is case 7.
//
// 🔒 Once the peer is known to be a trusted edge, its socket address is the EDGE and never the end
// client. With no attested client in the header, requester_ip must be ABSENT (fail-closed) — not the
// edge's own IP. This is the same claim as case 5 arrived at from the other direction: there, the
// header was present and broken; here it is simply not there.
//
// KT: HttpRequesterIpResolutionTest.kt#a blank or absent XFF from a trusted peer resolves to null — the edge's own address is not the requester
func TestABlankOrAbsentXFFFromATrustedPeerResolvesToNil(t *testing.T) {
	if got := resolved("10.0.0.9", nil, kotlinTrustedEdge()); got != "<nil>" {
		t.Errorf("an ABSENT xff behind a trusted edge resolved to %q, want <nil>", got)
	}
	if got := resolved("10.0.0.9", xffOf("   "), kotlinTrustedEdge()); got != "<nil>" {
		t.Errorf("a BLANK xff behind a trusted edge resolved to %q, want <nil>", got)
	}
}

// TestANullOrUnparseablePeerResolvesToNil is case 8: fail closed, never throw. The Kotlin's own words —
// "Never throws" — become "never panics" here, and both rows are the arms that would.
//
// KT: HttpRequesterIpResolutionTest.kt#a null or unparseable peer resolves to null — fail closed, never throws
func TestANullOrUnparseablePeerResolvesToNil(t *testing.T) {
	if got := resolvedNoPeer(nil, kotlinTrustedEdge()); got != "<nil>" {
		t.Errorf("no peer at all resolved to %q, want <nil>", got)
	}
	if got := resolved("not-an-ip", nil, edgeSet()); got != "<nil>" {
		t.Errorf("an unparseable peer resolved to %q, want <nil>", got)
	}
}

// TestAWellFormedPortIsStrippedToTheBareAddress is case 9. The strict stripper still ACCEPTS a
// well-formed `host:port` / `[v6]:port`, so an edge that appends a port does not spuriously lose the
// address — the strictness is about malformed shapes, not about ports.
//
// KT: HttpRequesterIpResolutionTest.kt#a peer or XFF entry carrying a well-formed port is stripped to the bare address
func TestAWellFormedPortIsStrippedToTheBareAddress(t *testing.T) {
	if got := resolved("192.0.2.10:54321", nil, edgeSet()); got != "192.0.2.10" {
		t.Errorf("a direct peer with a port resolved to %q, want 192.0.2.10", got)
	}
	if got := resolved("10.0.0.9", xffOf("[2001:db8::1]:443"), kotlinTrustedEdge()); got != "2001:db8::1" {
		t.Errorf("a bracketed v6 XFF entry with a port resolved to %q, want 2001:db8::1", got)
	}
}

// TestAnUntrustedPeerThatEqualsAnEntryOnlyAfterCleaningDoesNotMatch is case 10, and it is the subtlest
// case in the suite.
//
// The trusted-proxies test runs on the RAW peer string, BEFORE any port stripping — "exact socket-peer
// string match". So a peer of `10.0.0.9:12345` does NOT match the configured entry `10.0.0.9`, the
// header is ignored, and the answer is the (port-stripped) PEER — never the untrusted XFF value.
//
// ⚠️ Two plausible "tidyings" both break it in opposite directions. Cleaning the peer BEFORE the trust
// test would trust it and honor an attacker's header. Skipping the clean afterwards would make the
// answer `10.0.0.9:12345`, which fails Cedar's parse and drops requester_ip entirely.
//
// KT: HttpRequesterIpResolutionTest.kt#an untrusted peer that happens to equal an entry after cleaning does not match on the raw (uncleaned) form
func TestAnUntrustedPeerThatEqualsAnEntryOnlyAfterCleaningDoesNotMatch(t *testing.T) {
	got := resolved("10.0.0.9:12345", xffOf("203.0.113.5"), kotlinTrustedEdge())
	if got == "203.0.113.5" {
		t.Fatal("the XFF was honored from a peer that only matches the trusted entry AFTER cleaning — the " +
			"trust test must run on the RAW peer string")
	}
	if got != "10.0.0.9" {
		t.Errorf("got %q, want the port-stripped PEER 10.0.0.9", got)
	}
}

// TestRequestRequesterIPHonorsXFFOnlyWhenThePeerIsTrusted is case 11, the ApplicationCall wiring.
//
// The Kotlin runs it on Ktor's test host, whose socket peer is the fixed literal "localhost", and
// trusts that literal. Go's httptest server gives a REAL socket peer, so the equivalent is to trust
// 127.0.0.1 — which additionally exercises [RequestPeer]'s port stripping, since Go's RemoteAddr
// carries a port where Ktor's does not.
//
// The untrusted leg asserts the Kotlin's exact reasoning: the header is ignored AND the peer is not a
// usable answer either (there it is the non-IP "localhost"; here 127.0.0.1 IS a valid address, so the
// untrusted leg is asserted as "the peer, not the header" rather than as nil).
//
// KT: HttpRequesterIpResolutionTest.kt#httpRequesterIp honors X-Forwarded-For only when the test-host peer is configured as trusted
func TestRequestRequesterIPHonorsXFFOnlyWhenThePeerIsTrusted(t *testing.T) {
	var trusted map[string]struct{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := RequestRequesterIP(r, trusted)
		if got == nil {
			fmt.Fprint(w, "null")
			return
		}
		fmt.Fprint(w, *got)
	}))
	defer srv.Close()

	call := func() string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("X-Forwarded-For", "203.0.113.5")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(body)
	}

	trusted = edgeSet()
	if got := call(); got == "203.0.113.5" {
		t.Error("the loopback peer is not a configured trusted proxy, yet its X-Forwarded-For was honored")
	} else if got != "127.0.0.1" {
		t.Errorf("untrusted peer: got %q, want the peer 127.0.0.1", got)
	}

	trusted = edgeSet("127.0.0.1")
	if got := call(); got != "203.0.113.5" {
		t.Errorf("trusted peer: got %q, want the forwarded 203.0.113.5", got)
	}
}

// ---------------------------------------------------------------------------------------------
// ForwardedAuthorityTest.kt's second class: TrustedEdgeCidrTest
//
// [IsTrustedEdge] itself was ported early, but its CIDR half had only
// TestIsTrustedEdgeCIDRBlocks in scim_gate_test.go, written from the spec and explicitly labelled
// "Not a Kotlin test case". These seven are the Kotlin's, case for case. The ones that matter are the
// ones that must NOT match: a block WIDENS what may speak for a client.
// ---------------------------------------------------------------------------------------------

// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.a literal entry still matches exactly and nothing else
func TestALiteralEntryMatchesExactlyAndNothingElse(t *testing.T) {
	if !IsTrustedEdge("10.0.0.1", true, edgeSet("10.0.0.1")) {
		t.Error("a literal entry must match its own address")
	}
	if IsTrustedEdge("10.0.0.2", true, edgeSet("10.0.0.1")) {
		t.Error("a literal entry matched a DIFFERENT address; a literal is not a prefix")
	}
}

// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.an address inside a CIDR block is trusted and one outside it is not
func TestAnAddressInsideACIDRBlockIsTrustedAndOneOutsideIsNot(t *testing.T) {
	edge := edgeSet("10.10.0.0/16")
	for _, peer := range []string{"10.10.0.1", "10.10.255.254"} {
		if !IsTrustedEdge(peer, true, edge) {
			t.Errorf("%s is inside 10.10.0.0/16 — the whole /16 is covered", peer)
		}
	}
	for _, peer := range []string{"10.11.0.1", "203.0.113.9"} {
		if IsTrustedEdge(peer, true, edge) {
			t.Errorf("%s is OUTSIDE 10.10.0.0/16 and must not be trusted", peer)
		}
	}
}

// A /20 splits the third byte, so a whole-byte-only compare would wrongly accept 10.10.32.0 as well.
// That is not a rounding error: it would silently triple the address space allowed to speak for a
// client.
//
// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.a prefix that is not byte-aligned masks the boundary byte
func TestAPrefixThatIsNotByteAlignedMasksTheBoundaryByte(t *testing.T) {
	edge := edgeSet("10.10.16.0/20")
	for _, peer := range []string{"10.10.16.1", "10.10.31.255"} {
		if !IsTrustedEdge(peer, true, edge) {
			t.Errorf("%s is inside 10.10.16.0/20", peer)
		}
	}
	for _, peer := range []string{"10.10.32.0", "10.10.15.255"} {
		if IsTrustedEdge(peer, true, edge) {
			t.Errorf("%s is outside 10.10.16.0/20; a whole-byte compare would wrongly accept it", peer)
		}
	}
}

// 🔒 `::/0` is every IPv6 address, NOT every address, and `0.0.0.0/0` is every IPv4 one. The two
// address spaces are compared, never coerced — which is precisely what net.ParseIP alone would get
// wrong, since it normalises IPv4 to a v4-in-v6 form. parseIPLiteral's To4() is what keeps this true.
//
// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.IPv6 blocks work and never match across address families
func TestIPv6BlocksWorkAndNeverMatchAcrossAddressFamilies(t *testing.T) {
	if !IsTrustedEdge("2001:db8::1", true, edgeSet("2001:db8::/32")) {
		t.Error("2001:db8::1 is inside 2001:db8::/32")
	}
	if IsTrustedEdge("2001:db9::1", true, edgeSet("2001:db8::/32")) {
		t.Error("2001:db9::1 is outside 2001:db8::/32")
	}
	if IsTrustedEdge("10.0.0.1", true, edgeSet("::/0")) {
		t.Error("a v4 peer matched an all-IPv6 block; the families must never be coerced")
	}
	if IsTrustedEdge("2001:db8::1", true, edgeSet("0.0.0.0/0")) {
		t.Error("a v6 peer matched an all-IPv4 block; the families must never be coerced")
	}
}

// 🔒 THE SECURITY CASE: a typo must NARROW trust, never widen it. Each of these entries would be a
// disaster if a lenient parser read it as "match anything".
//
// The second half is [UnusableTrustedProxyEntries], which exists so the fail-closed silence is
// OBSERVABLE — a malformed entry that matches nothing is correct and completely invisible, and the
// symptom is "forwarded headers stopped working" with nothing naming the cause.
//
// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.a malformed entry matches nothing rather than everything
func TestAMalformedEntryMatchesNothingRatherThanEverything(t *testing.T) {
	for _, bad := range []string{"10.10.0.0/", "10.10.0.0/33", "10.10.0.0/-1", "not-an-ip/16", "/16", "10.10.0.0/abc"} {
		if IsTrustedEdge("10.10.0.1", true, edgeSet(bad)) {
			t.Errorf("malformed entry %q matched — a typo must fail closed, never open", bad)
		}
	}
	if got := UnusableTrustedProxyEntries(edgeSet("10.10.0.0/33", "nope")); len(got) != 2 {
		t.Errorf("UnusableTrustedProxyEntries = %v, want both entries reported", got)
	}
	if got := UnusableTrustedProxyEntries(edgeSet("10.10.0.0/16", "10.0.0.1", "2001:db8::/32")); len(got) != 0 {
		t.Errorf("UnusableTrustedProxyEntries = %v, want empty — all three are usable", got)
	}
	// The report is sorted, so a startup warning does not reshuffle per boot (Go map order is random).
	want := []string{"10.10.0.0/33", "also-bad", "nope"}
	if got := UnusableTrustedProxyEntries(edgeSet("nope", "10.10.0.0/33", "also-bad")); !reflect.DeepEqual(got, want) {
		t.Errorf("UnusableTrustedProxyEntries = %v, want the sorted %v", got, want)
	}
}

// 🔒 Resolving a hostname entry would make trust depend on DNS, which an attacker may influence, and
// would turn a config typo into a network call on EVERY request.
//
// ⚠️ Note the asymmetry this creates with [UnusableTrustedProxyEntries], which DOES report "localhost":
// the literal set lookup in IsTrustedEdge runs before any parsing, so a peer string of exactly
// "localhost" still matches. Both behaviours are the Kotlin's.
//
// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.a hostname entry is never resolved at match time
func TestAHostnameEntryIsNeverResolvedAtMatchTime(t *testing.T) {
	for _, peer := range []string{"10.0.0.1", "127.0.0.1"} {
		if IsTrustedEdge(peer, true, edgeSet("localhost")) {
			t.Errorf("peer %q matched the hostname entry \"localhost\" — entries are never resolved", peer)
		}
	}
}

// The default posture: PM_TRUSTED_PROXIES unset trusts NOBODY, so no forwarded header is honored until
// an operator opts in. The second row is Kotlin's `isTrustedEdge(null, ...)`: a request with no peer at
// all must never pass on a header alone.
//
// KT: ForwardedAuthorityTest.kt#TrustedEdgeCidrTest.an empty trusted set trusts nothing
func TestAnEmptyTrustedSetTrustsNothing(t *testing.T) {
	if IsTrustedEdge("10.0.0.1", true, edgeSet()) {
		t.Error("an empty trusted set trusted an address")
	}
	if IsTrustedEdge("", false, edgeSet("10.10.0.0/16")) {
		t.Error("a request with NO peer passed the trusted-edge test")
	}
}

// ---------------------------------------------------------------------------------------------
// StripToBareIP's own branches. Not Kotlin cases — the Kotlin only reaches this function through
// resolveHttpRequesterIp, whose Cedar validation hides which of the two rejected. These pin the
// stripper's answer directly so a port cannot drift into a laxer one and stay green because Cedar
// happened to reject the salvaged value anyway.
// ---------------------------------------------------------------------------------------------

func TestStripToBareIPBranches(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.5", "203.0.113.5"},
		{"/203.0.113.5:5432", "203.0.113.5"}, // the leading-slash strip
		{"  203.0.113.5  ", "203.0.113.5"},   // trim
		{"[2001:db8::1]", "2001:db8::1"},     // bracketed, no port
		{"[2001:db8::1]:443", "2001:db8::1"}, // bracketed with port
		{"2001:db8::1", "2001:db8::1"},       // bare v6: many colons, not a port
		{"[203.0.113.5", "<nil>"},            // unclosed bracket
		{"[203.0.113.5]junk", "<nil>"},       // garbage after ]
		{"[203.0.113.5]:", "<nil>"},          // ':' with no digits
		{"203.0.113.5:", "<nil>"},            // empty port
		{"203.0.113.5:x", "<nil>"},           // non-numeric port
		{"[]", "<nil>"},                      // empty brackets
		{":5432", "<nil>"},                   // empty host
		{"", "<nil>"},                        // empty
		{"   ", "<nil>"},                     // blank
		{"/", "<nil>"},                       // slash only
		{"not-an-ip", "not-an-ip"},           // passed through; Cedar rejects it later
	}
	for _, c := range cases {
		got := "<nil>"
		if v := StripToBareIP(c.in, true); v != nil {
			got = *v
		}
		if got != c.want {
			t.Errorf("StripToBareIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
