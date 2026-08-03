package authz

import "testing"

// 🔴 THE TWO-STAGE IP CHECK (98-cedar-spike-report.md § S5, work item W3).
//
// A2 owns only the ENGINE half — Authz.evaluatesInCedar (Authz.kt:307-315), which collapses to
// types.ParseIPAddr. The CHARSET ALLOWLIST half lives in A12's isStorableIpLiteral
// (RequesterIp.kt:209-214), which already takes evaluatesInCedar as a function parameter, so the two
// halves are separable by construction.
//
// These tests exist where the engine half lives, because this is where a future reader is most likely to
// conclude "Go's parser is stricter, so the allowlist is redundant" — and that conclusion is WRONG. The
// oracle is DebugRequesterIpDbTest.kt:156-195's 16 pinned literals: FAITHFUL (allowlist, then
// ParseIPAddr) = 16/16; NAIVE (ParseIPAddr alone) = 15/16.

// TestEvaluatesInCedar_AcceptsACIDRLiteral is the ENTIRE reason the allowlist must stay in front.
//
// 100.100.1.0/24 is the one literal of the 16 that a naive port gets wrong. types.ParseIPAddr ACCEPTS
// it, because Cedar's `ipaddr` type covers prefixes and a CIDR is a legal ip() argument INSIDE A POLICY.
// It is NOT a legal requester_ip VALUE, and the allowlist — which does not contain '/' — is the only
// thing that separates the two. Drop the allowlist and /auth/debug returns 200 where the Kotlin returns
// 400 (INV-A1-7), i.e. an operator can store a whole /24 as their simulated source address.
//
// If this assertion ever starts FAILING, the constraint has been removed upstream and A12's allowlist
// requirement should be re-derived — do not simply delete the test.
func TestEvaluatesInCedar_AcceptsACIDRLiteral(t *testing.T) {
	a := &Authz{}
	if !a.EvaluatesInCedar("100.100.1.0/24") {
		t.Fatal("premise changed: types.ParseIPAddr no longer accepts a CIDR. Re-derive W3 before " +
			"relying on the two-stage structure.")
	}
	for _, cidr := range []string{"100.100.1.10/32", "0.0.0.0/0", "::/0"} {
		if !a.EvaluatesInCedar(cidr) {
			t.Errorf("ParseIPAddr rejected %q; the S5 divergence table records it as accepted", cidr)
		}
	}
}

// TestEvaluatesInCedar_TheEngineHalfOfTheOracle pins the literals whose outcome the ENGINE half decides
// on its own — the ones the Kotlin's L1 allowlist lets through.
//
// Note the S5 finding these encode: for the leading-zero forms the FAILURE MOVES. cedar-java's IpAddress
// REGEX (L2) accepts 100.100.001.010 and 010.1.1.1 and only the ENGINE (L3) refuses them — which is what
// made evaluatesInCedar worth having at all. Go's net/netip rejects leading zeros at parse, so L2 and L3
// collapse into this one call. Same OUTCOME (400), different LAYER, which is why the Kotlin layering is
// not evidence for the Go layering.
func TestEvaluatesInCedar_TheEngineHalfOfTheOracle(t *testing.T) {
	a := &Authz{}
	accepted := []string{
		"100.100.1.10", // canonical IPv4, in the shipped -300 trusted range
		"::1",          // IPv6 loopback, compressed
		"2001:db8::1",  // documentation range, compressed
		"fe80::1",      // link-local WITHOUT a zone id
	}
	for _, ip := range accepted {
		if !a.EvaluatesInCedar(ip) {
			t.Errorf("%q must be accepted (DebugRequesterIpDbTest.kt:156-195)", ip)
		}
	}

	rejected := []string{
		"999.1.1.1",         // octet > 255
		"100.100.1.10:5432", // not a bare address
		"100.100.001.010",   // non-canonical IPv4 — cedar-java: L3; Go: parse
		"010.1.1.1",         // leading zero, the octal-ambiguity class
	}
	for _, ip := range rejected {
		if a.EvaluatesInCedar(ip) {
			t.Errorf("%q must be rejected (DebugRequesterIpDbTest.kt:156-195)", ip)
		}
	}
}

// TestEvaluatesInCedar_LiteralsTheAllowlistMustCatch documents, executably, which pinned rejections this
// half does NOT produce. Every literal here is rejected by the Kotlin at L1 and would otherwise reach
// storage.
//
// This is not asserting the Go behaviour is wrong — it is recording WHERE the responsibility sits, so
// A12's port cannot quietly drop the allowlist and still pass A2's suite.
func TestEvaluatesInCedar_LiteralsTheAllowlistMustCatch(t *testing.T) {
	a := &Authz{}
	// Kotlin rejects all of these at L1. Whether this half also rejects them is incidental; the
	// allowlist is what MUST.
	l1Rejected := map[string]string{
		"100.100.1.0/24": "'/' is not in the allowlist — and ParseIPAddr accepts it, so ONLY L1 catches this",
		"not-an-ip":      "letters outside a-f/A-F",
		"100.100.1.10\x00": "NUL. The Kotlin source states cedar-java's IpAddress ACCEPTS a NUL-bearing " +
			"string (its validator trims control characters), which Postgres then rejects at INSERT — " +
			"L1 exists precisely because L2 is too lax here",
		"100.100.1.10​": "ZERO WIDTH SPACE survives Kotlin trim() (which only removes chars <= ' ')",
		"fe80::1%lo0":   "zone id — note isTrustedEdge's SEPARATE parseIp DOES allowlist '%'; two allowlists in one file",
		"[::1]":         "brackets — bracket-stripping is the XFF path's job, not the debug-login path's",
	}
	caughtHere := 0
	for ip := range l1Rejected {
		if !a.EvaluatesInCedar(ip) {
			caughtHere++
		}
	}
	// The one that matters: the CIDR is NOT caught here, which is the whole finding.
	if !a.EvaluatesInCedar("100.100.1.0/24") {
		t.Error("see TestEvaluatesInCedar_AcceptsACIDRLiteral — this must be reached only by L1")
	}
	if caughtHere == len(l1Rejected) {
		t.Error("premise changed: the engine half now catches EVERY L1 literal, which would make the " +
			"allowlist look redundant. It is not — re-check 100.100.1.0/24 specifically.")
	}
}

// TestEvaluatesInCedar_NeverPersistIPAddrString records the S5 corollary as an executable warning:
// IPAddr.String() is NOT round-trip safe for v4-mapped v6. ::ffff:6464:010a renders as
// ::ffff:100.100.1.10, which ParseIPAddr then REJECTS — so any store that persists String() or
// MarshalJSON() output loses the value on reload.
func TestEvaluatesInCedar_NeverPersistIPAddrString(t *testing.T) {
	a := &Authz{}
	const hexForm = "::ffff:6464:010a"
	if !a.EvaluatesInCedar(hexForm) {
		t.Fatalf("premise changed: %q no longer parses", hexForm)
	}
	// cedar-go rejects the DOTTED v4-mapped v6 form while accepting the hex form of the same address.
	if a.EvaluatesInCedar("::ffff:100.100.1.10") {
		t.Error("premise changed: cedar-go now accepts dotted v4-mapped v6; the round-trip hazard may " +
			"be gone, but re-verify before persisting IPAddr.String() anywhere")
	}
}
