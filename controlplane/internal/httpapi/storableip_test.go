package httpapi

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
)

// ============================================================================================
// [IsStorableIPLiteral] — 🔒 INV-A1-7's arbiter, and the reason /auth/debug answers 400 rather than
// silently dropping a simulated address.
//
// THE ORACLE IS `DebugRequesterIpDbTest.kt:156-195` — 11 pinned rejections and 5 pinned acceptances,
// read this session from the worktree's own Kotlin tree. It is the frozen test assertion, not a
// reconstruction: there is no JVM here to run it.
//
// The engine half is driven by the REAL *authz.Authz.EvaluatesInCedar, not a stub, because the
// interesting property is the SEAM between the two stages — which literal each one catches. A stub
// would let the allowlist look sufficient on its own (it is not: `999.1.1.1` passes the charset test)
// and let the engine look sufficient on its own (it is not: `100.100.1.0/24` parses fine).
// ============================================================================================

// realEngineHalf is `authz::evaluatesInCedar`. The zero-value Authz is enough — EvaluatesInCedar
// touches no policy store, exactly as internal/authz/ip_test.go relies on.
func realEngineHalf() func(string) bool {
	a := &authz.Authz{}
	return a.EvaluatesInCedar
}

// TestIsStorableIPLiteralAcceptsThePinnedAddresses is DebugRequesterIpDbTest.kt:192-195's positive
// controls, and its comment says exactly why they are there: "the loop above must be rejecting these
// specific values rather than rejecting everything. IPv6 and surrounding whitespace are here because
// they are exactly what a too-eager tightening would break — an IPv4-only allowlist, or dropping the
// server-side trim, would sail past every rejection assertion above."
//
// The whitespace cases are NOT passed here: the route trims BEFORE calling this (`requesterIp?.trim()`),
// so `"  100.100.1.10  "` reaches this function already trimmed. That split is asserted at the route
// in internal/app — a leading space would fail the charset allowlist if it ever got this far.
func TestIsStorableIPLiteralAcceptsThePinnedAddresses(t *testing.T) {
	evaluates := realEngineHalf()
	for _, ip := range []string{
		"100.100.1.10", // canonical IPv4, in the shipped -300 trusted range
		"::1",          // IPv6 loopback, compressed
		"2001:db8::1",  // documentation range
		"fe80::1",      // link-local WITHOUT a zone id — the zone-bearing form is rejected below
	} {
		if !IsStorableIPLiteral(ip, evaluates) {
			t.Errorf("%q must be accepted (DebugRequesterIpDbTest.kt:192-195)", ip)
		}
	}
}

// TestIsStorableIPLiteralRejectsThePinnedMalformedAddresses is DebugRequesterIpDbTest.kt:172-183's
// eleven-value `bad` list, verbatim, each with the stage that must catch it.
//
// 🔒 Every one of these is a 400 `auth.invalid_requester_ip` at the route. The Kotlin's comment on
// why they are refused rather than dropped: "Dropping it to null would present as 'the tag rule does
// not work', sending the reader after a policy bug that isn't there."
func TestIsStorableIPLiteralRejectsThePinnedMalformedAddresses(t *testing.T) {
	evaluates := realEngineHalf()
	for _, tc := range []struct{ ip, caughtBy string }{
		{"not-an-ip", "L1 — letters outside a-f/A-F"},
		{"999.1.1.1", "the engine — octet > 255; L1 passes it"},
		{"100.100.1.10:5432", "the engine — not a bare address; L1 passes it, ':' is legal in IPv6"},
		{"100.100.1.0/24", "L1 ONLY — '/' is not in the allowlist, and the engine ACCEPTS a CIDR"},
		{"100.100.1.10\x00", "L1 — NUL. cedar-java's IpAddress accepts it; Postgres then rejects at INSERT"},
		{"100.100.1.10\x0012", "L1 — NUL mid-string, same class"},
		{"100.100.1.10​", "L1 — ZERO WIDTH SPACE survives Kotlin trim(), which only removes chars <= ' '"},
		{"fe80::1%lo0", "L1 — a zone id. isTrustedEdge's SEPARATE allowlist DOES permit '%'"},
		{"[::1]", "L1 — brackets. Bracket-stripping is the XFF path's job, not the debug-login path's"},
		{"100.100.001.010", "the engine — non-canonical IPv4. cedar-java's regex accepts it; L2 vs L3 in Kotlin"},
		{"010.1.1.1", "the engine — leading zero, the octal-ambiguity class"},
	} {
		if IsStorableIPLiteral(tc.ip, evaluates) {
			t.Errorf("%q must be rejected (%s) — DebugRequesterIpDbTest.kt:172-183", tc.ip, tc.caughtBy)
		}
	}
}

// TestIsStorableIPLiteralRejectsTheEmptyString is the `candidate.isEmpty()` guard.
//
// Unreachable from /auth/debug (`takeIf { it.isNotEmpty() }` turns a blank into an ABSENT address,
// not a rejected one, so the empty string never arrives) and reproduced anyway: this function is
// A12's, and A12 has other callers. Dropping the guard would make the charset loop vacuously true
// and hand "" to the engine.
func TestIsStorableIPLiteralRejectsTheEmptyString(t *testing.T) {
	if IsStorableIPLiteral("", func(string) bool {
		t.Fatal("the empty string must be rejected BEFORE the engine is consulted")
		return true
	}) {
		t.Error(`IsStorableIPLiteral("") = true, want false`)
	}
}

// 🔴 TestTheAllowlistIsTheOnlyThingRejectingACIDR is THE test of this file, and the one a future
// "Go's parser is stricter, so the allowlist is redundant" cleanup has to get past.
//
// `100.100.1.0/24` is the single literal of the sixteen where the two stages disagree. cedar's
// `ipaddr` type covers PREFIXES because a CIDR is a legal `ip()` argument INSIDE A POLICY, so the
// engine half ACCEPTS it — it is simply not a legal requester_ip VALUE. Remove the allowlist and
// /auth/debug answers 200 where the Kotlin answers 400, i.e. an operator can store a whole /24 as
// their simulated source address and every tag rule keyed on it then matches a range.
//
// internal/authz/ip_test.go asserts the same premise from the engine side, so the constraint is
// pinned from both ends and cannot be removed by editing one file.
func TestTheAllowlistIsTheOnlyThingRejectingACIDR(t *testing.T) {
	evaluates := realEngineHalf()

	if !evaluates("100.100.1.0/24") {
		t.Fatal("premise changed: the engine half no longer accepts a CIDR. The two-stage structure " +
			"was derived from that fact (98-cedar-spike-report.md § S5 / W3) — re-derive it before " +
			"relying on this test.")
	}
	if IsStorableIPLiteral("100.100.1.0/24", evaluates) {
		t.Error("a CIDR reached storage: the L1 charset allowlist has been dropped or now contains '/'")
	}
}

// TestTheEngineHalfIsReachedForLiteralsTheAllowlistPasses is the converse guard: the allowlist alone
// is not sufficient either, so a "simplification" that kept only stage 1 must fail too.
//
// `999.1.1.1` is all digits and dots, so the charset test passes it and ONLY the engine rejects it.
// Asserted by counting the calls rather than by outcome, because an implementation that returned
// false without asking would produce the same verdict for the wrong reason.
func TestTheEngineHalfIsReachedForLiteralsTheAllowlistPasses(t *testing.T) {
	calls := 0
	probe := func(ip string) bool {
		calls++
		return realEngineHalf()(ip)
	}

	if IsStorableIPLiteral("999.1.1.1", probe) {
		t.Error(`"999.1.1.1" must be rejected`)
	}
	if calls != 1 {
		t.Errorf("the engine half was consulted %d times, want 1 — the allowlist alone cannot reject "+
			"an in-charset out-of-range address", calls)
	}
}

// TestTheAllowlistShortCircuitsBeforeTheEngine pins the ORDER, which is not merely an optimisation:
// the Kotlin's cheap pre-filter runs first so a NUL-bearing or zero-width-space-bearing string never
// reaches an engine whose parser might accept it. Both of those are pinned rejections above; this
// asserts WHERE they are rejected, so a reordering shows up here rather than as a behaviour change
// only if cedar-go's parser ever loosens.
func TestTheAllowlistShortCircuitsBeforeTheEngine(t *testing.T) {
	for _, ip := range []string{"not-an-ip", "100.100.1.0/24", "100.100.1.10\x00", "[::1]", "fe80::1%lo0"} {
		reached := false
		if IsStorableIPLiteral(ip, func(string) bool { reached = true; return true }) {
			t.Errorf("%q was accepted by an always-true engine half — L1 did not reject it", ip)
		}
		if reached {
			t.Errorf("%q reached the engine half; the charset allowlist must reject it first", ip)
		}
	}
}
