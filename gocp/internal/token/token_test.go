package token

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// TestClampTTLSeconds is TokenTtlTest.kt, ported 1:1 — its four cases as four subtests.
//
// Its Kotlin doc states the reason it exists: "Wire tokens are always expiring and bounded (DESIGN.md —
// no persistent secrets). Guards the TTL clamp so a regression can't reintroduce an unbounded (or
// zero/negative) token lifetime."
//
// 🔒 INV-A4-52 — NO TOKEN IS PERMANENT and this clamp is the ONLY enforcement: `expires_at` is NOT NULL
// in V7 and every INSERT computes it as now() + ttl. The clamp also FLOORS zero and negative requests to
// 60 s rather than rejecting them, so a buggy client cannot mint an already-expired token.
//
// ⚠️ The Kotlin case names say "capped at 24h" and "floored to the minimum" and reach the constants by
// name; the subtests below use [MinTTLSeconds] / [MaxTTLSeconds] for the same reason — a literal 86_400
// here would still pass if the constant moved.
func TestClampTTLSeconds(t *testing.T) {
	assertClamp := func(t *testing.T, in, want int64) {
		t.Helper()
		if got := ClampTTLSeconds(in); got != want {
			t.Errorf("ClampTTLSeconds(%d) = %d, want %d", in, got, want)
		}
	}

	// KT: TokenTtlTest.kt#requests within the window are unchanged
	t.Run("requests within the window are unchanged", func(t *testing.T) {
		// The Kotlin's exact three probes: the A7 run-token floor, the /api/tokens default, and the
		// /api/wire-tokens default.
		assertClamp(t, 900, 900)
		assertClamp(t, DefaultUserTTLSeconds, 3600)
		assertClamp(t, SessionTTLSeconds, SessionTTLSeconds)
	})

	// KT: TokenTtlTest.kt#over-long requests are capped at 24h
	t.Run("over-long requests are capped at 24h", func(t *testing.T) {
		assertClamp(t, 999_999, MaxTTLSeconds)
		// 🔒 Kotlin probes Long.MAX_VALUE. math.MaxInt64 is the same value and the same hazard: the clamp
		// must be a comparison, never an arithmetic adjustment that could overflow.
		assertClamp(t, math.MaxInt64, MaxTTLSeconds)
	})

	// KT: TokenTtlTest.kt#tiny, zero, and negative requests are floored to the minimum
	t.Run("tiny, zero, and negative requests are floored to the minimum", func(t *testing.T) {
		assertClamp(t, 1, MinTTLSeconds)
		// 🔒 Zero is FLOORED, not rejected — an already-expired token must be unmintable, and refusing
		// the request instead would push the decision to six call sites.
		assertClamp(t, 0, MinTTLSeconds)
		assertClamp(t, -100, MinTTLSeconds)
	})

	// KT: TokenTtlTest.kt#every clamped ttl is a bounded, positive lifetime
	t.Run("every clamped ttl is a bounded, positive lifetime", func(t *testing.T) {
		// The Kotlin's PROPERTY case, over its exact input list. It is the one that would catch a clamp
		// rewritten in a way the three example cases happen to miss.
		for _, req := range []int64{-1, 0, 30, 60, 3600, 86_400, 86_401, math.MaxInt64} {
			ttl := ClampTTLSeconds(req)
			if ttl < MinTTLSeconds || ttl > MaxTTLSeconds {
				t.Errorf("ttl %d out of bounds [%d, %d] for request %d",
					ttl, MinTTLSeconds, MaxTTLSeconds, req)
			}
		}
	})

	// ADDED (not one of the four): the boundaries are INCLUSIVE. The Kotlin's property case only asserts
	// membership of the range, which a clamp that were exclusive at either end would still satisfy.
	t.Run("the boundaries are inclusive", func(t *testing.T) {
		assertClamp(t, MinTTLSeconds, MinTTLSeconds)
		assertClamp(t, MaxTTLSeconds, MaxTTLSeconds)
		assertClamp(t, 5, MinTTLSeconds)
	})
}

// TestHashIsPlainSHA256Hex pins INV-A4-53: ONE hashing definition, shared by the
// `proxy_token.token_hash` column and A7's requester-IP registry. Two hashers would silently
// desynchronize the decide-time IP lookup from the token row.
func TestHashIsPlainSHA256Hex(t *testing.T) {
	sum := sha256.Sum256([]byte("pmt_abc"))
	if got, want := Hash("pmt_abc"), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("Hash = %q, want %q", got, want)
	}
	if len(Hash("")) != 64 {
		t.Errorf("Hash produced %d hex chars, want 64", len(Hash("")))
	}
}

// TestKindFromWireFailsClosed — an unrecognized value returns ok=false rather than throwing, "so
// callers fail closed". Decide's call site turns that into UNAUTHENTICATED.
func TestKindFromWireFailsClosed(t *testing.T) {
	for _, name := range []string{"SESSION", "USER", "EDITOR", "APPROVER_EXEC"} {
		if k, ok := KindFromWire(name); !ok || string(k) != name {
			t.Errorf("KindFromWire(%q) = %v, %v; want the matching kind", name, k, ok)
		}
	}
	// ⚠️ MCP_ACCESS / MCP_REFRESH exist in the DATABASE but not in this enum (they are A11's), so they
	// are deliberately unrecognized here — the same answer the Kotlin gives.
	for _, name := range []string{"", "session", "MCP_ACCESS", "MCP_REFRESH", "ADMIN"} {
		if _, ok := KindFromWire(name); ok {
			t.Errorf("KindFromWire(%q) was recognized; it must fail closed", name)
		}
	}
}

// TestPrefixIsNotAKindSignal pins the trap the spec calls out explicitly.
//
// ⚠️ The prefix is `if (kind == SESSION) "pmt_" else "pmk_"`, so EDITOR and APPROVER_EXEC tokens are
// PREFIX-INDISTINGUISHABLE from USER tokens on the wire. Never infer a kind from a prefix; resolve it
// from the row.
func TestPrefixIsNotAKindSignal(t *testing.T) {
	if KindSession.Prefix() != "pmt_" {
		t.Errorf("SESSION prefix = %q, want pmt_", KindSession.Prefix())
	}
	for _, k := range []Kind{KindUser, KindEditor, KindApproverExec} {
		if k.Prefix() != "pmk_" {
			t.Errorf("%s prefix = %q, want pmk_ (the three share one prefix, deliberately)", k, k.Prefix())
		}
	}
}

// TestRandomTokenIsPrefixedAnd256Bits — prefix + base64url-nopad(32 bytes).
func TestRandomTokenIsPrefixedAnd256Bits(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		tok, err := RandomToken(KindSession)
		if err != nil {
			t.Fatalf("RandomToken: %v", err)
		}
		if !strings.HasPrefix(tok, "pmt_") {
			t.Fatalf("token %q lacks the SESSION prefix", tok)
		}
		// 32 bytes → 43 base64url chars with no padding.
		if got := len(strings.TrimPrefix(tok, "pmt_")); got != 43 {
			t.Fatalf("token body is %d chars, want 43 (32 CSPRNG bytes, base64url-nopad)", got)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("RandomToken repeated %q within 64 draws", tok)
		}
		seen[tok] = struct{}{}
	}
}

// 🔒 TestClampTTLSecondsLadderIsNotTotal is the REPRODUCE + PIN for F26 (00-INDEX.md:215,
// "🔒 The timeout ladder is not total — and my own A1/A7 docs asserted it was").
//
// A7 computes `runTokenTtlSeconds = max(900, queryTimeout + 180)`, where 180 is
// TOKEN_TTL_GRACE_SECONDS — the margin that exists so a run token cannot expire while its statement
// is still running. That value is then passed through ClampTTLSeconds, which caps at 86 400.
// `PM_QUERY_TIMEOUT` is bounded only by an overflow guard (MAX_QUERY_TIMEOUT_SECONDS = 9_223_372_006,
// Config.kt:138), so above queryTimeout = 86 220 s (23 h 57 m) THE GRACE IS SILENTLY ERASED and the
// token expires mid-statement — the exact failure the grace exists to prevent.
//
// 🔴 THE MISSING BOUND IS DELIBERATELY NOT ADDED — not here, and not in the config guard. This test
// asserts the DEFECT so that a later fix has to change it visibly. `ConfigGuardTest.kt:65-79` asserts
// only the pure function and never the stored `expires_at`, which is precisely why the hole survived
// on the Kotlin side; this test asserts the LADDER, which is the property that actually breaks.
func TestClampTTLSecondsLadderIsNotTotal(t *testing.T) {
	// A7's formula, reproduced locally so this test states the ladder rather than importing it.
	const grace int64 = 180
	runTokenTTL := func(queryTimeout int64) int64 {
		ttl := queryTimeout + grace
		if ttl < 900 {
			ttl = 900
		}
		return ttl
	}
	// The ladder holds below the break point.
	for _, queryTimeout := range []int64{30, 3600, 86_220} {
		if got := ClampTTLSeconds(runTokenTTL(queryTimeout)); got < queryTimeout+grace {
			t.Errorf("queryTimeout=%d: clamped run-token ttl %d is below timeout+grace %d — the ladder "+
				"was supposed to hold here", queryTimeout, got, queryTimeout+grace)
		}
	}
	// 86_221 is the first timeout at which the clamp eats into the grace margin.
	if got := ClampTTLSeconds(runTokenTTL(86_221)); got != MaxTTLSeconds {
		t.Fatalf("ClampTTLSeconds at the break point = %d, want the %d cap", got, MaxTTLSeconds)
	}
	// And beyond it the token expires BEFORE the statement's own timeout — not merely inside the
	// grace, but strictly before the query is even allowed to finish.
	for _, queryTimeout := range []int64{90_000, 1_000_000, 9_223_372_006} {
		got := ClampTTLSeconds(runTokenTTL(queryTimeout))
		if got >= queryTimeout {
			t.Errorf("F26 REGRESSION: queryTimeout=%d yielded run-token ttl %d, which no longer expires "+
				"mid-statement. If a bound on PM_QUERY_TIMEOUT (or a higher token cap) was just added, "+
				"that is a BEHAVIOUR FIX — take it as a separate decision and update this test "+
				"deliberately (00-INDEX.md PORT POLICY).", queryTimeout, got)
		}
	}
}
