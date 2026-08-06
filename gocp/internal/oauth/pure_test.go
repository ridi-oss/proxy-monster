package oauth

import (
	"math"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// 14-auth.md §3 — the five pure functions.
//
// ORACLE: 14-auth.md §3's per-function "Behavior" lists and §8's Q1/Q4, plus the Kotlin bodies at
// McpOAuth.kt:18-43. There is no JVM on this machine, so every expected value below is either
// (a) derived from the documented algorithm, or (b) a fixed point the algorithm cannot get wrong in
// two ways — a SHA-256 digest, a base64url alphabet. Each case says which.
// ---------------------------------------------------------------------------------------------

// 🔒 INV-A14-2's clamp, including the two boundaries a "generic min/max on an unsigned type" would
// get wrong (14-auth.md §3: "a negative request must floor to 60, not wrap").
func TestClampTTLSecondsIsTotalAndTwoSided(t *testing.T) {
	cases := []struct {
		in   int64
		want int64
	}{
		{math.MinInt64, 60}, {-1, 60}, {0, 60}, {59, 60},
		{60, 60}, {61, 61}, {600, 600}, {21_600, 21_600}, {86_400, 86_400},
		{86_401, 86_400}, {math.MaxInt64, 86_400},
	}
	for _, c := range cases {
		if got := ClampTTLSeconds(c.in); got != c.want {
			t.Errorf("ClampTTLSeconds(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// 🔒 F21 — the duplicate clamp. internal/token declares its own byte-identical copy and 14-auth.md Q3
// leaves unification OPEN, so the port keeps both. This asserts they agree TODAY without importing
// one into the other: if a later change splits TTL policy between MCP tokens and wire tokens, this
// test is where it becomes visible instead of silently shipping.
//
// It deliberately does NOT call token.ClampTTLSeconds — importing internal/token here would make the
// duplication invisible again by creating the very coupling F21 says does not exist.
func TestF21TheDuplicateClampBoundsMatchTokensCopy(t *testing.T) {
	// Tokens.kt:75-76, transcribed. Same literals, independently written.
	const tokensMin, tokensMax int64 = 60, 24 * 3600
	if TokenMinTTLSeconds != tokensMin || TokenMaxTTLSeconds != tokensMax {
		t.Fatalf("F21: the two TTL bounds have diverged — oauth has [%d,%d], Tokens.kt has [%d,%d]",
			TokenMinTTLSeconds, TokenMaxTTLSeconds, tokensMin, tokensMax)
	}
}

// 🔒 INV-A14-4 — CanonicalScopes is a DATABASE JOIN KEY. Golden vectors, per 14-auth.md's explicit
// instruction ("Freeze this function with a golden vector table in Step 3").
//
// Each row states which property it pins, because a canonicalization bug does not throw — it makes
// FindActiveConsent miss and ResolveAccess's five-column JOIN fail, i.e. every MCP request 401s with
// a valid token.
func TestCanonicalScopesGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty input is the empty string", nil, ""},
		{"one scope is itself", []string{"mcp:read"}, "mcp:read"},
		{"sorted, not insertion order", []string{"mcp:read", "mcp:identity:write"}, "mcp:identity:write mcp:read"},
		{"already sorted is unchanged", []string{"mcp:identity:write", "mcp:read"}, "mcp:identity:write mcp:read"},
		{"duplicates collapse", []string{"mcp:read", "mcp:read"}, "mcp:read"},
		{"all four, any order", MCPAScopes,
			"mcp:datasources:write mcp:identity:write mcp:policies:write mcp:read"},
		{"surrounding spaces are trimmed", []string{"  mcp:read  "}, "mcp:read"},
		{"tab and newline are trimmed", []string{"\tmcp:read\n"}, "mcp:read"},
		{"a whitespace-only element disappears entirely", []string{"mcp:read", "   "}, "mcp:read"},
		{"an empty element disappears", []string{"", "mcp:read"}, "mcp:read"},
		{"every element empty gives the empty string", []string{"", " ", "\t"}, ""},
		{"trim then dedupe, in that order", []string{" mcp:read", "mcp:read "}, "mcp:read"},
		// INNER whitespace is NOT touched — trim is edges only, so a scope containing a space stays
		// one element and the joined string becomes ambiguous. Reproduced, because the route path
		// rejects such a scope and the library path does not.
		{"inner whitespace survives", []string{"a b"}, "a b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CanonicalScopes(c.in); got != c.want {
				t.Errorf("CanonicalScopes(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// 🔒 14-auth.md Q4 — THE TRIM SET IS KOTLIN'S, NOT GO'S, and the two differ in BOTH directions.
// Pinned with the exact two code points the question names, because `strings.TrimSpace` would get
// each of them backwards and the result is a join key.
func TestCanonicalScopesUsesTheJVMTrimSetNotUnicodeIsSpace(t *testing.T) {
	// U+001C..U+001F: Java's Character.isWhitespace says yes (the four separator controls), Go's
	// unicode.IsSpace says no. Kotlin TRIMS them.
	for _, r := range []rune{0x1C, 0x1D, 0x1E, 0x1F} {
		in := string(r) + "mcp:read" + string(r)
		if got := CanonicalScopes([]string{in}); got != "mcp:read" {
			t.Errorf("U+%04X must be trimmed (Character.isWhitespace) — got %q", r, got)
		}
		if strings.TrimSpace(in) == "mcp:read" {
			t.Errorf("premise broken: strings.TrimSpace now trims U+%04X, so this test proves nothing", r)
		}
	}
	// U+0085 NEL: category Cc, so NEITHER Character.isWhitespace nor Character.isSpaceChar matches —
	// Kotlin does NOT trim it. Go's unicode.IsSpace does.
	const nel = "mcp:read"
	if got := CanonicalScopes([]string{nel}); got != nel {
		t.Errorf("U+0085 must NOT be trimmed (it is category Cc) — got %q", got)
	}
	if strings.TrimSpace(nel) != "mcp:read" {
		t.Fatal("premise broken: strings.TrimSpace no longer trims U+0085, so this test proves nothing")
	}
	// U+00A0 NBSP: Character.isWhitespace says NO (non-breaking), but Character.isSpaceChar says YES
	// (category Zs), and Kotlin's Char.isWhitespace is the UNION — so it IS trimmed. This is the case
	// a port that ported only Character.isWhitespace would get wrong.
	if got := CanonicalScopes([]string{" mcp:read "}); got != "mcp:read" {
		t.Errorf("U+00A0 must be trimmed (Character.isSpaceChar, category Zs) — got %q", got)
	}
}

// 🔒 The sort is UTF-16 code-unit order, not UTF-8 byte order. They agree everywhere in the BMP and
// disagree above U+FFFF, because a surrogate pair (0xD800..) sorts BEFORE U+E000..U+FFFF in UTF-16
// and AFTER them in UTF-8.
//
// No route can produce such a scope — `/oauth/authorize` rejects anything outside MCPAScopes — but
// RememberConsent and FindActiveConsent are library calls with no such guard, and they must agree
// with each other and with a Kotlin peer during cutover.
func TestCanonicalScopesSortsByUTF16CodeUnitsNotUTF8Bytes(t *testing.T) {
	const astral = "\U0001F600" // U+1F600, surrogate pair D83D DE00 in UTF-16
	const highBMP = ""         // private-use, one UTF-16 code unit
	got := CanonicalScopes([]string{highBMP, astral})
	want := astral + " " + highBMP
	if got != want {
		t.Errorf("UTF-16 order puts the surrogate pair first: got %q, want %q", got, want)
	}
	// The premise, stated so a future reader can see the two really do disagree.
	if !(astral > highBMP) {
		t.Fatal("premise broken: Go byte order no longer puts the astral scope AFTER U+E000")
	}
}

// 🔒 INV-A14-5 — SHA256Hex must be 64 lowercase hex characters over the UTF-8 bytes. The two vectors
// are RFC-published SHA-256 fixed points, so they are an oracle independent of this implementation.
func TestSHA256HexIsLowercaseHexOverUTF8(t *testing.T) {
	cases := map[string]string{
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	for in, want := range cases {
		if got := SHA256Hex(in); got != want {
			t.Errorf("SHA256Hex(%q) = %q, want %q", in, got, want)
		}
	}
	// UTF-8, not UTF-16 and not a lossy ASCII fold — contrast PKCES256 below.
	if SHA256Hex("é") == SHA256Hex("?") {
		t.Error("SHA256Hex must encode UTF-8, not fold non-ASCII to '?'")
	}
	if got := SHA256Hex("é"); got != strings.ToLower(got) {
		t.Errorf("SHA256Hex must be lowercase, got %q", got)
	}
}

// 🔒 PKCES256 produces a 43-character unpadded base64url challenge, and it is the value
// `isValidPkceChallenge` is checked against — so the two must agree on length by construction.
func TestPKCES256ProducesA43CharacterUnpaddedBase64URLChallenge(t *testing.T) {
	challenge := PKCES256(strings.Repeat("a", 43))
	if len(challenge) != 43 {
		t.Fatalf("challenge length = %d, want 43: %q", len(challenge), challenge)
	}
	if strings.ContainsAny(challenge, "=+/") {
		t.Errorf("challenge must be unpadded base64URL (no '=', '+' or '/'): %q", challenge)
	}
	if !IsValidPKCEChallenge(challenge) {
		t.Errorf("PKCES256 output must satisfy IsValidPKCEChallenge: %q", challenge)
	}
}

// 🔒 14-auth.md Q1 — REPRODUCE + PIN. Java's `String.getBytes(US_ASCII)` is LOSSY: an unmappable
// character becomes '?' rather than throwing, so a non-ASCII verifier hashes to a preimage containing
// '?'. Not exploitable (that preimage can never itself be a valid verifier), but the disposition is
// pin-either-way, because rejecting non-ASCII outright would be a narrowing and a narrowing is its
// own decision.
//
// The assertion is EQUALITY with the '?'-substituted string, which is the only way to tell the lossy
// fold from a UTF-8 encode.
func TestPKCES256EncodesTheVerifierAsLossyUSASCII(t *testing.T) {
	cases := []struct{ verifier, equivalent string }{
		{"é", "?"},
		{"aébc", "a?bc"},
		{"\U0001F600", "?"}, // one '?' for a surrogate PAIR, not two
		{"a b", "a?b"},
	}
	for _, c := range cases {
		if got, want := PKCES256(c.verifier), PKCES256(c.equivalent); got != want {
			t.Errorf("PKCES256(%q) = %q, want the lossy-ASCII equivalent PKCES256(%q) = %q",
				c.verifier, got, c.equivalent, want)
		}
	}
	// And the converse: a pure-ASCII verifier is NOT folded.
	if PKCES256("abc") == PKCES256("?bc") {
		t.Error("an ASCII verifier must not be folded")
	}
}

// 🔒 F29 — the two validators use Kotlin's UNICODE-AWARE Char.isLetterOrDigit, so 43 Hangul jamo pass.
// A port written as a base64url charset check would accept a strictly smaller set; the area doc says
// to reproduce the looseness and record the would-be tightening rather than let it be discovered as a
// diff.
func TestIsValidPKCEChallengeReproducesTheUnicodeAwareCharsetF29(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"exactly 43 base64url chars", strings.Repeat("a", 43), true},
		{"42 is too short", strings.Repeat("a", 42), false},
		{"44 is too long (the app is stricter than V7's 43..128 CHECK)", strings.Repeat("a", 44), false},
		{"empty", "", false},
		{"hyphen and underscore are allowed", strings.Repeat("-", 21) + "_" + strings.Repeat("_", 21), true},
		{"a dot is not", strings.Repeat("a", 42) + ".", false},
		{"a tilde is not (that is the VERIFIER charset)", strings.Repeat("a", 42) + "~", false},
		{"a plus is not", strings.Repeat("a", 42) + "+", false},
		{"a slash is not", strings.Repeat("a", 42) + "/", false},
		// F29 proper: Unicode letters and digits pass.
		{"43 Hangul jamo pass — storable but unredeemable", strings.Repeat("ᄀ", 43), true},
		{"43 accented letters pass", strings.Repeat("é", 43), true},
		{"43 Arabic-Indic digits pass (category Nd)", strings.Repeat("٣", 43), true},
		// …but only categories L* and Nd. No (½) and Nl (Ⅴ) are NOT digits to Character.isDigit.
		{"a vulgar fraction is not a digit", strings.Repeat("a", 42) + "½", false},
		{"a Roman numeral is not a digit", strings.Repeat("a", 42) + "Ⅴ", false},
		// Length is in UTF-16 CODE UNITS: an astral letter is TWO of them, and each surrogate is
		// category Cs, so it fails the charset test as well as skewing the count.
		{"an astral letter is two code units and two non-letters", strings.Repeat("a", 41) + "\U0001D400", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsValidPKCEChallenge(c.in); got != c.want {
				t.Errorf("IsValidPKCEChallenge(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// The verifier's charset is RFC 7636's `unreserved`: ALPHA / DIGIT / "-" / "." / "_" / "~", with the
// same Unicode caveat, over a 43..128 length window.
func TestIsValidPKCEVerifierCharsetAndLengthWindow(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"43 is the floor", strings.Repeat("a", 43), true},
		{"42 is below it", strings.Repeat("a", 42), false},
		{"128 is the ceiling", strings.Repeat("a", 128), true},
		{"129 is above it", strings.Repeat("a", 129), false},
		{"dot and tilde ARE allowed here, unlike the challenge", strings.Repeat("a", 41) + ".~", true},
		{"hyphen and underscore too", strings.Repeat("a", 41) + "-_", true},
		{"a slash is not", strings.Repeat("a", 42) + "/", false},
		{"a space is not", strings.Repeat("a", 42) + " ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsValidPKCEVerifier(c.in); got != c.want {
				t.Errorf("IsValidPKCEVerifier(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// 🔒 The prefix registry (14-auth.md §3): the WIDTHS are wire-visible and one of them is a documented
// collision. 32 bytes ⇒ 43 base64url characters, 24 ⇒ 32, 18 ⇒ 24.
func TestRandomSecretWidthsMatchThePrefixRegistry(t *testing.T) {
	cases := []struct {
		prefix string
		bytes  int
		want   int
	}{
		{"pmc_", 32, 43}, {"pma_", 32, 43}, {"pmr_", 32, 43}, {"pmf_", 24, 32}, {"csrf_", 18, 24},
	}
	for _, c := range cases {
		got, err := RandomSecret(c.prefix, c.bytes)
		if err != nil {
			t.Fatalf("RandomSecret(%q, %d): %v", c.prefix, c.bytes, err)
		}
		if !strings.HasPrefix(got, c.prefix) {
			t.Errorf("RandomSecret(%q, %d) = %q, missing prefix", c.prefix, c.bytes, got)
		}
		if body := strings.TrimPrefix(got, c.prefix); len(body) != c.want {
			t.Errorf("RandomSecret(%q, %d) body length = %d, want %d", c.prefix, c.bytes, len(body), c.want)
		}
		if strings.ContainsAny(got, "=+/") {
			t.Errorf("RandomSecret must be unpadded base64url: %q", got)
		}
	}
	// Distinct across calls — a fixed secret is the one failure this class of function can have that
	// nothing downstream would notice.
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		s, err := RandomSecret("pmc_", 32)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("RandomSecret repeated a value after %d draws: %q", i, s)
		}
		seen[s] = struct{}{}
	}
}

// The scope split on the READ side filters isNotBlank and splits on the single space only — NOT
// strings.Fields, which would also split a tab and silently repair a non-canonical legacy row.
func TestSplitScopesNotBlankSplitsOnTheSingleSpaceOnly(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"mcp:read", []string{"mcp:read"}},
		{"mcp:read mcp:identity:write", []string{"mcp:read", "mcp:identity:write"}},
		{"mcp:read  mcp:identity:write", []string{"mcp:read", "mcp:identity:write"}}, // the blank between is dropped
		{"  ", nil},
		{"a\tb", []string{"a\tb"}}, // ONE element: a tab is not a separator here
	}
	for _, c := range cases {
		got := splitScopesNotBlank(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitScopesNotBlank(%q) = %q, want %q", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitScopesNotBlank(%q) = %q, want %q", c.in, got, c.want)
				break
			}
		}
	}
}
