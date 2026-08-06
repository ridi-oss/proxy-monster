package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------------------------
// Constants — McpOAuth.kt:13-16
// ---------------------------------------------------------------------------------------------

// MCPAccessKind and MCPRefreshKind are `MCP_ACCESS_KIND` / `MCP_REFRESH_KIND` (McpOAuth.kt:13-14).
//
// ⚠️ F23 — the Kotlin references these constants at FIVE sites and hardcodes the same literals in
// THREE SQL strings (`:62`, `:322`, `:397`). A rename compiles and silently mismatches the SQL.
// REPRODUCED: the three statements below that embed `'MCP_ACCESS'` / `'MCP_REFRESH'` textually are
// [mcpAccessSelect] (MCPTokenStore.ResolveAccess), [revokeConsentCascadeSQL] and [revokeFamilySQL],
// and they use the literal, not the constant, exactly as the Kotlin does.
//
// 🔒 INV-A14-8 — these two kinds are unrepresentable in A4's [token.Kind] enum, by construction. The
// partition is enforced three ways at once (type, query filter, V7's CHECK) and a port that unified
// token handling behind one `kind` string would have to reproduce all three.
const (
	MCPAccessKind  = "MCP_ACCESS"
	MCPRefreshKind = "MCP_REFRESH"
)

// TokenMinTTLSeconds and TokenMaxTTLSeconds are `TOKEN_MIN_TTL_SECONDS` / `TOKEN_MAX_TTL_SECONDS`
// (McpOAuth.kt:15-16).
//
// ⚠️ F21 — BYTE-IDENTICAL DUPLICATES of [token.MinTTLSeconds] / [token.MaxTTLSeconds] (Tokens.kt:75-76),
// and [ClampTTLSeconds] duplicates [token.ClampTTLSeconds]. The Kotlin compiles with both in scope
// and which candidate resolves is unobservable today; that is exactly the hazard, because changing
// the cap in one place silently splits TTL policy between MCP tokens and wire tokens with no compile
// error. 14-auth.md Q3 leaves unification open, so the port REPRODUCEs both copies. Do not replace
// this with a call into internal/token.
const (
	TokenMinTTLSeconds int64 = 60
	TokenMaxTTLSeconds int64 = 24 * 3600
)

// ClampTTLSeconds is `clampTtlSeconds(ttlSeconds)` (McpOAuth.kt:18) — `coerceIn(60, 86400)`.
//
// Total: every input, including negatives and math.MinInt64, lands in [60, 86400].
//
// 🔒 INV-A14-2 — every credential this package issues expires, and no client is ever told a longer
// lifetime than the row has. The clamp is applied TWICE for one issuance ([insertToken] for the
// value that becomes `expires_at`, [AuthorizationStore.issuePair] for the `expiresIn` it returns)
// because the two are consumed by different parties — Postgres and the client — and a single clamp
// would let the other drift. Both are kept.
//
// ⚠️ The int64 signature is not incidental: "do not use a generic min(max(x, lo), hi) on an unsigned
// type — a negative request must floor to 60, not wrap" (14-auth.md §3).
func ClampTTLSeconds(ttlSeconds int64) int64 {
	if ttlSeconds < TokenMinTTLSeconds {
		return TokenMinTTLSeconds
	}
	if ttlSeconds > TokenMaxTTLSeconds {
		return TokenMaxTTLSeconds
	}
	return ttlSeconds
}

// ---------------------------------------------------------------------------------------------
// canonicalScopes — McpOAuth.kt:20
// ---------------------------------------------------------------------------------------------

// CanonicalScopes is
// `scopes.map(String::trim).filter(String::isNotEmpty).toSortedSet().joinToString(" ")`
// (McpOAuth.kt:20).
//
// 🔒 INV-A14-4 — THE CANONICAL SCOPE STRING IS A DATABASE JOIN KEY, and this is the single most
// port-fragile function in the area. Four separate predicates compare `scope` as an opaque string:
// `MCPTokenStore.ResolveAccess`'s five-column JOIN, `createAuthorizationCode`'s consent-selecting
// INSERT, `consentActive`, and `oauth_consent_active_tuple_uq`. A canonicalization that differs in
// ORDER, DEDUPE or WHITESPACE raises no error — it makes [AuthorizationStore.FindActiveConsent] miss
// an existing consent (so every login re-prompts) and makes ResolveAccess's JOIN fail for tokens
// minted under the other form, i.e. EVERY MCP REQUEST 401s with a perfectly valid token. Frozen with
// golden vectors in pure_test.go.
//
// The three steps and why each is spelled out rather than taken from the stdlib:
//
//  1. TRIM with Kotlin's set, not Go's. Kotlin `String.trim()` trims by `Char.isWhitespace()` =
//     `Character.isWhitespace(c) || Character.isSpaceChar(c)`; `strings.TrimSpace` trims by
//     `unicode.IsSpace`. 14-auth.md Q4: the two differ in BOTH directions — Kotlin trims the
//     Java-specific separator controls U+001C..U+001F, which Go does not, and Go trims U+0085 (NEL),
//     which Kotlin does not (it is category Cc, so neither Java predicate matches). See
//     [isKotlinWhitespace].
//  2. DROP EMPTIES AFTER TRIMMING, so a whitespace-only element disappears. Note this side filters
//     `isNotEmpty` while `MCPTokenStore.ResolveAccess`'s split filters `isNotBlank` — equivalent on
//     canonical input, and the asymmetry is reproduced on both sides rather than unified.
//  3. SORT AND DEDUPE by Kotlin's natural String order, which is UTF-16 CODE-UNIT lexicographic.
//     Go's byte order agrees for everything in the BMP and disagrees above U+FFFF (a surrogate pair
//     sorts before U+E000..U+FFFF in UTF-16 but after in UTF-8), so [lessUTF16] does the comparison
//     on code units. The route path guarantees ASCII (`/oauth/authorize` rejects anything outside
//     MCPAScopes), but RememberConsent and FindActiveConsent are library calls with no such guard.
func CanonicalScopes(scopes []string) string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if t := trimKotlin(s); t != "" {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, compareUTF16)
	out = slices.Compact(out)
	return strings.Join(out, " ")
}

// isKotlinWhitespace is `Char.isWhitespace()` on the JVM:
// `Character.isWhitespace(c) || Character.isSpaceChar(c)`.
//
//	Character.isWhitespace = Zs\{U+00A0,U+2007,U+202F} ∪ Zl ∪ Zp ∪ {U+0009..U+000D} ∪ {U+001C..U+001F}
//	Character.isSpaceChar  = Zs ∪ Zl ∪ Zp                      (the non-breaking ones included)
//	union                  = Zs ∪ Zl ∪ Zp ∪ {U+0009..U+000D} ∪ {U+001C..U+001F}
//
// U+0085 (NEL) is category Cc and is in NEITHER Java predicate, so it is deliberately absent even
// though `unicode.IsSpace` includes it.
func isKotlinWhitespace(r rune) bool {
	if (r >= 0x09 && r <= 0x0D) || (r >= 0x1C && r <= 0x1F) {
		return true
	}
	return unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}

// trimKotlin is Kotlin's `String.trim()`. See [isKotlinWhitespace].
func trimKotlin(s string) string { return strings.TrimFunc(s, isKotlinWhitespace) }

// isBlankKotlin is Kotlin's `String.isBlank()`: empty, or every character is [isKotlinWhitespace].
func isBlankKotlin(s string) bool { return trimKotlin(s) == "" }

// compareUTF16 is Kotlin's `String.compareTo` — lexicographic over UTF-16 CODE UNITS, then length.
// See step 3 of [CanonicalScopes].
func compareUTF16(a, b string) int {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------------------------
// The hashes — McpOAuth.kt:22-28
// ---------------------------------------------------------------------------------------------

// SHA256Hex is `sha256Hex(value)` (McpOAuth.kt:22-24): UTF-8 → SHA-256 → 64 lowercase hex chars.
//
// 🔒 INV-A14-5 — THREE independent SHA-256-hex helpers write the SAME `proxy_token.token_hash`
// column and must agree byte for byte: this one, [token.Hash] (Tokens.kt:91-94) and
// DaemonSession.kt:44-46's private copy. They agree today, and "they agree today" is a claim about
// the present, not a contract, so the port keeps three call sites with three tests rather than
// collapsing them (14-auth.md:307-315). Do not replace this body with a call into internal/token.
//
// ⚠️ The intermediate `sum` is REQUIRED, not style: sha256.Sum256 returns a [32]byte VALUE and Go
// cannot slice an unaddressable value, so `hex.EncodeToString(sha256.Sum256(x)[:])` does not compile.
func SHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// PKCES256 is `pkceS256(verifier)` (McpOAuth.kt:26-28) — the RFC 7636 S256 challenge, 43 unpadded
// base64url characters.
//
// 🔒 The verifier is encoded as US-ASCII, not UTF-8, and Java's `String.getBytes(US_ASCII)` is LOSSY:
// an unmappable character becomes `?` (0x3F) rather than throwing. That is reproduced by
// [asciiLossyBytes]. 14-auth.md Q1 works through why it is not exploitable — a non-ASCII verifier
// hashes to a preimage containing `?`, which can never itself be a valid verifier — but the
// disposition is REPRODUCE + PIN either way, because rejecting non-ASCII outright is a narrowing and
// a narrowing is its own decision. `TestPKCES256EncodesTheVerifierAsLossyUSASCII` is the pin.
//
// RawURLEncoding is base64url WITHOUT padding, matching `getUrlEncoder().withoutPadding()`; plain
// URLEncoding would append `=` and break every comparison.
func PKCES256(verifier string) string {
	sum := sha256.Sum256(asciiLossyBytes(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// asciiLossyBytes is Java's `String.getBytes(StandardCharsets.US_ASCII)`: every code point above
// U+007F becomes a single `?`.
//
// Ranging over a Go string yields ONE rune per code point (and U+FFFD for each invalid byte), which
// matches Java's encoder emitting one replacement per unmappable code point — including for a
// surrogate PAIR, which Java treats as one unmappable character rather than two.
func asciiLossyBytes(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0x7F {
			out = append(out, '?')
			continue
		}
		out = append(out, byte(r))
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// The two PKCE validators — McpOAuth.kt:30-36
// ---------------------------------------------------------------------------------------------

// IsValidPKCEChallenge is `isValidPkceChallenge(challenge)` (McpOAuth.kt:30-32):
// `challenge.length == 43 && challenge.all { it.isLetterOrDigit() || it == '-' || it == '_' }`.
//
// ⚠️ F29 — Kotlin's `Char.isLetterOrDigit()` is UNICODE-AWARE, so `ᄀ`, `é` and `٣` all pass. A
// challenge of 43 Hangul jamo satisfies this predicate AND V7's `CHECK (char_length BETWEEN 43 AND
// 128)`, so it is storable — but it can never equal any [PKCES256] output, so the code is simply
// unredeemable. Fail-closed, therefore not a vulnerability, but it IS a divergence trap: a port
// written as `strings.ContainsRune("A-Za-z0-9-_", r)` accepts a STRICTLY SMALLER set. That would be
// an improvement, and the area doc's instruction is to reproduce it rather than let the tightening
// be discovered later as an unexplained diff.
//
// Both the length and the character walk are over UTF-16 CODE UNITS, because Kotlin's `length` and
// `Char` are. That is observable: an astral letter such as U+1D400 is category Lu, so a rune-wise
// port would ACCEPT it while Kotlin sees two surrogates (category Cs, not letters) and rejects.
//
// ⚠️ The app is also STRICTER than the schema — it demands exactly 43 where V7 allows 43..128 and
// its comment claims it "pins it to the RFC 7636 length range". The 44..128 range is unreachable
// through any code path. Inconsistency, not a bug; both halves reproduced.
func IsValidPKCEChallenge(challenge string) bool {
	units := utf16.Encode([]rune(challenge))
	if len(units) != 43 {
		return false
	}
	for _, u := range units {
		r := rune(u)
		if isLetterOrDigitJVM(r) || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

// IsValidPKCEVerifier is `isValidPkceVerifier(verifier)` (McpOAuth.kt:34-36) — RFC 7636's
// `unreserved` charset, with the same Unicode-aware caveat as [IsValidPKCEChallenge].
//
// 🔒 INV-A14-7 — verifier validation runs BEFORE the hash comparison and is a SEPARATE rejection
// reason, but both land in the same `return null` (McpOAuth.kt:194-197), so an invalid-shape verifier
// and a wrong verifier are indistinguishable to the client. Deliberate: the token endpoint must not
// tell a client WHY an exchange failed beyond `invalid_grant`, or it becomes an oracle for probing
// code state.
func IsValidPKCEVerifier(verifier string) bool {
	units := utf16.Encode([]rune(verifier))
	if len(units) < 43 || len(units) > 128 {
		return false
	}
	for _, u := range units {
		r := rune(u)
		if isLetterOrDigitJVM(r) || r == '-' || r == '.' || r == '_' || r == '~' {
			continue
		}
		return false
	}
	return true
}

// isLetterOrDigitJVM is `Character.isLetterOrDigit(c)` = `isLetter(c) || isDigit(c)`, i.e. the five
// letter categories (Lu, Ll, Lt, Lm, Lo — Go's unicode.IsLetter) or DECIMAL_DIGIT_NUMBER (Nd — Go's
// unicode.IsDigit). Note `Character.isDigit` is Nd only: No and Nl do NOT count, so `Ⅴ` (U+2164,
// Nl) and `½` (U+00BD, No) are rejected by both languages.
func isLetterOrDigitJVM(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// ---------------------------------------------------------------------------------------------
// randomSecret — McpOAuth.kt:38-43
// ---------------------------------------------------------------------------------------------

// RandomSecret is `randomSecret(prefix, bytes = 32)` (McpOAuth.kt:40-43): `bytes` CSPRNG bytes,
// unpadded base64url, prefixed. 32 bytes ⇒ 43 characters after the prefix; 24 ⇒ 32; 18 ⇒ 24.
//
// The prefix registry, verbatim from 14-auth.md §3:
//
//	pmc_   32   authorization code           McpOAuth.kt:134
//	pma_   32   MCP access token             :355
//	pmr_   32   MCP refresh token            :356
//	pmf_   24   refresh-FAMILY id            :212
//	csrf_  18   OAuth consent-form CSRF      OAuthRoutes.kt:60,232
//
// ⚠️ `pmf_` IS NOT A CREDENTIAL. It is stored in CLEARTEXT in `proxy_token.refresh_family` and is the
// key [AuthorizationStore.revokeFamily] deletes by. It must never be accepted as a bearer token; it
// comes from the CSPRNG only so it is unguessable in logs.
//
// ⚠️ F22 — `pmr_` COLLIDES with A4's daemon renewal tokens (DaemonSession.kt:33-36). Different
// tables, no cross-acceptance (INV-A14-17's kind filter), so not an authentication hazard — but a
// leaked `pmr_…` cannot be typed during incident response without trying both tables.
//
// The Kotlin cannot fail here (SecureRandom.nextBytes does not throw); Go's crypto/rand read is
// surfaced as an error rather than swallowed, matching internal/oidc's RandomOpaqueToken. A silently
// predictable authorization code is the one outcome this must never produce.
func RandomSecret(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: CSPRNG read failed: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
