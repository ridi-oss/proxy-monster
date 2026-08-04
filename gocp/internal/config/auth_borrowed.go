package config

import "strings"

// The two symbols in this file belong to the Kotlin `auth/` module (A14, 14-auth.md), not to A1.
// Config.kt reaches them across the module boundary — `import ...auth.clampTtlSeconds` (Config.kt:3)
// and `typealias OidcGroupMapping = ...auth.OidcGroupMapping` (Config.kt:6) — so FromEnv cannot be
// written without them.
//
// TODO(A14): move both to the auth package when A14 lands, and leave a type alias here so this
// package keeps mirroring Config.kt:6's typealias seam. See 14-auth.md §3 and §on OidcGroupMapping.
//
// ⚠️ Do NOT collapse clampTTLSeconds into a single shared helper when A14 lands. F93 / A14 F21 records
// that `clampTtlSeconds`, `TOKEN_MIN_TTL_SECONDS` and `TOKEN_MAX_TTL_SECONDS` are declared TWICE,
// byte-identically, in auth/McpOAuth.kt:15-18 and Tokens.kt:75-81 — and 00-INDEX.md's port
// dispositions table settles it as REPRODUCE BOTH. Duplication is explicitly not grounds for OMIT.

// TokenMinTTLSeconds / TokenMaxTTLSeconds are auth/McpOAuth.kt:15-16.
const (
	TokenMinTTLSeconds int64 = 60
	TokenMaxTTLSeconds int64 = 24 * 3600
)

// clampTTLSeconds is auth/McpOAuth.kt:18 — `ttlSeconds.coerceIn(TOKEN_MIN, TOKEN_MAX)`.
//
// Total, never fails: every input including negatives and MaxInt64 lands in [60, 86400]. 14-auth.md
// §3 warns against a generic min/max on an unsigned type — a negative request must FLOOR to 60, not
// wrap.
//
// INV-A14-3: FromEnv clamping PM_OAUTH_ACCESS_TTL / PM_OAUTH_REFRESH_TTL here (Config.kt:249-250) is
// the FIRST of two deliberate clamps; the token store clamps again at insert. Keep both.
func clampTTLSeconds(ttlSeconds int64) int64 {
	if ttlSeconds < TokenMinTTLSeconds {
		return TokenMinTTLSeconds
	}
	if ttlSeconds > TokenMaxTTLSeconds {
		return TokenMaxTTLSeconds
	}
	return ttlSeconds
}

// OIDCGroupMapping is auth/Oidc.kt:103 — `data class OidcGroupMapping(map, prefix)`.
//
// Only Parse is needed by A1; `resolve` (and INV-A14-33/-34, the reserved-namespace asymmetry) is
// A14's and is deliberately NOT implemented here.
type OIDCGroupMapping struct {
	// Map is the operator-supplied IdP-group → local-group table from PM_OIDC_GROUP_MAP. Never nil
	// after Parse: 14-auth.md notes both the unset and the empty case must yield an EMPTY map.
	Map map[string]string
	// Prefix is PM_OIDC_GROUP_PREFIX, nil when unset or empty.
	Prefix *string
}

// ParseOIDCGroupMapping is auth/Oidc.kt:117-125 (`OidcGroupMapping.parse`), per 14-auth.md §on
// OidcGroupMapping:
//
//  1. Split PM_OIDC_GROUP_MAP on ',', skip any entry with no '='.
//  2. idp = text before the FIRST '=', local = everything after it, both trimmed — so `a=b=c` maps
//     `a` → `b=c`.
//  3. Either side blank ⇒ skip. `junk`, `=x` and `y=` are all dropped.
//  4. Duplicate keys: the LAST one wins (Kotlin's List<Pair>.toMap()).
//  5. prefix = prefixEnv when non-EMPTY.
//
// ⚠️ F39 / F63 — step 5 uses isNotEmpty while step 3 uses isBlank, so a prefix of " " SURVIVES while a
// blank map key is dropped. That asymmetry is REPRODUCEd here, not fixed.
func ParseOIDCGroupMapping(mapEnv, prefixEnv *string) OIDCGroupMapping {
	out := OIDCGroupMapping{Map: map[string]string{}}
	raw := ""
	if mapEnv != nil {
		raw = *mapEnv
	}
	for _, entry := range strings.Split(raw, ",") {
		i := strings.IndexByte(entry, '=')
		if i < 0 {
			continue
		}
		idp := strings.TrimSpace(entry[:i])
		local := strings.TrimSpace(entry[i+1:])
		if idp == "" || local == "" {
			continue
		}
		out.Map[idp] = local
	}
	if prefixEnv != nil && *prefixEnv != "" {
		p := *prefixEnv
		out.Prefix = &p
	}
	return out
}
