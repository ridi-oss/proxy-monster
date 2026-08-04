package oidc

import (
	"strings"
	"unicode"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
)

// ReservedGroupPrefix is `OidcGroupMapping.Companion.RESERVED_GROUP_PREFIX` (auth/Oidc.kt:112).
//
// ⚠️ This is a NAME-prefix notion of "reserved", while A3's route-level guard uses a COLUMN notion
// (`isSystemGroupByName` tests `app_group.source = 'SYSTEM'`, Users.kt:319-324). Two independent
// definitions of "protected group" that happen to coincide for the seeded rows. Not a bug — but a
// port must not merge them without checking both call sets.
const ReservedGroupPrefix = "system:"

// IsReservedGroupName is `fun isReservedGroupName(name)` (auth/Oidc.kt:114) —
// `name.startsWith(RESERVED_GROUP_PREFIX, ignoreCase = true)`.
//
// The comparison is written rune-by-rune rather than as strings.EqualFold over a byte slice. Kotlin's
// ignoreCase startsWith folds CHAR BY CHAR, so a fold variant whose UTF-8 encoding is a different
// LENGTH (U+212A KELVIN SIGN folds to 'k') still matches there; slicing name[:len(prefix)] would cut
// such a rune in half and silently miss it. Since the whole purpose of the function is that "no fold
// variant slips through", the loop is worth its ten lines.
func IsReservedGroupName(name string) bool {
	p := []rune(ReservedGroupPrefix)
	i := 0
	for _, r := range name {
		if i == len(p) {
			return true
		}
		if unicode.ToLower(r) != unicode.ToLower(p[i]) {
			return false
		}
		i++
	}
	return i == len(p)
}

// GroupMapping is `data class OidcGroupMapping(val map: Map<String, String>, val prefix: String?)`
// (auth/Oidc.kt:103).
//
// The Kotlin declares it ONCE, in the `auth` module, and `Config.kt:6` reaches it through a
// `typealias`. The port keeps that seam: [config.OIDCGroupMapping] carries the parsed value because
// `Config.fromEnv` needs it at boot, and this type — which owns the RESOLVER — converts from it via
// [FromConfig]. There is exactly one parse implementation and exactly one resolve implementation; see
// [ParseGroupMapping] for why the parse one stays in internal/config.
type GroupMapping struct {
	// Map is PM_OIDC_GROUP_MAP: IdP group name → local pm-group name. Operator-set, therefore
	// TRUSTED — that asymmetry against the IdP's untrusted claim is INV-A14-34, below.
	Map map[string]string
	// Prefix is PM_OIDC_GROUP_PREFIX, nil when unset or empty.
	Prefix *string
}

// FromConfig lifts the boot-parsed value into the resolving type.
func FromConfig(m config.OIDCGroupMapping) GroupMapping {
	return GroupMapping{Map: m.Map, Prefix: m.Prefix}
}

// ParseGroupMapping is `OidcGroupMapping.parse(mapEnv, prefixEnv)` (auth/Oidc.kt:117-125).
//
// It DELEGATES to [config.ParseOIDCGroupMapping] rather than re-deriving the six parse rules, because
// two copies of that function is exactly how the `y=` / `=x` / `a=b=c` / last-duplicate-wins /
// blank-vs-empty-prefix edge cases drift apart. The Kotlin has one implementation and so does this.
// (config's own doc records the F39/F63 asymmetry it reproduces: `isNotEmpty` on the prefix but
// `isBlank` on the map entries, so a prefix of " " survives while a blank map key is dropped.)
func ParseGroupMapping(mapEnv, prefixEnv *string) GroupMapping {
	return FromConfig(config.ParseOIDCGroupMapping(mapEnv, prefixEnv))
}

// Resolve is `fun resolve(idpGroups: List<String>): Set<String>` (auth/Oidc.kt:104-109).
//
// The Kotlin returns a LinkedHashSet, so the result is deduped AND ordered by first appearance in
// idpGroups. A []string preserves both; a Go map would silently randomise the order that
// [DirectoryProvisioner.Provision] then feeds to ensureGroup, which is observable in the order rows
// are created on a fresh install.
//
// The five steps, in order:
//
//  1. 🔒 INV-A14-34 — an EXPLICIT map entry WINS UNCONDITIONALLY, including one targeting the
//     reserved namespace. `PM_OIDC_GROUP_MAP` is operator-set, i.e. TRUSTED input, and the trusted
//     map IS the admin path: a port that applied the reserved-name filter uniformly to both branches
//     would lock operators out of ever granting `system:admin` via SSO. OidcGroupMappingTest case 7
//     pins it.
//  2. Otherwise strip Prefix when the group starts with it — CASE-SENSITIVELY, unlike step 4.
//  3. Drop a name that is BLANK after stripping (`raw.ifBlank { null }`). Blank, not empty: a
//     whitespace-only remainder is dropped too.
//  4. 🔒 INV-A14-33 — drop anything in the reserved `system:` namespace, CASE-INSENSITIVELY. Without
//     this an IdP group literally named `system:admin` — or `proxy-monster-system:admin` under a
//     prefix — would self-assign the seeded admin group on first login. Case 6 pins all four
//     sub-cases.
//  5. Dedupe, first appearance wins.
func (m GroupMapping) Resolve(idpGroups []string) []string {
	out := make([]string, 0, len(idpGroups))
	seen := make(map[string]struct{}, len(idpGroups))
	add := func(name string) {
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	for _, group := range idpGroups {
		if mapped, ok := m.Map[group]; ok {
			add(mapped) // step 1 — trusted, unfiltered.
			continue
		}
		raw := group
		if m.Prefix != nil && strings.HasPrefix(group, *m.Prefix) {
			raw = strings.TrimPrefix(group, *m.Prefix) // step 2.
		}
		if strings.TrimSpace(raw) == "" { // step 3 — Kotlin's isBlank.
			continue
		}
		if IsReservedGroupName(raw) { // step 4.
			continue
		}
		add(raw) // step 5.
	}
	return out
}
