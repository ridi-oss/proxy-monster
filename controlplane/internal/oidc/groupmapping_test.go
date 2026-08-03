package oidc

import (
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// Port of OidcGroupMappingTest.kt — 7 cases, "pure tests for the IdP-group → pm-group resolver".
//
// ORACLE: control-plane/src/test/kotlin/.../OidcGroupMappingTest.kt, read this session. The Kotlin
// asserts on Set<String>, which is a LinkedHashSet, so a set-equality assertion there is an
// order-INSENSITIVE assertion over an order-PRESERVING value. Resolve returns []string, so these
// assertions are STRICTER than the Kotlin's: they pin the order too. That is deliberate — the order
// reaches ensureGroup and therefore the order rows are created in.

func mapping(m map[string]string, prefix *string) GroupMapping {
	if m == nil {
		m = map[string]string{}
	}
	return GroupMapping{Map: m, Prefix: prefix}
}

func assertResolves(t *testing.T, m GroupMapping, in []string, want ...string) {
	t.Helper()
	got := m.Resolve(in)
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve(%v) = %v, want %v", in, got, want)
	}
}

// --- Case 1 · `parse reads idpGroup=pmGroup pairs and ignores malformed entries`
func TestParseGroupMapping_IgnoresMalformedEntries(t *testing.T) {
	m := ParseGroupMapping(
		types.Ptr("proxy-monster-admin=system:admin, proxy-monster-users=acme-users ,junk,=x,y="), nil)

	want := map[string]string{
		"proxy-monster-admin": "system:admin",
		"proxy-monster-users": "acme-users",
	}
	if !reflect.DeepEqual(m.Map, want) {
		t.Errorf("Map = %v, want %v", m.Map, want)
	}
	if m.Prefix != nil {
		t.Errorf("Prefix = %v, want nil", *m.Prefix)
	}
}

// --- Case 2 · `an explicit mapping wins over the prefix rule`
func TestResolve_ExplicitMappingWinsOverPrefix(t *testing.T) {
	m := mapping(map[string]string{"proxy-monster-admin": "system:admin"}, types.Ptr("proxy-monster-"))
	assertResolves(t, m, []string{"proxy-monster-admin"}, "system:admin")
}

// --- Case 3 · `an unmapped group is taken by name with the prefix stripped`
func TestResolve_UnmappedGroupIsPrefixStripped(t *testing.T) {
	m := mapping(nil, types.Ptr("proxy-monster-"))
	assertResolves(t, m, []string{"proxy-monster-analysts", "keep"}, "analysts", "keep")
}

// --- Case 4 · `no prefix keeps unmapped names as-is`
func TestResolve_NoPrefixKeepsNamesAsIs(t *testing.T) {
	assertResolves(t, mapping(nil, nil), []string{"eng", "on-call"}, "eng", "on-call")
}

// --- Case 5 · `a group that is blank after stripping the prefix is dropped`
func TestResolve_BlankAfterStrippingIsDropped(t *testing.T) {
	m := mapping(nil, types.Ptr("proxy-monster-"))
	assertResolves(t, m, []string{"proxy-monster-", "proxy-monster-x"}, "x")
}

// --- Case 6 🔒 · `the reserved system namespace is unreachable via the unmapped fallback`
//
// 🔒 INV-A14-33. All four sub-cases are the Kotlin's, in its order. Without this, an IdP group
// literally named `system:admin` would self-assign the seeded admin group on first login.
func TestResolve_ReservedNamespaceUnreachableViaFallback(t *testing.T) {
	// A raw "system:admin" in the IdP claim, with NO mapping.
	assertResolves(t, mapping(nil, nil), []string{"system:admin"})
	// Nor via prefix-stripping down into the reserved namespace.
	assertResolves(t, mapping(nil, types.Ptr("proxy-monster-")), []string{"proxy-monster-system:admin"})
	// Case-insensitively — no fold variant of the prefix slips through.
	assertResolves(t, mapping(nil, nil), []string{"System:Admin", "SYSTEM:admin"})
	// A non-reserved group alongside a reserved one still resolves; only the reserved one is dropped.
	assertResolves(t, mapping(nil, nil), []string{"system:admin", "analysts"}, "analysts")
}

// --- Case 7 🔒 · `an explicit mapping may target the reserved system namespace`
//
// 🔒 INV-A14-34 — the asymmetry IS the design. PM_OIDC_GROUP_MAP is operator-set (trusted); the IdP
// claim is not. A port that applied the reserved filter to both branches would lock operators out of
// granting `system:admin` via SSO at all.
func TestResolve_ExplicitMappingMayTargetReservedNamespace(t *testing.T) {
	m := mapping(map[string]string{"proxy-monster-admin": "system:admin"}, types.Ptr("proxy-monster-"))
	assertResolves(t, m, []string{"proxy-monster-admin"}, "system:admin")
}

// --- Extra, Go-specific: the LinkedHashSet contract the Kotlin's Set assertions cannot express.
//
// Kotlin's `mapNotNullTo(LinkedHashSet())` dedupes AND preserves first-appearance order. A Go port
// using a map[string]struct{} would pass every case above and randomise this one.
func TestResolve_DedupesPreservingFirstAppearance(t *testing.T) {
	assertResolves(t, mapping(nil, nil),
		[]string{"b", "a", "b", "c", "a"}, "b", "a", "c")

	// Two different IdP groups mapping to one local group collapse to a single entry, at the
	// position of the FIRST of them.
	m := mapping(map[string]string{"x": "shared", "y": "shared"}, nil)
	assertResolves(t, m, []string{"x", "z", "y"}, "shared", "z")
}

// --- Extra: IsReservedGroupName's fold behaviour, which case 6 exercises only through Resolve.
func TestIsReservedGroupName(t *testing.T) {
	for _, name := range []string{"system:", "system:admin", "SYSTEM:ADMIN", "SyStEm:x"} {
		if !IsReservedGroupName(name) {
			t.Errorf("IsReservedGroupName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "system", "syste", "sys:admin", "asystem:admin", " system:admin"} {
		if IsReservedGroupName(name) {
			t.Errorf("IsReservedGroupName(%q) = true, want false", name)
		}
	}
}

// --- Extra: the two nil/empty inputs 14-auth.md calls out as "must produce an EMPTY map, not a
// nil-deref". Kotlin's `"".split(',')` yields [""], which fails the '=' test; Go's
// strings.Split("", ",") also yields [""] — the behaviours coincide, but only by accident, so both
// are pinned.
func TestParseGroupMapping_NilAndEmptyBothYieldAnEmptyMap(t *testing.T) {
	for _, in := range []*string{nil, types.Ptr("")} {
		m := ParseGroupMapping(in, nil)
		if m.Map == nil {
			t.Fatal("Map is nil — every caller indexes it without a guard")
		}
		if len(m.Map) != 0 {
			t.Errorf("Map = %v, want empty", m.Map)
		}
		// And it must still resolve without panicking.
		assertResolves(t, m, []string{"eng"}, "eng")
	}
}

// --- Extra 🔒: F39/F63's prefix asymmetry, reproduced not fixed. `isNotEmpty` on the prefix but
// `isBlank` on the map entries, so a prefix of " " SURVIVES while a blank map key is dropped.
func TestParseGroupMapping_F39_WhitespacePrefixSurvives(t *testing.T) {
	m := ParseGroupMapping(nil, types.Ptr(" "))
	if m.Prefix == nil || *m.Prefix != " " {
		t.Fatalf("Prefix = %v, want a surviving single space (F39)", m.Prefix)
	}
	if m := ParseGroupMapping(nil, types.Ptr("")); m.Prefix != nil {
		t.Errorf("an EMPTY prefix must become nil, got %q", *m.Prefix)
	}
}
