package identity

import (
	"slices"
	"testing"
)

// Port of EffectiveRolesTest.kt (26 LOC, 4 cases, unit — no DB). 06-query-decision.md:628 counts it
// under A6 because `effectiveRoles` lives in Query.kt:197 there; the function is hosted in this
// package in the Go port (see doc.go), so its tests come with it.
//
// The four Kotlin cases assert SET equality. Go has no set literal, so assertRoleSet compares
// membership and rejects duplicates — a Kotlin Set cannot hold one, and neither may this slice.
//
// The fifth case is NEW and has no Kotlin counterpart: it pins the ORDER. Kotlin gets first-occurrence
// order for free from LinkedHashSet, so no Kotlin test had to state it; the Go port has to choose a
// representation, and the choice is only correct if it is asserted. See doc.go on why the order is
// observable.

// KT: EffectiveRolesTest.kt#group grants a role
func TestEffectiveRoles_GroupGrantsARole(t *testing.T) {
	got := EffectiveRoles(nil, nil, []string{"pii-reader"})
	if !slices.Contains(got, "pii-reader") {
		t.Errorf("EffectiveRoles(_, _, [pii-reader]) = %v, want it to contain pii-reader", got)
	}
}

// KT: EffectiveRolesTest.kt#principal in no group unaffected
func TestEffectiveRoles_PrincipalInNoGroupUnaffected(t *testing.T) {
	assertRoleSet(t, EffectiveRoles([]string{"analyst"}, nil, nil), "analyst")
}

// KT: EffectiveRolesTest.kt#union dedupes across sources
func TestEffectiveRoles_UnionDedupesAcrossSources(t *testing.T) {
	got := EffectiveRoles([]string{"analyst"}, []string{"pii-reader"}, []string{"pii-reader", "analyst"})
	assertRoleSet(t, got, "analyst", "pii-reader")
}

// KT: EffectiveRolesTest.kt#all empty invents no roles
func TestEffectiveRoles_AllEmptyInventsNoRoles(t *testing.T) {
	assertRoleSet(t, EffectiveRoles(nil, nil, nil))
}

// TestEffectiveRoles_PreservesFirstOccurrenceOrder is a Go-port addition, not a ported case.
//
// Kotlin's `(base + grant + group).toSet()` is a LinkedHashSet: deduplicated, ordered by first
// occurrence, and `Query.kt:366` hands exactly that order to the decision DTO's
// `effectiveRoles: List<String>`, which reaches the audit record, web/ and gRPC. A Go port that
// returned a map would randomise the wire order and turn every differential-conformance run into
// noise. This asserts the property the representation was chosen for.
func TestEffectiveRoles_PreservesFirstOccurrenceOrder(t *testing.T) {
	got := EffectiveRoles(
		[]string{"b", "a"},
		[]string{"a", "c"},
		[]string{"c", "d", "b"},
	)
	want := []string{"b", "a", "c", "d"}
	if !slices.Equal(got, want) {
		t.Errorf("EffectiveRoles order = %v, want %v (base, then grants, then groups; first occurrence wins)", got, want)
	}
}

// assertRoleSet compares a resolved role slice against an expected set: same membership, no
// duplicates. Order is deliberately NOT compared here — the ported Kotlin cases assert set equality,
// and only TestEffectiveRoles_PreservesFirstOccurrenceOrder is about order.
func assertRoleSet(t testing.TB, got []string, want ...string) {
	t.Helper()

	seen := make(map[string]int, len(got))
	for _, name := range got {
		seen[name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("role %q appears %d times in %v; a role set may not hold duplicates", name, n, got)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("role set = %v (%d distinct), want %v (%d)", got, len(seen), want, len(want))
		return
	}
	for _, name := range want {
		if seen[name] == 0 {
			t.Errorf("role set = %v, want it to contain %q", got, name)
		}
	}
}
