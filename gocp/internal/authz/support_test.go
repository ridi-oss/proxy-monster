package authz

import (
	"sort"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

// Test support for the 53 no-DB cases 02-authz.md §10 classifies as `unit` — the suites that construct
// CedarEngine(List<Pair<Long,String>>) directly, with no store, no Postgres and no Testcontainers.
//
// Fixtures come from the frozen spike corpus at cedar-spike/corpus/verdicts.json, whose policy sources
// and expectations were extracted from the Kotlin test files and cross-checked against a second oracle
// (Rust Cedar 4.3.3 via cedar-wasm, AGREE 184 / DISAGREE 0 over 186 records). Every test below carries
// its Kotlin case name VERBATIM as a comment.

// engineFor builds an in-memory CedarEngine over an id -> source map, feeding sources in ascending id
// order to match CedarPolicyStore.enabledSources()'s `ORDER BY id`.
func engineFor(t *testing.T, policies map[int64]string) *CedarEngine {
	t.Helper()
	e, err := NewCedarEngineFromSources(sourcesOf(policies))
	if err != nil {
		t.Fatalf("CedarEngine construction failed: %v", err)
	}
	return e
}

func sourcesOf(policies map[int64]string) []PolicySource {
	ids := make([]int64, 0, len(policies))
	for id := range policies {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]PolicySource, 0, len(ids))
	for _, id := range ids {
		out = append(out, PolicySource{ID: id, Src: policies[id]})
	}
	return out
}

// stubRoles is the RoleSource the unit suites wire in: a literal principal -> roles map, which is
// exactly what the Kotlin tests pass (Authz never resolves roles itself — RoleSource is the port).
func stubRoles(m map[string][]string) RoleSource {
	return RoleSourceFunc(func(principal string) []string { return m[principal] })
}

// authzFor is the standard unit fixture: an in-memory engine, no policy store, a literal role map.
func authzFor(t *testing.T, policies map[int64]string, roles map[string][]string) *Authz {
	t.Helper()
	return New(engineFor(t, policies), nil, stubRoles(roles))
}

func ptr[T any](v T) *T { return &v }

// mustPolicy parses a single Cedar statement, for tests that validate against an explicitly chosen
// schema instead of going through CedarSchema.Validate's self-augmentation.
func mustPolicy(t *testing.T, src string) *cedar.Policy {
	t.Helper()
	var p cedar.Policy
	if err := p.UnmarshalCedar([]byte(src)); err != nil {
		t.Fatalf("policy did not parse: %v", err)
	}
	return &p
}

func assertAllow(t *testing.T, d AuthzDecision, what string) {
	t.Helper()
	if !d.Allowed {
		t.Errorf("%s: expected Allow, got Deny(%q)", what, d.Reason)
	}
}

func assertDeny(t *testing.T, d AuthzDecision, what string) {
	t.Helper()
	if d.Allowed {
		t.Errorf("%s: expected Deny, got Allow", what)
	}
}

func assertValid(t *testing.T, src string) {
	t.Helper()
	if errs := DefaultSchema.Validate(src); len(errs) > 0 {
		t.Errorf("expected %q to validate, got errors %v", src, errs)
	}
}

func assertInvalid(t *testing.T, src string) {
	t.Helper()
	if errs := DefaultSchema.Validate(src); len(errs) == 0 {
		t.Errorf("expected %q to be rejected, got no errors", src)
	}
}

func assertStrings(t *testing.T, got, want []string, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v, want %v", what, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: got %v, want %v", what, got, want)
			return
		}
	}
}
