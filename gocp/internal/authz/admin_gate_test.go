package authz

import (
	_ "embed"
	"encoding/json"
	"testing"
)

// Port of AdminGateTest.kt — 86 LOC, 2 cases. 02-authz.md §10.
// Case names verbatim from the Kotlin.
//
// 📌 CORRECTION carried from the spike corpus (corpus/README.md): §10 classifies this suite as `unit`,
// but it is in fact DB-backed — requireDockerOrSkip + Flyway + SharedPostgres (AdminGateTest.kt:43-51).
// What it needs from the database is only the SEEDED POLICY SET and a literal role map, both of which
// are static, so the CEDAR half ports without a container: the 29 SYSTEM rows shipping enabled=true are
// frozen in testdata/migration_enabled.json, extracted from V8__seed.sql and cross-checked against
// PolicyOriginDbTest.kt:116-124's shippedEnabled/shippedDisabled lists and against the golden posture
// digest 6a1bb6ff914c542db83ba609cdd945f4 (PolicyOriginDbTest.kt:69).
//
// TODO(A2): the store-backed half — that these rows arrive via Flyway and CedarPolicyStore.enabledSources()
// rather than a fixture — belongs with the DB suites (CedarPolicyStoreTest, PolicyOriginDbTest,
// CedarPolicyOriginTest, CedarEngineCacheTest, PresetPolicyDbTest) in a later increment. See D13 for the
// testcontainers-go shape they should use.

//go:embed testdata/migration_enabled.json
var migrationEnabledJSON []byte

type migrationRow struct {
	ID        int64  `json:"id"`
	SystemKey string `json:"systemKey"`
	Name      string `json:"name"`
	Src       string `json:"src"`
}

// migrationEnabledSources is the shipped enabled posture, in `ORDER BY id` order — the order
// CedarPolicyStore.enabledSources() returns and therefore the order the PolicySet is built in.
func migrationEnabledSources(t *testing.T) []PolicySource {
	t.Helper()
	var rows []migrationRow
	if err := json.Unmarshal(migrationEnabledJSON, &rows); err != nil {
		t.Fatalf("migration fixture: %v", err)
	}
	if len(rows) != 29 {
		t.Fatalf("migration fixture has %d enabled rows, want 29", len(rows))
	}
	out := make([]PolicySource, 0, len(rows))
	for _, r := range rows {
		out = append(out, PolicySource{ID: r.ID, Src: r.Src})
	}
	return out
}

// adminGateEngine is AdminGateTest.kt:64-72's policy set: the 29 enabled migration rows plus one
// created USER row, `test-admin-grant`.
//
// Constructing it at all is a real assertion: 🔒 INV-A2-17 means CedarEngine construction validates
// EVERY source, so this failing would mean a shipped SYSTEM policy does not validate under cedar-go
// strict. That is S1's whole question, answered here against the real corpus rather than a fixture.
func adminGateEngine(t *testing.T) *CedarEngine {
	t.Helper()
	sources := append(migrationEnabledSources(t), PolicySource{
		ID:  1,
		Src: `permit(principal in Role::"system:admin", action in [Action::"admin.datasources", Action::"admin.policies", Action::"admin.identity"], resource);`,
	})
	e, err := NewCedarEngineFromSources(sources)
	if err != nil {
		t.Fatalf("the shipped enabled policy set failed validation: %v", err)
	}
	return e
}

// 1. 🔒 no admin role is denied `admin_policies`
// KT: AdminGateTest.kt#no admin role is denied admin_policies
func TestAdminGate_NoAdminRoleIsDeniedAdminPolicies(t *testing.T) {
	a := New(adminGateEngine(t), nil, stubRoles(map[string][]string{
		"admin@example.com": {"system:admin"},
	}))
	d := a.Authorize("analyst@example.com", ActionAdminPolicies, ResourceSystem{}, AuthzContext{})
	assertDeny(t, d, "analyst@example.com on admin.policies")
}

// 2. system-admin role is allowed `admin_policies`
// KT: AdminGateTest.kt#system-admin role is allowed admin_policies
func TestAdminGate_SystemAdminRoleIsAllowedAdminPolicies(t *testing.T) {
	a := New(adminGateEngine(t), nil, stubRoles(map[string][]string{
		"admin@example.com": {"system:admin"},
	}))
	d := a.Authorize("admin@example.com", ActionAdminPolicies, ResourceSystem{}, AuthzContext{})
	assertAllow(t, d, "admin@example.com on admin.policies")
}

// TestShippedEnabledPolicySetValidates is not a ported case; it is the S1 assertion the ported suites
// only reach incidentally. All 29 shipped enabled SYSTEM policies must validate individually under
// cedar-go strict, and the spike's whole GO verdict rests on that.
func TestShippedEnabledPolicySetValidates(t *testing.T) {
	for _, s := range migrationEnabledSources(t) {
		if errs := DefaultSchema.Validate(s.Src); len(errs) > 0 {
			t.Errorf("shipped policy #%d does not validate: %v\n  src: %s", s.ID, errs, s.Src)
		}
	}
}
