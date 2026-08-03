package query_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

// Shared scaffolding for the GATE SUITES of 06-query-decision.md §7 — the twelve files that each
// isolate one step of decideQuery's pipeline. Nothing here asserts anything; every assertion lives in
// the suite that owns it, under its Kotlin case name.
//
// The fixture constructor is enforcement_db_test.go's [newEnforcementFixture], NOT a second one: A6's
// three store seams must be wired to the PRODUCTION stores for every suite in this package, and a
// gate suite deciding against internal/dbtest's direct-SQL stand-ins (TODO(A9)/TODO(A3) in
// enforcement_run.go — the role default is missing active JIT grants and the deactivation
// short-circuit) would be asserting against a different stack than the Kotlin's.
//
// The Kotlin gate suites are `@TestInstance(PER_CLASS)` with a `@BeforeAll` fixture, so one
// EnforcementFixture is shared by every @Test of a class. Each Kotlin class is therefore ONE Go
// top-level Test function with `t.Run` subtests over one fixture, matching both the sharing and the
// declaration order. Where a Kotlin suite deliberately FUSED assertions into a single method to fix
// their order (UnanalyzableGateDbTest, CatalogCoverageGateDbTest — the floor DENY must be observed
// before the permit that persists on the shared fixture is created), the Go form keeps them fused for
// the same reason, and says so.

// shippedClassifier is the Kotlin gate suites' `SystemClassificationService()` — the service over the
// four SHIPPED manifests (postgres 16/17, mysql 8.0/8.4) and the static BaselineDangerousFunctions
// floor. datasource.NewBundledSystemClassificationService is the Go form of those two Kotlin default
// arguments.
//
// ⚠️ Which suites pass it, and which deliberately do NOT, is load-bearing:
//   - UtilityGate / SystemClassificationEnforcement / BaselineDangerousFunctionEnforcement /
//     DiagnosticRedactionDecide pass it, because their subject is what a manifest classifies.
//   - GateSqlglotRegression / KnownGaps / ScannedTableMySql go through EnforcementFixture.Run, whose
//     Kotlin twin `runEnforcedForTest` leaves `systemClassification` at its `= null` default
//     (EnforcementHarness.kt:120). Their dangerous-function denies therefore come from the BASELINE
//     FLOOR alone (classifyFunctions' elvis, steps 16/22) — which is exactly what makes
//     `query_to_xml` denying there a statement about the floor, not about the manifest.
func shippedClassifier(t *testing.T) query.SystemClassifier {
	t.Helper()
	svc, err := datasource.NewBundledSystemClassificationService(false)
	if err != nil {
		t.Fatalf("load the shipped system-classification manifests: %v", err)
	}
	return svc
}

// gateDecide is the gate suites' shared `decide(sql)` / `decideAs(who, sql)`: one statement, one
// principal, over the fixture's CURRENT datasource row, on Channel.WIRE — the channel every gate
// suite decides on.
//
// 🔒 "current datasource row" is the load-bearing part. Every Kotlin gate suite that flips posture
// tags or engine_version re-fetches with `fx.datasourceStore.get(fx.datasource.id)!!` on the very next
// line, because decideQuery reads `ds.tags` and `ds.engineVersion` off the row it is handed.
// [dbtest.EnforcementFixture.SetTags] / SetEngineVersion do that re-read, so this helper just passes
// through what they left behind.
//
// The classifier is a parameter rather than a fixture field because whether one is wired AT ALL is
// itself the subject of BaselineDangerousFunctionEnforcementDbTest case 1.
func gateDecide(
	fx *dbtest.EnforcementFixture, principal, sql string, classifier query.SystemClassifier,
) query.DecisionContext {
	fx.T.Helper()
	return fx.DecideWith(query.DecideQueryInput{
		Principal:            principal,
		SQL:                  sql,
		Channel:              query.ChannelWire,
		SystemClassification: classifier,
	})
}

// assignExistingRole gives `principal` an already-seeded role by name, through the PRODUCTION
// policy store — `fx.policyStore.listRoles().first { it.name == … }` + `createAssignment(...)`.
//
// Role resolution is entirely server-side; a direct `principal_role` row is how a fixture gives a
// principal roles, because no caller may assert a role list (RoleResolver.kt:6-12).
func assignExistingRole(t *testing.T, fx *dbtest.EnforcementFixture, principal, roleName string) {
	t.Helper()
	store := policy.NewPolicyStore(fx.Store.Pool)
	role, err := store.GetRoleByName(context.Background(), roleName)
	if err != nil || role == nil {
		t.Fatalf("read the seeded %q role: role=%v err=%v", roleName, role, err)
	}
	if _, err := store.CreateAssignment(context.Background(), policy.RoleAssignmentInput{
		Principal: principal, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign %s to %s: %v", roleName, principal, err)
	}
}

// grantNewRole is `fx.policyStore.createRole(RoleInput(name))` + `createAssignment(...)`: the
// two-liner the gate suites use to stand up a principal holding exactly one purpose-built role.
//
// It does NOT create the Cedar policy — the caller does, with [dbtest.EnforcementFixture.AddCedarPolicy],
// because WHICH policy the role carries is the subject of the case.
func grantNewRole(t *testing.T, fx *dbtest.EnforcementFixture, principal, roleName string) {
	t.Helper()
	store := policy.NewPolicyStore(fx.Store.Pool)
	role, err := store.CreateRole(context.Background(), policy.RoleInput{Name: roleName})
	if err != nil {
		t.Fatalf("create role %s: %v", roleName, err)
	}
	if _, err := store.CreateAssignment(context.Background(), policy.RoleAssignmentInput{
		Principal: principal, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign %s to %s: %v", roleName, principal, err)
	}
}

// detail renders DecisionContext.Detail for a failure message. The Kotlin interpolates `${r.detail}`,
// which prints "null" for an absent value.
func detail(d query.DecisionContext) string {
	if d.Detail == nil {
		return "null"
	}
	return *d.Detail
}

// wantAction asserts a decision's verdict, quoting the deny reason AND the detail on failure — the two
// fields the Kotlin assertion messages interpolate, and the two that say which gate produced the
// verdict when the verdict alone is ambiguous.
func wantAction(t *testing.T, got query.DecisionContext, want pb.EnfAction, format string, args ...any) {
	t.Helper()
	if got.Action != want {
		t.Errorf("%s: action = %v, want %v (denyReason=%s detail=%s)",
			fmt.Sprintf(format, args...), got.Action, want, reason(got), detail(got))
	}
}

// wantDetailContains is `assertTrue(ctx.detail?.contains(…) == true, "…: ${ctx.detail}")`.
//
// ⚠️ It asserts on DETAIL, not denyReason, wherever the Kotlin does — and the two are not
// interchangeable on every path. structuralDeny and policyDeny set both to the same string, but the
// two RELAY allows (steps 16 and 18) carry their attribution in `detail` with `denyReason` nil, so a
// `sql.unanalyzable` relay is only observable through this field.
func wantDetailContains(t *testing.T, got query.DecisionContext, want, msg string) {
	t.Helper()
	if !strings.Contains(detail(got), want) {
		t.Errorf("%s: detail = %s, want it to contain %q", msg, detail(got), want)
	}
}
