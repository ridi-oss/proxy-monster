package query_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/identity"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// DeactivationEnforcementDbTest.kt — 113 LOC, 4 cases (06-query-decision.md §7, step 5).
//
// The authoritative fail-closed regression for deprovisioning under the enforcement engine.
//
// 🔒 WHY THE OBVIOUS SIGNAL IS THE WRONG ONE. "RoleResolver erased their roles" is FAIL-OPEN here, and
// that inversion is the whole point of the suite: decideQuery builds column actions only from
// role-attached policies, and a statement that produces NO masks is an ALLOW (step 26). So a
// deactivated principal whose role set collapses to the empty set gets *no* masked-column policy to
// match, *no* mask, and therefore a cleartext ALLOW on the very query that MASK'd while they were
// employed — MORE access after deprovision, not less. Step 5's structural DENY, placed before role
// resolution ever runs, is what closes that.
//
// Each case therefore drives the decide → execute → mask harness end to end, not
// `RoleResolver.resolve` in isolation: checking only that the role set went empty is precisely the
// signal that is fail-open.
func TestDeactivationEnforcementDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EnginePostgres)
	ctx := context.Background()
	userGroups := identity.NewUserGroupStore(fx.Store.Pool)

	// grantAnalystRole gives `principal` the fixture's seeded `analyst` (MASK-on-rrn) role via a
	// DIRECT assignment — the Kotlin's private helper of the same name, over the production store.
	grantAnalystRole := func(t *testing.T, principal string) {
		t.Helper()
		assignExistingRole(t, fx, principal, dbtest.FixtureRole)
	}

	// deprovision is `fx.userGroupStore.createUser(AppUserInput(principal), …)` +
	// `setUserActive(principal, false)`: an app_user row now exists for this principal and is
	// deactivated — the SCIM active=false / IdP-liveness-failure path.
	//
	// ⚠️ TODO(A3): the Kotlin calls UserGroupStore.createUser/setUserActive, which internal/identity has
	// not ported (it has IsDeactivated and RolesForPrincipal only). The seeder writes the same two rows;
	// re-point at the production methods when they land — they own the revocation side effects too.
	deprovision := func(t *testing.T, principal string) {
		t.Helper()
		fx.Seed.User(principal)
		fx.Seed.SetUserActive(principal, false)
	}

	// `a deactivated principal is denied instead of falling open to cleartext`
	t.Run("a deactivated principal is denied instead of falling open to cleartext", func(t *testing.T) {
		const principal = "deactivated-analyst-1@example.com"
		grantAnalystRole(t, principal)

		// Sanity: while active, the same query MASKs the PII column as expected.
		active := runAs(t, fx, principal, "select id, rrn from users order by id")
		if action(active) != pb.EnfAction_MASK {
			t.Fatalf("sanity: query must MASK while the principal is active; got %v (%s)",
				action(active), respReason(active))
		}

		// Deprovision. Without the fail-closed gate, RoleResolver would resolve to the empty set, no
		// column policy would match, and the decision would ALLOW — cleartext rrn leaking to a
		// deprovisioned user.
		deprovision(t, principal)
		deactivated, err := userGroups.IsDeactivated(ctx, principal)
		if err != nil || !deactivated {
			t.Fatalf("isDeactivated(%s) = %v, %v — want true", principal, deactivated, err)
		}

		r := runAs(t, fx, principal, "select id, rrn from users order by id")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("a deactivated principal must be denied, not fall open to ALLOW; got %v", action(r))
		}
		if len(r.Rows) != 0 {
			t.Fatalf("a DENY must not return rows (no cleartext rrn leak), got %d", len(r.Rows))
		}
		if !strings.Contains(strings.ToLower(respReason(r)), "deprovision") {
			t.Errorf("deny reason should call out deprovisioning: %s", respReason(r))
		}
	})

	// `a deactivated principal is denied even for a non-sensitive lineage query`
	t.Run("a deactivated principal is denied even for a non-sensitive lineage query", func(t *testing.T) {
		const principal = "deactivated-nonsensitive@example.com"
		deprovision(t, principal)

		// Even a query touching no PII at all (would otherwise ALLOW cleanly) must still be denied —
		// the deactivation gate sits before the lineage triad, not folded into it.
		r := runAs(t, fx, principal, "select id, region from users order by id")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("deactivation must deny regardless of the query's own sensitivity; got %v", action(r))
		}
		if len(r.Rows) != 0 {
			t.Fatalf("a DENY must not return rows, got %d", len(r.Rows))
		}
	})

	// 🔒 `a deactivated principal is denied even a READONLY_META passthrough (the gate dominates passthrough)`
	//
	// INV-A6-8. This is the case 06-query-decision.md names as the pin for the ordering: step 5 sits
	// BEFORE step 14's metadata/session passthrough dispatch, so a deprovisioned principal cannot ride
	// a `readonly-meta` passthrough to an ALLOW. A regression that moved the gate after passthrough
	// classification would silently reopen it, and ONLY this case would catch it — the ALLOW half above
	// it proves the very same statement passes through for the very same principal while active, so the
	// DENY below cannot be attributed to anything else.
	t.Run("a deactivated principal is denied even a READONLY_META passthrough (the gate dominates passthrough)", func(t *testing.T) {
		const principal = "deactivated-passthrough@example.com"
		// The datasource.connect gate runs ahead of passthrough classification too, so `select
		// version()` needs a connect grant to ALLOW even while active — grant `analyst` (which has one)
		// so this isolates the deactivation gate, not the connect gate.
		grantAnalystRole(t, principal)

		// `select version()` is admitted as a READONLY_META passthrough (no lineage, no policy); for any
		// non-deactivated, connected principal it ALLOWs straight through. This principal has no
		// app_user row yet, so isDeactivated is false.
		activePass := runAs(t, fx, principal, "select version()")
		if action(activePass) != pb.EnfAction_ALLOW {
			t.Fatalf("sanity: a READONLY_META statement passes through while active; got %v (%s)",
				action(activePass), respReason(activePass))
		}

		deprovision(t, principal)

		r := runAs(t, fx, principal, "select version()")
		if action(r) != pb.EnfAction_DENY {
			t.Fatalf("INV-A6-8 VIOLATED: deactivation must dominate passthrough classification; got %v",
				action(r))
		}
		if len(r.Rows) != 0 {
			t.Fatalf("a DENY must not return rows, got %d", len(r.Rows))
		}

		// ⚠️ DELIBERATE STRENGTHENING over the Kotlin, and the ONLY assertion in this case that actually
		// bites. MEASURED by mutation: moving step 5 to sit after step 14's passthrough dispatch leaves
		// the two assertions above PASSING, because the production RoleResolver ALSO short-circuits a
		// deactivated principal to the empty role set (RoleResolver.kt:45-54) — so the reordered
		// decision still DENYs, at step 12's `datasource.connect` gate, with "no access to datasource".
		// A DENY for the wrong reason is not the invariant: this fixture's connect grant happens to be
		// role-scoped, and on a datasource whose connect is role-AGNOSTIC (a `permit(principal, action ==
		// datasource.connect, resource)` policy, or the shipped system:development preset) that
		// substitute deny does not exist and the passthrough ALLOWs.
		//
		// So the verdict alone cannot distinguish "the gate dominated the passthrough" from "the empty
		// role set happened to fail a later gate" — which is the exact fail-open signal this suite's own
		// doc comment warns against. Asserting the deny is the DEPROVISIONED one closes that.
		if !strings.Contains(strings.ToLower(respReason(r)), "deprovision") {
			t.Errorf("INV-A6-8 VIOLATED: the DENY must be the deprovisioning deny (step 5), not a "+
				"later gate denying because the role set collapsed; got %s", respReason(r))
		}
	})

	// `reactivating a principal restores normal enforcement`
	t.Run("reactivating a principal restores normal enforcement", func(t *testing.T) {
		const principal = "reactivated-analyst@example.com"
		grantAnalystRole(t, principal)
		deprovision(t, principal)
		if got := action(runAs(t, fx, principal, "select id, rrn from users order by id")); got != pb.EnfAction_DENY {
			t.Fatalf("decision while deactivated = %v, want DENY", got)
		}

		fx.Seed.SetUserActive(principal, true)
		r := runAs(t, fx, principal, "select id, rrn from users order by id")
		if action(r) != pb.EnfAction_MASK {
			t.Fatalf("reactivation must restore normal (masked) enforcement, not a stuck DENY; got %v (%s)",
				action(r), respReason(r))
		}
	})
}
