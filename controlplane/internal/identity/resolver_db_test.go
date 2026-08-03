package identity

import (
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// Port of ResolveRolesTest.kt (100 LOC, 4 cases, DB) — 03-identity-scim.md:1304.
//
// The Kotlin builds its state once in @BeforeAll and shares one database across the four cases. Go
// has no PER_CLASS lifecycle, and internal/dbtest hands out a fresh migrated database per call, so
// each case builds its own. That is a divergence in fixture LIFETIME, not in what is asserted —
// and it is strictly stronger: case 1 no longer depends on cases 2-4 having left the table alone.
// ---------------------------------------------------------------------------------------------

const resolvePrincipal = "resolve-roles@example.com"

// seedThreeSources is ResolveRolesTest's @BeforeAll (:45-60): one role per source, all three
// pointing at the same principal — a direct `principal_role` row, a group the principal belongs to
// whose `group_role` grants a role, and an approved (active) JIT grant.
func seedThreeSources(f *fixture) (directRole, groupRole, grantRole int64) {
	directRole = f.seed.Role("direct-role")
	groupRole = f.seed.Role("group-role")
	grantRole = f.seed.Role("grant-role")

	// direct: a principal_role assignment.
	f.seed.AssignRole(resolvePrincipal, directRole)

	// group: app_user + group_member + group_role.
	userID := f.seed.User(resolvePrincipal)
	groupID := f.seed.Group("resolve-roles-group")
	f.seed.GroupMember(groupID, userID)
	f.seed.GroupRole(groupID, groupRole)

	// JIT: an approved access_grant (Kotlin: createRequest + approve(durationSec = 3600)).
	f.grant(resolvePrincipal, grantRole, "1 hour")
	return directRole, groupRole, grantRole
}

// ResolveRolesTest case 1.
func TestResolve_UnionsDirectGroupAndJITGrantRoles(t *testing.T) {
	f := newFixture(t)
	seedThreeSources(f)

	f.assertResolves(resolvePrincipal, "direct-role", "group-role", "grant-role")
}

// ResolveRolesTest case 2 — `a revoked grant is excluded from resolve (activeOnly)`.
func TestResolve_RevokedGrantIsExcluded(t *testing.T) {
	f := newFixture(t)
	directRole, _, grantRole := seedThreeSources(f)

	const principal = "revoked-grant@example.com"
	f.seed.AssignRole(principal, directRole)
	grantID := f.grant(principal, grantRole, "1 hour")
	f.exec(`UPDATE access_grant SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, grantID)

	// "a revoked grant must not contribute a role"
	f.assertResolves(principal, "direct-role")
}

// ResolveRolesTest case 3 — `an expired grant is excluded from resolve (activeOnly)`.
//
// The Kotlin approves with `durationSec = -3600` so `expires_at <= now()`: the grant row exists but
// is stale. resolve() must fail closed on expires_at, not just on revoked_at.
func TestResolve_ExpiredGrantIsExcluded(t *testing.T) {
	f := newFixture(t)
	directRole, _, grantRole := seedThreeSources(f)

	const principal = "expired-grant@example.com"
	f.seed.AssignRole(principal, directRole)
	f.grant(principal, grantRole, "-1 hour")

	// "an expired grant must not contribute a role"
	f.assertResolves(principal, "direct-role")
}

// ResolveRolesTest case 4 — `unknown principal resolves to the empty set (fail-closed)`.
func TestResolve_UnknownPrincipalIsEmpty(t *testing.T) {
	f := newFixture(t)
	seedThreeSources(f)

	f.assertResolves("nobody@example.com")
}

// TestResolve_GrantWithNoExpiryStaysActive covers the arm neither Kotlin case reaches: activeOnly's
// predicate is `expires_at IS NULL OR expires_at > now()`, so a grant with NO expiry never lapses.
// Cases 2 and 3 pin the two ways a grant drops out; this pins the way it does not.
func TestResolve_GrantWithNoExpiryStaysActive(t *testing.T) {
	f := newFixture(t)
	_, _, grantRole := seedThreeSources(f)

	const principal = "eternal-grant@example.com"
	f.grant(principal, grantRole, "")

	f.assertResolves(principal, "grant-role")
}

// ---------------------------------------------------------------------------------------------
// INV-A3-9 / INV-A3-10 — the deactivation short-circuit.
// ---------------------------------------------------------------------------------------------

// TestResolve_DeactivationShortCircuitsEveryRoleSource is 🔒 INV-A3-9, the shape DeprovisionDbTest
// case 6 pins in the Kotlin (03-identity-scim.md:1273): direct ∪ group ∪ JIT all present, then all
// gone on deactivation, then restored on reactivation.
//
// It matters because `directRoles` and the JIT grants are keyed on the principal STRING and are
// independent of `app_user` entirely — only the group arm fails closed on its own (INV-A3-15). Drop
// the short-circuit and a deprovisioned user keeps every direct and JIT role.
func TestResolve_DeactivationShortCircuitsEveryRoleSource(t *testing.T) {
	f := newFixture(t)
	seedThreeSources(f)

	f.assertResolves(resolvePrincipal, "direct-role", "group-role", "grant-role")

	f.exec(`UPDATE app_user SET active = false WHERE principal = $1`, resolvePrincipal)
	if !f.isDeactivated(resolvePrincipal) {
		t.Fatal("fixture: the principal should read as deactivated after active=false")
	}
	f.assertResolves(resolvePrincipal) // the EMPTY set, across all three sources

	// The rows are still there — the short-circuit is what hid them, not a cascade.
	direct, err := f.resolver.DirectRoles(f.ctx, resolvePrincipal)
	if err != nil {
		t.Fatalf("directRoles: %v", err)
	}
	if !slices.Contains(direct, "direct-role") {
		t.Errorf("directRoles = %v, want it to still contain direct-role: INV-A3-9 is a short-circuit "+
			"in resolve, not a filter on the direct source", direct)
	}
	grantRoles, err := f.grants.ListGrantRoles(f.ctx, resolvePrincipal, true)
	if err != nil {
		t.Fatalf("listGrantRoles: %v", err)
	}
	if !slices.Contains(grantRoles, "grant-role") {
		t.Errorf("active grant roles = %v, want it to still contain grant-role", grantRoles)
	}

	f.exec(`UPDATE app_user SET active = true WHERE principal = $1`, resolvePrincipal)
	f.assertResolves(resolvePrincipal, "direct-role", "group-role", "grant-role")
}

// TestResolve_NoAppUserRowIsNotDeactivated is 🔒 INV-A3-10, pinned in the Kotlin by DeprovisionDbTest
// case 7 and ProvisionMergeDbTest case 17.
//
// A purely local `principal_role`-only identity — never synced into the directory — keeps its direct
// roles: there is nothing to deactivate. Inverting this to fail-closed-on-absence would break every
// local-only operator identity and every wire token minted before a directory row existed.
func TestResolve_NoAppUserRowIsNotDeactivated(t *testing.T) {
	f := newFixture(t)
	directRole, _, _ := seedThreeSources(f)

	const localOnly = "local-only@example.com"
	f.seed.AssignRole(localOnly, directRole)

	if f.isDeactivated(localOnly) {
		t.Error("isDeactivated with no app_user row = true, want false (INV-A3-10)")
	}
	f.assertResolves(localOnly, "direct-role")
}

// ---------------------------------------------------------------------------------------------
// UserGroupStore — the two reads this increment ports.
// ---------------------------------------------------------------------------------------------

// TestIsDeactivated_TruthTable states the whole contract in one place: true iff a row EXISTS and is
// inactive. 03-identity-scim.md:533 calls this the most widely depended-on predicate in the area —
// A4, A6, A7, A10 and A3 itself all gate on it — so the three states are worth spelling out.
func TestIsDeactivated_TruthTable(t *testing.T) {
	f := newFixture(t)

	f.seed.User("active@example.com")
	f.seed.User("inactive@example.com")
	f.exec(`UPDATE app_user SET active = false WHERE principal = 'inactive@example.com'`)

	cases := []struct {
		principal string
		want      bool
		why       string
	}{
		{"active@example.com", false, "a row that exists and is active"},
		{"inactive@example.com", true, "a row that exists and is inactive"},
		{"absent@example.com", false, "NO row at all — INV-A3-10, not deactivated"},
	}
	for _, c := range cases {
		if got := f.isDeactivated(c.principal); got != c.want {
			t.Errorf("isDeactivated(%q) = %v, want %v (%s)", c.principal, got, c.want, c.why)
		}
	}
}

// TestIsDeactivatedOn_ReadsTheCallersTransaction pins why the `(principal, c)` overload exists: it
// reads on the CALLER's handle, so a check inside the transaction holding the per-principal advisory
// lock sees that transaction's own uncommitted writes rather than a pooled snapshot from before them.
//
// 🔒 That is the mechanism INV-A3-7 rests on. `mintForActivePrincipalLocked` does
// `advisoryLockPrincipal(p); if (isDeactivated(p, c)) null else mint(c)` on ONE transaction; if the
// check silently ran on a second connection, a teardown could slip its commit between the check and
// the INSERT and leave a credential that outlives deprovisioning.
//
// TODO(A3): once mintForActivePrincipalLocked is ported, assert the blocking behaviour too
// (DeprovisionDbTest case 8 holds the lock from a raw connection and asserts the caller BLOCKS).
func TestIsDeactivatedOn_ReadsTheCallersTransaction(t *testing.T) {
	f := newFixture(t)
	f.seed.User("tx@example.com")

	tx, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()

	if _, err := tx.Exec(f.ctx, `UPDATE app_user SET active = false WHERE principal = 'tx@example.com'`); err != nil {
		t.Fatalf("deactivate inside tx: %v", err)
	}

	inTx, err := f.users.IsDeactivatedOn(f.ctx, tx, "tx@example.com")
	if err != nil {
		t.Fatalf("IsDeactivatedOn: %v", err)
	}
	if !inTx {
		t.Error("IsDeactivatedOn(tx) = false, want true: the connection form must read the caller's " +
			"uncommitted state (INV-A3-7)")
	}
	if f.isDeactivated("tx@example.com") {
		t.Error("IsDeactivated(pool) = true, want false: the own-handle form must NOT see another " +
			"transaction's uncommitted write")
	}
}

// TestRolesForPrincipal_FailsClosedOnItsOwn is 🔒 INV-A3-15: the joins start FROM `app_user` and are
// all INNER, plus `AND u.active`, so an unknown or inactive principal yields zero rows WITHOUT any
// help from Resolve's short-circuit. The group source is guarded twice; the direct and JIT sources
// only once.
func TestRolesForPrincipal_FailsClosedOnItsOwn(t *testing.T) {
	f := newFixture(t)

	roleA := f.seed.Role("role-a")
	roleB := f.seed.Role("role-b")
	userID := f.seed.User("grouped@example.com")
	g1 := f.seed.Group("g1")
	g2 := f.seed.Group("g2")
	f.seed.GroupMember(g1, userID)
	f.seed.GroupMember(g2, userID)
	f.seed.GroupRole(g1, roleA)
	f.seed.GroupRole(g2, roleA) // the same role from two groups — SELECT DISTINCT collapses it
	f.seed.GroupRole(g2, roleB)

	got, err := f.users.RolesForPrincipal(f.ctx, "grouped@example.com")
	if err != nil {
		t.Fatalf("rolesForPrincipal: %v", err)
	}
	assertRoleSet(t, got, "role-a", "role-b")

	f.exec(`UPDATE app_user SET active = false WHERE principal = 'grouped@example.com'`)
	got, err = f.users.RolesForPrincipal(f.ctx, "grouped@example.com")
	if err != nil {
		t.Fatalf("rolesForPrincipal (inactive): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("rolesForPrincipal(inactive) = %v, want empty (INV-A3-15 fails closed on its own)", got)
	}

	got, err = f.users.RolesForPrincipal(f.ctx, "never-heard-of@example.com")
	if err != nil {
		t.Fatalf("rolesForPrincipal (unknown): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("rolesForPrincipal(unknown) = %v, want empty", got)
	}
}

// TestDirectRoles_HasNoActiveOrExpiryFilter pins the absence that 03-identity-scim.md:422 calls out:
// `directRoles` applies NO active/expiry filter of any kind. Resolve's short-circuit is the only gate
// on this source, and A4's web-session routes call this method directly — so a filter added here
// would silently change what they see.
func TestDirectRoles_HasNoActiveOrExpiryFilter(t *testing.T) {
	f := newFixture(t)

	roleID := f.seed.Role("direct-only")
	f.seed.Role("unassigned")
	f.seed.AssignRole("direct@example.com", roleID)
	f.seed.User("direct@example.com")
	f.exec(`UPDATE app_user SET active = false WHERE principal = 'direct@example.com'`)

	got, err := f.resolver.DirectRoles(f.ctx, "direct@example.com")
	if err != nil {
		t.Fatalf("directRoles: %v", err)
	}
	assertRoleSet(t, got, "direct-only")

	got, err = f.resolver.DirectRoles(f.ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("directRoles (unknown): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("directRoles(unknown) = %v, want empty", got)
	}
}

// ---------------------------------------------------------------------------------------------
// hasActiveAssignee — port of ReadinessDiagnosticDbTest case 1, plus the F34 sweep.
// ---------------------------------------------------------------------------------------------

// TestHasActiveAssignee_MirrorsResolveAcrossDirectGroupAndJITPaths is the port of
// `ReadinessDiagnosticDbTest.kt:35-78` case 1 — 03-identity-scim.md counts it in A3 (its Q6 records
// why), and it is the only test of hasActiveAssignee anywhere.
//
// 🔒 INV-A3-13 — readiness must agree with Resolve, arm for arm. hasActiveAssignee is a SECOND,
// independent implementation of the same three-way union; two implementations of one predicate is a
// drift risk, and this test is the only thing holding them together. All thirteen assertion points
// from the Kotlin are here: ten mirrored (`("system:admin" in resolve(p)) == hasActiveAssignee(...)`,
// at :44,46,48,56,58,67,69,71,73,76) and three readiness-only (:41,51,60).
func TestHasActiveAssignee_MirrorsResolveAcrossDirectGroupAndJITPaths(t *testing.T) {
	f := newFixture(t)
	roleID := f.roleID("system:admin")
	groupID := f.groupID("system:admin")

	// :41 — 🔒 INV-A3-12. The seed's member-less group_role link is not an assignee.
	if f.hasActiveAssignee("system:admin") {
		t.Fatal("a fresh install reports system:admin as reachable: the seed's member-less group_role " +
			"link must NOT count (INV-A3-12 — arm 2 is an INNER join on purpose)")
	}

	// ---- arm 1: a direct principal_role assignment.
	f.exec(`INSERT INTO principal_role (principal, role_id) VALUES ('direct@example.com', $1)`, roleID)
	f.assertResolvedAndDiagnosed("direct@example.com", true)
	f.exec(`INSERT INTO app_user (principal, active) VALUES ('direct@example.com', false)`)
	f.assertResolvedAndDiagnosed("direct@example.com", false)
	f.exec(`UPDATE app_user SET active = true WHERE principal = 'direct@example.com'`)
	f.assertResolvedAndDiagnosed("direct@example.com", true)
	f.exec(`DELETE FROM principal_role WHERE principal = 'direct@example.com'`)
	f.exec(`DELETE FROM app_user WHERE principal = 'direct@example.com'`)
	// :51
	if f.hasActiveAssignee("system:admin") {
		t.Error("hasActiveAssignee after removing the direct assignment = true, want false")
	}

	// ---- arm 2: group membership.
	f.exec(`INSERT INTO app_user (principal, active) VALUES ('group@example.com', true)`)
	groupUserID := f.scalarInt64(`SELECT id FROM app_user WHERE principal = 'group@example.com'`)
	f.exec(`INSERT INTO group_member (group_id, user_id) VALUES ($1, $2)`, groupID, groupUserID)
	f.assertResolvedAndDiagnosed("group@example.com", true)
	f.exec(`UPDATE app_user SET active = false WHERE principal = 'group@example.com'`)
	f.assertResolvedAndDiagnosed("group@example.com", false)
	f.exec(`DELETE FROM app_user WHERE principal = 'group@example.com'`)
	// :60
	if f.hasActiveAssignee("system:admin") {
		t.Error("hasActiveAssignee after removing the group member = true, want false")
	}

	// ---- arm 3: an active JIT grant.
	f.exec(`INSERT INTO access_grant (principal, role_id, granted_by, expires_at)
	        VALUES ('jit@example.com', $1, 'approver@example.com', now() + interval '1 hour')`, roleID)
	f.assertResolvedAndDiagnosed("jit@example.com", true)
	f.exec(`UPDATE access_grant SET expires_at = now() - interval '1 second' WHERE principal = 'jit@example.com'`)
	f.assertResolvedAndDiagnosed("jit@example.com", false)
	f.exec(`UPDATE access_grant SET expires_at = NULL, revoked_at = NULL WHERE principal = 'jit@example.com'`)
	f.assertResolvedAndDiagnosed("jit@example.com", true)
	f.exec(`INSERT INTO app_user (principal, active) VALUES ('jit@example.com', false)`)
	f.assertResolvedAndDiagnosed("jit@example.com", false)
	f.exec(`UPDATE app_user SET active = true WHERE principal = 'jit@example.com'`)
	f.exec(`UPDATE access_grant SET revoked_at = now() WHERE principal = 'jit@example.com'`)
	f.assertResolvedAndDiagnosed("jit@example.com", false)
}

// assertResolvedAndDiagnosed is ReadinessDiagnosticDbTest's own helper (:105-108): the two
// predicates must give the same answer for `system:admin`, every time.
func (f *fixture) assertResolvedAndDiagnosed(principal string, expected bool) {
	f.t.Helper()
	if got := slices.Contains(f.resolve(principal), "system:admin"); got != expected {
		f.t.Errorf("resolve disagreed for %s: system:admin present = %v, want %v", principal, got, expected)
	}
	if got := f.hasActiveAssignee("system:admin"); got != expected {
		f.t.Errorf("readiness disagreed for %s: hasActiveAssignee = %v, want %v", principal, got, expected)
	}
}

// TestHasActiveAssignee_AllSevenSeededSystemGroups is ⚠️ F34, on the readiness side.
//
// `V8__seed.sql:48-58` installs EIGHT app_group rows: `query-approvers` (source=LOCAL) plus SEVEN
// with source=SYSTEM — system:admin, system:developer, and five system:production-*. All seven carry
// zero seeded members ("Membership is always assigned at login from the IdP claim, never seeded"),
// and every Kotlin test names only `system:admin`.
//
// So this sweeps all seven. For each: every role that group grants must be unreachable on a fresh
// install (INV-A3-12's INNER join, seven times over), and must become reachable the moment ONE active
// member joins that group — and only that group's roles.
func TestHasActiveAssignee_AllSevenSeededSystemGroups(t *testing.T) {
	f := newFixture(t)

	// The seeded group → roles map, from V8__seed.sql:62-74. system:developer aggregates the five
	// development roles; each production group is 1:1 with its role.
	systemGroups := []struct {
		group string
		roles []string
	}{
		{"system:admin", []string{"system:admin"}},
		{"system:developer", []string{
			"system:development-viewer", "system:development-pii-accessor", "system:development-updater",
			"system:development-deleter", "system:development-architect",
		}},
		{"system:production-viewer", []string{"system:production-viewer"}},
		{"system:production-pii-accessor", []string{"system:production-pii-accessor"}},
		{"system:production-updater", []string{"system:production-updater"}},
		{"system:production-deleter", []string{"system:production-deleter"}},
		{"system:production-architect", []string{"system:production-architect"}},
	}

	// The seed really does install seven SYSTEM groups and one LOCAL one. Assert it rather than
	// trusting the table above: if a later migration adds an eighth, this test must notice.
	if n := f.scalarInt64(`SELECT count(*) FROM app_group WHERE source = 'SYSTEM'`); n != int64(len(systemGroups)) {
		t.Fatalf("app_group has %d source=SYSTEM rows, want %d — F34's table is stale", n, len(systemGroups))
	}

	// Fresh install: every one of the eleven system-granted roles is unreachable.
	for _, g := range systemGroups {
		for _, role := range g.roles {
			if f.hasActiveAssignee(role) {
				t.Errorf("hasActiveAssignee(%q) = true on a fresh install: %q has a group_role link but "+
					"zero members, so INV-A3-12 must not count it", role, g.group)
			}
		}
	}

	// One active member at a time: that group's roles become reachable, and nothing else moves.
	for _, g := range systemGroups {
		principal := "member-of-" + g.group + "@example.com"
		userID := f.seed.User(principal)
		f.seed.GroupMember(f.groupID(g.group), userID)

		for _, role := range g.roles {
			if !f.hasActiveAssignee(role) {
				t.Errorf("hasActiveAssignee(%q) = false after an ACTIVE member joined %q, want true",
					role, g.group)
			}
			if !slices.Contains(f.resolve(principal), role) {
				t.Errorf("resolve(%s) is missing %q — INV-A3-13: readiness and resolve must agree",
					principal, role)
			}
		}

		// Deactivating the member closes it again, on all of that group's roles.
		f.exec(`UPDATE app_user SET active = false WHERE principal = $1`, principal)
		for _, role := range g.roles {
			if f.hasActiveAssignee(role) {
				t.Errorf("hasActiveAssignee(%q) = true with only an INACTIVE member in %q, want false",
					role, g.group)
			}
		}
		f.exec(`DELETE FROM app_user WHERE principal = $1`, principal)
	}

	// `system:auditor` is seeded and `system:`-prefixed but no group grants it, so no group
	// membership can ever make it reachable. The name is never the test.
	if f.hasActiveAssignee("system:auditor") {
		t.Error("hasActiveAssignee(system:auditor) = true, want false: no seeded group grants it")
	}
}
