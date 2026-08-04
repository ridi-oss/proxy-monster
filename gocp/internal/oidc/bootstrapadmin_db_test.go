package oidc

import (
	"context"
	"slices"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `BootstrapAdminDbTest.kt`'s LOGIN cases — the IdP-claim half of the first-admin bootstrap.
//
// The seeded half (the `system:admin` SYSTEM group, the role, their link, and the group's empty
// membership) is asserted in internal/identity/bootstrapseed_db_test.go. What is asserted HERE is the
// only path that turns that wiring into an actual admin: a login whose group claim the operator's
// PM_OIDC_GROUP_MAP points at the reserved group.
//
// 🔒 EVERY CASE GOES THROUGH RoleResolver, not through group membership. That is the difference from
// provisioner_db_test.go, which asserts what landed in `group_member`. "The claim created the right
// membership" and "the principal therefore RESOLVES system:admin" are two claims, and the second is the
// one the escalation-closed case is about — the group_role link, the INNER join on active membership and
// the mapping all have to line up for it to hold.
// ---------------------------------------------------------------------------------------------

// adminMapping is BootstrapAdminDbTest.kt:28's `OidcGroupMapping(mapOf("proxy-monster-admin" to
// "system:admin"), "proxy-monster-")` — one explicit map entry PLUS a prefix, so both branches of the
// resolver are live in the same fixture and a case can show which one it took.
func adminMapping() GroupMapping {
	return GroupMapping{
		Map:    map[string]string{"proxy-monster-admin": "system:admin"},
		Prefix: types.Ptr("proxy-monster-"),
	}
}

// resolverOver builds the real Layer-1 resolver over the fixture's database, wired the way
// ControlPlaneCore does it — one UserGroupStore, one RoleResolver, both over the same pool.
func (f *provFixture) resolverOver() *identity.RoleResolver {
	users := identity.NewUserGroupStore(f.db.Pool)
	return identity.NewRoleResolver(f.db.Pool, users, grantRoles{access.NewStore(f.db.Pool)})
}

// grantRoles is core.grantRolesAdapter: identity.AccessGrants' TODO(A6) seam, which keeps the
// `.map { roleName }` on the caller's side rather than growing a method on AccessStore. internal/core
// is not importable from a test in this package's own directory without pulling in the whole
// composition root, so the three lines are repeated rather than shared.
type grantRoles struct{ store *access.Store }

func (g grantRoles) ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error) {
	grants, err := g.store.ListGrants(ctx, &principal, activeOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(grants))
	for _, gr := range grants {
		out = append(out, gr.RoleName)
	}
	return out, nil
}

func (f *provFixture) resolves(r *identity.RoleResolver, principal, role string) bool {
	f.t.Helper()
	roles, err := r.Resolve(f.ctx, principal)
	if err != nil {
		f.t.Fatalf("resolve(%s): %v", principal, err)
	}
	return slices.Contains(roles, role)
}

// 🔒 BootstrapAdminDbTest case 2 — `an IdP admin-group member resolves system-admin and loses it when
// the group is dropped (sync)`.
//
// This is the whole bootstrap, end to end, in one case: a mapped IdP group makes the first admin on
// their first login, and — the half that is a security property rather than a convenience —
// REMOVING them from that group at the IdP revokes `system:admin` on their NEXT login, because
// provisioning RECONCILES membership to exactly the claim. If membership were merged instead of
// reconciled, offboarding at the IdP would silently leave a standing admin behind.
// KT: BootstrapAdminDbTest.kt#an IdP admin-group member resolves system-admin and loses it when the group is dropped (sync)
func TestAnIdPAdminGroupMemberResolvesSystemAdminAndLosesItWhenTheGroupIsDropped(t *testing.T) {
	f := newProvFixture(t)
	r := f.resolverOver()
	const principal = "boot-admin@example.com"

	f.provision(principal, types.Ptr(principal), []string{"proxy-monster-admin"}, adminMapping())
	assertGroups(t, f.groupsOf(principal), "system:admin")
	if !f.resolves(r, principal, "system:admin") {
		t.Fatal("membership in the seeded system:admin group did not confer the system:admin role — " +
			"the bootstrap is closed and nobody can ever open the console")
	}

	// The next login without the IdP admin group.
	f.provision(principal, types.Ptr(principal), nil, adminMapping())
	assertGroups(t, f.groupsOf(principal))
	if f.resolves(r, principal, "system:admin") {
		t.Error("dropping the IdP admin group did NOT revoke system:admin — offboarding at the IdP " +
			"leaves a standing admin, which is the failure the reconcile (not merge) exists to prevent")
	}
}

// BootstrapAdminDbTest case 3 — `an unmapped IdP group is created by name with the prefix stripped`.
//
// The prefix branch is how an operator avoids listing every group by hand: `proxy-monster-analysts`
// becomes the local group `analysts`. The part worth asserting beyond the name is that a group arriving
// this way is NOT a SYSTEM group — the create-by-name fallback must never mint something immutable,
// or an IdP could manufacture protected groups.
// KT: BootstrapAdminDbTest.kt#an unmapped IdP group is created by name with the prefix stripped
func TestAnUnmappedIdPGroupIsCreatedByNameWithThePrefixStripped(t *testing.T) {
	f := newProvFixture(t)
	users := identity.NewUserGroupStore(f.db.Pool)

	f.provision("analyst@example.com", nil, []string{"proxy-monster-analysts"}, adminMapping())
	assertGroups(t, f.groupsOf("analyst@example.com"), "analysts")

	groupID := f.scalarInt64(`SELECT id FROM app_group WHERE name = 'analysts'`)
	system, err := users.IsSystemGroup(f.ctx, groupID)
	if err != nil {
		t.Fatalf("isSystemGroup: %v", err)
	}
	if system {
		t.Error("a JIT-created group is a SYSTEM group — the create-by-name fallback must not be able " +
			"to mint an immutable group from an untrusted claim")
	}
	if got := f.groupSource("analysts"); got != "OIDC" {
		t.Errorf("a JIT-created group's source = %q, want OIDC", got)
	}
}

// 🔒 BootstrapAdminDbTest case 5 — `a raw reserved-name claim without a mapping does not confer admin
// (escalation closed)`. **This is the privilege escalation the reserved-namespace gate caught.**
//
// An IdP token whose `groups` claim literally contains `system:admin`, with NO PM_OIDC_GROUP_MAP, must
// not self-assign the seeded admin group: the create-by-name fallback may not reach the reserved
// namespace. Anyone who can name their own IdP groups — which, at many IdPs, is anyone who can create
// one — would otherwise become a control-plane admin by naming a group after the role.
//
// The mapped contrast is in the same case on purpose: it shows the gate closed the ESCALATION and not
// the FEATURE. A port that refused the reserved namespace unconditionally would pass the first half and
// break the only supported way to make a first admin.
// KT: BootstrapAdminDbTest.kt#a raw reserved-name claim without a mapping does not confer admin (escalation closed)
func TestARawReservedNameClaimWithoutAMappingConfersNoAdmin(t *testing.T) {
	f := newProvFixture(t)
	r := f.resolverOver()

	// No mapping at all: the claim is entirely untrusted input.
	noMapping := GroupMapping{Map: map[string]string{}}
	f.provision("intruder@example.com", nil, []string{"system:admin"}, noMapping)
	assertGroups(t, f.groupsOf("intruder@example.com"))
	if f.resolves(r, "intruder@example.com", "system:admin") {
		t.Error("🔒 ESCALATION OPEN: a raw `system:admin` groups claim conferred the system:admin role " +
			"with no operator mapping — anyone who can name an IdP group is an admin")
	}
	// The seeded group must be untouched, not merely un-joined: a matched-and-refused push and a
	// never-matched one look the same from the membership side.
	if got := f.groupSource("system:admin"); got != "SYSTEM" {
		t.Errorf("system:admin source = %q, want SYSTEM", got)
	}

	// The intended admin route still works.
	f.provision("mapped-admin@example.com", nil, []string{"proxy-monster-admin"}, adminMapping())
	if !f.resolves(r, "mapped-admin@example.com", "system:admin") {
		t.Error("an explicit PM_OIDC_GROUP_MAP entry no longer confers admin — the gate closed the " +
			"feature rather than the escalation")
	}
}

// scalarInt64 reads one bigint, failing the test if the query does not.
func (f *provFixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}
