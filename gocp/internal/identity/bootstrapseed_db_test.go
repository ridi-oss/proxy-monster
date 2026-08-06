package identity

import "testing"

// The two seeded names V8__seed.sql installs. They are string literals rather than constants because
// internal/identity has none: the group name lives in the seed migration and the role name in A1's
// app.SystemAdminRole, and this package must not import internal/app.
const (
	seededAdminGroup = "system:admin"
	seededAdminRole  = "system:admin"
)

// ---------------------------------------------------------------------------------------------
// `BootstrapAdminDbTest.kt`'s SEED-SHAPE cases — what a freshly migrated control plane ships with,
// before anyone has logged in.
//
// This is the first-admin bootstrap: nobody can grant themselves `system:admin` through the console,
// because reaching the console already requires it. The only way in is the seeded
// `system:admin` group → `system:admin` role link plus an IdP group claim mapped onto that group. Both
// halves of that link are asserted here; the claim half is in internal/oidc.
// ---------------------------------------------------------------------------------------------

// 🔒 BootstrapAdminDbTest case 1 — `the seed installs the system-admin group (SYSTEM), the system-admin
// role, and their link`.
//
// All three parts matter and each fails differently: without the GROUP there is nothing for the IdP
// claim to map onto; without the ROLE the group grants nothing; without the LINK the mapping exists and
// confers no admin at all. `source = 'SYSTEM'` is what makes the group immutable, which is what stops
// SCIM or the admin API from re-pointing the bootstrap at a group the caller controls.
// KT: BootstrapAdminDbTest.kt#the seed installs the system-admin group (SYSTEM), the system-admin role, and their link
func TestTheSeedInstallsTheSystemAdminGroupTheRoleAndTheirLink(t *testing.T) {
	f := newWriteFixture(t)

	groups, err := f.store.ListGroups(f.ctx)
	if err != nil {
		t.Fatalf("listGroups: %v", err)
	}
	var admin *AppGroup
	for i := range groups {
		if groups[i].Name == seededAdminGroup {
			admin = &groups[i]
			break
		}
	}
	if admin == nil {
		t.Fatalf("V8__seed.sql installs no %q group — nothing an IdP claim can map onto, so the "+
			"first-admin bootstrap has no door", seededAdminGroup)
	}
	if admin.Source != SystemSource {
		t.Errorf("%s source = %q, want %q — a non-SYSTEM group is freely mutable through SCIM and "+
			"the admin API", seededAdminGroup, admin.Source, SystemSource)
	}
	system, err := f.store.IsSystemGroup(f.ctx, admin.ID)
	if err != nil {
		t.Fatalf("isSystemGroup: %v", err)
	}
	if !system {
		t.Errorf("isSystemGroup(%s) = false: the immutability predicate disagrees with the seeded "+
			"source column", seededAdminGroup)
	}

	roles, err := f.store.ListGroupRoles(f.ctx, admin.ID)
	if err != nil {
		t.Fatalf("listGroupRoles: %v", err)
	}
	linked := false
	for _, r := range roles {
		if r.RoleName == seededAdminRole {
			linked = true
		}
	}
	if !linked {
		t.Errorf("the %s group does not grant the %s role (%+v) — membership would confer no admin",
			seededAdminGroup, seededAdminRole, roles)
	}
}

// 🔒 BootstrapAdminDbTest case 7 — `the seeded system-admin group carries only the intended wiring and
// no members`.
//
// Three absences, each load-bearing:
//
//   - ZERO MEMBERS. Who is an admin comes only from the IdP group claim at login. A seeded member would
//     be a standing admin identity nobody provisioned and no IdP can revoke.
//   - NO external_id. A stored external_id is replayable: a later `POST /Groups` carrying it would
//     resolve this row by the externalId arm, which is the exact path
//     TestUpsertScimGroupRefusesEverySeededSystemGroupByNameAndByExternalID has to defend.
//   - EXACTLY ONE role link. The group confers admin and nothing else, so "member of system:admin" has
//     one meaning.
//
// The Kotlin opens a SECOND database for this case, because its class-scoped one is shared and a
// sibling case provisions an admin member into it. Go's fixture is per-test, so the isolation is
// structural rather than something this case has to arrange.
// KT: BootstrapAdminDbTest.kt#the seeded system-admin group carries only the intended wiring and no members
func TestTheSeededSystemAdminGroupCarriesOnlyItsWiringAndNoMembers(t *testing.T) {
	f := newWriteFixture(t)

	groupID := f.scalarInt64(`SELECT id FROM app_group WHERE name = $1`, seededAdminGroup)
	group := f.groupByID(groupID)
	if group.ExternalID != nil {
		t.Errorf("the seeded admin group carries external_id %q — a later POST /Groups could replay it "+
			"to re-match this row", *group.ExternalID)
	}

	members, err := f.store.ListMembers(f.ctx, groupID)
	if err != nil {
		t.Fatalf("listMembers: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("%d seeded member(s) in %s (%+v) — membership must come ONLY from the IdP claim at login",
			len(members), seededAdminGroup, members)
	}
	if group.MemberCount != 0 {
		t.Errorf("memberCount = %d, want 0", group.MemberCount)
	}

	roles, err := f.store.ListGroupRoles(f.ctx, groupID)
	if err != nil {
		t.Fatalf("listGroupRoles: %v", err)
	}
	if len(roles) != 1 || roles[0].RoleName != seededAdminRole {
		t.Errorf("the admin group grants %+v, want exactly [%s] — it confers admin and only that",
			roles, seededAdminRole)
	}
}
