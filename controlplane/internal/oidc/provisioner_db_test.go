package oidc

import (
	"context"
	"sort"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// DB-backed suite for [DirectoryProvisioner] — 14-auth.md §6's INV-A14-35 … -39, plus the DESTRUCTIVE
// half of F24.
//
// ORACLE: auth/src/main/kotlin/.../OidcDirectoryProvisioner.kt, read this session. A3's
// ProvisionMergeDbTest is the Kotlin suite that covers these (counted in A3, not A14), so this file
// pins the invariants 14-auth.md states rather than re-deriving that suite's case list.

type provFixture struct {
	t     testing.TB
	ctx   context.Context
	db    *store.Db
	prov  *DirectoryProvisioner
	seedT *dbtest.Seed
}

func newProvFixture(t *testing.T) *provFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &provFixture{
		t: t, ctx: context.Background(), db: db,
		prov:  NewDirectoryProvisioner(db.Pool),
		seedT: dbtest.NewSeed(t, db),
	}
}

func (f *provFixture) provision(principal string, email *string, groups []string, m GroupMapping) int64 {
	f.t.Helper()
	id, err := f.prov.Provision(f.ctx, principal, email, groups, m)
	if err != nil {
		f.t.Fatalf("Provision(%q): %v", principal, err)
	}
	return id
}

// groupsOf reads the user's CURRENT group names, sorted for a stable assertion.
func (f *provFixture) groupsOf(principal string) []string {
	f.t.Helper()
	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT g.name FROM app_group g
		   JOIN group_member gm ON gm.group_id = g.id
		   JOIN app_user u ON u.id = gm.user_id
		  WHERE u.principal = $1`, principal)
	if err != nil {
		f.t.Fatalf("read groups: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (f *provFixture) user(principal string) (email *string, source string, active bool) {
	f.t.Helper()
	err := f.db.Pool.QueryRow(f.ctx,
		`SELECT email, source, active FROM app_user WHERE principal = $1`, principal).Scan(&email, &source, &active)
	if err != nil {
		f.t.Fatalf("read app_user %q: %v", principal, err)
	}
	return
}

func (f *provFixture) groupSource(name string) string {
	f.t.Helper()
	var src string
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT source FROM app_group WHERE name = $1`, name).Scan(&src); err != nil {
		f.t.Fatalf("read app_group %q: %v", name, err)
	}
	return src
}

func assertGroups(t testing.TB, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("groups = %v, want %v", got, want)
		}
	}
}

// --- · a first login inserts the user as source=OIDC, active, with the claimed groups.
func TestProvision_FirstLoginCreatesUserAndGroups(t *testing.T) {
	f := newProvFixture(t)
	id := f.provision("alice@example.com", types.Ptr("alice@example.com"),
		[]string{"engineering", "eng-leads"}, GroupMapping{Map: map[string]string{}})
	if id == 0 {
		t.Fatal("Provision returned id 0")
	}
	email, source, active := f.user("alice@example.com")
	if email == nil || *email != "alice@example.com" {
		t.Errorf("email = %v", email)
	}
	if source != "OIDC" {
		t.Errorf("source = %q, want OIDC", source)
	}
	if !active {
		t.Error("a newly inserted user must be active")
	}
	assertGroups(t, f.groupsOf("alice@example.com"), "engineering", "eng-leads")
	if got := f.groupSource("engineering"); got != "OIDC" {
		t.Errorf("a NEW group's source = %q, want OIDC", got)
	}
}

// --- 🔒 INV-A14-37 · membership is FULLY RECONCILED, not merged.
//
// "Dropping someone from the IdP admin group revokes their `system:admin` on their next login."
func TestProvision_MembershipIsReconciledNotMerged(t *testing.T) {
	f := newProvFixture(t)
	m := GroupMapping{Map: map[string]string{}}

	f.provision("alice@example.com", nil, []string{"a", "b", "c"}, m)
	assertGroups(t, f.groupsOf("alice@example.com"), "a", "b", "c")

	// A narrower claim REMOVES what is no longer claimed, and adds what is new.
	f.provision("alice@example.com", nil, []string{"b", "d"}, m)
	assertGroups(t, f.groupsOf("alice@example.com"), "b", "d")

	// An EMPTY claim strips everything. This is the mechanism F24 weaponises.
	f.provision("alice@example.com", nil, []string{}, m)
	assertGroups(t, f.groupsOf("alice@example.com"))
}

// --- 🔒 INV-A14-37 · a MANUAL group assignment is reconciled away too.
//
// step 4 reads EVERY group_member row "regardless of the group's source", which is what makes this
// happen. 14-auth.md quotes A3 calling it "accepted for now — no membership-origin column yet".
func TestProvision_ManualMembershipIsReconciledAway(t *testing.T) {
	f := newProvFixture(t)
	userID := f.provision("alice@example.com", nil, []string{"claimed"}, GroupMapping{Map: map[string]string{}})

	manual := f.seedT.Group("hand-assigned")
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO group_member (group_id, user_id) VALUES ($1, $2)`, manual, userID); err != nil {
		t.Fatalf("seed manual membership: %v", err)
	}
	assertGroups(t, f.groupsOf("alice@example.com"), "claimed", "hand-assigned")

	f.provision("alice@example.com", nil, []string{"claimed"}, GroupMapping{Map: map[string]string{}})
	assertGroups(t, f.groupsOf("alice@example.com"), "claimed")
}

// --- 🔒 INV-A14-35 · SCIM WINS, and the conflict is ABSORBED rather than raised.
//
// A `source='SCIM'` row is left COMPLETELY untouched — email, source and active — while the login
// still succeeds and group reconciliation still runs.
func TestProvision_ScimManagedUserIsNeverClobbered(t *testing.T) {
	f := newProvFixture(t)
	if _, err := f.db.Pool.Exec(f.ctx,
		`INSERT INTO app_user (principal, email, source, active) VALUES ($1, $2, 'SCIM', TRUE)`,
		"scim@example.com", "scim-address@example.com"); err != nil {
		t.Fatalf("seed SCIM user: %v", err)
	}

	f.provision("scim@example.com", types.Ptr("oidc-address@example.com"), []string{"engineering"},
		GroupMapping{Map: map[string]string{}})

	email, source, active := f.user("scim@example.com")
	if email == nil || *email != "scim-address@example.com" {
		t.Errorf("email = %v, want the SCIM address untouched", email)
	}
	if source != "SCIM" {
		t.Errorf("source = %q, want SCIM — the login must not steal the row", source)
	}
	if !active {
		t.Error("active must be untouched")
	}
	// …and the login still succeeded, so groups were still reconciled.
	assertGroups(t, f.groupsOf("scim@example.com"), "engineering")
}

// --- 🔒 · `email = COALESCE(EXCLUDED.email, app_user.email)` — an email-less login must not ERASE a
// known address.
func TestProvision_NilEmailDoesNotEraseAKnownAddress(t *testing.T) {
	f := newProvFixture(t)
	f.provision("alice@example.com", types.Ptr("alice@example.com"), nil, GroupMapping{Map: map[string]string{}})

	f.provision("alice@example.com", nil, nil, GroupMapping{Map: map[string]string{}})
	email, _, _ := f.user("alice@example.com")
	if email == nil || *email != "alice@example.com" {
		t.Fatalf("email = %v, want the previously known address preserved", email)
	}
}

// --- 🔒 INV-A14-36 · `active` is set ONLY on INSERT, so a JIT login CANNOT reactivate a deactivated
// account.
//
// ⚠️ The invariant lives ONLY in the shape of the DO UPDATE set-list, with no comment in the Kotlin
// saying so (14-auth.md §8 Q2). It is exactly the kind of thing a port "tidies up" by adding
// `active = TRUE`, which would let anyone deactivated resurrect themselves by logging in.
func TestProvision_CannotReactivateADeactivatedAccount(t *testing.T) {
	f := newProvFixture(t)
	f.provision("alice@example.com", types.Ptr("alice@example.com"), []string{"eng"}, GroupMapping{Map: map[string]string{}})
	f.seedT.SetUserActive("alice@example.com", false)

	f.provision("alice@example.com", types.Ptr("alice@example.com"), []string{"eng"}, GroupMapping{Map: map[string]string{}})

	if _, _, active := f.user("alice@example.com"); active {
		t.Fatal("a JIT login reactivated a deactivated account — INV-A14-36 is the containment for A3's deprovisioning")
	}
}

// --- 🔒 INV-A14-39 · ensureGroup's `DO UPDATE SET name = EXCLUDED.name` is a NO-OP self-assignment.
//
// Two properties depend on the exact shape: RETURNING id must still fire on conflict, and an EXISTING
// group must KEEP ITS OWN SOURCE. "Simplifying" it to `DO UPDATE SET source = 'OIDC'` would flip the
// seeded `system:admin` group to source='OIDC' and defeat every A3 guard keyed on source='SYSTEM'.
func TestProvision_ExistingGroupKeepsItsOwnSource(t *testing.T) {
	f := newProvFixture(t)

	// V8__seed.sql seeds system:admin with source='SYSTEM'.
	before := f.groupSource("system:admin")
	if before != "SYSTEM" {
		t.Fatalf("precondition: system:admin source = %q, want SYSTEM", before)
	}

	// Reach it through the TRUSTED map branch, which is the only way a claim may name a system group.
	f.provision("admin@example.com", nil, []string{"idp-admins"},
		GroupMapping{Map: map[string]string{"idp-admins": "system:admin"}})

	if got := f.groupSource("system:admin"); got != "SYSTEM" {
		t.Fatalf("system:admin source = %q, want SYSTEM — flipping it to OIDC defeats every A3 SYSTEM guard", got)
	}
	assertGroups(t, f.groupsOf("admin@example.com"), "system:admin")
}

// ============================================================================================
// 🔒 REPRODUCE + PIN — F24, THE DESTRUCTIVE HALF (00-INDEX.md:214).
//
// TestValidate_F24_MalformedGroupsClaimSilentlyBecomesEmpty pins where the emptiness is manufactured.
// THIS pins what it then does: because provisioning RECONCILES membership to exactly the claim, an
// IdP that changes its groups claim SHAPE — array to bare string, or array to comma-joined string —
// strips every group from every user on their next login, `system:admin` included, with no error
// logged anywhere.
//
// The test drives the REAL composition: [IDTokenValidator.Validate] over a signed token whose `groups`
// claim is a bare string, then [DirectoryProvisioner.Provision] with whatever came out. Asserting the
// two separately would let the pair drift; this is the sequence that actually loses the admin.
//
// ⚠️ ASSERTS THE BUG ON PURPOSE. A later fix — coercing a bare string, or refusing to reconcile on a
// malformed claim — must change this test deliberately and visibly.
// ============================================================================================

func TestProvision_F24_MalformedShapeStripsSystemAdmin(t *testing.T) {
	f := newProvFixture(t)
	idp := newFakeIdP(t, "f24-kid")
	v := idp.validatorFor(testClientID)
	m := GroupMapping{Map: map[string]string{"idp-admins": "system:admin"}}
	const principal = "admin@example.com"

	// Day 1 — the IdP emits the claim as a JSON ARRAY. The admin is provisioned.
	day1 := idp.defaultClaims(testClientID)
	day1.groups = []any{"idp-admins", "engineering"}
	claims := v.Validate(context.Background(), idp.sign(day1, nil), types.Ptr("the-nonce"))
	if claims == nil {
		t.Fatal("day 1 token must validate")
	}
	f.provision(principal, types.Ptr(principal), claims.Groups, m)
	assertGroups(t, f.groupsOf(principal), "engineering", "system:admin")

	// Day 2 — the IdP ships a change and now emits the SAME groups as a comma-joined STRING. Nothing
	// about the token is otherwise different, and it still validates.
	day2 := idp.defaultClaims(testClientID)
	day2.groups = "idp-admins,engineering"
	claims = v.Validate(context.Background(), idp.sign(day2, nil), types.Ptr("the-nonce"))
	if claims == nil {
		t.Fatal("F24: a malformed groups claim must NOT fail validation — it silently empties")
	}
	if len(claims.Groups) != 0 {
		t.Fatalf("F24: Groups = %v, want empty. If validation now recovers the groups, the defect was "+
			"fixed — update the finding and this test together, do not just delete the assertion.", claims.Groups)
	}

	f.provision(principal, types.Ptr(principal), claims.Groups, m)
	assertGroups(t, f.groupsOf(principal))

	// The user row survives; only the authorization is gone. That is what makes the failure silent:
	// the login SUCCEEDS, and the user simply has no roles any more.
	if _, _, active := f.user(principal); !active {
		t.Error("the user row itself must be untouched — F24 destroys membership, not the account")
	}

	// And the seeded group is still SYSTEM-sourced, so nothing about the DIRECTORY looks wrong to an
	// operator inspecting it afterwards.
	if got := f.groupSource("system:admin"); got != "SYSTEM" {
		t.Errorf("system:admin source = %q, want SYSTEM", got)
	}
}

// --- 🔒 · the trusted map may name a system group, and the untrusted claim may not — end to end
// through the database rather than only through Resolve (INV-A14-33 / -34).
func TestProvision_ReservedNamespaceIsUnreachableFromTheClaim(t *testing.T) {
	f := newProvFixture(t)

	// The untrusted branch: a raw `system:admin` in the claim, no mapping.
	f.provision("attacker@example.com", nil, []string{"system:admin", "SYSTEM:Admin", "analysts"},
		GroupMapping{Map: map[string]string{}})
	assertGroups(t, f.groupsOf("attacker@example.com"), "analysts")

	// The trusted branch: the operator's map.
	f.provision("operator@example.com", nil, []string{"idp-admins"},
		GroupMapping{Map: map[string]string{"idp-admins": "system:admin"}})
	assertGroups(t, f.groupsOf("operator@example.com"), "system:admin")
}

// --- · an empty delta is a no-op, not an error.
//
// JDBC's executeBatch() with zero batches is legal and returns an empty array; 14-auth.md warns that a
// Go port "building IN (...) or a COPY must handle the empty case explicitly".
func TestProvision_EmptyDeltaIsANoOp(t *testing.T) {
	f := newProvFixture(t)
	m := GroupMapping{Map: map[string]string{}}
	f.provision("alice@example.com", nil, []string{"eng"}, m)

	// Same claim twice: nothing to add, nothing to remove.
	id := f.provision("alice@example.com", nil, []string{"eng"}, m)
	if id == 0 {
		t.Fatal("Provision returned id 0 on a no-op reconciliation")
	}
	assertGroups(t, f.groupsOf("alice@example.com"), "eng")

	// And a user with no groups at all, twice.
	f.provision("bob@example.com", nil, nil, m)
	f.provision("bob@example.com", nil, nil, m)
	assertGroups(t, f.groupsOf("bob@example.com"))
}

// --- · the adapter A3 will replace discards the id, exactly as `oidcRoutes` does.
func TestProvisionerAdapter_SatisfiesTheSeam(t *testing.T) {
	f := newProvFixture(t)
	var seam UserGroupProvisioner = Provisioner{f.prov}
	if err := seam.ProvisionFromOidc(f.ctx, "alice@example.com", nil, []string{"eng"},
		GroupMapping{Map: map[string]string{}}); err != nil {
		t.Fatalf("ProvisionFromOidc: %v", err)
	}
	assertGroups(t, f.groupsOf("alice@example.com"), "eng")
}
