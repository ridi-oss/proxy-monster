package identity

import (
	"errors"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `ScimUsersDbTest.kt` (14 cases), `ScimGroupsDbTest.kt` (6) and the SCIM half of
// `ProvisionMergeDbTest.kt` — plus `BootstrapAdminDbTest` case 6, the INV-A3-33/-34 regression.
//
// Added beyond the Kotlin: F36. Every immutability case in the Kotlin names `system:admin` while
// every guard is keyed on the `source` COLUMN, and V8__seed.sql installs SEVEN source=SYSTEM groups.
// A port that special-cased the string would leave six production-capability groups freely mutable
// through SCIM and no existing test would catch it, so the guard cases here are parameterised over
// all seven.
// ---------------------------------------------------------------------------------------------

// seededSystemGroups is the seven `source='SYSTEM'` rows V8__seed.sql:48-58 installs.
func (f *writeFixture) seededSystemGroups() []AppGroup {
	f.t.Helper()
	groups, err := f.store.ListGroups(f.ctx)
	if err != nil {
		f.t.Fatalf("listGroups: %v", err)
	}
	var out []AppGroup
	for _, g := range groups {
		if g.Source == SystemSource {
			out = append(out, g)
		}
	}
	if len(out) != 7 {
		f.t.Fatalf("%d seeded SYSTEM groups, want 7 — V8__seed.sql:48-58 (F36)", len(out))
	}
	return out
}

// Case 1 + 2 — `upsertScimUser provisions a source=SCIM row keyed on externalId`, and is IDEMPOTENT
// on repeated pushes for the same externalId.
// KT: ScimUsersDbTest.kt#upsertScimUser is idempotent on repeated pushes for the same externalId
// KT: ScimUsersDbTest.kt#upsertScimUser never clobbers a SCIM row's source
// KT: ScimUsersDbTest.kt#upsertScimUser provisions a source=SCIM row keyed on externalId
func TestUpsertScimUserProvisionsAndIsIdempotent(t *testing.T) {
	f := newWriteFixture(t)

	first, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com",
		types.Ptr("alice@example.com"), types.Ptr("Alice"), true, f.creds)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if first.Source != "SCIM" || first.ExternalID == nil || *first.ExternalID != "okta-1" {
		t.Fatalf("want a source=SCIM row keyed on okta-1, got %+v", first)
	}
	// The rest of the projected row, which case 1 asserts field by field.
	if first.Principal != "alice@example.com" || first.DisplayName == nil || *first.DisplayName != "Alice" || !first.Active {
		t.Fatalf("the returned row must carry the pushed principal, displayName and active: %+v", first)
	}

	// The second push carries a DIFFERENT displayName, because idempotence here means "same row,
	// updated", not "same row, ignored" — case 2 asserts the new value is what the row then reads.
	second, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com",
		types.Ptr("alice@example.com"), types.Ptr("Alice A."), true, f.creds)
	if err != nil {
		t.Fatalf("re-push: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("a repeated push created a SECOND row (%d then %d)", first.ID, second.ID)
	}
	if got := f.scalarInt64(`SELECT count(*) FROM app_user`); got != 1 {
		t.Errorf("%d app_user rows, want 1", got)
	}
	reread := f.user(first.ID, "after the second push")
	if reread.DisplayName == nil || *reread.DisplayName != "Alice A." {
		t.Errorf("displayName = %v, want the second push's value — an idempotent upsert still UPDATES",
			reread.DisplayName)
	}
	// Case 5 — a push onto an ALREADY-SCIM row never clobbers its source.
	if second.Source != "SCIM" || reread.Source != "SCIM" {
		t.Errorf("source went %q (row: %q) on a re-push, want SCIM to stay SCIM", second.Source, reread.Source)
	}
}

// 🔒 Case 3 + ProvisionMergeDbTest case 10 — `upsertScimUser active=false deactivates the row` AND
// revokes the principal's credentials atomically. INV-A3-6.
// KT: ScimUsersDbTest.kt#upsertScimUser active=false deactivates the row
// KT: ProvisionMergeDbTest.kt#upsertScimUser active=false atomically revokes the principal credentials
func TestUpsertScimUserInactiveDeactivatesAndRevokesAtomically(t *testing.T) {
	f := newWriteFixture(t)
	const principal = "alice@example.com"

	if _, err := f.store.UpsertScimUser(f.ctx, "okta-1", principal, nil, nil, true, f.creds); err != nil {
		t.Fatalf("provision: %v", err)
	}
	creds := f.seedCredentials(principal, "reader")
	// Pre-state sanity (the Kotlin's "in-window before the deactivate"): every class is live, so the
	// revocation assertions below are not asserting the fixture back.
	f.assertAllLive(creds, "before the active=false push")

	after, err := f.store.UpsertScimUser(f.ctx, "okta-1", principal, nil, nil, false, f.creds)
	if err != nil {
		t.Fatalf("deactivating push: %v", err)
	}
	if after.Active {
		t.Errorf("active=%v after an active=false push", after.Active)
	}
	// active=false on the projected row is not the same claim as the predicate every auth chokepoint
	// actually calls; the Kotlin asserts both, so both are asserted here.
	if !f.isDeactivated(principal) {
		t.Errorf("isDeactivated(%s) = false after an active=false push — the gates would still let it in",
			principal)
	}
	f.assertAllRevoked(creds, "an active=false SCIM push")
}

// 🔒 Case 4 + INV-A3-31 — `upsertScimUser reconciles an existing OIDC-provisioned row instead of
// duplicating it`, and case 5 — it never clobbers a SCIM row's source. The MATCH ORDER external_id →
// email → principal is the anti-duplication rule.
// KT: ScimUsersDbTest.kt#upsertScimUser reconciles an existing OIDC-provisioned row instead of duplicating it
// KT: ProvisionMergeDbTest.kt#upsertScimUser matches an existing JIT user by email and reconciles it to SCIM
// KT: ProvisionMergeDbTest.kt#upsertScimUser matches by external_id first, even if principal or email changed at the IdP
// KT: ProvisionMergeDbTest.kt#upsertScimUser matches by principal when external_id and email are both new
func TestUpsertScimUserMatchOrderReconcilesRatherThanDuplicating(t *testing.T) {
	f := newWriteFixture(t)

	// A prior JIT row: source=OIDC, no external_id, matched by EMAIL.
	jitID := f.scalarInt64(
		`INSERT INTO app_user (principal, email, source, active) VALUES ($1, $2, 'OIDC', TRUE) RETURNING id`,
		"bob@example.com", "bob@corp.example")

	reconciled, err := f.store.UpsertScimUser(f.ctx, "okta-2", "bob@example.com",
		types.Ptr("bob@corp.example"), nil, true, f.creds)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if reconciled.ID != jitID {
		t.Errorf("the JIT row was DUPLICATED (%d then %d) — the email arm of the match order is missing",
			jitID, reconciled.ID)
	}
	if reconciled.Source != "SCIM" {
		t.Errorf("source %q, want SCIM — the IdP now manages this principal", reconciled.Source)
	}

	// 🔒 Case 6 — external_id wins even when BOTH userName and email changed at the IdP.
	renamedBoth, err := f.store.UpsertScimUser(f.ctx, "okta-2", "robert@example.com",
		types.Ptr("robert@corp.example"), nil, true, f.creds)
	if err != nil {
		t.Fatalf("re-push with both keys changed: %v", err)
	}
	if renamedBoth.ID != jitID {
		t.Errorf("external_id must match FIRST: got a new row %d, want %d", renamedBoth.ID, jitID)
	}
	// Matching the row is only half of it — the IdP's new userName and email must actually land on it.
	// An upsert that resolved by external_id and then left the old keys in place would still answer
	// with this id while the directory kept serving a stale principal string.
	if renamedBoth.Principal != "robert@example.com" {
		t.Errorf("principal = %q, want the IdP's new userName robert@example.com", renamedBoth.Principal)
	}
	if renamedBoth.Email == nil || *renamedBoth.Email != "robert@corp.example" {
		t.Errorf("email = %v, want the IdP's new robert@corp.example", renamedBoth.Email)
	}

	// Case 18 — the third arm: a LOCAL admin-made row matched by PRINCIPAL when external_id and email
	// are both new.
	localID := f.scalarInt64(
		`INSERT INTO app_user (principal, source, active) VALUES ($1, 'LOCAL', TRUE) RETURNING id`,
		"carol@example.com")
	byPrincipal, err := f.store.UpsertScimUser(f.ctx, "okta-3", "carol@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("upsert by principal: %v", err)
	}
	if byPrincipal.ID != localID || byPrincipal.Source != "SCIM" {
		t.Errorf("the LOCAL row must reconcile to SCIM in place, got %+v (want id %d)", byPrincipal, localID)
	}

	// KT: ScimUsersDbTest.kt#distinct externalIds never collide into the same row
	// Case 8 — distinct externalIds never collide into the same row.
	if got := f.scalarInt64(`SELECT count(DISTINCT id) FROM app_user WHERE external_id IS NOT NULL`); got != 2 {
		t.Errorf("%d distinct externalId-bearing rows, want 2", got)
	}
}

// 🔒 Case 9 — `replaceScimUserById mutates the row AT this id — never a different row a body-key match
// would have resolved`. **INV-A3-32, the cross-resource-write regression, and the sharpest
// behavioural difference between POST and PUT.**
//
// The trap is constructed exactly as the Kotlin builds it: a SECOND row already owns the email the PUT
// body reuses, so an implementation that re-resolved by body key would mutate THAT row.
// KT: ScimUsersDbTest.kt#replaceScimUserById mutates the row AT this id — never a different row a body-key match would have resolved
// KT: ScimUsersDbTest.kt#replaceScimUserById is null (404) for a nonexistent id
func TestReplaceScimUserByIDNeverReDiscoversADifferentRow(t *testing.T) {
	f := newWriteFixture(t)

	target, err := f.store.UpsertScimUser(f.ctx, "okta-target", "target@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision target: %v", err)
	}
	// The decoy owns the email the PUT body is about to carry, and its own external_id.
	decoy, err := f.store.UpsertScimUser(f.ctx, "okta-decoy", "decoy@example.com",
		types.Ptr("shared@corp.example"), types.Ptr("Decoy"), true, f.creds)
	if err != nil {
		t.Fatalf("provision decoy: %v", err)
	}

	// The body RENAMES the target, exactly as the Kotlin's does: "the row at this id was mutated" and
	// "no other row was mutated" are two different claims, and a PUT that resolved the right id and
	// then wrote nothing would satisfy only the second.
	updated, err := f.store.ReplaceScimUserByID(f.ctx, target.ID, "target-renamed@example.com",
		types.Ptr("shared@corp.example"), types.Ptr("Target Renamed"), "okta-target", true, f.creds)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if updated == nil || updated.ID != target.ID {
		t.Fatalf("the PUT must land on the id in the URI, got %+v", updated)
	}
	if updated.Principal != "target-renamed@example.com" {
		t.Errorf("principal = %q, want the PUT body's target-renamed@example.com", updated.Principal)
	}
	if updated.DisplayName == nil || *updated.DisplayName != "Target Renamed" {
		t.Errorf("displayName = %v, want the PUT body's \"Target Renamed\"", updated.DisplayName)
	}

	after := f.user(decoy.ID, "the decoy")
	if after.Principal != "decoy@example.com" || after.DisplayName == nil || *after.DisplayName != "Decoy" {
		t.Errorf("the OTHER row was mutated — that is an accidental cross-resource write: %+v", after)
	}

	// Case 12 — nil (404 at the route) for a nonexistent id.
	missing, err := f.store.ReplaceScimUserByID(f.ctx, 987654321, "x@example.com", nil, nil, "okta-x", true, f.creds)
	if err != nil {
		t.Fatalf("replace(missing): %v", err)
	}
	if missing != nil {
		t.Errorf("a nonexistent id must answer nil, got %+v", missing)
	}
}

// Case 10 — `replaceScimUserById rejects an externalId that already belongs to a DIFFERENT row`. The
// Kotlin expects a RAW SQLException; the Go form is the pgx error the route then maps with
// store.IsUniqueViolation to 409 `uniqueness`.
// KT: ScimUsersDbTest.kt#replaceScimUserById rejects an externalId that already belongs to a DIFFERENT row
func TestReplaceScimUserByIDRejectsAnExternalIDOwnedByAnotherRow(t *testing.T) {
	f := newWriteFixture(t)

	mine, err := f.store.UpsertScimUser(f.ctx, "okta-mine", "mine@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := f.store.UpsertScimUser(f.ctx, "okta-theirs", "theirs@example.com", nil, nil, true, f.creds); err != nil {
		t.Fatalf("provision other: %v", err)
	}

	_, err = f.store.ReplaceScimUserByID(f.ctx, mine.ID, "mine@example.com", nil, nil, "okta-theirs", true, f.creds)
	if err == nil {
		t.Fatalf("stealing another row's externalId must fail — otherwise the directory splits brain")
	}
	if !store.IsUniqueViolation(err) {
		t.Errorf("want SQLSTATE 23505 (the route maps it to 409 uniqueness), got %v", err)
	}
}

// 🔒 ProvisionMergeDbTest cases 7 + 8 — a SCIM rename retires the old principal string so it cannot
// keep authenticating, and atomically revokes its tokens, grants and daemon/web sessions.
// KT: ProvisionMergeDbTest.kt#a SCIM rename retires the old principal string so it cannot keep authenticating
// KT: ProvisionMergeDbTest.kt#a SCIM rename atomically revokes the old principal's active credentials — tokens, grants, and daemon session window
// KT-OMIT: ProvisionMergeDbTest.kt#the public 5-arg upsertScimUser rename revokes the old principal credentials — the case exists
//
//	ONLY to prove the Kotlin's 5-arg convenience overload delegates to the 8-arg teardown path. Go has no
//	overload: this package cannot import internal/token or internal/access without inverting the dependency
//	direction, so UpsertScimUser takes the teardown explicitly and there is exactly ONE path. The teardown it
//	asserts is this test. See UpsertScimUser's DEVIATION note in scimstore.go.
func TestScimRenameRetiresAndRevokesTheOldPrincipal(t *testing.T) {
	f := newWriteFixture(t)
	const old = "old@example.com"
	const renamed = "new@example.com"

	before, err := f.store.UpsertScimUser(f.ctx, "okta-1", old, nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	oldCreds := f.seedCredentials(old, "reader")
	// The Kotlin's pre-state sanity: the string is live and every credential class usable, so the
	// post-rename assertions below cannot pass vacuously on rows that were never valid.
	if f.isDeactivated(old) {
		t.Fatalf("sanity: %s must be active before the rename", old)
	}
	f.assertAllLive(oldCreds, "before the rename")

	after, err := f.store.UpsertScimUser(f.ctx, "okta-1", renamed, nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("renaming push: %v", err)
	}
	// An in-place rename on the SAME identity: external_id matched, so the row moved rather than a
	// second row appearing next to a still-live old one.
	if after.ID != before.ID {
		t.Errorf("the rename created a new row (%d then %d) — external_id must match the same identity",
			before.ID, after.ID)
	}
	if after.Principal != renamed {
		t.Fatalf("principal %q, want %q", after.Principal, renamed)
	}
	if !f.isDeactivated(old) {
		t.Errorf("the vacated string must read isDeactivated == true (INV-A3-21)")
	}
	// And the renamed-TO string stays usable: a teardown that tombstoned the new principal too would
	// lock the surviving identity out of its own account.
	if f.isDeactivated(renamed) {
		t.Errorf("%s must stay active — the rename retires only the vacated string", renamed)
	}
	f.assertAllRevoked(oldCreds, "the retired principal")
}

// Case 6 — `findUserByExternalId finds a provisioned user and is null for an unknown id`, and its
// group twin (ScimGroupsDbTest case 3). Both are production-dead and test-live (F27).
// KT: ScimGroupsDbTest.kt#findGroupByExternalId finds a provisioned group and is null for an unknown id
// KT: ProvisionMergeDbTest.kt#findUserByExternalId and findGroupByExternalId round-trip
// KT: ScimUsersDbTest.kt#findUserByExternalId finds a provisioned user and is null for an unknown id
func TestFindByExternalIDRoundTrips(t *testing.T) {
	f := newWriteFixture(t)

	provisioned, err := f.store.UpsertScimUser(f.ctx, "okta-1", "alice@example.com", nil, nil, true, f.creds)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	found, err := f.store.FindUserByExternalID(f.ctx, "okta-1")
	if err != nil || found == nil || found.ID != provisioned.ID {
		t.Errorf("findUserByExternalId: got %+v, %v", found, err)
	}
	found, err = f.store.FindUserByExternalID(f.ctx, "nope")
	if err != nil || found != nil {
		t.Errorf("an unknown externalId must answer nil, got %+v, %v", found, err)
	}

	group, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("provision group: %v", err)
	}
	foundGroup, err := f.store.FindGroupByExternalID(f.ctx, "okta-g1")
	if err != nil || foundGroup == nil || foundGroup.ID != group.ID {
		t.Errorf("findGroupByExternalId: got %+v, %v", foundGroup, err)
	}
	foundGroup, err = f.store.FindGroupByExternalID(f.ctx, "nope")
	if err != nil || foundGroup != nil {
		t.Errorf("an unknown group externalId must answer nil, got %+v, %v", foundGroup, err)
	}
}

// ScimGroupsDbTest cases 1, 2, 4 and ProvisionMergeDbTest case 14 — provision, idempotence, distinct
// externalIds, and the `external_id → name` match order (including a JIT group later claimed by SCIM).
// KT: ScimGroupsDbTest.kt#upsertScimGroup provisions a source=SCIM group keyed on externalId
// KT: ScimGroupsDbTest.kt#upsertScimGroup is idempotent on repeated pushes for the same externalId
// KT: ScimGroupsDbTest.kt#distinct externalIds never collide into the same group row
// KT: ProvisionMergeDbTest.kt#upsertScimGroup matches an existing group by external_id then by name
func TestUpsertScimGroupProvisionsAndMatchesByExternalIDThenName(t *testing.T) {
	f := newWriteFixture(t)

	first, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if first.Source != "SCIM" || first.ExternalID == nil || *first.ExternalID != "okta-g1" || first.Name != "engineering" {
		t.Fatalf("want source=SCIM named engineering keyed on okta-g1, got %+v", first)
	}

	again, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil || again.ID != first.ID {
		t.Errorf("idempotence: got %+v, %v", again, err)
	}

	// A DISTINCT externalId is a distinct row, never a collision into the first one.
	other, err := f.store.UpsertScimGroup(f.ctx, "okta-g-other", "operations")
	if err != nil {
		t.Fatalf("provision a second group: %v", err)
	}
	if other.ID == first.ID {
		t.Errorf("two distinct externalIds collided into group row %d", other.ID)
	}

	// external_id wins over name: a rename at the IdP moves THIS row rather than creating a second.
	renamed, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "platform")
	if err != nil || renamed.ID != first.ID || renamed.Name != "platform" {
		t.Errorf("external_id must match first: got %+v, %v", renamed, err)
	}

	// A JIT group (source=OIDC, no external_id) is claimed BY NAME and reconciled to SCIM.
	jitID := f.scalarInt64(
		`INSERT INTO app_group (name, source) VALUES ('data-team', 'OIDC') RETURNING id`)
	claimed, err := f.store.UpsertScimGroup(f.ctx, "okta-g2", "data-team")
	if err != nil {
		t.Fatalf("claim by name: %v", err)
	}
	if claimed.ID != jitID {
		t.Errorf("a JIT group must be claimed in place (%d), got %d", jitID, claimed.ID)
	}
	if claimed.Source != "SCIM" {
		t.Errorf("source %q, want SCIM", claimed.Source)
	}
}

// 🔒 BootstrapAdminDbTest case 6 — `upsertScimGroup refuses to mutate the SYSTEM group atomically (by
// name and by externalId)`. **INV-A3-33 / INV-A3-34.**
//
// The by-externalId arm is the one that matters: it plants an `external_id` on the system row so the
// resolution goes down the path a route-level guard would have raced on, and asserts the row is
// UNTOUCHED afterwards. The by-name arm is INV-A3-34 — the seeded group always matches by name, so it
// can never be created or hijacked here.
//
// ⚠️ F36 — parameterised over ALL SEVEN seeded SYSTEM groups, not just `system:admin`. Every guard is
// keyed on the `source` column; a port that special-cased the admin string would pass the Kotlin's
// version of this case and leave six production-capability groups mutable.
// KT: BootstrapAdminDbTest.kt#upsertScimGroup refuses to mutate the SYSTEM group atomically (by name and by externalId)
func TestUpsertScimGroupRefusesEverySeededSystemGroupByNameAndByExternalID(t *testing.T) {
	f := newWriteFixture(t)

	for _, system := range f.seededSystemGroups() {
		// By NAME.
		_, err := f.store.UpsertScimGroup(f.ctx, "okta-hijack", system.Name)
		var immutable *SystemGroupImmutableError
		if !errors.As(err, &immutable) {
			t.Errorf("%s by name: got %v, want SystemGroupImmutableError", system.Name, err)
		}
		after := f.groupByID(system.ID)
		if after.Source != SystemSource || after.ExternalID != nil || after.Name != system.Name {
			t.Errorf("%s was mutated by a refused push: %+v", system.Name, after)
		}

		// By EXTERNAL_ID — plant one on the system row first, which is the resolution path a
		// route-level guard on a separate connection would have raced.
		f.exec(`UPDATE app_group SET external_id = $1 WHERE id = $2`, "planted-"+system.Name, system.ID)
		_, err = f.store.UpsertScimGroup(f.ctx, "planted-"+system.Name, "some-other-name")
		if !errors.As(err, &immutable) {
			t.Errorf("%s by externalId: got %v, want SystemGroupImmutableError", system.Name, err)
		}
		after = f.groupByID(system.ID)
		if after.Source != SystemSource || after.Name != system.Name {
			t.Errorf("%s was mutated through the externalId path: %+v", system.Name, after)
		}
		f.exec(`UPDATE app_group SET external_id = NULL WHERE id = $1`, system.ID)
	}
}

// 🔒 ScimGroupsDbTest case 6 — `a group with roles mapped via group_role is unaffected by SCIM
// provisioning`. The IdP supplies MEMBERSHIP only, never roles: `group_role` is the local,
// admin-owned map and that separation is the whole reason A3 exists as its own layer.
// KT: ScimGroupsDbTest.kt#a group with roles mapped via group_role is unaffected by SCIM provisioning
func TestScimProvisioningNeverTouchesGroupRoleMappings(t *testing.T) {
	f := newWriteFixture(t)

	groupID := f.seed.Group("engineering")
	roleID := f.seed.Role("reader")
	f.seed.GroupRole(groupID, roleID)

	claimed, err := f.store.UpsertScimGroup(f.ctx, "okta-g1", "engineering")
	if err != nil {
		t.Fatalf("claim by name: %v", err)
	}
	// The Kotlin pins the reconciliation itself: the push lands on THIS group row rather than creating a
	// second, role-less one beside it. Without this, the mapping below could survive simply because SCIM
	// never touched the group at all.
	if claimed.ID != groupID {
		t.Fatalf("the push created group %d beside %d instead of claiming it by name", claimed.ID, groupID)
	}
	if got := f.scalarInt64(`SELECT count(*) FROM app_group WHERE name = 'engineering'`); got != 1 {
		t.Errorf("%d groups named engineering, want 1 — the by-name claim must reconcile, not duplicate", got)
	}

	roles, err := f.store.ListGroupRoles(f.ctx, groupID)
	if err != nil {
		t.Fatalf("listGroupRoles: %v", err)
	}
	if len(roles) != 1 || roles[0].RoleID != roleID {
		t.Errorf("the group_role mapping must survive SCIM provisioning, got %+v", roles)
	}
}

// ⚠️ INV-A3-45's weaker half — `replaceScimGroupById` has NO SYSTEM guard of its own; the route
// checks first. This pins the ABSENCE, so anyone who later moves the guard into the store is doing it
// deliberately (03-identity-scim.md Q2) rather than by accident.
func TestReplaceScimGroupByIDHasNoSystemGuardOfItsOwn(t *testing.T) {
	f := newWriteFixture(t)
	system := f.seededSystemGroups()[0]

	updated, err := f.store.ReplaceScimGroupByID(f.ctx, system.ID, "okta-hijack", "hijacked")
	if err != nil {
		t.Fatalf("replaceScimGroupById: %v", err)
	}
	if updated == nil {
		t.Fatalf("the store must have mutated the row — it has no guard")
	}
	if updated.Source != "SCIM" || updated.Name != "hijacked" {
		t.Errorf("got %+v — this test pins that the STORE does not refuse; the ROUTE does", updated)
	}

	// The seed is down one SYSTEM group: the store really is unguarded, and the route is the only
	// thing standing between an IdP PUT and a seeded system group.
	if left := f.scalarInt64(`SELECT count(*) FROM app_group WHERE source = 'SYSTEM'`); left != 6 {
		t.Errorf("%d SYSTEM groups left after hijacking one through the store, want 6", left)
	}

	// nil (404 at the route) for a nonexistent id.
	missing, err := f.store.ReplaceScimGroupByID(f.ctx, 987654321, "okta-x", "x")
	if err != nil || missing != nil {
		t.Errorf("a nonexistent id must answer nil, got %+v, %v", missing, err)
	}
}

// groupByID reads a group back, failing the test if it vanished.
func (f *writeFixture) groupByID(id int64) AppGroup {
	f.t.Helper()
	out, err := f.store.GetGroup(f.ctx, id)
	if err != nil {
		f.t.Fatalf("getGroup(%d): %v", id, err)
	}
	if out == nil {
		f.t.Fatalf("group %d does not exist", id)
	}
	return *out
}
