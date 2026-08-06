package management

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A11-32 — THREE SYSTEM-IMMUTABILITY GUARDS, THREE DIFFERENT MECHANISMS.
//
// 11-mcp-oauth-management.md §9 lists these under "nothing directly tests". They are the reason this
// service layer exists at all: `UserGroupStore` deliberately does NOT refuse a SYSTEM group (OIDC
// group sync manages `system:admin` membership by calling straight through it), so the ONLY thing
// standing between the admin API and a seeded SYSTEM group is this layer.
//
// 🔒 F34 — every fixture below names its SYSTEM group something that does NOT start with `system:`.
// A guard that passed only because of the name prefix would fail these, and V8__seed.sql seeds SEVEN
// SYSTEM groups whose protection must come from the `source` COLUMN.
// ---------------------------------------------------------------------------------------------

// ---- Guard #1: rejectSystem — an isSystemGroup read, NO row lock --------------------------------

// 🔒 `rejectSystem` guards FOUR management paths: update group, delete group, add member, remove
// member. All four must answer `group.system_immutable` (409 at the edge) and must leave the row
// untouched. Missing it on any ONE of them is a complete bypass, because they overlap in effect —
// e.g. an unguarded delete-group makes the guarded update-group irrelevant.
func TestRejectSystemGuardsAllFourGroupAndMemberPaths(t *testing.T) {
	f := newFixture(t)
	groupID := f.systemGroup("protected-group")
	userID := f.seed.User("alice@example.com")

	t.Run("update by id", func(t *testing.T) {
		_, err := f.identities.UpdateGroupByID(f.ctx, groupID, identity.AppGroupInput{Name: "renamed"})
		assertManagementCode(t, err, CodeGroupSystemImmutable, "update by id")
	})
	t.Run("update by name", func(t *testing.T) {
		_, err := f.identities.UpdateGroupByName(f.ctx, "protected-group", ptr("renamed"), nil)
		assertManagementCode(t, err, CodeGroupSystemImmutable, "update by name")
	})
	t.Run("delete by id", func(t *testing.T) {
		_, err := f.identities.DeleteGroupByID(f.ctx, groupID)
		assertManagementCode(t, err, CodeGroupSystemImmutable, "delete by id")
	})
	t.Run("delete by name", func(t *testing.T) {
		_, err := f.identities.DeleteGroupByName(f.ctx, "protected-group")
		assertManagementCode(t, err, CodeGroupSystemImmutable, "delete by name")
	})
	t.Run("add member by id", func(t *testing.T) {
		_, err := f.identities.AddGroupMemberByID(f.ctx, groupID, userID)
		assertManagementCode(t, err, CodeGroupSystemImmutable, "add member by id")
	})
	t.Run("add member by name", func(t *testing.T) {
		_, err := f.identities.AddGroupMemberByName(f.ctx, "protected-group", "alice@example.com")
		assertManagementCode(t, err, CodeGroupSystemImmutable, "add member by name")
	})
	t.Run("remove member by id", func(t *testing.T) {
		_, err := f.identities.RemoveGroupMemberByID(f.ctx, groupID, userID)
		assertManagementCode(t, err, CodeGroupSystemImmutable, "remove member by id")
	})
	t.Run("remove member by name", func(t *testing.T) {
		_, err := f.identities.RemoveGroupMemberByName(f.ctx, "protected-group", "alice@example.com")
		assertManagementCode(t, err, CodeGroupSystemImmutable, "remove member by name")
	})

	// Nothing above may have landed. The row is still there, still named, still SYSTEM, still empty.
	if n := f.scalarInt64(`SELECT COUNT(*) FROM app_group WHERE id=$1 AND name='protected-group' AND source='SYSTEM'`,
		groupID); n != 1 {
		t.Errorf("the SYSTEM group must be untouched, matching rows: %d", n)
	}
	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_member WHERE group_id=$1`, groupID); n != 0 {
		t.Errorf("no membership may have been created, got %d", n)
	}
}

// 🔒 The guard runs BEFORE validation, so a SYSTEM group renamed to blank is 409, not 400. A caller
// told "your name is blank" retries with a good name; a caller told "this group is immutable"
// stops. The order is ManagementServices.kt:595-597.
func TestSystemGroupImmutabilityIsDecidedBeforeFieldValidation(t *testing.T) {
	f := newFixture(t)
	groupID := f.systemGroup("protected-group")

	_, err := f.identities.UpdateGroupByID(f.ctx, groupID, identity.AppGroupInput{Name: "   "})
	assertManagementCode(t, err, CodeGroupSystemImmutable, "blank rename of a SYSTEM group")

	// The same blank rename on a LOCAL group DOES reach the validation.
	localID := f.seed.Group("engineering")
	_, err = f.identities.UpdateGroupByID(f.ctx, localID, identity.AppGroupInput{Name: "   "})
	e := assertManagementCode(t, err, "common.field_required", "blank rename of a LOCAL group")
	assertParam(t, e, "fields", "name", "blank rename of a LOCAL group")
}

// A LOCAL group is fully mutable through the same paths — otherwise the guard above would pass for
// the trivial reason that nothing works.
func TestALocalGroupIsMutableThroughEveryGuardedPath(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	userID := f.seed.User("alice@example.com")

	updated, err := f.identities.UpdateGroupByID(f.ctx, groupID,
		identity.AppGroupInput{Name: "engineering", Description: ptr("the eng team")})
	assertNoError(t, err, "update local group")
	if updated.Description == nil || *updated.Description != "the eng team" {
		t.Errorf("description: got %v, want the updated one", updated.Description)
	}

	member, err := f.identities.AddGroupMemberByName(f.ctx, "engineering", "alice@example.com")
	assertNoError(t, err, "add member")
	if member.UserID != userID {
		t.Errorf("member userId: got %d, want %d", member.UserID, userID)
	}

	// 🔒 `ON CONFLICT DO NOTHING` makes the add IDEMPOTENT — a re-add is a success returning the same
	// entry, not a 409. The management layer discards the store's boolean and re-reads.
	again, err := f.identities.AddGroupMemberByName(f.ctx, "engineering", "alice@example.com")
	assertNoError(t, err, "re-add member")
	if again.UserID != userID {
		t.Errorf("re-add must answer the same entry, got %+v", again)
	}
	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_member WHERE group_id=$1`, groupID); n != 1 {
		t.Errorf("re-add must not duplicate the row, got %d", n)
	}

	removed, err := f.identities.RemoveGroupMemberByName(f.ctx, "engineering", "alice@example.com")
	assertNoError(t, err, "remove member")
	if !removed.Deleted {
		t.Errorf("remove: got deleted=false, want true")
	}
	// ⚠️ A second remove is `deleted: false` and NOT a 404 — the DeleteResult is a body, not a status.
	removed, err = f.identities.RemoveGroupMemberByName(f.ctx, "engineering", "alice@example.com")
	assertNoError(t, err, "second remove")
	if removed.Deleted {
		t.Errorf("second remove: got deleted=true, want false")
	}

	deleted, err := f.identities.DeleteGroupByName(f.ctx, "engineering")
	assertNoError(t, err, "delete local group")
	if !deleted.Deleted {
		t.Errorf("delete: got deleted=false, want true")
	}
}

// ---- Guard #2: lockMutableGroup — SELECT source … FOR UPDATE -------------------------------------

// 🔒 The group→role paths use a DIFFERENT guard from the member paths: a `SELECT source … FOR UPDATE`
// rather than an `isSystemGroup` read. Same verdict, different mechanism, and both must be present —
// mapping a role onto `system:admin` is how you would grant yourself the admin role without touching
// any protected role.
func TestLockMutableGroupGuardsBothGroupRolePaths(t *testing.T) {
	f := newFixture(t)
	groupID := f.systemGroup("protected-group")
	roleID := f.seed.Role("reader")

	_, err := f.identities.AddGroupRole(f.ctx, groupID, roleID)
	assertManagementCode(t, err, CodeGroupSystemImmutable, "addGroupRole")

	_, err = f.identities.RemoveGroupRole(f.ctx, groupID, roleID)
	assertManagementCode(t, err, CodeGroupSystemImmutable, "removeGroupRole")

	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_role WHERE group_id=$1`, groupID); n != 0 {
		t.Errorf("no mapping may have been created, got %d", n)
	}
}

// 🔒 THE `FOR UPDATE` IS THE POINT, and this is the case that distinguishes the guard from a plain
// read: while `addGroupRole` holds the group's row, a concurrent transaction that tries to flip
// `source` to SYSTEM must BLOCK until the first commits. With a plain SELECT the flip would land
// between the check and the INSERT and the mapping would be written onto a system group.
//
// The test drives it from the other side, which is the observable one: it takes the row lock in raw
// SQL first, then shows the management call blocks rather than proceeding.
func TestLockMutableGroupActuallyTakesARowLock(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	roleID := f.seed.Role("reader")

	// Hold `app_group` row `groupID` under FOR UPDATE in an uncommitted transaction.
	holder, err := f.db.Pool.Begin(f.ctx)
	assertNoError(t, err, "begin holder")
	defer func() { _ = holder.Rollback(f.ctx) }()
	var source string
	assertNoError(t, holder.QueryRow(f.ctx,
		`SELECT source FROM app_group WHERE id=$1 FOR UPDATE`, groupID).Scan(&source), "holder lock")

	// The management call must not complete while the lock is held.
	blocked, cancel := context.WithTimeout(f.ctx, 400*time.Millisecond)
	defer cancel()
	_, err = f.identities.AddGroupRole(blocked, groupID, roleID)
	if err == nil {
		t.Fatalf("addGroupRole completed while another transaction held the row — the FOR UPDATE is missing")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the call to block until the deadline, got %v", err)
	}
	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_role WHERE group_id=$1`, groupID); n != 0 {
		t.Errorf("the blocked call must not have written, got %d rows", n)
	}

	// Release, and the same call now succeeds — so the block was the lock, not a broken query.
	assertNoError(t, holder.Rollback(f.ctx), "release holder")
	entry, err := f.identities.AddGroupRole(f.ctx, groupID, roleID)
	assertNoError(t, err, "addGroupRole after release")
	if entry.RoleName != "reader" {
		t.Errorf("entry: got %+v, want the resolved role", entry)
	}
}

// ⚠️ Q4's ASYMMETRY, PINNED — and pinned DETERMINISTICALLY, not by timing luck.
//
// The discriminator is a SYSTEM group with its row held under `FOR UPDATE` by another transaction.
// Both guards then reach their verdict before any write, so the only question is whether the guard
// itself waits for the lock:
//
//   - `rejectSystem` reads `source` WITHOUT `FOR UPDATE`, and a plain read never waits on a row lock
//     in Postgres — so update-group answers `group.system_immutable` IMMEDIATELY.
//   - `lockMutableGroup` reads it WITH `FOR UPDATE` — so addGroupRole BLOCKS, and never gets to
//     answer at all.
//
// One held row, two guards, two different outcomes. That is the asymmetry in one observation.
//
// This is REPRODUCE, not a bug report against the port: 11-mcp-oauth-management.md Q4 asks whether
// the group-update/member path is genuinely not racy or whether the lock is missing there. Recorded
// so that when Q4 is answered, adding a lock to `rejectSystem` is a deliberate edit to a named test
// rather than an accidental behaviour change.
func TestRejectSystemDeliberatelyTakesNoRowLockWhileLockMutableGroupDoes(t *testing.T) {
	f := newFixture(t)
	groupID := f.systemGroup("protected-group")
	roleID := f.seed.Role("reader")

	holder, err := f.db.Pool.Begin(f.ctx)
	assertNoError(t, err, "begin holder")
	defer func() { _ = holder.Rollback(f.ctx) }()
	var source string
	assertNoError(t, holder.QueryRow(f.ctx,
		`SELECT source FROM app_group WHERE id=$1 FOR UPDATE`, groupID).Scan(&source), "holder lock")

	// rejectSystem: unlocked read ⇒ the verdict arrives while the row is still held.
	unlocked, cancelUnlocked := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancelUnlocked()
	_, err = f.identities.UpdateGroupByID(unlocked, groupID, identity.AppGroupInput{Name: "renamed"})
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rejectSystem BLOCKED on the held row — it has acquired a FOR UPDATE it did not have. " +
			"That may be the right fix for Q4, but it is a behaviour change and this test is the pin.")
	}
	assertManagementCode(t, err, CodeGroupSystemImmutable, "rejectSystem under a held row lock")

	// lockMutableGroup: FOR UPDATE ⇒ it never reaches its verdict.
	locked, cancelLocked := context.WithTimeout(f.ctx, 400*time.Millisecond)
	defer cancelLocked()
	_, err = f.identities.AddGroupRole(locked, groupID, roleID)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lockMutableGroup must BLOCK on the held row; got %v", err)
	}

	t.Log("Q4 ASYMMETRY (reproduced, not fixed): rejectSystem reads `source` without FOR UPDATE, so a " +
		"concurrent transaction can flip it between the check and the mutation. lockMutableGroup and " +
		"setGroupRoles do take the lock.")
}

// ---- Guard #3: setGroupRoles' own inline FOR UPDATE, keyed on the NAME ---------------------------

func TestSetGroupRolesRefusesASystemGroup(t *testing.T) {
	f := newFixture(t)
	groupID := f.systemGroup("protected-group")
	f.seed.Role("reader")

	_, err := f.identities.SetGroupRoles(f.ctx, "protected-group", []string{"reader"})
	assertManagementCode(t, err, CodeGroupSystemImmutable, "setGroupRoles on a SYSTEM group")

	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_role WHERE group_id=$1`, groupID); n != 0 {
		t.Errorf("nothing may have been mapped, got %d", n)
	}
}

// 🔒 IT IS A DIFF, NOT A REPLACE — the invariant §8 states in as many words. The rows for roles that
// stay must be the SAME rows: `remove current - requested`, `add requested - current`. A
// delete-all-then-insert-all would be invisible from outside the transaction but would churn every
// row on every call, and this test is what tells the two apart.
//
// `group_role` has no surrogate key, so identity is proved by xmin — Postgres's per-row transaction
// id, which changes on any DELETE+INSERT and does not on a row left alone.
func TestSetGroupRolesDiffsRatherThanReplacing(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	keepID := f.seed.Role("keeper")
	dropID := f.seed.Role("dropped")
	f.seed.Role("added")
	f.seed.GroupRole(groupID, keepID)
	f.seed.GroupRole(groupID, dropID)

	before := f.scalarInt64(`SELECT xmin::text::bigint FROM group_role WHERE group_id=$1 AND role_id=$2`,
		groupID, keepID)

	out, err := f.identities.SetGroupRoles(f.ctx, "engineering", []string{"keeper", "added"})
	assertNoError(t, err, "setGroupRoles")

	// The answer is the RE-READ, in ORDER BY r.name order — not the caller's order.
	assertStrings(t, out.RoleNames, []string{"added", "keeper"}, "returned role names")
	if out.Group != "engineering" {
		t.Errorf("group: got %q, want %q", out.Group, "engineering")
	}
	assertStrings(t, f.groupRoleNames(groupID), []string{"added", "keeper"}, "group_role rows")

	after := f.scalarInt64(`SELECT xmin::text::bigint FROM group_role WHERE group_id=$1 AND role_id=$2`,
		groupID, keepID)
	if before != after {
		t.Errorf("the row for the role that STAYED was rewritten (xmin %d → %d) — that is a replace, "+
			"not a diff", before, after)
	}
}

// 🔒 EVERY NAME IS RESOLVED BEFORE ANYTHING IS MUTATED. One unknown name and the group's existing
// mappings are untouched — the same resolve-all-first discipline replaceDirectRoles has, and for the
// same reason: a partially-applied set is worse than a rejected one.
//
// ⚠️ The failure says just `role`, NOT `role '<name>'` — unlike replaceDirectRoles
// (ManagementServices.kt:694 vs :433). The caller gets no indication of WHICH name was wrong. That
// inconsistency between two methods doing the same job is the Kotlin's; REPRODUCE.
func TestSetGroupRolesRejectsAnUnknownNameWithoutTouchingTheExistingSet(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	existingID := f.seed.Role("keeper")
	f.seed.Role("added")
	f.seed.GroupRole(groupID, existingID)

	_, err := f.identities.SetGroupRoles(f.ctx, "engineering", []string{"added", "no-such-role"})
	e := assertManagementCode(t, err, "common.not_found", "unknown role name")
	assertParam(t, e, "resource", "role", "unknown role name")
	if e.Params["resource"] == "role 'no-such-role'" {
		t.Errorf("setGroupRoles must NOT name the offending role — that is replaceDirectRoles' behaviour")
	}

	assertStrings(t, f.groupRoleNames(groupID), []string{"keeper"},
		"the existing set must survive a rejected request")
}

// An empty request is a deliberate WIPE, not a no-op: `current - requested` is everything.
func TestSetGroupRolesWithAnEmptySetRemovesEveryMapping(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	f.seed.GroupRole(groupID, f.seed.Role("reader"))
	f.seed.GroupRole(groupID, f.seed.Role("writer"))

	out, err := f.identities.SetGroupRoles(f.ctx, "engineering", nil)
	assertNoError(t, err, "setGroupRoles with nil")
	assertStrings(t, out.RoleNames, []string{}, "returned role names")
	assertStrings(t, f.groupRoleNames(groupID), []string{}, "group_role rows")
	assertJSON(t, out, `{"group":"engineering","roleNames":[]}`, "wire shape of a wiped set")
}

// The validations `setGroupRoles` opens with, in the Kotlin's order: the group name, then EVERY role
// name. A blank role name is `common.field_required{fields: roleNames}` — plural key, plural field.
func TestSetGroupRolesValidatesTheGroupNameAndEveryRoleName(t *testing.T) {
	f := newFixture(t)
	f.seed.Group("engineering")

	_, err := f.identities.SetGroupRoles(f.ctx, "  ", []string{"reader"})
	e := assertManagementCode(t, err, "common.field_required", "blank group name")
	assertParam(t, e, "fields", "groupName", "blank group name")

	_, err = f.identities.SetGroupRoles(f.ctx, "engineering", []string{"reader", ""})
	e = assertManagementCode(t, err, "common.field_required", "blank role name")
	assertParam(t, e, "fields", "roleNames", "blank role name")

	_, err = f.identities.SetGroupRoles(f.ctx, "no-such-group", nil)
	e = assertManagementCode(t, err, "common.not_found", "unknown group")
	assertParam(t, e, "resource", "group", "unknown group")
}

// A duplicate name in the request is harmless — Kotlin's `Set<String>` cannot carry one, and the Go
// slice's duplicates collapse in the resolution map exactly as `associateWith` would.
func TestSetGroupRolesTreatsARepeatedNameAsOne(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	f.seed.Role("reader")

	out, err := f.identities.SetGroupRoles(f.ctx, "engineering", []string{"reader", "reader"})
	assertNoError(t, err, "setGroupRoles with a duplicate")
	assertStrings(t, out.RoleNames, []string{"reader"}, "returned role names")
	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_role WHERE group_id=$1`, groupID); n != 1 {
		t.Errorf("one mapping, got %d", n)
	}
}

// 🔒 setGroupRoles' lock is on the NAME, and it is a THIRD statement — not `lockMutableGroup`, which
// keys on the id. Proved the deterministic way: hold the group's row externally and the call must
// block, because its very first statement after the two `required` checks is the locking read.
//
// Without it, two concurrent calls would each read the same `current`, each compute a diff against
// it, and the committed result would be neither caller's set.
func TestSetGroupRolesTakesItsOwnNameKeyedRowLock(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	f.seed.Role("reader")

	holder, err := f.db.Pool.Begin(f.ctx)
	assertNoError(t, err, "begin holder")
	defer func() { _ = holder.Rollback(f.ctx) }()
	var source string
	assertNoError(t, holder.QueryRow(f.ctx,
		`SELECT source FROM app_group WHERE name='engineering' FOR UPDATE`).Scan(&source), "holder lock")

	blocked, cancel := context.WithTimeout(f.ctx, 400*time.Millisecond)
	defer cancel()
	_, err = f.identities.SetGroupRoles(blocked, "engineering", []string{"reader"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("setGroupRoles must block on the held row; got %v — its inline FOR UPDATE is missing", err)
	}
	if n := f.scalarInt64(`SELECT COUNT(*) FROM group_role WHERE group_id=$1`, groupID); n != 0 {
		t.Errorf("the blocked call must not have written, got %d rows", n)
	}

	assertNoError(t, holder.Rollback(f.ctx), "release holder")
	out, err := f.identities.SetGroupRoles(f.ctx, "engineering", []string{"reader"})
	assertNoError(t, err, "after release")
	assertStrings(t, out.RoleNames, []string{"reader"}, "after release")
}

// The property the lock buys, run repeatedly so a single lucky scheduling cannot pass for
// correctness: two goroutines, disjoint sets, one group. Whatever lands must be exactly one caller's
// set — never the union.
func TestSetGroupRolesUnderConcurrencyCommitsOneCallersSet(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	for _, name := range []string{"a1", "a2", "b1", "b2"} {
		f.seed.Role(name)
	}

	setA := []string{"a1", "a2"}
	setB := []string{"b1", "b2"}

	for round := range 25 {
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i, set := range [][]string{setA, setB} {
			wg.Add(1)
			go func(i int, set []string) {
				defer wg.Done()
				<-start
				_, errs[i] = f.identities.SetGroupRoles(context.Background(), "engineering", set)
			}(i, set)
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			assertNoError(t, err, "concurrent setGroupRoles")
		}

		got := f.groupRoleNames(groupID)
		if !sameSet(got, setA) && !sameSet(got, setB) {
			t.Fatalf("round %d: the committed set is neither caller's: got %v, want %v or %v — the two "+
				"diffs interleaved", round, got, setA, setB)
		}
	}
}

// ---- Reads, and the wire shapes they produce -----------------------------------------------------

func TestGroupReadsJoinMembersAndRolesAndAnswerNotFoundByName(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("engineering")
	userID := f.seed.User("alice@example.com")
	f.seed.GroupMember(groupID, userID)
	f.seed.GroupRole(groupID, f.seed.Role("reader"))

	group, err := f.identities.GetGroup(f.ctx, "engineering")
	assertNoError(t, err, "getGroup")
	if group.MemberCount != 1 {
		t.Errorf("memberCount: got %d, want 1", group.MemberCount)
	}
	if len(group.Roles) != 1 || group.Roles[0].Name != "reader" {
		t.Errorf("roles: got %+v, want [reader]", group.Roles)
	}
	if group.Source != "LOCAL" {
		t.Errorf("source: got %q, want LOCAL", group.Source)
	}

	_, err = f.identities.GetGroup(f.ctx, "no-such-group")
	e := assertManagementCode(t, err, "common.not_found", "unknown group")
	assertParam(t, e, "resource", "group", "unknown group")

	_, err = f.identities.GetUser(f.ctx, "nobody@example.com")
	e = assertManagementCode(t, err, "common.not_found", "unknown user")
	assertParam(t, e, "resource", "user", "unknown user")
}

// INV-A1-4 against real rows: a group with no roles and a user with no groups both marshal `[]`, and
// their absent optionals are omitted rather than null.
func TestIdentityReadsMarshalEmptyCollectionsAsArrays(t *testing.T) {
	f := newFixture(t)
	f.seed.Group("engineering")
	f.seed.User("alice@example.com")

	group, err := f.identities.GetGroup(f.ctx, "engineering")
	assertNoError(t, err, "getGroup")
	assertJSON(t, group,
		`{"id":`+itoa(group.ID)+`,"name":"engineering","source":"LOCAL","memberCount":0,"roles":[]}`,
		"AppGroup with nothing attached")

	user, err := f.identities.GetUser(f.ctx, "alice@example.com")
	assertNoError(t, err, "getUser")
	if len(user.Groups) != 0 {
		t.Fatalf("groups: got %+v, want none", user.Groups)
	}
	// createdAt is a timestamp, so the shape is asserted field by field rather than byte for byte.
	if user.DisplayName != nil || user.Email != nil || user.ExternalID != nil {
		t.Errorf("absent optionals must be nil (and therefore omitted), got %+v", user)
	}
	if !user.Active || user.Source != "LOCAL" {
		t.Errorf("a seeded user is active and LOCAL, got active=%v source=%q", user.Active, user.Source)
	}
}

// The user-write wrappers, which replaced the ErrUserWritesNotPorted stubs once A3's
// principal-mutating store landed. What is asserted here is ONLY the management layer's three
// guards; the teardown ORDERING they wrap is A3's and is asserted in
// internal/identity/usergroupwrites_db_test.go against real credential rows.
//
// ⚠️ The `unique` resource literal is `principal` while `notFound` says `user` — two different i18n
// keys for one table, both wire-visible, both reproduced.
func TestUserWriteWrappersEnforceRequiredUniqueAndNotFound(t *testing.T) {
	f := newFixture(t)

	// required("principal") — blank, and whitespace-only, are both field_required.
	_, err := f.identities.CreateUser(f.ctx, identity.AppUserInput{Principal: "", Active: true})
	assertManagementCode(t, err, "common.field_required", "createUser blank principal")
	_, err = f.identities.CreateUser(f.ctx, identity.AppUserInput{Principal: "   ", Active: true})
	assertManagementCode(t, err, "common.field_required", "createUser whitespace principal")

	created, err := f.identities.CreateUser(f.ctx, identity.AppUserInput{Principal: "alice@example.com", Active: true})
	assertNoError(t, err, "createUser")
	if !created.Active || created.Source != "LOCAL" {
		t.Errorf("a created user is active and LOCAL, got active=%v source=%q", created.Active, created.Source)
	}

	// unique("principal", …) — SQLSTATE 23505 becomes common.already_exists{resource: principal}.
	_, err = f.identities.CreateUser(f.ctx, identity.AppUserInput{Principal: "alice@example.com", Active: true})
	var me *Error
	if !errors.As(err, &me) || me.Err.Code != "common.already_exists" {
		t.Fatalf("duplicate principal: got %v, want common.already_exists", err)
	}
	if me.Err.Params["resource"] != ResourcePrincipal {
		t.Errorf("resource param %q, want %q (NOT %q — two different call sites)",
			me.Err.Params["resource"], ResourcePrincipal, ResourceUser)
	}

	// notFound("user") on an unknown id, from both id-keyed writes.
	_, err = f.identities.UpdateUser(f.ctx, 987654321, identity.AppUserInput{Principal: "x@example.com", Active: true})
	assertManagementCode(t, err, "common.not_found", "updateUser unknown id")
	_, err = f.identities.DeprovisionUserByID(f.ctx, 987654321)
	assertManagementCode(t, err, "common.not_found", "deprovisionUserByID unknown id")
	_, err = f.identities.DeprovisionUser(f.ctx, "nobody@example.com")
	assertManagementCode(t, err, "common.not_found", "deprovisionUser unknown principal")

	// 🔒 INV-A3-19 — deprovision is a soft delete: the row survives, inactive.
	result, err := f.identities.DeprovisionUserByID(f.ctx, created.ID)
	assertNoError(t, err, "deprovisionUserByID")
	if !result.Deleted {
		t.Errorf("deleted=%v, want true", result.Deleted)
	}
	after, err := f.userStore.GetUser(f.ctx, created.ID)
	assertNoError(t, err, "re-read")
	if after == nil {
		t.Fatalf("the row was HARD-deleted; INV-A3-19 says it must survive inactive")
	}
	if after.Active {
		t.Errorf("active=%v after deprovision, want false", after.Active)
	}
}

// A caller composing another write onto the same transaction gets the same guards — the `…On`
// overloads are not a bypass. This is the shape the MCP mutation executor uses to land its audit row
// atomically with the mutation.
func TestTheConnectionTakingOverloadsEnforceTheSameGuards(t *testing.T) {
	f := newFixture(t)
	f.systemGroup("protected-group")
	f.seed.Role("reader")

	err := store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		_, err := f.identities.SetGroupRolesOn(ctx, tx, "protected-group", []string{"reader"})
		return err
	})
	assertManagementCode(t, err, CodeGroupSystemImmutable, "SetGroupRolesOn")

	err = store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		_, err := f.identities.DeleteGroupByNameOn(ctx, tx, "protected-group")
		return err
	})
	assertManagementCode(t, err, CodeGroupSystemImmutable, "DeleteGroupByNameOn")
}

// sameSet reports whether two string slices hold the same members, order ignored.
func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, s := range got {
		seen[s]++
	}
	for _, s := range want {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
