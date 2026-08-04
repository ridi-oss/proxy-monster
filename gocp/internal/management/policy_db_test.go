package management

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

const validCedarSrc = `permit(principal in Role::"tester", action == Action::"audit.read", resource);`

const invalidCedarSrc = `permit(principal, action ==`

// ---------------------------------------------------------------------------------------------
// 🔒 INV-A11-30 — `isSystemRole` IS enforced on updateRole and deleteRole, at all FOUR call sites.
//
// F6 was raised by A9 because `Policies.kt` declares `isSystemRole` and never calls it; A11 closed it
// by finding the four sites in ManagementServices.kt (:362, :370, :382, :389). 11-mcp-oauth-management.md
// §9: "the guard F6 was worried about is present but UNVERIFIED". These are the verification.
//
// What the guard protects: a system role is one granted by a `source='SYSTEM'` group. Renaming it
// silently detaches every Cedar policy that names it — the policies keep referring to a role nothing
// grants, so every decision that depended on it starts denying. Deleting it is worse:
// `principal_role.role_id` and `group_role.role_id` are both ON DELETE CASCADE.
// ---------------------------------------------------------------------------------------------

// systemRole seeds a role granted by a SYSTEM-sourced group, which is what makes it a "system role".
//
// 🔒 INV-A9-1 / F34 — the name is deliberately ordinary. "System role" is DERIVED from the granting
// group's `source` column, never from a `system:` prefix and never from a column on `app_role`.
func systemRole(f *fixture, roleName string) int64 {
	f.t.Helper()
	roleID := f.seed.Role(roleName)
	groupID := f.systemGroup("granting-system-group-" + roleName)
	f.seed.GroupRole(groupID, roleID)
	return roleID
}

func TestUpdateRoleRefusesASystemRoleThroughBothOverloads(t *testing.T) {
	f := newFixture(t)
	roleID := systemRole(f, "protected")

	_, err := f.policies.UpdateRole(f.ctx, roleID, policy.RoleInput{Name: "renamed"})
	assertManagementCode(t, err, "role.system_immutable", "updateRole by id (ManagementServices.kt:362)")

	_, err = f.policies.UpdateRoleByName(f.ctx, "protected", ptr("renamed"), nil)
	assertManagementCode(t, err, "role.system_immutable", "updateRole by name (ManagementServices.kt:370)")

	if n := f.scalarInt64(`SELECT COUNT(*) FROM app_role WHERE id=$1 AND name='protected'`, roleID); n != 1 {
		t.Errorf("the role must still be named 'protected', matching rows: %d", n)
	}
}

func TestDeleteRoleRefusesASystemRoleThroughBothOverloads(t *testing.T) {
	f := newFixture(t)
	roleID := systemRole(f, "protected")
	f.seed.AssignRole("alice@example.com", roleID)

	err := f.policies.DeleteRole(f.ctx, roleID)
	assertManagementCode(t, err, "role.system_immutable", "deleteRole by id (ManagementServices.kt:382)")

	_, err = f.policies.DeleteRoleByName(f.ctx, "protected")
	assertManagementCode(t, err, "role.system_immutable", "deleteRole by name (ManagementServices.kt:389)")

	if n := f.scalarInt64(`SELECT COUNT(*) FROM app_role WHERE id=$1`, roleID); n != 1 {
		t.Errorf("the role must survive, got %d rows", n)
	}
	// The cascade the guard is protecting against: had the delete landed, this assignment would have
	// gone with it, silently.
	if n := f.scalarInt64(`SELECT COUNT(*) FROM principal_role WHERE role_id=$1`, roleID); n != 1 {
		t.Errorf("the direct assignment must survive, got %d rows", n)
	}
}

// 🔒 INV-A9-1 — protection is DERIVED and therefore REVOCABLE. A role stops being a system role the
// moment the last `source='SYSTEM'` group mapping is removed, because the guard asks about
// `group_role`/`app_group`, not about `app_role`.
//
// This is the semantics an `app_role.is_system` column would change, which is why the port must not
// add one. It is also why the guard cannot take a row lock: there is no single row to lock.
func TestSystemRoleProtectionIsDerivedFromTheGrantingGroupNotFromTheRole(t *testing.T) {
	f := newFixture(t)
	roleID := f.seed.Role("borderline")
	systemGroupID := f.systemGroup("granting-system-group")
	localGroupID := f.seed.Group("engineering")
	f.seed.GroupRole(systemGroupID, roleID)
	f.seed.GroupRole(localGroupID, roleID)

	_, err := f.policies.UpdateRoleByName(f.ctx, "borderline", ptr("renamed"), nil)
	assertManagementCode(t, err, "role.system_immutable", "while a SYSTEM group grants it")

	// A LOCAL group granting it changes nothing — remove the SYSTEM one and it becomes mutable.
	f.exec(`DELETE FROM group_role WHERE group_id=$1 AND role_id=$2`, systemGroupID, roleID)

	updated, err := f.policies.UpdateRoleByName(f.ctx, "borderline", ptr("renamed"), nil)
	assertNoError(t, err, "after the SYSTEM mapping is gone")
	if updated.Name != "renamed" {
		t.Errorf("name: got %q, want %q", updated.Name, "renamed")
	}
}

// 🔒 The guard runs BEFORE the field validation, at both overloads: renaming a system role to blank
// is 409 `role.system_immutable`, not 400 `common.field_required`. ManagementServices.kt:362-363.
func TestRoleImmutabilityIsDecidedBeforeFieldValidation(t *testing.T) {
	f := newFixture(t)
	roleID := systemRole(f, "protected")

	_, err := f.policies.UpdateRole(f.ctx, roleID, policy.RoleInput{Name: "  "})
	assertManagementCode(t, err, "role.system_immutable", "blank rename of a system role, by id")

	_, err = f.policies.UpdateRoleByName(f.ctx, "protected", ptr("  "), nil)
	assertManagementCode(t, err, "role.system_immutable", "blank rename of a system role, by name")

	// The same blank rename on an ordinary role DOES reach the validation, and the field it names is
	// `newName` on the name-keyed overload and `name` on the id-keyed one.
	ordinaryID := f.seed.Role("ordinary")
	_, err = f.policies.UpdateRole(f.ctx, ordinaryID, policy.RoleInput{Name: "  "})
	e := assertManagementCode(t, err, "common.field_required", "blank rename by id")
	assertParam(t, e, "fields", "name", "blank rename by id")

	_, err = f.policies.UpdateRoleByName(f.ctx, "ordinary", ptr("  "), nil)
	e = assertManagementCode(t, err, "common.field_required", "blank rename by name")
	assertParam(t, e, "fields", "newName", "blank rename by name")
}

// ---------------------------------------------------------------------------------------------
// 🔒 `unique(resource, name) { }` — the SQLSTATE 23505 mapping, against a REAL constraint violation.
// 11-mcp-oauth-management.md §9 lists it as untested.
// ---------------------------------------------------------------------------------------------

func TestDuplicateNamesMapSqlstate23505ToAlreadyExistsWithTheCallSitesResource(t *testing.T) {
	f := newFixture(t)
	f.seed.Role("reader")

	// `unique("role", name)` — app_role.name UNIQUE.
	_, err := f.policies.CreateRoleByName(f.ctx, "reader", nil)
	e := assertManagementCode(t, err, "common.already_exists", "duplicate role, name-keyed")
	assertParam(t, e, "resource", "role", "duplicate role")
	assertParam(t, e, "name", "reader", "duplicate role")

	_, err = f.policies.CreateRole(f.ctx, policy.RoleInput{Name: "reader"})
	e = assertManagementCode(t, err, "common.already_exists", "duplicate role, id-keyed")
	assertParam(t, e, "resource", "role", "duplicate role, id-keyed")

	// A RENAME onto an existing name hits the same constraint through the update path.
	f.seed.Role("writer")
	_, err = f.policies.UpdateRoleByName(f.ctx, "writer", ptr("reader"), nil)
	e = assertManagementCode(t, err, "common.already_exists", "rename onto an existing role")
	assertParam(t, e, "name", "reader", "rename onto an existing role")

	// `unique("mask function", name)` — mask_fn.name UNIQUE.
	_, err = f.policies.CreateMaskFn(f.ctx, policy.MaskFnInput{Name: "mask_email", Kind: "FIXED"})
	assertNoError(t, err, "first mask fn")
	_, err = f.policies.CreateMaskFn(f.ctx, policy.MaskFnInput{Name: "mask_email", Kind: "FIXED"})
	e = assertManagementCode(t, err, "common.already_exists", "duplicate mask fn")
	assertParam(t, e, "resource", "mask function", "duplicate mask fn")
}

// `mapPolicyErrors`' four arms, exercised through the NAME-KEYED policy methods A11 owns.
// 11-mcp-oauth-management.md:461-463.
func TestMapPolicyErrorsTranslatesAllFourArmsOnTheNameKeyedPath(t *testing.T) {
	f := newFixture(t)

	// SQLSTATE 23505 ⇒ common.already_exists{resource: policy}.
	_, err := f.policies.CreatePolicyByName(f.ctx, "dup", validCedarSrc, true, nil)
	assertNoError(t, err, "first create")
	_, err = f.policies.CreatePolicyByName(f.ctx, "dup", validCedarSrc, true, nil)
	e := assertManagementCode(t, err, "common.already_exists", "duplicate policy name")
	assertParam(t, e, "resource", "policy", "duplicate policy name")

	// ReservedPolicyNameException ⇒ policy.reserved_name.
	_, err = f.policies.CreatePolicyByName(f.ctx, "system:forged", validCedarSrc, true, nil)
	e = assertManagementCode(t, err, "policy.reserved_name", "reserved name")
	assertParam(t, e, "name", "system:forged", "reserved name")

	// InvalidCedarPolicyException ⇒ CedarValidationError, which is NOT a management failure and
	// carries the validator's raw array. Its wire body is `{errors: […]}`, not an ApiError.
	_, err = f.policies.CreatePolicyByName(f.ctx, "broken", invalidCedarSrc, true, nil)
	var cve *CedarValidationError
	if !errors.As(err, &cve) {
		t.Fatalf("invalid Cedar: got %T (%v), want *CedarValidationError", err, err)
	}
	if len(cve.Errors) == 0 {
		t.Errorf("the validator's raw error array must be preserved, got %v", cve.Errors)
	}
	var me *Error
	if errors.As(err, &me) {
		t.Errorf("a Cedar validation failure must not also be a management failure (code %q)", me.Err.Code)
	}

	// SystemPolicyImmutableException ⇒ policy.system_immutable. A SYSTEM policy can only be seeded
	// with a negative id — V3__policy.sql ties origin to the id's sign.
	f.exec(`INSERT INTO policy (id, name, cedar_src, enabled, origin, system_key)
	        VALUES (-9001, 'system:seeded', $1, TRUE, 'SYSTEM', 'seeded')`, validCedarSrc)
	_, err = f.policies.DeletePolicyByName(f.ctx, "system:seeded")
	assertManagementCode(t, err, "policy.system_immutable", "delete of a SYSTEM policy")
}

// 🔒 INV-A11-31 — `markCommittedMutation()` runs AFTER the transaction commits, and `deletePolicy`
// runs it ONLY WHEN A ROW WAS ACTUALLY DELETED. [policy.CedarPolicyStore.StateVersion] is the
// counter; the shared Cedar engine rebuilds its PolicySet when it changes.
func TestPolicyMutationsBumpAfterCommitAndDeleteOnlyWhenARowWent(t *testing.T) {
	f := newFixture(t)

	before := f.cedarStore.StateVersion()
	_, err := f.policies.CreatePolicyByName(f.ctx, "bump-me", validCedarSrc, true, nil)
	assertNoError(t, err, "create")
	if f.cedarStore.StateVersion() == before {
		t.Fatalf("create must bump the version")
	}

	before = f.cedarStore.StateVersion()
	_, err = f.policies.UpdatePolicyByName(f.ctx, "bump-me", nil, validCedarSrc, true, nil)
	assertNoError(t, err, "update")
	if f.cedarStore.StateVersion() == before {
		t.Errorf("update must bump the version")
	}

	before = f.cedarStore.StateVersion()
	_, err = f.policies.SetPolicyEnabledByName(f.ctx, "bump-me", false, nil)
	assertNoError(t, err, "disable")
	if f.cedarStore.StateVersion() == before {
		t.Errorf("setEnabled must bump the version")
	}

	before = f.cedarStore.StateVersion()
	out, err := f.policies.DeletePolicyByName(f.ctx, "bump-me")
	assertNoError(t, err, "delete")
	if !out.Deleted || f.cedarStore.StateVersion() == before {
		t.Errorf("a delete that removed a row must bump: deleted=%v", out.Deleted)
	}

	// 🔒 A delete that resolved nothing is a 404 and MUST NOT bump — the asymmetry the area doc cites
	// per-method. A spurious bump makes every control-plane instance rebuild its PolicySet for a
	// request that changed nothing.
	before = f.cedarStore.StateVersion()
	_, err = f.policies.DeletePolicyByName(f.ctx, "never-existed")
	assertManagementCode(t, err, "common.not_found", "delete of an absent policy")
	if f.cedarStore.StateVersion() != before {
		t.Errorf("a delete that removed nothing must NOT bump")
	}
}

// The name-keyed reads answer `common.not_found` with their own resource literal, and — unlike the
// mutating name-keyed methods — do NOT require a non-blank name. Reproduced as-is.
func TestNameKeyedReadsAnswerNotFoundWithTheirOwnResourceLiteral(t *testing.T) {
	f := newFixture(t)

	_, err := f.policies.GetPolicyByName(f.ctx, "ghost")
	e := assertManagementCode(t, err, "common.not_found", "getPolicy")
	assertParam(t, e, "resource", "policy", "getPolicy")

	_, err = f.policies.GetRoleByName(f.ctx, "ghost")
	e = assertManagementCode(t, err, "common.not_found", "getRole")
	assertParam(t, e, "resource", "role", "getRole")

	_, err = f.policies.GetMaskFnByName(f.ctx, "ghost")
	e = assertManagementCode(t, err, "common.not_found", "getMaskFn")
	assertParam(t, e, "resource", "mask function", "getMaskFn")

	// ⚠️ A BLANK name is a plain 404 here, not a 400 — the read overloads have no `required` call
	// while every mutating name-keyed method does.
	_, err = f.policies.GetPolicyByName(f.ctx, "")
	assertManagementCode(t, err, "common.not_found", "getPolicy with a blank name")

	// ⚠️ Filtering assignments by an UNKNOWN role is 404, not an empty list.
	_, err = f.policies.ListAssignmentsByRoleName(f.ctx, nil, ptr("ghost"))
	e = assertManagementCode(t, err, "common.not_found", "listAssignments by an unknown role")
	assertParam(t, e, "resource", "role", "listAssignments by an unknown role")
}

// ⚠️ The two id-keyed assignment paths answer DIFFERENTLY for the same bad input, and both are the
// Kotlin's. `assignRole(principal, roleId)` resolves the role and 404s; `createAssignment(input)` does
// not, so the unknown id reaches the FK as SQLSTATE 23503 — which store.IsUniqueViolation
// deliberately does not match (F29) and nothing else maps, so it surfaces as a plain error and
// StatusPages answers 500.
func TestTheTwoIdKeyedAssignmentPathsDisagreeOnAnUnknownRoleId(t *testing.T) {
	f := newFixture(t)
	const absent = int64(987654321)

	_, err := f.policies.AssignRoleByID(f.ctx, "alice@example.com", absent)
	e := assertManagementCode(t, err, "common.not_found", "assignRole(principal, roleId)")
	assertParam(t, e, "resource", "role", "assignRole(principal, roleId)")

	_, err = f.policies.CreateAssignment(f.ctx,
		policy.RoleAssignmentInput{Principal: "alice@example.com", RoleID: absent})
	if err == nil {
		t.Fatalf("createAssignment with an unknown role id must fail on the foreign key")
	}
	var me *Error
	if errors.As(err, &me) {
		t.Errorf("F29: the FK violation must NOT be mapped to a management failure, got %q", me.Err.Code)
	}
}

// ---------------------------------------------------------------------------------------------
// 🔒 `replaceDirectRoles` — FOUR invariants in one method. 11-mcp-oauth-management.md §9 singles the
// fourth out: "the ADVISORY-LOCK CONCURRENCY property, which is exactly the kind of thing that
// passes single-threaded and corrupts under load".
// ---------------------------------------------------------------------------------------------

// Invariants 1-3: resolve-all-before-delete-any; unknown names are REJECTED, never created; and the
// error names the OFFENDING role.
func TestReplaceDirectRolesResolvesEveryNameBeforeDeletingAnything(t *testing.T) {
	f := newFixture(t)
	f.seed.AssignRole("alice@example.com", f.seed.Role("existing"))
	f.seed.Role("wanted")

	_, err := f.policies.ReplaceDirectRoles(f.ctx, "alice@example.com", []string{"wanted", "typoed-role"})

	// 3. The rejection NAMES the offending role: the caller asked for a SET and the whole request
	//    fails on any one member, so "which one" is the only actionable part of the answer.
	e := assertManagementCode(t, err, "common.not_found", "unknown role in the set")
	assertParam(t, e, "resource", "role 'typoed-role'", "unknown role in the set")

	// 1. The EXISTING set is untouched — not stripped and then failed.
	assertStrings(t, f.directRoleNames("alice@example.com"), []string{"existing"},
		"the existing set must survive")

	// 2. Nothing was created. A typo that silently became a real role would resolve fine on the next
	//    call and then deny every query, since no policy references it.
	if n := f.scalarInt64(`SELECT COUNT(*) FROM app_role WHERE name='typoed-role'`); n != 0 {
		t.Errorf("an unknown name must never be created, found %d rows", n)
	}
}

// The happy path: the claim IS the whole intended set. Only DIRECT `principal_role` rows are touched
// — group-derived roles and JIT grants are separate sources and are deliberately left alone.
func TestReplaceDirectRolesMakesTheClaimTheWholeDirectSetAndLeavesGroupRolesAlone(t *testing.T) {
	f := newFixture(t)
	f.seed.AssignRole("alice@example.com", f.seed.Role("dropped"))
	f.seed.Role("kept")
	f.seed.Role("added")
	f.seed.AssignRole("alice@example.com", f.scalarInt64(`SELECT id FROM app_role WHERE name='kept'`))

	// A group-derived role for the same principal, which must survive untouched.
	groupID := f.seed.Group("engineering")
	userID := f.seed.User("alice@example.com")
	f.seed.GroupMember(groupID, userID)
	f.seed.GroupRole(groupID, f.seed.Role("from-group"))

	out, err := f.policies.ReplaceDirectRoles(f.ctx, "alice@example.com", []string{"kept", "added"})
	assertNoError(t, err, "replaceDirectRoles")
	if len(out) != 2 {
		t.Fatalf("returned assignments: got %d, want 2", len(out))
	}
	assertStrings(t, f.directRoleNames("alice@example.com"), []string{"added", "kept"}, "direct set")
	assertStrings(t, f.groupRoleNames(groupID), []string{"from-group"}, "group-derived roles")

	// An EMPTY claim is a deliberate wipe of the direct set, not a no-op.
	out, err = f.policies.ReplaceDirectRoles(f.ctx, "alice@example.com", nil)
	assertNoError(t, err, "replaceDirectRoles with an empty set")
	if out == nil {
		t.Errorf("the empty result must be `[]`, never nil — INV-A1-4")
	}
	assertStrings(t, f.directRoleNames("alice@example.com"), []string{}, "wiped direct set")
	assertStrings(t, f.groupRoleNames(groupID), []string{"from-group"}, "group roles after the wipe")

	// A blank principal is 400, not an assignment on the empty string.
	_, err = f.policies.ReplaceDirectRoles(f.ctx, "  ", nil)
	e := assertManagementCode(t, err, "common.field_required", "blank principal")
	assertParam(t, e, "fields", "principal", "blank principal")
}

// 🔒 INVARIANT 4, HALF ONE — THE LOCK IS TAKEN, WITH THE RIGHT KEY, BEFORE ANY READ OR WRITE.
//
// Deterministic rather than timing-dependent: an external transaction takes
// `pg_advisory_xact_lock(hashtext(<principal>))` — the SAME expression store.AdvisoryLockPrincipal
// issues, INV-A3-4 — and the replacement must then BLOCK. If the lock were absent, or keyed on
// anything else, the call would sail past and complete.
//
// This also pins the KEY: a port that hashed in-process and passed an integer would not contend with
// this raw-SQL lock, and a rolling Kotlin↔Go cutover would silently lose mutual exclusion for the
// whole deploy.
func TestReplaceDirectRolesTakesThePerPrincipalAdvisoryLockFirst(t *testing.T) {
	f := newFixture(t)
	f.seed.Role("wanted")
	const principal = "alice@example.com"

	holder, err := f.db.Pool.Begin(f.ctx)
	assertNoError(t, err, "begin holder")
	defer func() { _ = holder.Rollback(f.ctx) }()
	_, err = holder.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, principal)
	assertNoError(t, err, "holder takes the lock")

	blocked, cancel := context.WithTimeout(f.ctx, 500*time.Millisecond)
	defer cancel()
	_, err = f.policies.ReplaceDirectRoles(blocked, principal, []string{"wanted"})
	if err == nil {
		t.Fatalf("replaceDirectRoles completed while another transaction held the principal's advisory " +
			"lock — the lock is missing, or keyed on something else")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the call to block until the deadline, got %v", err)
	}
	if n := f.scalarInt64(`SELECT COUNT(*) FROM principal_role WHERE principal=$1`, principal); n != 0 {
		t.Errorf("the blocked call must not have written, got %d rows", n)
	}

	// A DIFFERENT principal is NOT blocked — the lock is per-principal, not global.
	other, cancelOther := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancelOther()
	_, err = f.policies.ReplaceDirectRoles(other, "bob@example.com", []string{"wanted"})
	assertNoError(t, err, "a different principal must not contend")

	assertNoError(t, holder.Rollback(f.ctx), "release holder")
	_, err = f.policies.ReplaceDirectRoles(f.ctx, principal, []string{"wanted"})
	assertNoError(t, err, "after release")
	assertStrings(t, f.directRoleNames(principal), []string{"wanted"}, "after release")
}

// 🔒 INVARIANT 4, HALF TWO — THE UNION BUG DOES NOT OCCUR.
//
// The failure this prevents, in the Kotlin's own words: "at READ COMMITTED a list-delete-insert is a
// read-modify-write, so two concurrent replacements each delete only the ids THEY listed and then
// insert their own — committing the UNION rather than either caller's set."
//
// Two goroutines, disjoint sets, one principal, repeated so a single lucky scheduling cannot pass for
// correctness. Whatever commits must be EXACTLY one caller's set. The companion test below shows the
// same shape WITHOUT the lock does produce the union, so a pass here is the lock and not the absence
// of a race.
func TestReplaceDirectRolesUnderConcurrencyCommitsOneCallersSetNotTheUnion(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"a1", "a2", "b1", "b2"} {
		f.seed.Role(name)
	}
	setA := []string{"a1", "a2"}
	setB := []string{"b1", "b2"}
	const principal = "alice@example.com"

	const rounds = 25
	for round := range rounds {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for i, set := range [][]string{setA, setB} {
			wg.Add(1)
			go func(i int, set []string) {
				defer wg.Done()
				<-start
				_, errs[i] = f.policies.ReplaceDirectRoles(context.Background(), principal, set)
			}(i, set)
		}
		close(start)
		wg.Wait()

		for _, err := range errs {
			assertNoError(t, err, fmt.Sprintf("round %d", round))
		}
		got := f.directRoleNames(principal)
		if !sameSet(got, setA) && !sameSet(got, setB) {
			t.Fatalf("round %d: the committed set is neither caller's: got %v, want %v or %v — the two "+
				"replacements interleaved and committed the UNION", round, got, setA, setB)
		}
	}
}

// 🔴 THE CONTROL. It performs replaceDirectRoles' exact sequence — list, delete each listed id,
// insert the requested set — WITHOUT the advisory lock, with a barrier forcing the interleave the
// lock exists to prevent, and asserts the UNION does commit.
//
// It proves the test above can fail. Without it, a green concurrency test is indistinguishable from
// one whose goroutines never overlapped, which is the standard way this class of bug survives a test
// suite. It asserts a DEFECT, deliberately: if the day comes that READ COMMITTED stops behaving this
// way, this is the test that says so.
func TestWithoutTheAdvisoryLockTheSameSequenceCommitsTheUnion(t *testing.T) {
	f := newFixture(t)
	roleIDs := map[string]int64{}
	for _, name := range []string{"a1", "a2", "b1", "b2"} {
		roleIDs[name] = f.seed.Role(name)
	}
	const principal = "alice@example.com"

	// Both callers must have READ before either DELETES; that is the read-modify-write window.
	read := make(chan struct{}, 2)
	proceed := make(chan struct{})

	unlockedReplace := func(set []string) error {
		return store.InTxDo(context.Background(), f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
			// NO store.AdvisoryLockPrincipal here — that is the whole point.
			existing, err := f.policyStore.ListAssignmentsOn(ctx, tx, ptr(principal), nil)
			if err != nil {
				return err
			}
			read <- struct{}{}
			<-proceed
			for _, a := range existing {
				if _, err := f.policyStore.DeleteAssignmentOn(ctx, tx, a.ID); err != nil {
					return err
				}
			}
			for _, name := range set {
				if _, err := f.policyStore.CreateAssignmentOn(ctx, tx,
					policy.RoleAssignmentInput{Principal: principal, RoleID: roleIDs[name]}); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// Seed a set for both to observe, so "delete only the ids THEY listed" has something to miss.
	f.seed.AssignRole(principal, roleIDs["a1"])

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, set := range [][]string{{"a1", "a2"}, {"b1", "b2"}} {
		wg.Add(1)
		go func(i int, set []string) {
			defer wg.Done()
			errs[i] = unlockedReplace(set)
		}(i, set)
	}
	<-read
	<-read
	close(proceed)
	wg.Wait()
	for _, err := range errs {
		assertNoError(t, err, "unlocked replacement")
	}

	got := f.directRoleNames(principal)
	if sameSet(got, []string{"a1", "a2"}) || sameSet(got, []string{"b1", "b2"}) {
		t.Fatalf("the unlocked control was expected to corrupt and did not (got %v) — the concurrency "+
			"test above is therefore not proving anything and this control needs strengthening", got)
	}
	t.Logf("REPRODUCED THE BUG THE LOCK PREVENTS: the committed set is %v — the UNION of two "+
		"replacements, which is neither caller's claim.", got)
}

// The `…On` overload composes onto a caller's transaction, which is what INV-A1-6 (`/auth/debug`,
// which mints a session for exactly these roles) needs: both writes commit together, under one lock.
// A rollback of the outer transaction must take the replacement with it.
func TestReplaceDirectRolesOnRollsBackWithItsCallersTransaction(t *testing.T) {
	f := newFixture(t)
	f.seed.AssignRole("alice@example.com", f.seed.Role("existing"))
	f.seed.Role("wanted")

	sentinel := errors.New("the caller's own later write failed")
	err := store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := f.policies.ReplaceDirectRolesOn(ctx, tx, "alice@example.com", []string{"wanted"}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the sentinel, got %v", err)
	}
	assertStrings(t, f.directRoleNames("alice@example.com"), []string{"existing"},
		"the replacement must have rolled back with its caller")
}
