package management

import (
	"sync"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
)

// ---------------------------------------------------------------------------------------------
// `UserAdminDeprovisionDbTest.kt`'s two REST-SHAPED cases — the ones that go through this service
// layer rather than through the store, and which internal/identity's port of that suite deliberately
// left here (see the ownership note at the top of usergroupwrites_db_test.go).
// ---------------------------------------------------------------------------------------------

// 🔒 UserAdminDeprovisionDbTest case 9 — `REST-shaped ID deprovision still targets the original row
// after a principal rename`.
//
// The REST surface addresses a user by ID, and the ID is the ONLY stable handle: `principal` is
// mutable, globally unique, and — because a rename leaves a TOMBSTONE on the vacated string
// (INV-A3-21) — the old value keeps resolving to a row afterwards. So a deprovision that re-resolved
// the principal it was handed, or that looked the id up by any body field, would have TWO rows to
// choose between and could deactivate the tombstone while the live identity kept its access.
//
// The console does exactly this sequence: rename a user, then deprovision them from the same page,
// against the id it loaded before the rename.
// KT: UserAdminDeprovisionDbTest.kt#REST-shaped ID deprovision still targets the original row after a principal rename
func TestRestShapedIDDeprovisionStillTargetsTheOriginalRowAfterARename(t *testing.T) {
	f := newFixture(t)
	const before = "id-stable-before@example.com"
	const after = "id-stable-after@example.com"

	original, err := f.identities.CreateUser(f.ctx, identity.AppUserInput{Principal: before, Active: true})
	assertNoError(t, err, "createUser")

	renamed, err := f.identities.UpdateUser(f.ctx, original.ID,
		identity.AppUserInput{Principal: after, Active: true})
	assertNoError(t, err, "updateUser (rename)")
	if renamed.Principal != after {
		t.Fatalf("the rename did not land: %+v", renamed)
	}
	// The tombstone on the vacated string is what makes this case bite: there are now TWO rows, and
	// only the id says which one the request meant.
	if n := f.scalarInt64(`SELECT count(*) FROM app_user WHERE principal = $1`, before); n != 1 {
		t.Fatalf("expected a tombstone row on the vacated string, found %d", n)
	}

	result, err := f.identities.DeprovisionUserByID(f.ctx, original.ID)
	assertNoError(t, err, "deprovisionUserByID")
	if !result.Deleted {
		t.Errorf("deleted = false for a live row")
	}

	addressed, err := f.userStore.GetUser(f.ctx, original.ID)
	assertNoError(t, err, "re-read the addressed row")
	if addressed == nil {
		t.Fatalf("the addressed row was HARD-deleted; deprovision is a soft delete (INV-A3-19)")
	}
	if addressed.Principal != after {
		t.Errorf("the deprovision landed on principal %q, want %q — it followed a stale principal "+
			"rather than the id in the URI", addressed.Principal, after)
	}
	if addressed.Active {
		t.Errorf("the addressed row is still active — the deprovision hit some other row")
	}
}

// 🔒 UserAdminDeprovisionDbTest case 10 — `concurrent REST-shaped group role additions retain both
// mappings`.
//
// `lockMutableGroup` serializes both callers on the GROUP's row (`SELECT source … FOR UPDATE`), which
// is what its SYSTEM guard needs — and the risk that creates is that a coarse lock plus a
// read-modify-write turns two ADDITIONS into one. Two operators mapping two different roles onto the
// same group at the same moment must end with BOTH mappings, not with the later one having replaced
// the earlier: `add` is not `set`.
//
// Both calls must also SUCCEED. A port that surfaced the lock wait as a serialization failure would
// leave the console showing an error for a mapping that is perfectly legal.
// KT: UserAdminDeprovisionDbTest.kt#concurrent REST-shaped group role additions retain both mappings
func TestConcurrentGroupRoleAdditionsRetainBothMappings(t *testing.T) {
	f := newFixture(t)
	groupID := f.seed.Group("concurrent-group-roles")
	first := f.seed.Role("concurrent-role-first")
	second := f.seed.Role("concurrent-role-second")

	// One barrier, released once both goroutines are parked on it, so the two calls really do overlap
	// rather than running in sequence because the first finished before the second started.
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, roleID := range []int64{first, second} {
		wg.Add(1)
		go func(slot int, role int64) {
			defer wg.Done()
			<-start
			_, errs[slot] = f.identities.AddGroupRole(f.ctx, groupID, role)
		}(i, roleID)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent addGroupRole #%d failed: %v — a lock WAIT must not surface as an error "+
				"on a legal mapping", i, err)
		}
	}

	entries, err := f.userStore.ListGroupRoles(f.ctx, groupID)
	assertNoError(t, err, "listGroupRoles")
	got := map[int64]bool{}
	for _, e := range entries {
		got[e.RoleID] = true
	}
	if len(entries) != 2 || !got[first] || !got[second] {
		t.Errorf("group_role holds %+v, want both %d and %d — one concurrent ADD overwrote the other",
			entries, first, second)
	}
}
