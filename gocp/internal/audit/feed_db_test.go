package audit

import (
	"context"
	"reflect"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// TestLifecycleRowsAreVisibleInRecentAndGet is AuditFeedDbTest case 1.
//
// The audit feed carries EVERY kind, not just `decision`. An approval-lifecycle row ("this requester
// viewed their own stored result") is an audit event like any other, and a feed that filtered on
// kind = 'decision' would drop exactly the rows an auditor most wants. Nothing in the three read
// queries mentions kind — this case is what keeps it that way.
// KT: AuditFeedDbTest.kt#lifecycle rows are visible in recent and get
func TestLifecycleRowsAreVisibleInRecentAndGet(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	normal, err := s.Insert(ctx, types.NewAuditEvent("bob", "d", "select 1", types.DecisionAllow))
	if err != nil {
		t.Fatalf("insert normal: %v", err)
	}
	lifecycleRec := types.NewAuditEvent("alice", "d", "approval #1 result-viewed-by-requester", types.DecisionAllow)
	lifecycleRec.Kind = "approval_lifecycle"
	lifecycle, err := s.Insert(ctx, lifecycleRec)
	if err != nil {
		t.Fatalf("insert lifecycle: %v", err)
	}

	recent, err := s.Recent(ctx, 100)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if !containsID(recent, normal) {
		t.Errorf("recent(100) is missing the normal row %d", normal)
	}
	found := false
	for _, r := range recent {
		if r.ID != nil && *r.ID == lifecycle && r.Kind == "approval_lifecycle" {
			found = true
		}
	}
	if !found {
		t.Errorf("recent(100) is missing the approval_lifecycle row %d", lifecycle)
	}

	got, err := s.Get(ctx, normal)
	if err != nil || got == nil {
		t.Fatalf("get(%d) = %v, %v", normal, got, err)
	}
	gotLifecycle, err := s.Get(ctx, lifecycle)
	if err != nil || gotLifecycle == nil {
		t.Fatalf("get(%d) = %v, %v", lifecycle, gotLifecycle, err)
	}
	if gotLifecycle.Kind != "approval_lifecycle" {
		t.Errorf("get(%d).kind = %q, want approval_lifecycle", lifecycle, gotLifecycle.Kind)
	}
}

// TestEffectiveNamespaceRoundTripsThroughRecentAndGet is AuditFeedDbTest case 2.
//
// 🔒 INV-A8-5's other half. effective_namespace preserves INPUT ORDER — it is the resolved search
// path, and ["a","b"] is not the same namespace resolution as ["b","a"]. The four set-valued lists
// (roles, maskedColumns, piiTouched, contextTags) sort inside canon; this one must not, in canon OR in
// storage. A jsonb array preserves order, so the storage half is free — this case is what proves the
// read path does not reorder or dedupe on the way back.
// KT: AuditFeedDbTest.kt#effective namespace round-trips through recent and get
func TestEffectiveNamespaceRoundTripsThroughRecentAndGet(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	rec := types.NewAuditEvent("namespace-audit", "d", "select namespace_round_trip", types.DecisionMask)
	rec.EffectiveNamespace = []string{"a", "b"}
	id, err := s.Insert(ctx, rec)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	want := []string{"a", "b"}
	got, err := s.Get(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("get(%d) = %v, %v", id, got, err)
	}
	if !reflect.DeepEqual(got.EffectiveNamespace, want) {
		t.Errorf("get effectiveNamespace = %v, want %v", got.EffectiveNamespace, want)
	}

	recent, err := s.Recent(ctx, 100)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	single := findByID(t, recent, id)
	if !reflect.DeepEqual(single.EffectiveNamespace, want) {
		t.Errorf("recent effectiveNamespace = %v, want %v", single.EffectiveNamespace, want)
	}
}

// TestPrincipalScopedFeedFiltersBeforeLimit is AuditFeedDbTest case 3 — 🔒 INV-A8-4.
//
// The setup is built so the two implementations DISAGREE. Three rows with ascending timestamps:
// alice, alice-lifecycle, then bob (the NEWEST). `recent(1)` therefore returns bob's row. If
// `recent(1, alice)` fetched one row and then filtered, it would fetch bob's, discard it, and return
// NOTHING — alice's own audit feed would read as empty on a system where anyone else is busier than
// she is. With `WHERE principal` in the SQL it returns alice's newest, which is the lifecycle row.
//
// The lifecycle row being the answer is the second half of the case: ownership filtering must not
// quietly also filter by kind.
//
// KT: AuditFeedDbTest.kt#principal-scoped feed includes owned lifecycle rows before applying the limit
func TestPrincipalScopedFeedFiltersBeforeLimit(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	const alice = "audit-scope-alice"
	const bob = "audit-scope-bob"

	aliceNormal := types.NewAuditEvent(alice, "d", "select alice_scope_normal", types.DecisionAllow)
	aliceNormal.TS = types.Ptr("2099-01-01T00:00:00Z")
	if _, err := s.Insert(ctx, aliceNormal); err != nil {
		t.Fatalf("insert alice normal: %v", err)
	}

	aliceLifecycleRec := types.NewAuditEvent(alice, "d", "approval #2 result-viewed-by-requester", types.DecisionAllow)
	aliceLifecycleRec.TS = types.Ptr("2099-01-02T00:00:00Z")
	aliceLifecycleRec.Kind = "approval_lifecycle"
	aliceLifecycle, err := s.Insert(ctx, aliceLifecycleRec)
	if err != nil {
		t.Fatalf("insert alice lifecycle: %v", err)
	}

	bobNormalRec := types.NewAuditEvent(bob, "d", "select bob_scope_normal", types.DecisionAllow)
	bobNormalRec.TS = types.Ptr("2099-01-03T00:00:00Z")
	bobNormal, err := s.Insert(ctx, bobNormalRec)
	if err != nil {
		t.Fatalf("insert bob normal: %v", err)
	}

	whole, err := s.Recent(ctx, 1)
	if err != nil {
		t.Fatalf("recent(1): %v", err)
	}
	if len(whole) != 1 || *whole[0].ID != bobNormal {
		t.Fatalf("recent(1) = %v, want the single newest row %d", ids(whole), bobNormal)
	}

	owned, err := s.RecentForPrincipal(ctx, 1, alice)
	if err != nil {
		t.Fatalf("recent(1, alice): %v", err)
	}
	if len(owned) != 1 {
		t.Fatalf("recent(1, %s) returned %d rows, want 1 — the ownership filter must run BEFORE the limit (INV-A8-4)", alice, len(owned))
	}
	if *owned[0].ID != aliceLifecycle {
		t.Errorf("recent(1, %s) = %d, want %d", alice, *owned[0].ID, aliceLifecycle)
	}
	if owned[0].Kind != "approval_lifecycle" {
		t.Errorf("kind = %q, want approval_lifecycle", owned[0].Kind)
	}
	for _, r := range owned {
		if r.Principal != alice {
			t.Errorf("recent(1, %s) returned a row owned by %s", alice, r.Principal)
		}
	}
}

// TestGetReturnsNilForAMissingId closes one of 08-audit.md §4's named coverage gaps: the Kotlin only
// ever exercises `get` for a nonexistent id through the route, so nothing pins the STORE's answer.
// (nil, nil) — not an error — is what makes Reader.Detail able to conflate missing with denied.
func TestGetReturnsNilForAMissingId(t *testing.T) {
	s, _ := newStore(t)
	got, err := s.Get(context.Background(), 999_999)
	if err != nil {
		t.Fatalf("get of a missing id errored: %v", err)
	}
	if got != nil {
		t.Errorf("get of a missing id = %v, want nil", got)
	}
}

// TestRecentReturnsAnEmptyNonNilSlice pins ArrayList<AuditEvent>()'s Go equivalent: an empty feed is
// [] and never nil, so the response body is `[]` and not `null` (INV-A1-4 reaches the collection too).
func TestRecentReturnsAnEmptyNonNilSlice(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	for _, got := range []func() ([]types.AuditEvent, error){
		func() ([]types.AuditEvent, error) { return s.Recent(ctx, 100) },
		func() ([]types.AuditEvent, error) { return s.RecentForPrincipal(ctx, 100, "nobody") },
	} {
		out, err := got()
		if err != nil {
			t.Fatalf("read an empty feed: %v", err)
		}
		if out == nil {
			t.Error("an empty feed must be [], not nil")
		}
		if len(out) != 0 {
			t.Errorf("an empty feed returned %d rows", len(out))
		}
	}
}

func containsID(records []types.AuditEvent, id int64) bool {
	for _, r := range records {
		if r.ID != nil && *r.ID == id {
			return true
		}
	}
	return false
}

func findByID(t *testing.T, records []types.AuditEvent, id int64) types.AuditEvent {
	t.Helper()
	var found []types.AuditEvent
	for _, r := range records {
		if r.ID != nil && *r.ID == id {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one row with id %d, got %d", id, len(found))
	}
	return found[0]
}

func ids(records []types.AuditEvent) []int64 {
	out := make([]int64, 0, len(records))
	for _, r := range records {
		if r.ID != nil {
			out = append(out, *r.ID)
		}
	}
	return out
}
