package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// chainEvent is AuditChainDbTest's `event(statement, ts)` helper.
//
// The role list is not arbitrary. "finance,prod" carries a COMMA and "a" appears TWICE: a store that
// flattened the list into a comma-joined string would round-trip the first lossily and would drop the
// duplicate, and the recomputed hash would then disagree with the stored one. This is what makes the
// jsonb column a correctness requirement rather than a style choice (V4__audit.sql says so in prose;
// this event is what proves it).
func chainEvent(statement string, ts *string) types.AuditEvent {
	rec := types.NewAuditEvent("audit-chain", "main", statement, types.DecisionAllow)
	rec.TS = ts
	rec.Roles = []string{"finance,prod", "a", "a"}
	rec.EffectiveNamespace = []string{"main", "public"}
	rec.ContextTags = []string{"trusted", "alpha"}
	return rec
}

// TestSingleArgumentInsertsAllocateContiguousIds is AuditChainDbTest case 1 (INV-A8-1).
//
// Three claims in one: ids are contiguous, row N+1's prev_hash IS row N's row_hash, and every stored
// row's hash is reproducible from its stored columns. The fourth assertion is INV-A8-2's: a ts given
// to nanosecond precision reads back TRUNCATED TO MICROS, which is only true if the truncation
// happens before the hash as well as before the INSERT.
//
// KT: AuditChainDbTest.kt#single-argument inserts allocate contiguous ids and persist a recomputable chain
func TestSingleArgumentInsertsAllocateContiguousIds(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	first, err := s.Insert(ctx, chainEvent("single first", types.Ptr("2026-07-01T01:02:03.123456789Z")))
	if err != nil {
		t.Fatalf("insert first: %v", err)
	}
	second, err := s.Insert(ctx, chainEvent("single second", types.Ptr("2026-07-01T01:02:04.654321999Z")))
	if err != nil {
		t.Fatalf("insert second: %v", err)
	}
	if second != first+1 {
		t.Fatalf("ids are not contiguous: first %d, second %d", first, second)
	}

	rows := readRows(t, pool, []int64{first, second})
	if len(rows) != 2 {
		t.Fatalf("read %d rows, want 2", len(rows))
	}
	if !bytes.Equal(rows[0].rowHash, rows[1].prevHash) {
		t.Error("row 2's prev_hash is not row 1's row_hash — the chain is not linked")
	}
	for _, row := range rows {
		want, err := RowHash(row.id, row.event, row.tsMicros, row.prevHash)
		if err != nil {
			t.Fatalf("recompute row %d: %v", row.id, err)
		}
		if !bytes.Equal(want, row.rowHash) {
			t.Errorf("persisted row %d must reproduce its stored hash", row.id)
		}
	}

	// 🔒 INV-A8-2 — .123456789 in, .123456 out. Also pins FormatInstant: Go's RFC3339Nano would agree
	// on this particular value but not on a trailing-zero one, so canon_test covers the rest.
	if got := *rows[0].event.TS; got != "2026-07-01T01:02:03.123456Z" {
		t.Errorf("ts = %s, want 2026-07-01T01:02:03.123456Z", got)
	}
	mustVerifyWalk(t, pool)
}

// TestConnectionOverloadCommitsLinkedAndRollbackLeavesNothing is AuditChainDbTest case 2.
//
// 🔒 The case that fails if InsertOn is ever reimplemented to open its own transaction. The audit row
// and the state change it describes have to commit or roll back TOGETHER; an InsertOn that started its
// own transaction would leave a committed audit row behind after the caller rolled back, which is a
// record of something that did not happen — and it would also advance the chain head past a row that
// no longer exists, breaking every later verification.
//
// KT: AuditChainDbTest.kt#connection overload commits linked and rollback leaves both event and head untouched
func TestConnectionOverloadCommitsLinkedAndRollbackLeavesNothing(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	committed, err := store.InTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		return s.InsertOn(ctx, tx, chainEvent("connection commit", nil))
	})
	if err != nil {
		t.Fatalf("insert on a caller transaction: %v", err)
	}
	got, err := s.Get(ctx, committed)
	if err != nil {
		t.Fatalf("get committed: %v", err)
	}
	if got == nil || *got.ID != committed {
		t.Fatalf("committed row %d is not readable", committed)
	}

	headLastBefore, headHashBefore := chainHead(t, pool)

	// The rollback half, spelled out rather than through InTx: the caller owns the transaction, takes
	// the id InsertOn allocated, and then rolls back anyway.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rolledBack, err := s.InsertOn(ctx, tx, chainEvent("connection rollback", nil))
	if err != nil {
		t.Fatalf("insert before rollback: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	after, err := s.Get(ctx, rolledBack)
	if err != nil {
		t.Fatalf("get rolled-back: %v", err)
	}
	if after != nil {
		t.Errorf("rolled-back event %d is still readable", rolledBack)
	}
	headLastAfter, headHashAfter := chainHead(t, pool)
	if headLastAfter != headLastBefore {
		t.Errorf("chain head last_id moved across a rollback: %d -> %d", headLastBefore, headLastAfter)
	}
	if !bytes.Equal(headHashBefore, headHashAfter) {
		t.Error("chain head hash moved across a rollback")
	}
	mustVerifyWalk(t, pool)
}

// TestCompletionFieldsRoundTripAndRejectBogusDecisionId is AuditChainDbTest case 3.
//
// The completion half covers the three nullable bigints (rows_returned, bytes_returned, decision_id)
// and the non-default kind. The rejection half covers decision_id's foreign key back to audit_event:
// a completion may point at a RECORDED decision, never at one that does not exist — and, crucially,
// the failed append must leave the chain head exactly where it was, because Insert's transaction rolls
// back the head UPDATE along with the INSERT.
//
// 23503 (foreign-key violation) is deliberately NOT matched by store.IsUniqueViolation (F29); the test
// asserts the raw SQLSTATE so the two error classes stay distinguishable.
//
// KT: AuditChainDbTest.kt#completion fields round-trip chain and reject a bogus decision id
func TestCompletionFieldsRoundTripAndRejectBogusDecisionId(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	decisionID, err := s.Insert(ctx, chainEvent("decision source", nil))
	if err != nil {
		t.Fatalf("insert decision: %v", err)
	}

	completion := chainEvent("completion event", nil)
	completion.Kind = "completion"
	completion.RowsReturned = types.Ptr(int64(123))
	completion.BytesReturned = types.Ptr(int64(4567))
	completion.DecisionID = &decisionID
	completionID, err := s.Insert(ctx, completion)
	if err != nil {
		t.Fatalf("insert completion: %v", err)
	}

	stored, err := s.Get(ctx, completionID)
	if err != nil || stored == nil {
		t.Fatalf("get completion %d: %v", completionID, err)
	}
	if stored.Kind != "completion" {
		t.Errorf("kind = %q, want completion", stored.Kind)
	}
	if stored.RowsReturned == nil || *stored.RowsReturned != 123 {
		t.Errorf("rowsReturned = %v, want 123", stored.RowsReturned)
	}
	if stored.BytesReturned == nil || *stored.BytesReturned != 4567 {
		t.Errorf("bytesReturned = %v, want 4567", stored.BytesReturned)
	}
	if stored.DecisionID == nil || *stored.DecisionID != decisionID {
		t.Errorf("decisionId = %v, want %d", stored.DecisionID, decisionID)
	}
	mustVerifyWalk(t, pool)

	headLastBefore, headHashBefore := chainHead(t, pool)
	bogus := chainEvent("bad completion", nil)
	bogus.Kind = "completion"
	bogus.DecisionID = types.Ptr(int64(math.MaxInt64))
	if _, err := s.Insert(ctx, bogus); err == nil {
		t.Fatal("a completion pointing at a nonexistent decision was accepted")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Errorf("want SQLSTATE 23503 (foreign key violation), got %v", err)
		}
		if store.IsUniqueViolation(err) {
			t.Error("F29: IsUniqueViolation must NOT match a foreign-key violation")
		}
	}
	headLastAfter, headHashAfter := chainHead(t, pool)
	if headLastAfter != headLastBefore || !bytes.Equal(headHashBefore, headHashAfter) {
		t.Error("a failed append moved the chain head")
	}
	mustVerifyWalk(t, pool)
}

// TestVerifyWalkDetectsHistoricalMutation is AuditChainDbTest case 4 — the tamper-evidence property
// itself, and the reason the whole construction exists.
//
// An UPDATE to a stored `statement` is a legitimate SQL statement that a DBA with write access can run
// and that leaves no trace in the row. What it cannot do is produce a row_hash that still covers the
// new bytes. Restoring the original value makes the walk pass again, which is the other half of the
// property: the detector keys on the CONTENT, not on some mutation counter that a tamperer could also
// reset.
//
// KT: AuditChainDbTest.kt#verify walk detects a historical event mutation
func TestVerifyWalkDetectsHistoricalMutation(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	id, err := s.Insert(ctx, chainEvent("tamper original", nil))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	mustVerifyWalk(t, pool)

	setStatement := func(value string) {
		t.Helper()
		tag, err := pool.Exec(ctx, `UPDATE audit_event SET statement = $1 WHERE id = $2`, value, id)
		if err != nil {
			t.Fatalf("tamper: %v", err)
		}
		if tag.RowsAffected() != 1 {
			t.Fatalf("tamper affected %d rows, want 1", tag.RowsAffected())
		}
	}

	setStatement("tampered")
	if err := verifyWalk(t, pool); err == nil {
		t.Fatal("the verification walk did not detect a mutated event")
	}

	setStatement("tamper original")
	mustVerifyWalk(t, pool)
}

// TestConcurrentAppendsSerialize is AuditChainDbTest case 5 — 🔒 THE case that fails if the FOR UPDATE
// chain-head lock is dropped (INV-A8-1).
//
// Six workers × eight appends, all released from one barrier so the writes genuinely overlap rather
// than lining up behind a slow test. Without the lock, two transactions read the same last_id, both
// compute the same newId, and one of three things happens: a duplicate-key failure, a lost update on
// the chain head, or two rows carrying the same prev_hash — a FORKED chain that verifies row-by-row
// and is still wrong. The three assertions below catch all three:
//
//   - every append returned an id, and the ids are DISTINCT;
//   - the ids are a contiguous run with no gap;
//   - the full verification walk still passes, i.e. the chain is one line, not a fork.
//
// The pool is capped at store.MaxPoolSize = 10 (HikariCP's maximumPoolSize), so six concurrent
// transactions fit without the test deadlocking on connection acquisition — worth knowing before
// raising the worker count.
//
// KT: AuditChainDbTest.kt#concurrent appends serialize without duplicate ids and preserve the chain
func TestConcurrentAppendsSerialize(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	const workers = 6
	const perWorker = 8

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := make([]int64, 0, workers*perWorker)
	errs := make([]error, 0)

	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := range perWorker {
				id, err := s.Insert(ctx, chainEvent(fmt.Sprintf("concurrent-%d-%d", worker, i), nil))
				mu.Lock()
				if err != nil {
					errs = append(errs, err)
				} else {
					ids = append(ids, id)
				}
				mu.Unlock()
			}
		}(w)
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Errorf("concurrent insert failed: %v", err)
	}
	if len(ids) != workers*perWorker {
		t.Fatalf("got %d ids, want %d", len(ids), workers*perWorker)
	}

	seen := make(map[int64]bool, len(ids))
	minID, maxID := ids[0], ids[0]
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate id %d — the chain-head lock did not serialise the appends", id)
		}
		seen[id] = true
		if id < minID {
			minID = id
		}
		if id > maxID {
			maxID = id
		}
	}
	if maxID-minID+1 != int64(len(ids)) {
		t.Errorf("ids %d..%d are not a contiguous run of %d", minID, maxID, len(ids))
	}
	mustVerifyWalk(t, pool)
}
