package result_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// QueryResultStoreDbTest.kt — 8 cases, DB (07-tasks-approvals-results.md §10).
//
// The suite is one Go test with subtests rather than eight top-level tests, which reproduces the
// Kotlin's @TestInstance(PER_CLASS) + @BeforeAll shape: ONE migrated database and one datasource for
// the whole class, with the cases sharing it. The fixture's cleanup then runs after the last subtest.
//
// It lives in package result_test (an external test package) because the cases drive the PARENT
// through the production AccessStore — internal/access imports internal/result for RetentionSec, so an
// in-package test importing access would be an import cycle.

// resultFixture is the Kotlin @BeforeAll: a fresh migrated store, one datasource, an AccessStore and a
// QueryResultStore over the same fixed 0x00..0x1f key ResultCryptoTest uses.
type resultFixture struct {
	ctx          context.Context
	pool         *pgxpool.Pool
	store        *result.Store
	access       *access.Store
	datasourceID int64
}

func newResultFixture(t *testing.T) *resultFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	seed := dbtest.NewSeed(t, db)
	key := make([]byte, result.KeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	crypto, err := result.NewCrypto(key)
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	return &resultFixture{
		ctx:    context.Background(),
		pool:   db.Pool,
		store:  result.NewStore(db.Pool, crypto),
		access: access.NewStore(db.Pool),
		datasourceID: seed.Datasource(dbtest.DatasourceSpec{
			Name: "ds", Engine: dbtest.EnginePostgres, Host: "h", Port: 5432, DBName: "d",
		}),
	}
}

// newTask is the Kotlin helper: a WORKFLOW query task with one not-started child carrying
// "select id, rrn from users".
func (f *resultFixture) newTask(t *testing.T) int64 {
	t.Helper()
	req, err := f.access.CreateQueryRequest(f.ctx, access.CreateQueryRequestInput{
		Principal:         "alice@example.com",
		DatasourceID:      f.datasourceID,
		SQL:               "select id, rrn from users",
		Reason:            ptr("r"),
		Title:             ptr("t"),
		EvaluatedDecision: ptr("MASK"),
	})
	if err != nil {
		t.Fatalf("createQueryRequest: %v", err)
	}
	return req.ID
}

func ptr[T any](v T) *T { return &v }

// sampleResult is the Kotlin `result()`: two rows carrying the PM_SECRET_ markers the ciphertext
// assertion looks for.
func sampleResult() result.DecryptedResult {
	return result.DecryptedResult{
		Columns: []string{"id", "rrn"},
		Rows: [][]*string{
			{ptr("1"), ptr("PM_SECRET_900101")},
			{ptr("2"), ptr("PM_SECRET_850202")},
		},
	}
}

func rowsEqual(a, b [][]*string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			switch {
			case a[i][j] == nil && b[i][j] == nil:
			case a[i][j] == nil || b[i][j] == nil:
				return false
			case *a[i][j] != *b[i][j]:
				return false
			}
		}
	}
	return true
}

func resultEqual(a, b result.DecryptedResult) bool {
	if len(a.Columns) != len(b.Columns) {
		return false
	}
	for i := range a.Columns {
		if a.Columns[i] != b.Columns[i] {
			return false
		}
	}
	return rowsEqual(a.Rows, b.Rows)
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// approve flips the parent to APPROVED with raw SQL, exactly as the Kotlin helper does — the point of
// cases 3 and 4 is the CLAIM, so the parent is put in place without going through a decision.
func (f *resultFixture) approve(t *testing.T, id int64) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, "UPDATE access_request SET status = 'APPROVED' WHERE id = $1", id); err != nil {
		t.Fatalf("approve %d: %v", id, err)
	}
}

func TestQueryResultStore(t *testing.T) {
	f := newResultFixture(t)
	ctx := f.ctx

	// KT: QueryResultStoreDbTest.kt#child transitions from pending to running to done with encrypted rows
	// 1. child transitions from pending to running to done with encrypted rows
	t.Run("child transitions from pending to running to done with encrypted rows", func(t *testing.T) {
		id := f.newTask(t)

		running, err := f.store.StartRun(ctx, id, "bob@example.com")
		if err != nil {
			t.Fatalf("StartRun: %v", err)
		}
		if running == nil || str(running.Status) != "RUNNING" {
			t.Fatalf("StartRun status = %v, want RUNNING", running)
		}
		if str(running.ExecutedBy) != "bob@example.com" {
			t.Errorf("child executedBy = %q, want bob@example.com", str(running.ExecutedBy))
		}
		// The parent's executedBy is the correlated subquery over its earliest child.
		parent, err := f.access.GetRequest(ctx, id)
		if err != nil {
			t.Fatalf("GetRequest: %v", err)
		}
		if str(parent.ExecutedBy) != "bob@example.com" {
			t.Errorf("request executedBy = %q, want bob@example.com", str(parent.ExecutedBy))
		}

		done, err := f.store.CompleteRun(ctx, id, sampleResult(), 3600, nil)
		if err != nil {
			t.Fatalf("CompleteRun: %v", err)
		}
		if done == nil || str(done.Status) != "DONE" {
			t.Fatalf("CompleteRun status = %v, want DONE", done)
		}
		if done.RowCount == nil || *done.RowCount != 2 {
			t.Errorf("rowCount = %v, want 2", done.RowCount)
		}

		access, err := f.store.AccessFor(ctx, id)
		if err != nil {
			t.Fatalf("AccessFor: %v", err)
		}
		got, err := access.Decrypted()
		if err != nil {
			t.Fatalf("Decrypted: %v", err)
		}
		if got == nil || !resultEqual(*got, sampleResult()) {
			t.Errorf("decrypted = %+v, want %+v", got, sampleResult())
		}

		// cancel-after-DONE is an idempotent no-op
		cancelled, err := f.store.CancelRun(ctx, id, nil)
		if err != nil {
			t.Fatalf("CancelRun after DONE: %v", err)
		}
		if cancelled != nil {
			t.Errorf("CancelRun after DONE = %+v, want nil", cancelled)
		}

		// 🔒 the stored bytes must not contain the cleartext marker.
		var ciphertext []byte
		if err := f.pool.QueryRow(ctx, "SELECT ciphertext FROM query_result WHERE task_id = $1", id).Scan(&ciphertext); err != nil {
			t.Fatalf("read ciphertext: %v", err)
		}
		if bytes.Contains(ciphertext, []byte("PM_SECRET_900101")) {
			t.Error("the stored blob contains the cleartext value")
		}
	})

	// KT: QueryResultStoreDbTest.kt#failed child stores a stable error code without ciphertext
	// 2. failed child stores a stable error code without ciphertext
	t.Run("failed child stores a stable error code without ciphertext", func(t *testing.T) {
		id := f.newTask(t)
		if running, err := f.store.StartRun(ctx, id, "bob@example.com"); err != nil || running == nil {
			t.Fatalf("StartRun = %v, %v", running, err)
		}
		failed, err := f.store.FailRun(ctx, id, "approval.execute_denied", nil)
		if err != nil {
			t.Fatalf("FailRun: %v", err)
		}
		if failed == nil || str(failed.Status) != "FAILED" {
			t.Fatalf("FailRun status = %v, want FAILED", failed)
		}
		if str(failed.ErrorCode) != "approval.execute_denied" {
			t.Errorf("errorCode = %q, want approval.execute_denied", str(failed.ErrorCode))
		}
		acc, err := f.store.AccessFor(ctx, id)
		if err != nil {
			t.Fatalf("AccessFor: %v", err)
		}
		got, err := acc.Decrypted()
		if err != nil {
			t.Fatalf("Decrypted: %v", err)
		}
		if got != nil {
			t.Errorf("a FAILED child decrypted to %+v, want nil", got)
		}
	})

	// 3. 🔒 claimAndStartRun atomically claims the parent and starts the child, closing the cancel
	//    window (INV-A7-7)
	// KT: QueryResultStoreDbTest.kt#claimAndStartRun atomically claims the parent and starts the child, closing the cancel window
	t.Run("claimAndStartRun atomically claims the parent and starts the child closing the cancel window", func(t *testing.T) {
		id := f.newTask(t)
		f.approve(t, id)

		// While APPROVED there is no RUNNING child yet — a cancel would find nothing to cancel.
		if got, err := f.store.CancelRun(ctx, id, nil); err != nil || got != nil {
			t.Fatalf("CancelRun before the run starts = %v, %v; want nil, nil", got, err)
		}

		// One transaction: parent APPROVED→EXECUTING AND child NULL→RUNNING commit together, so a
		// cancel can never observe an EXECUTING parent without a RUNNING child (the window that let a
		// canceled query run).
		started, err := f.store.ClaimAndStartRun(ctx, id, "bob@example.com",
			func(ctx context.Context, c store.Queryer) (bool, error) {
				return f.access.ClaimExecutionOn(ctx, c, id)
			})
		if err != nil {
			t.Fatalf("ClaimAndStartRun: %v", err)
		}
		if started == nil || str(started.Status) != "RUNNING" {
			t.Fatalf("ClaimAndStartRun status = %v, want RUNNING", started)
		}
		if str(started.ExecutedBy) != "bob@example.com" {
			t.Errorf("executedBy = %q, want bob@example.com", str(started.ExecutedBy))
		}
		if parent, err := f.access.GetRequest(ctx, id); err != nil || parent.Status != "EXECUTING" {
			t.Fatalf("parent status = %v, %v; want EXECUTING", parent, err)
		}

		// Now that the parent is EXECUTING it ALWAYS has a RUNNING child a cancel catches.
		cancelled, err := f.store.CancelRun(ctx, id, func(ctx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
			won, err := f.access.MarkCancelledOn(ctx, c, id)
			if err != nil {
				return err
			}
			if !won {
				t.Error("markCancelled did not fire inside the cancel hook")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("CancelRun: %v", err)
		}
		if cancelled == nil || str(cancelled.Status) != "CANCELLED" {
			t.Fatalf("CancelRun status = %v, want CANCELLED", cancelled)
		}
		if parent, err := f.access.GetRequest(ctx, id); err != nil || parent.Status != "CANCELLED" {
			t.Fatalf("parent status = %v, %v; want CANCELLED", parent, err)
		}
	})

	// 4. claimAndStartRun is single-shot — a second claim on a non-APPROVED task loses
	// KT: QueryResultStoreDbTest.kt#claimAndStartRun is single-shot - a second claim on a non-APPROVED task loses
	t.Run("claimAndStartRun is single-shot - a second claim on a non-APPROVED task loses", func(t *testing.T) {
		id := f.newTask(t)
		f.approve(t, id)
		claim := func(ctx context.Context, c store.Queryer) (bool, error) {
			return f.access.ClaimExecutionOn(ctx, c, id)
		}
		if first, err := f.store.ClaimAndStartRun(ctx, id, "bob@example.com", claim); err != nil || first == nil {
			t.Fatalf("first ClaimAndStartRun = %v, %v", first, err)
		}
		// Parent is already EXECUTING → claimExecution returns false → the whole step is a nil no-op,
		// NOT an error: the caller treats it as already-executed.
		second, err := f.store.ClaimAndStartRun(ctx, id, "carol@example.com", claim)
		if err != nil {
			t.Fatalf("second ClaimAndStartRun: %v", err)
		}
		if second != nil {
			t.Errorf("second ClaimAndStartRun = %+v, want nil", second)
		}
		meta, err := f.store.Meta(ctx, id)
		if err != nil {
			t.Fatalf("Meta: %v", err)
		}
		if str(meta.ExecutedBy) != "bob@example.com" {
			t.Errorf("executedBy = %q, want bob@example.com (the loser must not overwrite it)", str(meta.ExecutedBy))
		}
	})

	// KT: QueryResultStoreDbTest.kt#cancelRun atomically cancels the child and parent and wins late completion
	// 5. cancelRun atomically cancels the child and parent and wins late completion
	t.Run("cancelRun atomically cancels the child and parent and wins late completion", func(t *testing.T) {
		id := f.newTask(t)
		if _, err := f.pool.Exec(ctx, "UPDATE access_request SET status = 'EXECUTING' WHERE id = $1", id); err != nil {
			t.Fatalf("force EXECUTING: %v", err)
		}
		if running, err := f.store.StartRun(ctx, id, "bob@example.com"); err != nil || running == nil {
			t.Fatalf("StartRun = %v, %v", running, err)
		}
		cancelled, err := f.store.CancelRun(ctx, id, func(ctx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
			won, err := f.access.MarkCancelledOn(ctx, c, id)
			if err == nil && !won {
				t.Error("markCancelled did not fire inside the cancel hook")
			}
			return err
		})
		if err != nil {
			t.Fatalf("CancelRun: %v", err)
		}
		if cancelled == nil || str(cancelled.Status) != "CANCELLED" {
			t.Fatalf("CancelRun status = %v, want CANCELLED", cancelled)
		}
		if str(cancelled.ErrorCode) != "approval.canceled" {
			t.Errorf("errorCode = %q, want approval.canceled", str(cancelled.ErrorCode))
		}
		if cancelled.ExpiresAt == nil {
			t.Error("a cancelled child must carry expires_at so purgeExpired eventually GCs it")
		}
		if parent, err := f.access.GetRequest(ctx, id); err != nil || parent.Status != "CANCELLED" {
			t.Fatalf("parent status = %v, %v; want CANCELLED", parent, err)
		}

		late, err := f.store.CompleteRun(ctx, id, sampleResult(), 3600, nil)
		if err != nil {
			t.Fatalf("late CompleteRun: %v", err)
		}
		if late != nil {
			t.Errorf("late completion = %+v, want nil (it must lose the child CAS)", late)
		}
		again, err := f.store.CancelRun(ctx, id, nil)
		if err != nil {
			t.Fatalf("second CancelRun: %v", err)
		}
		if again != nil {
			t.Errorf("cancel-after-terminal = %+v, want nil (idempotent no-op)", again)
		}
	})

	// KT: QueryResultStoreDbTest.kt#one task supports multiple children and latest metadata wins
	// 6. one task supports multiple children and latest metadata wins
	t.Run("one task supports multiple children and latest metadata wins", func(t *testing.T) {
		id := f.newTask(t)
		if _, err := f.pool.Exec(ctx,
			"INSERT INTO query_result (task_id, sql, sql_hash) VALUES ($1, 'select 2', 'second')", id); err != nil {
			t.Fatalf("seed second child: %v", err)
		}
		var count int64
		if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM query_result WHERE task_id = $1", id).Scan(&count); err != nil {
			t.Fatalf("count children: %v", err)
		}
		if count != 2 {
			t.Fatalf("child count = %d, want 2", count)
		}
		meta, err := f.store.Meta(ctx, id)
		if err != nil {
			t.Fatalf("Meta: %v", err)
		}
		if meta.Status != nil {
			t.Errorf("latest child status = %q, want null (not started)", str(meta.Status))
		}
		if running, err := f.store.StartRun(ctx, id, "bob@example.com"); err != nil || running == nil {
			t.Fatalf("StartRun = %v, %v", running, err)
		}
		failed, err := f.store.FailRun(ctx, id, "approval.query_failed", nil)
		if err != nil {
			t.Fatalf("FailRun: %v", err)
		}
		if failed == nil || str(failed.Status) != "FAILED" {
			t.Fatalf("FailRun status = %v, want FAILED", failed)
		}
	})

	// KT: QueryResultStoreDbTest.kt#accessFor binds the released child's own sql to its ciphertext, not the first child's
	// 7. 🔒 accessFor binds the released child's own sql to its ciphertext, not the first child's
	//    (INV-A7-9)
	t.Run("accessFor binds the released child's own sql to its ciphertext not the first child's", func(t *testing.T) {
		// Regression: a task with plural children whose SQL differs. accessFor returns the LATEST
		// child's ciphertext, so it must also return that SAME child's sql — the view re-decides the
		// released bytes against their own statement, never the first child's (which would let a later
		// child's PII be released under an earlier child's non-PII verdict when the output labels
		// happen to match).
		id := f.newTask(t) // first child carries "select id, rrn from users"
		if _, err := f.pool.Exec(ctx,
			"INSERT INTO query_result (task_id, sql, sql_hash) VALUES ($1, 'select rrn as v from users', 'second')",
			id); err != nil {
			t.Fatalf("seed second child: %v", err)
		}
		if running, err := f.store.StartRun(ctx, id, "bob@example.com"); err != nil || running == nil {
			t.Fatalf("StartRun (claims the latest NULL child) = %v, %v", running, err)
		}
		payload := result.DecryptedResult{Columns: []string{"v"}, Rows: [][]*string{{ptr("PM_SECRET_900101")}}}
		done, err := f.store.CompleteRun(ctx, id, payload, 3600, nil)
		if err != nil {
			t.Fatalf("CompleteRun: %v", err)
		}
		if done == nil || str(done.Status) != "DONE" {
			t.Fatalf("CompleteRun status = %v, want DONE", done)
		}

		acc, err := f.store.AccessFor(ctx, id)
		if err != nil || acc == nil {
			t.Fatalf("AccessFor = %v, %v", acc, err)
		}
		if str(acc.SQL) != "select rrn as v from users" {
			t.Errorf("accessFor.sql = %q, want the latest (released) child's own sql", str(acc.SQL))
		}
		got, err := acc.Decrypted()
		if err != nil {
			t.Fatalf("Decrypted: %v", err)
		}
		if got == nil || !rowsEqual(got.Rows, payload.Rows) {
			t.Errorf("decrypted rows = %+v, want that same child's %+v", got, payload.Rows)
		}
	})

	// KT: QueryResultStoreDbTest.kt#expiry purges the payload but keeps the child row and its sql for audit
	// 8. expiry purges the payload but keeps the child row and its sql for audit (INV-A7-10)
	t.Run("expiry purges the payload but keeps the child row and its sql for audit", func(t *testing.T) {
		id := f.newTask(t)
		if _, err := f.store.StartRun(ctx, id, "bob@example.com"); err != nil {
			t.Fatalf("StartRun: %v", err)
		}
		if _, err := f.store.CompleteRun(ctx, id, sampleResult(), -1, nil); err != nil { // already expired
			t.Fatalf("CompleteRun: %v", err)
		}
		purged, err := f.store.PurgeExpired(ctx)
		if err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		if purged < 1 {
			t.Fatalf("PurgeExpired swept %d rows, want >= 1", purged)
		}

		// The child row survives: sql/sql_hash/status stay for durable audit + web preview, but the
		// decryptable payload (ciphertext, row_count, columns) is gone.
		var (
			childSQL, sqlHash, status string
			ciphertext                []byte
			rowCount                  *int
			columns                   *string
		)
		if err := f.pool.QueryRow(ctx,
			"SELECT sql, sql_hash, status, ciphertext, row_count, columns FROM query_result WHERE task_id = $1", id,
		).Scan(&childSQL, &sqlHash, &status, &ciphertext, &rowCount, &columns); err != nil {
			t.Fatalf("read purged child: %v", err)
		}
		if childSQL != "select id, rrn from users" {
			t.Errorf("sql = %q, want the statement kept for audit", childSQL)
		}
		if sqlHash == "" {
			t.Error("sql_hash was dropped")
		}
		if status != "DONE" {
			t.Errorf("status = %q, want DONE", status)
		}
		if ciphertext != nil {
			t.Error("ciphertext survived the purge")
		}
		if rowCount != nil {
			t.Errorf("row_count = %d, want NULL", *rowCount)
		}
		if columns != nil {
			t.Errorf("columns = %q, want NULL", *columns)
		}

		// A subsequent read finds the row DONE but with no decryptable payload — /result returns 410.
		acc, err := f.store.AccessFor(ctx, id)
		if err != nil || acc == nil {
			t.Fatalf("AccessFor = %v, %v", acc, err)
		}
		if str(acc.Meta.Status) != "DONE" {
			t.Errorf("meta.status = %q, want DONE", str(acc.Meta.Status))
		}
		got, err := acc.Decrypted()
		if err != nil {
			t.Fatalf("Decrypted: %v", err)
		}
		if got != nil {
			t.Errorf("decrypted = %+v, want nil", got)
		}
	})

	// PIN, beyond the Kotlin suite: 🔒 INV-A7-9's LAZY half. The Kotlin asserts the one-read half
	// (case 7) but never that a caller which stops at meta does not decrypt. Corrupting the stored
	// blob makes the difference observable: AccessFor still succeeds and still serves meta, and only
	// touching Decrypted() surfaces the failure. An eager decrypt would fail AccessFor itself, which
	// would deny a viewer their 409/410 and turn every unauthorized view into a 500.
	t.Run("PIN accessFor does not decrypt until the payload is asked for", func(t *testing.T) {
		id := f.newTask(t)
		if _, err := f.store.StartRun(ctx, id, "bob@example.com"); err != nil {
			t.Fatalf("StartRun: %v", err)
		}
		if _, err := f.store.CompleteRun(ctx, id, sampleResult(), 3600, nil); err != nil {
			t.Fatalf("CompleteRun: %v", err)
		}
		if _, err := f.pool.Exec(ctx,
			// Flip the last byte of the stored tag: the row stays DONE and unexpired, so AccessFor
			// hands the payload to the closure, but the closure can no longer authenticate it.
			`UPDATE query_result SET ciphertext = overlay(ciphertext placing
			     set_byte(substring(ciphertext from length(ciphertext) for 1), 0,
			              get_byte(ciphertext, length(ciphertext) - 1) # 1)
			     from length(ciphertext) for 1)
			   WHERE task_id = $1`, id); err != nil {
			t.Fatalf("tamper with the stored blob: %v", err)
		}
		acc, err := f.store.AccessFor(ctx, id)
		if err != nil {
			t.Fatalf("AccessFor over a tampered blob failed eagerly: %v", err)
		}
		if str(acc.Meta.Status) != "DONE" {
			t.Fatalf("meta.status = %q, want DONE", str(acc.Meta.Status))
		}
		if _, err := acc.Decrypted(); err == nil {
			t.Error("Decrypted() over a tampered blob returned no error")
		}
	})

	// PIN, beyond the Kotlin suite: 🔒 INV-A7-10's ORDER. purgeExpired NULLs expires_at on EVERY
	// expired child, editor ones included, so an editor sweep ordered AFTER it never matches again and
	// the editor rows linger forever, payload-stripped. The A1 background loop runs
	// purgeExpiredEditorChildren() THEN purgeExpired() — this pins the mechanism that makes that order
	// load-bearing rather than stylistic (A1 INV-A1-5).
	t.Run("PIN purgeExpired first strands editor children the editor sweep can no longer match", func(t *testing.T) {
		task, err := f.access.CreateEditorTask(ctx, "ivan@example.com", f.datasourceID, "select id from t",
			[]string{"analyst"}, "ivan@example.com")
		if err != nil {
			t.Fatalf("CreateEditorTask: %v", err)
		}
		if _, err := f.store.StartRun(ctx, task.ID, "ivan@example.com"); err != nil {
			t.Fatalf("StartRun: %v", err)
		}
		if _, err := f.store.CompleteRun(ctx, task.ID, sampleResult(), -1, nil); err != nil { // already expired
			t.Fatalf("CompleteRun: %v", err)
		}

		// The WRONG order: payload sweep first.
		if _, err := f.store.PurgeExpired(ctx); err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		swept, err := f.store.PurgeExpiredEditorChildren(ctx)
		if err != nil {
			t.Fatalf("PurgeExpiredEditorChildren: %v", err)
		}
		if swept != 0 {
			t.Errorf("the editor sweep matched %d rows after purgeExpired cleared expires_at, want 0", swept)
		}
		var remaining int64
		if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM query_result WHERE task_id = $1", task.ID).Scan(&remaining); err != nil {
			t.Fatalf("count children: %v", err)
		}
		if remaining != 1 {
			t.Errorf("editor child count = %d, want 1 — the stranded row this order produces", remaining)
		}
	})

	// PIN, beyond the Kotlin suite: 🔒 INV-A7-7's failure arm. A claimed parent with no pending child
	// is an invariant violation: the Kotlin error()s, which rolls the WHOLE claim back and leaves the
	// task APPROVED. A port that let the claim commit would strand a task EXECUTING with nothing to
	// cancel — precisely the state INV-A7-7 exists to make impossible.
	t.Run("PIN claimAndStartRun rolls the parent claim back when the task has no pending child", func(t *testing.T) {
		id := f.newTask(t)
		f.approve(t, id)
		if _, err := f.pool.Exec(ctx, "DELETE FROM query_result WHERE task_id = $1", id); err != nil {
			t.Fatalf("drop the child: %v", err)
		}
		got, err := f.store.ClaimAndStartRun(ctx, id, "bob@example.com",
			func(ctx context.Context, c store.Queryer) (bool, error) {
				return f.access.ClaimExecutionOn(ctx, c, id)
			})
		if !errors.Is(err, result.ErrNoPendingChild) {
			t.Fatalf("ClaimAndStartRun = %v, %v; want ErrNoPendingChild", got, err)
		}
		parent, err := f.access.GetRequest(ctx, id)
		if err != nil {
			t.Fatalf("GetRequest: %v", err)
		}
		if parent.Status != "APPROVED" {
			t.Errorf("status = %q, want APPROVED — the claim must roll back with the child start", parent.Status)
		}
		if parent.ExecutingAt != nil {
			t.Errorf("executing_at = %q, want null — the rolled-back claim must leave no stamp", *parent.ExecutingAt)
		}
	})
}
