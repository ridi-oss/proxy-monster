package access_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
)

// TaskStoreDbTest.kt — 14 cases, DB (06-query-decision.md §7).
//
// The AccessStore task-lifecycle transitions — ClaimExecution, MarkExecuted, MarkFailed, MarkDeleted,
// Resubmit, ReconcileOrphanedExecutions — plus their CAS guards and the child-metadata reshape, run
// against a real PostgreSQL control-plane store on the full ten-migration chain.
//
// Task state is read with plain `SELECT status/...` and child state through result.Store.Meta, so a
// regression in any of these `UPDATE … WHERE status = $n` compare-and-sets (or in the reconcile pass)
// fails here on the store SQL itself rather than on a helper.
//
// ⚠️ Two deliberate divergences from the Kotlin, both test infrastructure rather than behaviour:
//
//  1. The Kotlin builds EnforcementFixture.postgres() and uses two things from it — a datasource row
//     and a role. That fixture also spins up a TARGET database and introspects its whole
//     information_schema, none of which this suite touches, so the Go form seeds the two rows
//     directly (the same choice EditorTaskStoreDbTest and QueryResultStoreDbTest already make in the
//     Kotlin).
//  2. seedDecision writes the audit_event row with raw SQL. A8's AuditStore is not ported, and
//     `audit_event.id` deliberately carries NO sequence default (INV-A8-1: AuditStore allocates it
//     under the chain-head lock so id order and chain order are the same order), so the helper
//     allocates one. TODO(A8): replace with the production AuditStore.insert — a test that keeps its
//     own INSERT is a second definition of what a valid row looks like.

type taskFixture struct {
	ctx          context.Context
	pool         *pgxpool.Pool
	store        *access.Store
	resultStore  *result.Store
	datasourceID int64
	seed         *dbtest.Seed
}

func newTaskFixture(t *testing.T) *taskFixture {
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
	return &taskFixture{
		ctx:         context.Background(),
		pool:        db.Pool,
		store:       access.NewStore(db.Pool),
		resultStore: result.NewStore(db.Pool, crypto),
		seed:        seed,
		datasourceID: seed.Datasource(dbtest.DatasourceSpec{
			Name: "ds", Engine: dbtest.EnginePostgres, Host: "h", Port: 5432, DBName: "d",
		}),
	}
}

func ptr[T any](v T) *T { return &v }

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// seedTaskOpts mirrors the Kotlin helper's default arguments.
type seedTaskOpts struct {
	executeAs        []string
	creatorKind      string
	approvedAt       bool
	sourceDecisionID *int64
}

// seedTask inserts a QUERY task in the given status and returns its id.
func (f *taskFixture) seedTask(t *testing.T, status string, opts ...seedTaskOpts) int64 {
	t.Helper()
	o := seedTaskOpts{executeAs: []string{"role-r"}, creatorKind: "WORKFLOW"}
	if len(opts) > 0 {
		o = opts[0]
		if o.executeAs == nil {
			o.executeAs = []string{"role-r"}
		}
		if o.creatorKind == "" {
			o.creatorKind = "WORKFLOW"
		}
	}
	executeAs, err := json.Marshal(o.executeAs)
	if err != nil {
		t.Fatalf("marshal execute_as: %v", err)
	}
	var id int64
	err = f.pool.QueryRow(f.ctx,
		`INSERT INTO access_request
		    (principal, requested_duration_sec, status, created_at, kind, datasource_id, execute_as, creator_kind, approved_at, source_decision_id)
		    VALUES ('requester@example.com', 3600, $1, now(), 'QUERY', $2, $3::jsonb, $4, CASE WHEN $5::boolean THEN now() END, $6)
		    RETURNING id`,
		status, f.datasourceID, string(executeAs), o.creatorKind, o.approvedAt, o.sourceDecisionID).Scan(&id)
	if err != nil {
		t.Fatalf("seed %s task: %v", status, err)
	}
	return id
}

// seedChild inserts a statement child for taskID in the given status (nil = not started), leaving the
// `sql` column unset.
func (f *taskFixture) seedChild(t *testing.T, taskID int64, status *string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(f.ctx,
		"INSERT INTO query_result (task_id, status) VALUES ($1, $2) RETURNING id", taskID, status).Scan(&id); err != nil {
		t.Fatalf("seed child of %d: %v", taskID, err)
	}
	return id
}

// seedDecision inserts an audit_event and returns its id — see the divergence note above.
func (f *taskFixture) seedDecision(t *testing.T, statement string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO audit_event (id, principal, datasource, statement, decision)
		    VALUES ((SELECT coalesce(max(id), 0) + 1 FROM audit_event), 'requester@example.com', 'ds', $1, 'ALLOW')
		    RETURNING id`, statement).Scan(&id); err != nil {
		t.Fatalf("seed decision %q: %v", statement, err)
	}
	return id
}

func (f *taskFixture) taskStatus(t *testing.T, id int64) string {
	t.Helper()
	var status string
	if err := f.pool.QueryRow(f.ctx, "SELECT status FROM access_request WHERE id = $1", id).Scan(&status); err != nil {
		t.Fatalf("read status of %d: %v", id, err)
	}
	return status
}

func (f *taskFixture) timestampSet(t *testing.T, id int64, column string) bool {
	t.Helper()
	var set bool
	if err := f.pool.QueryRow(f.ctx,
		"SELECT "+column+" IS NOT NULL FROM access_request WHERE id = $1", id).Scan(&set); err != nil {
		t.Fatalf("read %s of %d: %v", column, id, err)
	}
	return set
}

func (f *taskFixture) childCount(t *testing.T, taskID int64) int64 {
	t.Helper()
	var n int64
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM query_result WHERE task_id = $1", taskID).Scan(&n); err != nil {
		t.Fatalf("count children of %d: %v", taskID, err)
	}
	return n
}

func TestTaskStore(t *testing.T) {
	f := newTaskFixture(t)
	ctx := f.ctx

	// KT: TaskStoreDbTest.kt#claimExecution moves APPROVED to EXECUTING and stamps executing_at
	// 1. claimExecution moves APPROVED to EXECUTING and stamps executing_at
	t.Run("claimExecution moves APPROVED to EXECUTING and stamps executing_at", func(t *testing.T) {
		id := f.seedTask(t, "APPROVED")
		if f.timestampSet(t, id, "executing_at") {
			t.Fatal("executing_at must start null")
		}
		won, err := f.store.ClaimExecution(ctx, id)
		if err != nil || !won {
			t.Fatalf("ClaimExecution = %v, %v; want true", won, err)
		}
		if got := f.taskStatus(t, id); got != "EXECUTING" {
			t.Errorf("status = %q, want EXECUTING", got)
		}
		if !f.timestampSet(t, id, "executing_at") {
			t.Error("the winning claim must stamp executing_at")
		}
	})

	// KT: TaskStoreDbTest.kt#claimExecution fires only from APPROVED
	// 2. claimExecution fires only from APPROVED
	t.Run("claimExecution fires only from APPROVED", func(t *testing.T) {
		for _, from := range []string{"DRAFT", "PENDING", "REJECTED", "EXECUTING", "EXECUTED", "FAILED"} {
			id := f.seedTask(t, from)
			won, err := f.store.ClaimExecution(ctx, id)
			if err != nil {
				t.Fatalf("ClaimExecution from %s: %v", from, err)
			}
			if won {
				t.Errorf("claim must not fire from %s", from)
			}
			if got := f.taskStatus(t, id); got != from {
				t.Errorf("a rejected claim moved the task out of %s to %s", from, got)
			}
		}
	})

	// KT: TaskStoreDbTest.kt#two concurrent claims on separate connections yield exactly one winner
	// KT: ApprovalExecuteRouteDbTest.kt#claimExecution is race-safe - two concurrent callers on separate connections yield exactly one winner — the same claim, asserted once; the Kotlin states it in both suites
	// 3. 🔒 two concurrent claims on separate connections yield exactly one winner (INV-A6-18)
	t.Run("two concurrent claims on separate connections yield exactly one winner", func(t *testing.T) {
		id := f.seedTask(t, "APPROVED")
		// Genuinely concurrent: two goroutines released by one barrier, each taking its own pooled
		// connection. This is the test that fails if a port ever replaces the guarded UPDATE with a
		// read-then-write — a single-threaded suite would not notice.
		var (
			start   = make(chan struct{})
			wg      sync.WaitGroup
			mu      sync.Mutex
			results []bool
		)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				won, err := f.store.ClaimExecution(ctx, id)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					t.Errorf("ClaimExecution: %v", err)
					return
				}
				results = append(results, won)
			}()
		}
		close(start)
		wg.Wait()

		if len(results) != 2 {
			t.Fatalf("%d claims completed, want 2", len(results))
		}
		winners := 0
		for _, won := range results {
			if won {
				winners++
			}
		}
		if winners != 1 {
			t.Errorf("%d of two racing claims won, want exactly 1", winners)
		}
		if got := f.taskStatus(t, id); got != "EXECUTING" {
			t.Errorf("status = %q, want EXECUTING", got)
		}
	})

	// KT: TaskStoreDbTest.kt#markExecuted moves EXECUTING to EXECUTED and stamps executed_at, only from EXECUTING
	// 4. markExecuted moves EXECUTING to EXECUTED and stamps executed_at, only from EXECUTING
	t.Run("markExecuted moves EXECUTING to EXECUTED and stamps executed_at only from EXECUTING", func(t *testing.T) {
		id := f.seedTask(t, "EXECUTING")
		if won, err := f.store.MarkExecuted(ctx, id); err != nil || !won {
			t.Fatalf("MarkExecuted = %v, %v; want true", won, err)
		}
		if got := f.taskStatus(t, id); got != "EXECUTED" {
			t.Errorf("status = %q, want EXECUTED", got)
		}
		if !f.timestampSet(t, id, "executed_at") {
			t.Error("terminal success must stamp executed_at")
		}

		notExecuting := f.seedTask(t, "APPROVED")
		if won, err := f.store.MarkExecuted(ctx, notExecuting); err != nil || won {
			t.Errorf("MarkExecuted from APPROVED = %v, %v; want false", won, err)
		}
		if got := f.taskStatus(t, notExecuting); got != "APPROVED" {
			t.Errorf("status = %q, want APPROVED", got)
		}
	})

	// KT: TaskStoreDbTest.kt#markFailed moves EXECUTING to FAILED, only from EXECUTING
	// 5. markFailed moves EXECUTING to FAILED, only from EXECUTING
	t.Run("markFailed moves EXECUTING to FAILED only from EXECUTING", func(t *testing.T) {
		id := f.seedTask(t, "EXECUTING")
		if won, err := f.store.MarkFailed(ctx, id); err != nil || !won {
			t.Fatalf("MarkFailed = %v, %v; want true", won, err)
		}
		if got := f.taskStatus(t, id); got != "FAILED" {
			t.Errorf("status = %q, want FAILED", got)
		}

		approved := f.seedTask(t, "APPROVED")
		if won, err := f.store.MarkFailed(ctx, approved); err != nil || won {
			t.Errorf("MarkFailed from APPROVED = %v, %v; want false", won, err)
		}
		if got := f.taskStatus(t, approved); got != "APPROVED" {
			t.Errorf("status = %q, want APPROVED", got)
		}
	})

	// KT: TaskStoreDbTest.kt#markCancelled moves only EXECUTING to CANCELLED and blocks later terminal transitions
	// 6. markCancelled moves only EXECUTING to CANCELLED and blocks later terminal transitions
	t.Run("markCancelled moves only EXECUTING to CANCELLED and blocks later terminal transitions", func(t *testing.T) {
		id := f.seedTask(t, "EXECUTING")
		if won, err := f.store.MarkCancelled(ctx, id); err != nil || !won {
			t.Fatalf("MarkCancelled = %v, %v; want true", won, err)
		}
		if got := f.taskStatus(t, id); got != "CANCELLED" {
			t.Errorf("status = %q, want CANCELLED", got)
		}
		if won, err := f.store.MarkExecuted(ctx, id); err != nil || won {
			t.Errorf("late success must lose to cancellation: %v, %v", won, err)
		}
		if won, err := f.store.MarkFailed(ctx, id); err != nil || won {
			t.Errorf("late failure must lose to cancellation: %v, %v", won, err)
		}
		if got := f.taskStatus(t, id); got != "CANCELLED" {
			t.Errorf("status = %q, want CANCELLED", got)
		}

		for _, from := range []string{"EXECUTED", "FAILED"} {
			terminal := f.seedTask(t, from)
			if won, err := f.store.MarkCancelled(ctx, terminal); err != nil || won {
				t.Errorf("cancellation must not overwrite %s: %v, %v", from, won, err)
			}
			if got := f.taskStatus(t, terminal); got != from {
				t.Errorf("status = %q, want %s", got, from)
			}
		}
	})

	// KT: TaskStoreDbTest.kt#no-child WIRE tasks use the shared terminal lifecycle
	// 7. no-child WIRE tasks use the shared terminal lifecycle
	t.Run("no-child WIRE tasks use the shared terminal lifecycle", func(t *testing.T) {
		wireDecisionID := f.seedDecision(t, "wire lookup")
		executed := f.seedTask(t, "APPROVED", seedTaskOpts{
			executeAs: []string{"analyst"}, creatorKind: "WIRE", approvedAt: true, sourceDecisionID: &wireDecisionID,
		})
		if n := f.childCount(t, executed); n != 0 {
			t.Fatalf("a WIRE task has %d children, want 0", n)
		}
		got, err := f.store.WireTaskIDForDecision(ctx, f.pool, wireDecisionID)
		if err != nil {
			t.Fatalf("WireTaskIDForDecision: %v", err)
		}
		if got == nil || *got != executed {
			t.Fatalf("WireTaskIDForDecision = %v, want %d", got, executed)
		}
		if won, err := f.store.ClaimExecution(ctx, executed); err != nil || !won {
			t.Fatalf("ClaimExecution = %v, %v", won, err)
		}
		if s := f.taskStatus(t, executed); s != "EXECUTING" {
			t.Errorf("status = %q, want EXECUTING", s)
		}
		if won, err := f.store.MarkExecuted(ctx, executed); err != nil || !won {
			t.Fatalf("MarkExecuted = %v, %v", won, err)
		}
		if s := f.taskStatus(t, executed); s != "EXECUTED" {
			t.Errorf("status = %q, want EXECUTED", s)
		}

		// 🔒 INV-A6-17 — a WORKFLOW task carrying the same kind of decision link must NOT match: a
		// proxy completion must never terminalize a human approval.
		workflowDecisionID := f.seedDecision(t, "workflow lookup")
		workflow := f.seedTask(t, "APPROVED", seedTaskOpts{
			creatorKind: "WORKFLOW", sourceDecisionID: &workflowDecisionID,
		})
		match, err := f.store.WireTaskIDForDecision(ctx, f.pool, workflowDecisionID)
		if err != nil {
			t.Fatalf("WireTaskIDForDecision: %v", err)
		}
		if match != nil {
			t.Errorf("a workflow task matched a proxy completion: %d", *match)
		}
		if s := f.taskStatus(t, workflow); s != "APPROVED" {
			t.Errorf("status = %q, want APPROVED", s)
		}

		failed := f.seedTask(t, "APPROVED", seedTaskOpts{
			executeAs: []string{"analyst"}, creatorKind: "WIRE", approvedAt: true,
		})
		if n := f.childCount(t, failed); n != 0 {
			t.Fatalf("a WIRE task has %d children, want 0", n)
		}
		if won, err := f.store.ClaimExecution(ctx, failed); err != nil || !won {
			t.Fatalf("ClaimExecution = %v, %v", won, err)
		}
		if won, err := f.store.MarkFailed(ctx, failed); err != nil || !won {
			t.Fatalf("MarkFailed = %v, %v", won, err)
		}
		if s := f.taskStatus(t, failed); s != "FAILED" {
			t.Errorf("status = %q, want FAILED", s)
		}
	})

	// KT: TaskStoreDbTest.kt#markDeleted fires from DRAFT PENDING REJECTED but never from live states
	// 8. markDeleted fires from DRAFT PENDING REJECTED but never from live states
	t.Run("markDeleted fires from DRAFT PENDING REJECTED but never from live states", func(t *testing.T) {
		for _, from := range []string{"DRAFT", "PENDING", "REJECTED"} {
			id := f.seedTask(t, from)
			if won, err := f.store.MarkDeleted(ctx, id); err != nil || !won {
				t.Errorf("markDeleted must fire from %s: %v, %v", from, won, err)
			}
			if got := f.taskStatus(t, id); got != "DELETED" {
				t.Errorf("status = %q, want DELETED", got)
			}
		}
		for _, from := range []string{"APPROVED", "EXECUTING", "EXECUTED", "FAILED"} {
			id := f.seedTask(t, from)
			if won, err := f.store.MarkDeleted(ctx, id); err != nil || won {
				t.Errorf("markDeleted must not fire from %s: %v, %v", from, won, err)
			}
			if got := f.taskStatus(t, id); got != from {
				t.Errorf("status = %q, want %s", got, from)
			}
		}
	})

	// KT: TaskStoreDbTest.kt#resubmit moves REJECTED to PENDING but never other states
	// 9. resubmit moves REJECTED to PENDING but never other states
	t.Run("resubmit moves REJECTED to PENDING but never other states", func(t *testing.T) {
		rejected := f.seedTask(t, "REJECTED")
		if won, err := f.store.Resubmit(ctx, rejected); err != nil || !won {
			t.Fatalf("Resubmit = %v, %v; want true", won, err)
		}
		if got := f.taskStatus(t, rejected); got != "PENDING" {
			t.Errorf("status = %q, want PENDING", got)
		}
		for _, from := range []string{"PENDING", "APPROVED", "EXECUTING", "DELETED"} {
			id := f.seedTask(t, from)
			if won, err := f.store.Resubmit(ctx, id); err != nil || won {
				t.Errorf("resubmit must not fire from %s: %v, %v", from, won, err)
			}
			if got := f.taskStatus(t, id); got != from {
				t.Errorf("status = %q, want %s", got, from)
			}
		}
	})

	// KT: TaskStoreDbTest.kt#execute_as and creator_kind round-trip through the reshaped columns
	// 10. execute_as and creator_kind round-trip through the reshaped columns
	t.Run("execute_as and creator_kind round-trip through the reshaped columns", func(t *testing.T) {
		id := f.seedTask(t, "APPROVED", seedTaskOpts{executeAs: []string{"role-a", "role-b"}, creatorKind: "WORKFLOW"})
		var (
			executeAs   string
			creatorKind string
		)
		if err := f.pool.QueryRow(ctx,
			"SELECT execute_as, creator_kind FROM access_request WHERE id = $1", id).Scan(&executeAs, &creatorKind); err != nil {
			t.Fatalf("read columns: %v", err)
		}
		if !strings.Contains(executeAs, "role-a") || !strings.Contains(executeAs, "role-b") {
			t.Errorf("execute_as did not round-trip: %s", executeAs)
		}
		if creatorKind != "WORKFLOW" {
			t.Errorf("creator_kind = %q, want WORKFLOW", creatorKind)
		}
		// And through the DTO, which is where a mis-ordered scan destination would show up.
		req, err := f.store.GetRequest(ctx, id)
		if err != nil || req == nil {
			t.Fatalf("GetRequest = %v, %v", req, err)
		}
		if len(req.ExecuteAs) != 2 || req.ExecuteAs[0] != "role-a" || req.ExecuteAs[1] != "role-b" {
			t.Errorf("executeAs = %v, want [role-a role-b]", req.ExecuteAs)
		}
		if str(req.CreatorKind) != "WORKFLOW" {
			t.Errorf("creatorKind = %q, want WORKFLOW", str(req.CreatorKind))
		}
	})

	// KT: TaskStoreDbTest.kt#a task carries one-to-many statement children, latest wins in meta
	// 11. a task carries one-to-many statement children, latest wins in meta
	t.Run("a task carries one-to-many statement children latest wins in meta", func(t *testing.T) {
		id := f.seedTask(t, "APPROVED")
		f.seedChild(t, id, ptr("FAILED"))
		f.seedChild(t, id, ptr("RUNNING"))
		if n := f.childCount(t, id); n != 2 {
			t.Fatalf("child count = %d, want 2 (a task may accrue multiple children)", n)
		}
		meta, err := f.resultStore.Meta(ctx, id)
		if err != nil || meta == nil {
			t.Fatalf("Meta = %v, %v", meta, err)
		}
		if str(meta.Status) != "RUNNING" {
			t.Errorf("meta.status = %q, want RUNNING (the newest child)", str(meta.Status))
		}
	})

	// KT: TaskStoreDbTest.kt#reconcileOrphanedExecutions terminalizes EXECUTING tasks and RUNNING children, idempotently
	// 12. reconcileOrphanedExecutions terminalizes EXECUTING tasks and RUNNING children, idempotently
	//     (INV-A6-20)
	t.Run("reconcileOrphanedExecutions terminalizes EXECUTING tasks and RUNNING children idempotently", func(t *testing.T) {
		id := f.seedTask(t, "EXECUTING")
		f.seedChild(t, id, ptr("RUNNING"))

		if err := f.store.ReconcileOrphanedExecutions(ctx); err != nil {
			t.Fatalf("ReconcileOrphanedExecutions: %v", err)
		}
		if got := f.taskStatus(t, id); got != "FAILED" {
			t.Errorf("status = %q, want FAILED (an orphaned EXECUTING task is failed on reconcile)", got)
		}
		meta, err := f.resultStore.Meta(ctx, id)
		if err != nil || meta == nil {
			t.Fatalf("Meta = %v, %v", meta, err)
		}
		if str(meta.Status) != "FAILED" {
			t.Errorf("child status = %q, want FAILED", str(meta.Status))
		}
		if str(meta.ErrorCode) != "task.orphaned_on_restart" {
			t.Errorf("child errorCode = %q, want task.orphaned_on_restart", str(meta.ErrorCode))
		}
		// 🔒 INV-A6-20 — the sweep must stamp expires_at, or a NULL-expiry FAILED row accumulates on
		// every restart-with-orphan. The Kotlin suite does not assert this; the invariant says it is
		// the whole point of the second UPDATE, so it is pinned here.
		if meta.ExpiresAt == nil {
			t.Error("the orphaned child carries no expires_at — purgeExpired can never GC it")
		}

		// Idempotent: a second pass finds nothing EXECUTING/RUNNING and leaves the terminal states
		// intact.
		if err := f.store.ReconcileOrphanedExecutions(ctx); err != nil {
			t.Fatalf("second ReconcileOrphanedExecutions: %v", err)
		}
		if got := f.taskStatus(t, id); got != "FAILED" {
			t.Errorf("status = %q, want FAILED", got)
		}
		if meta, err := f.resultStore.Meta(ctx, id); err != nil || str(meta.Status) != "FAILED" {
			t.Errorf("child status = %v, %v; want FAILED", meta, err)
		}
	})

	// KT: TaskStoreDbTest.kt#createQueryRequest persists execute_as, creator_kind, and a not-started statement child
	// 13. createQueryRequest persists execute_as, creator_kind, and a not-started statement child
	t.Run("createQueryRequest persists execute_as creator_kind and a not-started statement child", func(t *testing.T) {
		roleID := f.seed.Role("task-store-round-trip")
		req, err := f.store.CreateQueryRequest(ctx, access.CreateQueryRequestInput{
			Principal: "alice@example.com", DatasourceID: f.datasourceID, SQL: "select 1",
			Reason: ptr("need it"), EvaluatedDecision: ptr("DENY"), RoleID: &roleID,
		})
		if err != nil {
			t.Fatalf("CreateQueryRequest: %v", err)
		}
		if len(req.ExecuteAs) != 1 || req.ExecuteAs[0] != "task-store-round-trip" {
			t.Errorf("executeAs = %v, want [task-store-round-trip] (seeded from the picked role)", req.ExecuteAs)
		}
		if str(req.CreatorKind) != "WORKFLOW" {
			t.Errorf("creatorKind = %q, want WORKFLOW", str(req.CreatorKind))
		}
		meta, err := f.resultStore.Meta(ctx, req.ID)
		if err != nil || meta == nil {
			t.Fatalf("Meta = %v, %v", meta, err)
		}
		if meta.Status != nil {
			t.Errorf("child status = %q, want null (created not-started)", str(meta.Status))
		}
	})

	// KT: TaskStoreDbTest.kt#decideQueryRequest approve stamps approved_at, reject leaves it null
	// 14. decideQueryRequest approve stamps approved_at, reject leaves it null
	t.Run("decideQueryRequest approve stamps approved_at reject leaves it null", func(t *testing.T) {
		approved := f.seedTask(t, "PENDING")
		a, err := f.store.DecideQueryRequest(ctx, approved, true, nil, "approver@example.com")
		if err != nil {
			t.Fatalf("DecideQueryRequest(approve): %v", err)
		}
		if a == nil || a.Status != "APPROVED" {
			t.Fatalf("status = %v, want APPROVED", a)
		}
		if a.ApprovedAt == nil {
			t.Error("approve must stamp approved_at")
		}

		rejected := f.seedTask(t, "PENDING")
		r, err := f.store.DecideQueryRequest(ctx, rejected, false, ptr("no"), "approver@example.com")
		if err != nil {
			t.Fatalf("DecideQueryRequest(reject): %v", err)
		}
		if r == nil || r.Status != "REJECTED" {
			t.Fatalf("status = %v, want REJECTED", r)
		}
		if r.ApprovedAt != nil {
			t.Errorf("reject must not stamp approved_at, got %q", *r.ApprovedAt)
		}
	})

	// PIN, beyond the Kotlin suite: F11 — AccessStore.reject UPDATEs with NO status guard.
	//
	// 06-query-decision.md §7 Q1 flags this as a probable bug; the disposition is REPRODUCE + PIN,
	// because the unguarded UPDATE is observable on the wire. Contrast decideQueryRequest above, which
	// guards on PENDING and returns nil when it loses. A later fix has to change this test, which is
	// the point of writing it.
	t.Run("PIN F11 reject is unguarded and overwrites an already-decided request", func(t *testing.T) {
		// A ROLE request, the kind reject is routed for. It is created PENDING, then decided.
		roleID := f.seed.Role("f11-role")
		req, err := f.store.CreateRequest(ctx, "alice@example.com", access.AccessRequestInput{RoleID: roleID})
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		first, err := f.store.Reject(ctx, req.ID, "first reason", "approver-one@example.com")
		if err != nil {
			t.Fatalf("Reject: %v", err)
		}
		if first.Status != "REJECTED" || str(first.RejectionReason) != "first reason" {
			t.Fatalf("first reject = %+v", first)
		}

		// 🐞 The defect: a SECOND reject on the already-REJECTED request still fires, silently
		// replacing the reason and the decider. A guarded UPDATE would have returned the row unchanged.
		second, err := f.store.Reject(ctx, req.ID, "second reason", "approver-two@example.com")
		if err != nil {
			t.Fatalf("second Reject: %v", err)
		}
		if str(second.RejectionReason) != "second reason" {
			t.Errorf("rejectionReason = %q, want %q — F11 reproduced: the UPDATE has no status guard",
				str(second.RejectionReason), "second reason")
		}
		if str(second.DecidedBy) != "approver-two@example.com" {
			t.Errorf("decidedBy = %q, want approver-two@example.com — the previous decider is overwritten",
				str(second.DecidedBy))
		}

		// 🐞 Worse: an APPROVED request can be flipped to REJECTED after the fact, and the grant the
		// approval minted stays live because reject touches only access_request.
		approvedReq, err := f.store.CreateRequest(ctx, "bob@example.com", access.AccessRequestInput{RoleID: roleID})
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		if _, err := f.store.Approve(ctx, approvedReq.ID, ptr(int64(60)), "approver-one@example.com"); err != nil {
			t.Fatalf("Approve: %v", err)
		}
		flipped, err := f.store.Reject(ctx, approvedReq.ID, "changed my mind", "approver-two@example.com")
		if err != nil {
			t.Fatalf("Reject after approve: %v", err)
		}
		if flipped.Status != "REJECTED" {
			t.Errorf("status = %q, want REJECTED — F11 reproduced: an APPROVED request is re-decidable",
				flipped.Status)
		}
		grants, err := f.store.ListGrants(ctx, ptr("bob@example.com"), true)
		if err != nil {
			t.Fatalf("ListGrants: %v", err)
		}
		if len(grants) != 1 {
			t.Errorf("bob holds %d active grants, want 1 — the flip to REJECTED does not revoke it", len(grants))
		}
	})

	// PIN, beyond the Kotlin suite: 🔒 INV-A6-21 — the partial-index upsert is what makes "one pending
	// request per denied decision" atomic. No Kotlin store test covers it (the route suites exercise
	// the 409 it produces), and it is the one place where a Go port could silently substitute a
	// read-then-insert and still pass every other case here.
	t.Run("PIN createQueryRequest raises DuplicatePendingQueryRequest and leaves no orphan child", func(t *testing.T) {
		decisionID := f.seedDecision(t, "select rrn from users")
		in := access.CreateQueryRequestInput{
			Principal: "alice@example.com", DatasourceID: f.datasourceID, SQL: "select rrn from users",
			DenyReason: ptr("sql.unmaskable"), SourceDecisionID: &decisionID, EvaluatedDecision: ptr("DENY"),
		}
		first, err := f.store.CreateQueryRequest(ctx, in)
		if err != nil {
			t.Fatalf("first CreateQueryRequest: %v", err)
		}
		if first.Status != "PENDING" {
			t.Fatalf("status = %q, want PENDING", first.Status)
		}

		second, err := f.store.CreateQueryRequest(ctx, in)
		if !errors.Is(err, access.ErrDuplicatePendingQueryRequest) {
			t.Fatalf("second CreateQueryRequest = %v, %v; want ErrDuplicatePendingQueryRequest", second, err)
		}
		// The child insert shares the transaction with the parent, so the losing attempt leaves NO
		// orphan query_result row behind.
		var tasks, children int64
		if err := f.pool.QueryRow(ctx,
			`SELECT (SELECT count(*) FROM access_request WHERE source_decision_id = $1),
			        (SELECT count(*) FROM query_result WHERE task_id IN (SELECT id FROM access_request WHERE source_decision_id = $1))`,
			decisionID).Scan(&tasks, &children); err != nil {
			t.Fatalf("count rows for the decision: %v", err)
		}
		if tasks != 1 || children != 1 {
			t.Errorf("the decision carries %d tasks and %d children, want 1 and 1", tasks, children)
		}

		// The index is partial: once the pending request is decided, a NEW one may be raised for the
		// same decision. That is the behaviour the WHERE clause on the index buys, not a leak.
		if _, err := f.store.DecideQueryRequest(ctx, first.ID, false, ptr("no"), "approver@example.com"); err != nil {
			t.Fatalf("DecideQueryRequest: %v", err)
		}
		if _, err := f.store.CreateQueryRequest(ctx, in); err != nil {
			t.Errorf("a request for a DECIDED decision must be allowed again: %v", err)
		}

		// And a request with NO source decision is exempt from the index entirely — two of them
		// coexist, because NULLs are excluded by `source_decision_id IS NOT NULL`.
		noSource := access.CreateQueryRequestInput{
			Principal: "alice@example.com", DatasourceID: f.datasourceID, SQL: "select 1",
		}
		if _, err := f.store.CreateQueryRequest(ctx, noSource); err != nil {
			t.Fatalf("first source-less CreateQueryRequest: %v", err)
		}
		if _, err := f.store.CreateQueryRequest(ctx, noSource); err != nil {
			t.Errorf("a source-less request must not conflict: %v", err)
		}
	})
}
