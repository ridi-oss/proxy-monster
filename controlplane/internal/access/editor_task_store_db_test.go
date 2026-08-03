package access_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/access"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// EditorTaskStoreDbTest.kt — 7 cases, DB (06-query-decision.md §7).
//
// The async-editor data model + lifecycle (editor-as-task), at the store layer. A CreateEditorTask
// submit is a born-APPROVED EDITOR task with ONE result child (task:child 1:1), executing as the
// caller's OWN roles — no elevation, no separate editor status path. It drives the SAME
// single-execution status machine an approved workflow task does (ClaimExecution APPROVED → EXECUTING,
// then the child RUNNING → DONE with the parent EXECUTED). The delete/purge methods back close-tab,
// delete-on-logout and GC.
//
// It shares taskFixture with TaskStoreDbTest's port (same test package, same seeding vocabulary); the
// Kotlin's two classes each build their own database and this Go form keeps them separate too, since
// each Test function calls newTaskFixture.

func editorResult() result.DecryptedResult {
	return result.DecryptedResult{Columns: []string{"id"}, Rows: [][]*string{{ptr("1")}, {ptr("2")}}}
}

// expireChild backdates every child of taskID so the sweeps match it.
func (f *taskFixture) expireChild(t *testing.T, taskID int64) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE query_result SET expires_at = $1 WHERE task_id = $2",
		time.Now().Add(-60*time.Second), taskID); err != nil {
		t.Fatalf("expire children of %d: %v", taskID, err)
	}
}

func (f *taskFixture) newEditorTask(t *testing.T, principal string) *access.AccessRequest {
	t.Helper()
	task, err := f.store.CreateEditorTask(f.ctx, principal, f.datasourceID, "select id from t", []string{"analyst"}, principal)
	if err != nil {
		t.Fatalf("CreateEditorTask(%s): %v", principal, err)
	}
	return task
}

func TestEditorTaskStore(t *testing.T) {
	f := newTaskFixture(t)
	ctx := f.ctx

	// 1. createEditorTask is born APPROVED as EDITOR with own roles and one child (INV-A6-22)
	t.Run("createEditorTask is born APPROVED as EDITOR with own roles and one child", func(t *testing.T) {
		task := f.newEditorTask(t, "alice@example.com")
		if task.Status != "APPROVED" {
			t.Errorf("status = %q, want APPROVED", task.Status)
		}
		if str(task.CreatorKind) != "EDITOR" {
			t.Errorf("creatorKind = %q, want EDITOR", str(task.CreatorKind))
		}
		if task.Kind != "QUERY" {
			t.Errorf("kind = %q, want QUERY", task.Kind)
		}
		if len(task.ExecuteAs) != 1 || task.ExecuteAs[0] != "analyst" {
			t.Errorf("executeAs = %v, want [analyst] — the caller's OWN roles, never an elevation", task.ExecuteAs)
		}
		if str(task.DecidedBy) != "alice@example.com" {
			t.Errorf("decidedBy = %q, want alice@example.com (self-approved)", str(task.DecidedBy))
		}
		if task.Principal != "alice@example.com" {
			t.Errorf("principal = %q, want alice@example.com", task.Principal)
		}
		if n := f.childCount(t, task.ID); n != 1 {
			t.Errorf("child count = %d, want 1 (task:child is 1:1 per editor submit)", n)
		}
		if again, err := f.store.GetRequest(ctx, task.ID); err != nil || again == nil {
			t.Errorf("the task is not re-readable: %v, %v", again, err)
		}
		childID, err := f.store.EditorChildID(ctx, task.ID)
		if err != nil || childID == nil || *childID <= 0 {
			t.Errorf("EditorChildID = %v, %v; want a positive id", childID, err)
		}
	})

	// 2. createWireTask is born APPROVED as WIRE linked to its decision and has no child
	t.Run("createWireTask is born APPROVED as WIRE linked to its decision and has no child", func(t *testing.T) {
		principal := "wire@example.com"
		executeAs := []string{"analyst", "reporter"}
		decisionID := f.seedDecision(t, "select 1")

		taskID, err := store.InTx(ctx, f.pool, func(ctx context.Context, tx pgx.Tx) (int64, error) {
			return f.store.CreateWireTask(ctx, tx, principal, f.datasourceID, executeAs, decisionID)
		})
		if err != nil {
			t.Fatalf("CreateWireTask: %v", err)
		}
		task, err := f.store.GetRequest(ctx, taskID)
		if err != nil || task == nil {
			t.Fatalf("wire task was not re-readable: %v, %v", task, err)
		}

		if task.Status != "APPROVED" {
			t.Errorf("status = %q, want APPROVED", task.Status)
		}
		if str(task.CreatorKind) != "WIRE" {
			t.Errorf("creatorKind = %q, want WIRE", str(task.CreatorKind))
		}
		if task.Kind != "QUERY" {
			t.Errorf("kind = %q, want QUERY", task.Kind)
		}
		if len(task.ExecuteAs) != 2 || task.ExecuteAs[0] != "analyst" || task.ExecuteAs[1] != "reporter" {
			t.Errorf("executeAs = %v, want %v", task.ExecuteAs, executeAs)
		}
		if str(task.DecidedBy) != principal {
			t.Errorf("decidedBy = %q, want %q", str(task.DecidedBy), principal)
		}
		if task.Principal != principal {
			t.Errorf("principal = %q, want %q", task.Principal, principal)
		}
		if task.SourceDecisionID == nil || *task.SourceDecisionID != decisionID {
			t.Errorf("sourceDecisionId = %v, want %d", task.SourceDecisionID, decisionID)
		}
		if n := f.childCount(t, task.ID); n != 0 {
			t.Errorf("child count = %d, want 0 — the relay streams to the client and saves no child", n)
		}
		// With no child, the three correlated subqueries in reqSelect all read null.
		if task.SQL != nil || task.SQLHash != nil || task.ExecutedBy != nil {
			t.Errorf("a childless task read sql=%v sqlHash=%v executedBy=%v, want all null",
				task.SQL, task.SQLHash, task.ExecutedBy)
		}

		if won, err := f.store.ClaimExecution(ctx, task.ID); err != nil || !won {
			t.Fatalf("APPROVED → EXECUTING = %v, %v", won, err)
		}
		if won, err := f.store.MarkExecuted(ctx, task.ID); err != nil || !won {
			t.Fatalf("EXECUTING → EXECUTED = %v, %v", won, err)
		}
		if got, err := f.store.GetRequest(ctx, task.ID); err != nil || got.Status != "EXECUTED" {
			t.Errorf("status = %v, %v; want EXECUTED", got, err)
		}

		failedDecisionID := f.seedDecision(t, "select 2")
		failedID, err := store.InTx(ctx, f.pool, func(ctx context.Context, tx pgx.Tx) (int64, error) {
			return f.store.CreateWireTask(ctx, tx, principal, f.datasourceID, executeAs, failedDecisionID)
		})
		if err != nil {
			t.Fatalf("CreateWireTask: %v", err)
		}
		if won, err := f.store.ClaimExecution(ctx, failedID); err != nil || !won {
			t.Fatalf("APPROVED → EXECUTING = %v, %v", won, err)
		}
		if won, err := f.store.MarkFailed(ctx, failedID); err != nil || !won {
			t.Fatalf("EXECUTING → FAILED = %v, %v", won, err)
		}
		if got, err := f.store.GetRequest(ctx, failedID); err != nil || got.Status != "FAILED" {
			t.Errorf("status = %v, %v; want FAILED", got, err)
		}
	})

	// 3. the born-APPROVED editor task runs the same single-execution status machine
	t.Run("the born-APPROVED editor task runs the same single-execution status machine", func(t *testing.T) {
		task := f.newEditorTask(t, "bob@example.com")
		if won, err := f.store.ClaimExecution(ctx, task.ID); err != nil || !won {
			t.Fatalf("APPROVED → EXECUTING = %v, %v", won, err)
		}
		if got, err := f.store.GetRequest(ctx, task.ID); err != nil || got.Status != "EXECUTING" {
			t.Fatalf("status = %v, %v; want EXECUTING", got, err)
		}
		if won, err := f.store.ClaimExecution(ctx, task.ID); err != nil || won {
			t.Errorf("a second claim on a non-APPROVED task must lose: %v, %v", won, err)
		}

		running, err := f.resultStore.StartRun(ctx, task.ID, "bob@example.com")
		if err != nil || running == nil || str(running.Status) != "RUNNING" {
			t.Fatalf("StartRun = %v, %v; want RUNNING", running, err)
		}
		// INV-A6-19: the parent's EXECUTED flip rides the child's DONE transaction.
		done, err := f.resultStore.CompleteRun(ctx, task.ID, editorResult(), 3600,
			func(ctx context.Context, c store.Queryer, _ result.QueryResultMeta) error {
				won, err := f.store.MarkExecutedOn(ctx, c, task.ID)
				if err == nil && !won {
					t.Error("markExecuted did not fire inside the completion transaction")
				}
				return err
			})
		if err != nil {
			t.Fatalf("CompleteRun: %v", err)
		}
		if done == nil || str(done.Status) != "DONE" {
			t.Fatalf("CompleteRun status = %v, want DONE", done)
		}
		if done.RowCount == nil || *done.RowCount != 2 {
			t.Errorf("rowCount = %v, want 2", done.RowCount)
		}
		if got, err := f.store.GetRequest(ctx, task.ID); err != nil || got.Status != "EXECUTED" {
			t.Errorf("status = %v, %v; want EXECUTED", got, err)
		}
	})

	// 4. deleteResultsForTask drops the child but leaves the task, idempotently
	t.Run("deleteResultsForTask drops the child but leaves the task idempotently", func(t *testing.T) {
		task := f.newEditorTask(t, "carol@example.com")
		if _, err := f.resultStore.StartRun(ctx, task.ID, "carol@example.com"); err != nil {
			t.Fatalf("StartRun: %v", err)
		}
		if _, err := f.resultStore.CompleteRun(ctx, task.ID, editorResult(), 3600, nil); err != nil {
			t.Fatalf("CompleteRun: %v", err)
		}
		if n, err := f.resultStore.DeleteResultsForTask(ctx, task.ID); err != nil || n != 1 {
			t.Fatalf("DeleteResultsForTask = %d, %v; want 1", n, err)
		}
		if n := f.childCount(t, task.ID); n != 0 {
			t.Errorf("child count = %d, want 0", n)
		}
		if n, err := f.resultStore.DeleteResultsForTask(ctx, task.ID); err != nil || n != 0 {
			t.Errorf("second DeleteResultsForTask = %d, %v; want 0 (idempotent)", n, err)
		}
		if got, err := f.store.GetRequest(ctx, task.ID); err != nil || got == nil {
			t.Errorf("the task row must survive — only its rows are gone: %v, %v", got, err)
		}
	})

	// 5. deleteEditorResultsForPrincipal drops only that principal's editor children (INV-A7-11)
	t.Run("deleteEditorResultsForPrincipal drops only that principal's editor children", func(t *testing.T) {
		mine := f.newEditorTask(t, "dave@example.com")
		other := f.newEditorTask(t, "erin@example.com")
		// A WORKFLOW task (creator_kind != EDITOR) owned by dave must be untouched by the
		// editor-scoped delete.
		workflow, err := f.store.CreateQueryRequest(ctx, access.CreateQueryRequestInput{
			Principal: "dave@example.com", DatasourceID: f.datasourceID, SQL: "select id from t",
			Reason: ptr("r"), Title: ptr("t"), EvaluatedDecision: ptr("MASK"),
		})
		if err != nil {
			t.Fatalf("CreateQueryRequest: %v", err)
		}

		// The count is TASKS deleted, not children: the delete drops the access_request row and lets
		// the FK cascade take the child (INV-A7-11).
		if n, err := f.resultStore.DeleteEditorResultsForPrincipal(ctx, "dave@example.com"); err != nil || n != 1 {
			t.Fatalf("DeleteEditorResultsForPrincipal = %d, %v; want 1", n, err)
		}
		if n := f.childCount(t, mine.ID); n != 0 {
			t.Errorf("dave's editor child count = %d, want 0", n)
		}
		if n := f.childCount(t, other.ID); n != 1 {
			t.Errorf("erin's editor child count = %d, want 1 (untouched)", n)
		}
		if n := f.childCount(t, workflow.ID); n != 1 {
			t.Errorf("dave's WORKFLOW child count = %d, want 1 (untouched)", n)
		}
		// And the whole task is gone, not merely its child — that is what terminalizes an editor task
		// still EXECUTING when the session ended.
		if got, err := f.store.GetRequest(ctx, mine.ID); err != nil || got != nil {
			t.Errorf("dave's editor TASK survived: %v, %v", got, err)
		}
	})

	// 6. purgeExpiredEditorChildren deletes only expired editor children (A1 INV-A1-5)
	t.Run("purgeExpiredEditorChildren deletes only expired editor children", func(t *testing.T) {
		expired := f.newEditorTask(t, "frank@example.com")
		live := f.newEditorTask(t, "grace@example.com")
		f.expireChild(t, expired.ID)

		if n, err := f.resultStore.PurgeExpiredEditorChildren(ctx); err != nil || n != 1 {
			t.Fatalf("PurgeExpiredEditorChildren = %d, %v; want 1", n, err)
		}
		if n := f.childCount(t, expired.ID); n != 0 {
			t.Errorf("expired editor child count = %d, want 0 (deleted whole, not payload-stripped)", n)
		}
		if n := f.childCount(t, live.ID); n != 1 {
			t.Errorf("unexpired editor child count = %d, want 1", n)
		}
	})

	// 7. deleteEditorTask cascades the child and is owner + EDITOR scoped
	t.Run("deleteEditorTask cascades the child and is owner + EDITOR scoped", func(t *testing.T) {
		task := f.newEditorTask(t, "heidi@example.com")
		if won, err := f.store.DeleteEditorTask(ctx, task.ID, "mallory@example.com"); err != nil || won {
			t.Errorf("a non-owner must not be able to delete it: %v, %v", won, err)
		}
		if n := f.childCount(t, task.ID); n != 1 {
			t.Errorf("child count = %d, want 1", n)
		}
		if got, err := f.store.GetRequest(ctx, task.ID); err != nil || got == nil {
			t.Errorf("the task must survive a non-owner delete: %v, %v", got, err)
		}

		if won, err := f.store.DeleteEditorTask(ctx, task.ID, "heidi@example.com"); err != nil || !won {
			t.Fatalf("DeleteEditorTask = %v, %v; want true", won, err)
		}
		if got, err := f.store.GetRequest(ctx, task.ID); err != nil || got != nil {
			t.Errorf("the task row must be gone: %v, %v", got, err)
		}
		if n := f.childCount(t, task.ID); n != 0 {
			t.Errorf("child count = %d, want 0 (cascaded away)", n)
		}
		if won, err := f.store.DeleteEditorTask(ctx, task.ID, "heidi@example.com"); err != nil || won {
			t.Errorf("second DeleteEditorTask = %v, %v; want false (idempotent)", won, err)
		}
	})
}
