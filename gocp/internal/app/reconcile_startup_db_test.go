package app_test

// PORT of `TaskReconcileStartupDbTest` — RESTART RECOVERY, asserted at the BOOT SEAM.
//
// internal/access already covers ReconcileOrphanedExecutions itself (TaskStoreDbTest case 12). What
// only a boot test can state is that BOOTING RUNS IT: `app.Boot` STEP 4 and `NewHTTPSurface` both call
// it, and deleting either call leaves every store-level test green while a crashed run stays EXECUTING
// forever — the exact failure the sweep exists to prevent.
//
// The Kotlin boots the module TWICE for the same reason this does: the second pass must match no
// EXECUTING task and no RUNNING child, so a sweep that is not idempotent (or that re-stamps terminal
// rows) is caught rather than merely suspected.

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/access"
	"github.com/ridi-oss/proxy-monster/gocp/internal/app"
	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/result"
)

// bootOn boots the real wiring against an EXISTING logical database, so a test can boot the same
// database more than once. It is bootE2E minus the fresh-database step and minus the gRPC client.
func bootOn(t *testing.T, dbName string) *app.App {
	t.Helper()
	backend := dbtest.Postgres(t)
	cfg, err := config.FromEnv(config.EnvOf(map[string]string{
		"PM_HTTP_PORT": "0",
		"PM_GRPC_PORT": "0",
		"PM_DB_URL":    backend.PostgresJDBCURL(dbName),
		"PM_DB_USER":   "proxymonster",
		"PM_DEV":       "true",
	}))
	if err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	cfg.DBUser, cfg.DBPassword = credsFromJDBC(t, backend.PostgresDSN(dbName))

	a, err := app.Boot(cfg, app.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.Shutdown(ctx)
	})
	return a
}

// childState is the Kotlin's private helper: the newest child's (status, errorCode).
func childState(t *testing.T, results *result.Store, taskID int64) (*string, *string) {
	t.Helper()
	meta, err := results.Meta(context.Background(), taskID)
	if err != nil {
		t.Fatalf("child meta for %d: %v", taskID, err)
	}
	if meta == nil {
		t.Fatalf("task %d has no child row at all", taskID)
	}
	return meta.Status, meta.ErrorCode
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// 🔒 BOOT FAILS ORPHANED EXECUTIONS, SPARES NOT-STARTED AND COMPLETED TASKS, AND IS IDEMPOTENT.
//
// Three shapes, and each is load-bearing:
//
//   - the ORPHAN (EXECUTING parent + RUNNING child) is what a process death leaves behind. It must
//     reach FAILED with `task.orphaned_on_restart` so nothing is stuck forever.
//   - the NOT-STARTED task (APPROVED, child status NULL) must be untouched. A sweep keyed on "not
//     terminal" instead of on EXECUTING/RUNNING would fail every approved-but-unrun task on the next
//     deploy.
//   - the COMPLETED task (EXECUTED parent + DONE child) must be untouched too — a DONE child must
//     never be dragged to FAILED under its EXECUTED parent.
//
// KT: TaskReconcileStartupDbTest.kt#boot fails orphaned executions, spares not-started tasks, and is idempotent
func TestBootFailsOrphanedExecutionsSparesNotStartedTasksAndIsIdempotent(t *testing.T) {
	dbName := dbtest.FreshPostgresDatabase(t, "reconcile_startup")

	// Boot #1 migrates the fresh database. Its own reconcile pass sweeps an EMPTY schema, so every
	// assertion below is about boot #2's.
	first := bootOn(t, dbName)
	pool := first.Db.Pool
	ctx := context.Background()
	seed := dbtest.NewSeed(t, first.Db)
	accessStore := access.NewStore(pool)
	results := result.NewStore(pool, nil)

	datasourceID := seed.Datasource(dbtest.DatasourceSpec{
		Name: "reconcile-ds", Engine: "postgres", Host: "localhost", Port: 5432, DBName: "app",
	})
	newTask := func(sql string) int64 {
		t.Helper()
		reason, evaluated := "need it", "DENY"
		req, err := accessStore.CreateQueryRequest(ctx, access.CreateQueryRequestInput{
			Principal: "requester@example.com", DatasourceID: datasourceID, SQL: sql,
			Reason: &reason, EvaluatedDecision: &evaluated,
		})
		if err != nil {
			t.Fatalf("CreateQueryRequest: %v", err)
		}
		return req.ID
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}

	// An ORPHAN: claimed for execution and its child moved to RUNNING, then the process "died".
	orphan := newTask("select 1")
	exec(`UPDATE access_request SET status='APPROVED' WHERE id=$1`, orphan)
	if won, err := accessStore.ClaimExecution(ctx, orphan); err != nil || !won {
		t.Fatalf("ClaimExecution: won=%v err=%v", won, err)
	}
	exec(`UPDATE query_result SET status='RUNNING' WHERE task_id=$1`, orphan)

	// A task that NEVER STARTED: APPROVED with its statement child still NULL.
	notStarted := newTask("select 2")
	exec(`UPDATE access_request SET status='APPROVED' WHERE id=$1`, notStarted)

	// A COMPLETED task: EXECUTED parent with a DONE child — completion commits both atomically, so
	// this is the only shape a finished run can take.
	completed := newTask("select 3")
	exec(`UPDATE access_request SET status='EXECUTED', executing_at=now(), executed_at=now() WHERE id=$1`, completed)
	exec(`UPDATE query_result SET status='DONE' WHERE task_id=$1`, completed)

	assertSwept := func(pass string) {
		t.Helper()
		if got := taskStatus(t, accessStore, orphan); got != "FAILED" {
			t.Errorf("%s: orphaned EXECUTING task is %q, want FAILED", pass, got)
		}
		status, code := childState(t, results, orphan)
		if str(status) != "FAILED" || str(code) != "task.orphaned_on_restart" {
			t.Errorf("%s: orphaned child is (%s, %s), want (FAILED, task.orphaned_on_restart)",
				pass, str(status), str(code))
		}

		if got := taskStatus(t, accessStore, notStarted); got != "APPROVED" {
			t.Errorf("%s: a not-started task is %q, want APPROVED (untouched)", pass, got)
		}
		if status, code := childState(t, results, notStarted); status != nil || code != nil {
			t.Errorf("%s: a not-started child is (%s, %s), want (NULL, NULL)", pass, str(status), str(code))
		}
		req, err := accessStore.GetRequest(ctx, notStarted)
		if err != nil || req == nil {
			t.Fatalf("%s: GetRequest(notStarted): %v", pass, err)
		}
		if req.ExecutedAt != nil {
			t.Errorf("%s: a not-started task was stamped executedAt=%q", pass, *req.ExecutedAt)
		}

		if got := taskStatus(t, accessStore, completed); got != "EXECUTED" {
			t.Errorf("%s: a completed task is %q, want EXECUTED (untouched)", pass, got)
		}
		if status, code := childState(t, results, completed); str(status) != "DONE" || code != nil {
			t.Errorf("%s: a completed child is (%s, %s), want (DONE, NULL) — never dragged to FAILED",
				pass, str(status), str(code))
		}
	}

	// BOOT #2 — the sweep under test.
	bootOn(t, dbName)
	assertSwept("first sweep")

	// BOOT #3 — idempotent: nothing is EXECUTING or RUNNING any more, so every row stays as it is.
	bootOn(t, dbName)
	assertSwept("second sweep")
}

func taskStatus(t *testing.T, store *access.Store, id int64) string {
	t.Helper()
	req, err := store.GetRequest(context.Background(), id)
	if err != nil || req == nil {
		t.Fatalf("GetRequest(%d): req=%v err=%v", id, req, err)
	}
	return req.Status
}
