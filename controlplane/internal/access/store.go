package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// reqSelect is `AccessStore.REQ_SELECT` verbatim, with JDBC's `?` rewritten to pgx's `$n` in the
// WHERE clauses each caller appends.
//
// The three correlated subqueries read the task's EARLIEST child (`ORDER BY qr.id LIMIT 1`), which is
// why a WIRE task — which has no child at all — reads null sql, sqlHash and executedBy.
const reqSelect = `SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
                          ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by, ar.decided_at, ar.rejection_reason, ar.created_at,
                          ar.kind,
                          (SELECT qr.sql FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.id LIMIT 1) AS task_sql,
                          (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.id LIMIT 1) AS task_sql_hash,
                          (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.id LIMIT 1) AS executed_by,
                          ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
                          ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind
                   FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
                   LEFT JOIN datasource d ON d.id = ar.datasource_id`

// grantSelect is `AccessStore.GRANT_SELECT` verbatim. The JOIN is INNER, so a grant whose role was
// deleted disappears from every listing rather than reading with a null name.
const grantSelect = `SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name,
                            ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
                     FROM access_grant ag JOIN app_role r ON r.id = ag.role_id`

// Store is the task lifecycle store — access requests, the grants they mint, and the QUERY task
// status machine the three origins share. It is the port of `class AccessStore(dataSource)`
// (Access.kt:70-564; 06-query-decision.md §5).
//
// 🔒 INV-A6-17 — `creator_kind` is what keeps the three origins apart. All three are
// `kind = 'QUERY'`: WORKFLOW (human-decided, starts PENDING, 1 child), EDITOR (self-approved, born
// APPROVED, 1 child) and WIRE (born APPROVED, NO child). [Store.ListQueryRequests] filters
// `creator_kind = 'WORKFLOW'` so editor tabs and per-statement wire authorizations never surface on
// the human approval queue, and [Store.WireTaskIDForDecision] filters 'WIRE' because a WORKFLOW task
// ALSO carries the DENY decision that spawned it and a proxy completion must never terminalize one.
//
// 🔒 INV-A6-18 — every status transition is a SINGLE guarded conditional UPDATE whose row count is the
// answer. That is the concurrency control: exactly one of N concurrent ClaimExecution callers wins,
// with no explicit lock. Nothing here reads-then-writes, and a port that did would silently lose the
// property while still passing a single-threaded test.
type Store struct {
	db store.DB
}

// NewStore builds the store over a pool (or any handle that can begin a transaction).
func NewStore(db store.DB) *Store { return &Store{db: db} }

// ---- reads -------------------------------------------------------------------------------------

// GetRequest reads one request by id, of any kind. nil when absent.
func (s *Store) GetRequest(ctx context.Context, id int64) (*AccessRequest, error) {
	req, err := scanRequest(s.db.QueryRow(ctx, reqSelect+" WHERE ar.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ListRequests lists ROLE requests, optionally filtered by status, newest first.
func (s *Store) ListRequests(ctx context.Context, status *string) ([]AccessRequest, error) {
	sql := reqSelect + " WHERE ar.kind = 'ROLE' ORDER BY ar.created_at DESC"
	var args []any
	if status != nil {
		sql = reqSelect + " WHERE ar.kind = 'ROLE' AND ar.status = $1 ORDER BY ar.created_at DESC"
		args = append(args, *status)
	}
	return s.queryRequests(ctx, sql, args...)
}

// ListQueryRequests is the human query-approval feed: WORKFLOW-origin QUERY tasks only.
//
// 🔒 INV-A6-17 — EDITOR and WIRE tasks share the access_request table but are internal lifecycle
// records (an editor tab's saved result; a native-wire statement's per-statement authorization). They
// carry null SQL, are never decided by an approver, and must never surface on /api/approvals. The
// creator_kind filter is what keeps them off it.
func (s *Store) ListQueryRequests(ctx context.Context, status, principal *string) ([]AccessRequest, error) {
	sql := reqSelect + " WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW'"
	var args []any
	if status != nil {
		args = append(args, *status)
		sql += " AND ar.status = $" + strconv.Itoa(len(args))
	}
	if principal != nil {
		args = append(args, *principal)
		sql += " AND ar.principal = $" + strconv.Itoa(len(args))
	}
	sql += " ORDER BY ar.created_at DESC"
	return s.queryRequests(ctx, sql, args...)
}

func (s *Store) queryRequests(ctx context.Context, sql string, args ...any) ([]AccessRequest, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessRequest{}
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *req)
	}
	return out, rows.Err()
}

// PendingQueryRequestExists is the application-level pre-check for "one pending request per denied
// decision". It is NOT the enforcement — [Store.CreateQueryRequest]'s partial-index upsert is
// (INV-A6-21) — it exists so a route can answer the question without attempting an insert.
func (s *Store) PendingQueryRequestExists(ctx context.Context, sourceDecisionID int64) (bool, error) {
	var one int
	err := s.db.QueryRow(ctx,
		`SELECT 1 FROM access_request
		    WHERE kind = 'QUERY' AND source_decision_id = $1 AND status = 'PENDING'
		    LIMIT 1`, sourceDecisionID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// WireTaskIDForDecision finds the native-wire task correlated to decisionID, on the caller's handle.
//
// 🔒 INV-A6-17 — the `creator_kind = 'WIRE'` filter is required: WORKFLOW tasks also carry the DENY
// decision that spawned them, and a proxy completion must never terminalize one.
func (s *Store) WireTaskIDForDecision(ctx context.Context, c store.Queryer, decisionID int64) (*int64, error) {
	var id int64
	err := c.QueryRow(ctx,
		`SELECT id FROM access_request
		    WHERE kind = 'QUERY' AND creator_kind = 'WIRE' AND source_decision_id = $1`, decisionID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// EditorChildID is the id of an EDITOR task's single result child (task:child 1:1) — carried in the
// submit ack.
func (s *Store) EditorChildID(ctx context.Context, taskID int64) (*int64, error) {
	var id int64
	err := s.db.QueryRow(ctx,
		"SELECT id FROM query_result WHERE task_id = $1 ORDER BY id DESC LIMIT 1", taskID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// ---- creates -----------------------------------------------------------------------------------

// CreateRequest opens a ROLE elevation request.
func (s *Store) CreateRequest(ctx context.Context, principal string, input AccessRequestInput) (*AccessRequest, error) {
	var id int64
	err := s.db.QueryRow(ctx,
		`INSERT INTO access_request (principal, role_id, datasource_id, reason, requested_duration_sec)
		    VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		principal, input.RoleID, input.DatasourceID, input.Reason, input.Duration()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetRequest(ctx, id)
}

// CreateQueryRequest opens a WORKFLOW query-approval task and its not-started statement child, in ONE
// transaction.
//
// 🔒 INV-A6-21 — the insert carries
// `ON CONFLICT (source_decision_id) WHERE kind='QUERY' AND status='PENDING' AND source_decision_id IS
// NOT NULL DO NOTHING RETURNING id`. NO ROW RETURNED means a pending request already exists for that
// decision ⇒ [ErrDuplicatePendingQueryRequest], and the transaction rolls back so no orphan child is
// left behind. A read-then-insert would race; the partial index is what makes the rule atomic.
//
// `executeAs` is resolved INSIDE the transaction by looking up app_role.name for RoleID — a role
// deleted between the pick and the insert yields an empty list rather than a stale name.
func (s *Store) CreateQueryRequest(ctx context.Context, in CreateQueryRequestInput) (*AccessRequest, error) {
	sqlHash := sha256Hex(in.SQL)
	id, err := store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		executeAs := []string{}
		if in.RoleID != nil {
			var name string
			err := tx.QueryRow(ctx, "SELECT name FROM app_role WHERE id = $1", *in.RoleID).Scan(&name)
			switch {
			case errors.Is(err, pgx.ErrNoRows): // stays empty
			case err != nil:
				return 0, err
			default:
				executeAs = []string{name}
			}
		}
		executeAsJSON, err := marshalStringList(executeAs)
		if err != nil {
			return 0, err
		}
		var taskID int64
		err = tx.QueryRow(ctx,
			// F16: `execute_as` is bound through an explicit `$10::jsonb` cast here, while A7's
			// completeRun binds a bare jsonb parameter (the Kotlin's PGobject). Two idioms for one
			// problem, both REPRODUCE.
			`INSERT INTO access_request
			    (principal, kind, role_id, datasource_id, deny_reason, source_decision_id, reason, title,
			     evaluated_decision, requested_duration_sec, execute_as, creator_kind)
			    VALUES ($1, 'QUERY', $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, 'WORKFLOW')
			    ON CONFLICT (source_decision_id) WHERE kind = 'QUERY' AND status = 'PENDING' AND source_decision_id IS NOT NULL
			    DO NOTHING
			    RETURNING id`,
			in.Principal, in.RoleID, in.DatasourceID, in.DenyReason, in.SourceDecisionID, in.Reason,
			in.Title, in.EvaluatedDecision, in.duration(), executeAsJSON).Scan(&taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrDuplicatePendingQueryRequest
		}
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO query_result (task_id, sql, sql_hash) VALUES ($1, $2, $3)",
			taskID, in.SQL, sqlHash); err != nil {
			return 0, err
		}
		return taskID, nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetRequest(ctx, id)
}

// CreateEditorTask creates a born-APPROVED EDITOR task with ONE result child (task:child 1:1 per
// editor submit). Unlike CreateQueryRequest — a human-decided WORKFLOW request that starts PENDING
// under an elevation role R — an editor submit auto-approves itself.
//
// 🔒 INV-A6-22 — executeAs is the caller's OWN server-resolved roles, freshly resolved at submit:
// never an elevation, never frozen across submits, so a revoked role fails closed on the next submit.
// approver is the self-approver (== principal). The row is stamped APPROVED/decided so the same
// single-execution status machine and the boot reconcile drive it verbatim — there is no editor-only
// status path.
func (s *Store) CreateEditorTask(
	ctx context.Context,
	principal string,
	datasourceID int64,
	sql string,
	executeAs []string,
	approver string,
) (*AccessRequest, error) {
	sqlHash := sha256Hex(sql)
	executeAsJSON, err := marshalStringList(executeAs)
	if err != nil {
		return nil, err
	}
	id, err := store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		now := time.Now()
		var taskID int64
		if err := tx.QueryRow(ctx,
			`INSERT INTO access_request
			    (principal, kind, datasource_id, status, decided_by, decided_at, approved_at,
			     requested_duration_sec, execute_as, creator_kind)
			    VALUES ($1, 'QUERY', $2, 'APPROVED', $3, $4, $5, $6, $7::jsonb, 'EDITOR')
			    RETURNING id`,
			principal, datasourceID, approver, now, now, DefaultRequestedDurationSec, executeAsJSON,
		).Scan(&taskID); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO query_result (task_id, sql, sql_hash) VALUES ($1, $2, $3)",
			taskID, sql, sqlHash); err != nil {
			return 0, err
		}
		return taskID, nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetRequest(ctx, id)
}

// CreateWireTask creates the lifecycle record for ONE native-wire statement authorization, on the
// caller's transaction so the decision event and its task commit atomically (INV-A6-22).
//
// sourceDecisionID links the CHILDLESS task to the decision audit event that carries the statement
// text and verdict. The task stays APPROVED until the proxy's post-relay completion confirms
// execution; because the relay streams directly to the client and saves no result child, GetRequest
// reads sql, sqlHash and executedBy as null.
func (s *Store) CreateWireTask(
	ctx context.Context,
	c store.Queryer,
	principal string,
	datasourceID int64,
	executeAs []string,
	sourceDecisionID int64,
) (int64, error) {
	executeAsJSON, err := marshalStringList(executeAs)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	var id int64
	err = c.QueryRow(ctx,
		`INSERT INTO access_request
		    (principal, kind, datasource_id, status, decided_by, decided_at, approved_at,
		     requested_duration_sec, execute_as, creator_kind, source_decision_id)
		    VALUES ($1, 'QUERY', $2, 'APPROVED', $3, $4, $5, $6, $7::jsonb, 'WIRE', $8)
		    RETURNING id`,
		principal, datasourceID, principal, now, now, DefaultRequestedDurationSec, executeAsJSON, sourceDecisionID,
	).Scan(&id)
	return id, err
}

// DeleteEditorTask is an owner-scoped delete of an EDITOR task (close-tab). It CASCADEs to the task's
// query_result child(ren). Restricted to `creator_kind = 'EDITOR'` + the owner so a leaked task id can
// never delete another principal's task, nor a human-approval WORKFLOW task. Idempotent: false when
// nothing matched.
func (s *Store) DeleteEditorTask(ctx context.Context, taskID int64, principal string) (bool, error) {
	return s.exec(ctx, s.db,
		"DELETE FROM access_request WHERE id = $1 AND kind = 'QUERY' AND creator_kind = 'EDITOR' AND principal = $2",
		taskID, principal)
}

// ---- the status machine ------------------------------------------------------------------------
//
// 🔒 INV-A6-18 — every method below is ONE conditional UPDATE whose row count is the return value.
// The guard lives in the WHERE clause, never in a preceding read.

// DecideQueryRequest atomically decides a pending QUERY task. Approval authorizes execution; it does
// not run the statement. `approved_at` is stamped only when approving.
func (s *Store) DecideQueryRequest(
	ctx context.Context,
	id int64,
	approved bool,
	rejectionReason *string,
	decidedBy string,
) (*AccessRequest, error) {
	decidedAt := time.Now()
	status := "REJECTED"
	var approvedAt *time.Time
	if approved {
		status = "APPROVED"
		approvedAt = &decidedAt
	}
	won, err := s.exec(ctx, s.db,
		`UPDATE access_request
		    SET status = $1, decided_by = $2, decided_at = $3, approved_at = $4, rejection_reason = $5
		    WHERE id = $6 AND kind = 'QUERY' AND status = 'PENDING'`,
		status, decidedBy, decidedAt, approvedAt, rejectionReason, id)
	if err != nil || !won {
		return nil, err
	}
	return s.GetRequest(ctx, id)
}

// ClaimExecution atomically claims an approved task for execution. Exactly one concurrent caller wins.
func (s *Store) ClaimExecution(ctx context.Context, id int64) (bool, error) {
	return s.ClaimExecutionOn(ctx, s.db, id)
}

// ClaimExecutionOn is ClaimExecution composed onto a caller-supplied transaction — the form
// [result.Store.ClaimAndStartRun] takes, so the parent's claim and the child's start commit together
// (INV-A7-7).
func (s *Store) ClaimExecutionOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	return s.exec(ctx, c,
		"UPDATE access_request SET status = 'EXECUTING', executing_at = $1 WHERE id = $2 AND kind = 'QUERY' AND status = 'APPROVED'",
		time.Now(), id)
}

// MarkExecuted flips EXECUTING → EXECUTED and stamps executed_at.
func (s *Store) MarkExecuted(ctx context.Context, id int64) (bool, error) {
	return s.MarkExecutedOn(ctx, s.db, id)
}

// MarkExecutedOn is MarkExecuted composed onto a caller-supplied handle.
//
// 🔒 INV-A6-19 — it exists so the parent's EXECUTING → EXECUTED flip commits in the SAME transaction
// as the child's DONE (A7's CompleteRun audit hook). Keeping both writes in one commit is what makes
// terminal success atomic: a crash can never leave a readable DONE child under a still-EXECUTING task.
func (s *Store) MarkExecutedOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	return s.exec(ctx, c,
		"UPDATE access_request SET status = 'EXECUTED', executed_at = $1 WHERE id = $2 AND kind = 'QUERY' AND status = 'EXECUTING'",
		time.Now(), id)
}

// MarkFailed flips EXECUTING → FAILED. It stamps no timestamp: `executed_at` is terminal-success only.
func (s *Store) MarkFailed(ctx context.Context, id int64) (bool, error) {
	return s.MarkFailedOn(ctx, s.db, id)
}

// MarkFailedOn is MarkFailed composed onto a caller-supplied handle, for A7's FailRun hook — terminal
// failure is atomic in the same way terminal success is (INV-A6-19).
func (s *Store) MarkFailedOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	return s.exec(ctx, c,
		"UPDATE access_request SET status = 'FAILED' WHERE id = $1 AND kind = 'QUERY' AND status = 'EXECUTING'", id)
}

// MarkCancelled flips EXECUTING → CANCELLED.
func (s *Store) MarkCancelled(ctx context.Context, id int64) (bool, error) {
	return s.MarkCancelledOn(ctx, s.db, id)
}

// MarkCancelledOn atomically terminalizes an executing task in the caller's transaction — A7's
// CancelRun hook, which is what lets a cancel win a late completion.
func (s *Store) MarkCancelledOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	return s.exec(ctx, c,
		"UPDATE access_request SET status = 'CANCELLED' WHERE id = $1 AND kind = 'QUERY' AND status = 'EXECUTING'", id)
}

// MarkDeleted flips DRAFT | PENDING | REJECTED → DELETED. Never from a live state.
func (s *Store) MarkDeleted(ctx context.Context, id int64) (bool, error) {
	return s.exec(ctx, s.db,
		"UPDATE access_request SET status = 'DELETED' WHERE id = $1 AND kind = 'QUERY' AND status IN ('DRAFT', 'PENDING', 'REJECTED')",
		id)
}

// Resubmit flips REJECTED → PENDING and clears the decision fields.
func (s *Store) Resubmit(ctx context.Context, id int64) (bool, error) {
	return s.exec(ctx, s.db,
		"UPDATE access_request SET status = 'PENDING', decided_by = NULL, decided_at = NULL, rejection_reason = NULL WHERE id = $1 AND kind = 'QUERY' AND status = 'REJECTED'",
		id)
}

// ReconcileOrphanedExecutions fails every task left EXECUTING by a crash, and every child left
// RUNNING, in ONE transaction. Called twice at boot (Main.kt:50 and App.kt:351); idempotent.
//
// 🔒 INV-A6-20 — the child update MUST set `expires_at = now + RESULT_RETENTION_SEC`. purgeExpired
// matches on expires_at, so without it a NULL-expiry FAILED row accumulates on every
// restart-with-orphan: no ciphertext, but unbounded growth. Same class of bug as A1 INV-A1-5.
func (s *Store) ReconcileOrphanedExecutions(ctx context.Context) error {
	return store.InTxDo(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			"UPDATE access_request SET status = 'FAILED' WHERE kind = 'QUERY' AND status = 'EXECUTING'"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			"UPDATE query_result SET status = 'FAILED', error_code = 'task.orphaned_on_restart', expires_at = $1 WHERE status = 'RUNNING'",
			time.Now().Add(time.Duration(result.RetentionSec)*time.Second))
		return err
	})
}

// ---- the ROLE elevation path -------------------------------------------------------------------

// Approve marks a ROLE request APPROVED and inserts its time-boxed grant. Returns nil if the request
// or its roleId is absent.
//
// ⚠️ F14 — this is the ONE method in the file that hand-rolls its transaction instead of using the
// shared inTx helper (`autoCommit = false` / commit / rollback / `finally autoCommit = true`,
// Access.kt:450-473). It is reproduced hand-rolled here, in the same shape, rather than folded into
// store.InTx: inconsistency is not grounds for OMIT, and unifying it is a refactor to take against a
// working Go service, as its own change. The one part with no Go analogue is the autoCommit
// restore — pgx has no per-connection autocommit flag and pgxpool resets a connection on release —
// which internal/store/tx.go already OMITs for the same reason.
//
// Note what the Kotlin does NOT do: there is no status guard on the UPDATE, so approving an already
// decided ROLE request overwrites it and mints a SECOND grant. That is the same missing-guard class as
// [Store.Reject]'s F11; the spec calls out reject, and this is its sibling.
func (s *Store) Approve(ctx context.Context, id int64, durationSec *int64, decidedBy string) (*AccessRequest, error) {
	req, err := s.GetRequest(ctx, id)
	if err != nil || req == nil {
		return nil, err
	}
	if req.RoleID == nil {
		return nil, nil
	}
	dur := req.RequestedDurationSec
	if durationSec != nil {
		dur = *durationSec
	}
	expires := time.Now().Add(time.Duration(dur) * time.Second)

	tx, err := s.db.Begin(ctx) // c.autoCommit = false
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		"UPDATE access_request SET status='APPROVED', decided_by=$1, decided_at=now() WHERE id=$2",
		decidedBy, id); err != nil {
		_ = tx.Rollback(ctx) // catch { c.rollback(); throw e }
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO access_grant (request_id, principal, role_id, granted_by, granted_at, expires_at)
		    VALUES ($1, $2, $3, $4, now(), $5)`,
		id, req.Principal, *req.RoleID, decidedBy, expires); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return s.GetRequest(ctx, id)
}

// Reject marks a request REJECTED.
//
// ⚠️ F11 — REPRODUCED DEFECT, PINNED. The UPDATE carries NO status guard and no kind guard: only the
// existence check above it. Rejecting an already-decided request therefore SILENTLY OVERWRITES its
// status, decided_by, decided_at and rejection_reason — an APPROVED ROLE request can be flipped to
// REJECTED after the fact, and a previous rejector's name replaced. Contrast [Store.DecideQueryRequest],
// which guards on `status = 'PENDING'` and returns nil when it loses.
//
// It reads as a bug (06-query-decision.md §7 Q1 agrees), and the disposition is REPRODUCE regardless:
// the unguarded UPDATE is observable on the wire. TestRejectIsUnguardedF11 asserts the BUGGY
// behaviour, so a later fix has to change a test that says why it exists.
func (s *Store) Reject(ctx context.Context, id int64, reason string, decidedBy string) (*AccessRequest, error) {
	req, err := s.GetRequest(ctx, id)
	if err != nil || req == nil {
		return nil, err
	}
	if _, err := s.exec(ctx, s.db,
		"UPDATE access_request SET status='REJECTED', rejection_reason=$1, decided_by=$2, decided_at=now() WHERE id=$3",
		reason, decidedBy, id); err != nil {
		return nil, err
	}
	return s.GetRequest(ctx, id)
}

// ---- grants ------------------------------------------------------------------------------------

// ListGrants lists grants, optionally for one principal, optionally only the live ones. activeOnly
// adds `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())` — a grant with no expiry is
// active forever, which is a shape the ROLE path can mint.
func (s *Store) ListGrants(ctx context.Context, principal *string, activeOnly bool) ([]AccessGrant, error) {
	sql := grantSelect + " WHERE 1=1"
	var args []any
	if principal != nil {
		args = append(args, *principal)
		sql += " AND ag.principal = $" + strconv.Itoa(len(args))
	}
	if activeOnly {
		sql += " AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())"
	}
	sql += " ORDER BY ag.granted_at DESC"

	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessGrant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// GetGrant reads one grant by id. nil when absent.
func (s *Store) GetGrant(ctx context.Context, id int64) (*AccessGrant, error) {
	g, err := scanGrant(s.db.QueryRow(ctx, grantSelect+" WHERE ag.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

// Revoke revokes one grant, guarded on `revoked_at IS NULL` so a second revoke does not move the
// timestamp.
func (s *Store) Revoke(ctx context.Context, id int64) (bool, error) {
	return s.exec(ctx, s.db, "UPDATE access_grant SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", id)
}

// RevokeAllForPrincipal revokes every currently-active JIT grant for principal — the deprovisioning
// backstop (docs/auth-model.md), paired with TokenStore.revokeAllForPrincipal. Returns the number
// revoked.
func (s *Store) RevokeAllForPrincipal(ctx context.Context, principal string) (int64, error) {
	return s.RevokeAllForPrincipalOn(ctx, s.db, principal)
}

// RevokeAllForPrincipalOn is RevokeAllForPrincipal composed onto a caller-supplied handle, so the
// revoke joins the teardown transaction.
func (s *Store) RevokeAllForPrincipalOn(ctx context.Context, c store.Queryer, principal string) (int64, error) {
	tag, err := c.Exec(ctx, "UPDATE access_grant SET revoked_at = now() WHERE principal = $1 AND revoked_at IS NULL", principal)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---- scanning ----------------------------------------------------------------------------------

// exec runs a guarded UPDATE/DELETE and reports whether it matched — the Go form of
// `executeUpdate() > 0`, which is INV-A6-18's whole concurrency control.
func (s *Store) exec(ctx context.Context, c store.Queryer, sql string, args ...any) (bool, error) {
	tag, err := c.Exec(ctx, sql, args...)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// scanRequest is the port of `ResultSet.toRequest()`. The destination order is reqSelect's column
// order — the single biggest mechanical hazard in the port, since a mis-ordered destination is a
// silent wrong-value bug rather than a compile error.
func scanRequest(row pgx.Row) (*AccessRequest, error) {
	var (
		r           AccessRequest
		decidedAt   *time.Time
		createdAt   time.Time
		approvedAt  *time.Time
		executingAt *time.Time
		executedAt  *time.Time
		executeAs   *string
	)
	if err := row.Scan(
		&r.ID, &r.Principal, &r.RoleID, &r.RoleName, &r.DatasourceID, &r.DatasourceName,
		&r.Reason, &r.RequestedDurationSec, &r.Status, &r.DecidedBy, &decidedAt, &r.RejectionReason, &createdAt,
		&r.Kind,
		&r.SQL, &r.SQLHash, &r.ExecutedBy,
		&r.DenyReason, &r.SourceDecisionID, &r.Title, &r.EvaluatedDecision,
		&approvedAt, &executingAt, &executedAt, &executeAs, &r.CreatorKind,
	); err != nil {
		return nil, err
	}
	r.DecidedAt = instant.FormatPtr(decidedAt)
	r.CreatedAt = instant.Format(createdAt)
	r.ApprovedAt = instant.FormatPtr(approvedAt)
	r.ExecutingAt = instant.FormatPtr(executingAt)
	r.ExecutedAt = instant.FormatPtr(executedAt)
	list, err := decodeStringList(executeAs)
	if err != nil {
		return nil, err
	}
	r.ExecuteAs = list
	return &r, nil
}

// scanGrant is the port of `ResultSet.toGrant()`.
func scanGrant(row pgx.Row) (*AccessGrant, error) {
	var (
		g         AccessGrant
		grantedAt time.Time
		expiresAt *time.Time
		revokedAt *time.Time
	)
	if err := row.Scan(&g.ID, &g.Principal, &g.RoleID, &g.RoleName, &g.GrantedBy, &grantedAt, &expiresAt, &revokedAt); err != nil {
		return nil, err
	}
	g.GrantedAt = instant.Format(grantedAt)
	g.ExpiresAt = instant.FormatPtr(expiresAt)
	g.RevokedAt = instant.FormatPtr(revokedAt)
	return &g, nil
}

// sha256Hex is `MessageDigest.getInstance("SHA-256").digest(sql.toByteArray(UTF_8)).joinToString("")
// { "%02x".format(it) }` — the `sql_hash` every statement child carries.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// marshalStringList renders a List<String> for a jsonb column; nil marshals as [], never null.
func marshalStringList(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeStringList is `json.decodeFromString(stringList, getString("execute_as") ?: "[]")`.
func decodeStringList(s *string) ([]string, error) {
	if s == nil {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(*s), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}
