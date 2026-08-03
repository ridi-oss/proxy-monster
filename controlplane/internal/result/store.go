package result

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// RetentionSec is `QueryResultStore.RESULT_RETENTION_SEC = 86_400L` — 24 hours. FailRun and CancelRun
// stamp `expires_at = now + RetentionSec`; A6's reconcileOrphanedExecutions reads the same constant
// for the orphan sweep (INV-A6-20), which is why it is exported.
const RetentionSec int64 = 86_400

// metaCols is `QueryResultStore.META_COLS` verbatim — the eight columns [QueryResultMeta] is built
// from. AccessFor appends `qr.sql, ciphertext` to it and nothing else.
const metaCols = "task_id, executed_by, executed_at, row_count, expires_at, status, error_code, columns"

// startRunSQL is the child's `NULL → RUNNING` compare-and-set, used by both StartRun and
// ClaimAndStartRun. One constant because the Kotlin repeats the identical statement text in both
// (QueryResultStore.kt:62,86) — the same statement, not two.
const startRunSQL = `UPDATE query_result SET status = 'RUNNING', executed_by = $1, error_code = NULL WHERE id = $2 AND status IS NULL`

// Errors ClaimAndStartRun raises through Kotlin's `error(...)`. Both roll the whole claim back,
// leaving the task APPROVED — a claimed parent with no startable child is an invariant violation, not
// a state the caller may proceed from.
var (
	// ErrNoPendingChild is `error("task $taskId claimed for execution but has no pending child")`.
	ErrNoPendingChild = errors.New("claimed for execution but has no pending child")
	// ErrChildNotStartable is `error("task $taskId child $childId not startable")` — the child was
	// selected as `status IS NULL` and then failed its own guard.
	ErrChildNotStartable = errors.New("child not startable")
)

// Store is the child state machine over `query_result`: `NULL → RUNNING → DONE | FAILED | CANCELLED`.
// It is the port of `class QueryResultStore(dataSource, crypto)` (QueryResultStore.kt, 289 LOC;
// 07-tasks-approvals-results.md §4).
//
// The parent statuses on `access_request` are A6's (internal/access); this type never writes them. It
// composes with them instead: [Store.ClaimAndStartRun] takes the parent claim as a callback and
// [Store.CompleteRun]/[Store.FailRun]/[Store.CancelRun] hand their transaction to one, so the parent's
// flip and the child's commit together (INV-A6-19, INV-A7-7).
//
// 🔒 INV-A7-8 — the active child is selected by a SEPARATE, unlocked read and then updated by its own
// id, but the per-status guard stays on the UPDATE. The transition is a race-safe compare-and-set even
// though the select is not locked: `latestChildID` + `WHERE id = $n AND status = '…'`.
type Store struct {
	db     store.DB
	crypto *Crypto
}

// NewStore builds the store over a pool (or any handle that can begin a transaction) and the result
// key. A nil crypto is not defended against: PM_RESULT_KEY being unset means this store is never
// constructed at all, and approver-exec is refused fail-closed one layer up (A1).
func NewStore(db store.DB, crypto *Crypto) *Store { return &Store{db: db, crypto: crypto} }

// StartRun flips the latest not-started child to RUNNING, standalone (no parent claim). Returns nil
// when there is no pending child or when the guard loses.
func (s *Store) StartRun(ctx context.Context, taskID int64, executedBy string) (*QueryResultMeta, error) {
	childID, err := latestChildID(ctx, s.db, taskID, "status IS NULL")
	if err != nil || childID == nil {
		return nil, err
	}
	tag, err := s.db.Exec(ctx, startRunSQL, executedBy, *childID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, nil
	}
	return metaOn(ctx, s.db, taskID)
}

// ClaimParent is the parent's `APPROVED → EXECUTING` claim, handed the transaction the child's start
// runs in — the Go form of `claimParent: (Connection) -> Boolean`. In production it is
// `accessStore.ClaimExecutionOn`.
type ClaimParent func(ctx context.Context, c store.Queryer) (bool, error)

// ClaimAndStartRun atomically claims a task for execution AND starts its run: the parent's
// `APPROVED → EXECUTING` flip (via claimParent) and the child's `NULL → RUNNING` flip commit in ONE
// transaction.
//
// 🔒 INV-A7-7 — this is what closes the cancel window. A separate claim-then-start left a gap where a
// cancel arriving between the two saw an EXECUTING parent with no RUNNING child yet, so CancelRun
// no-oped AND THE QUERY RAN ANYWAY. After this, an EXECUTING task always has a RUNNING child for a
// cancel to catch.
//
// Returns the RUNNING child meta on success; nil when claimParent finds the task not APPROVED
// (already claimed or terminal → the caller treats it as already-executed). A claimed parent with no
// pending child returns [ErrNoPendingChild] and rolls the whole claim back, leaving the task APPROVED.
func (s *Store) ClaimAndStartRun(
	ctx context.Context,
	taskID int64,
	executedBy string,
	claimParent ClaimParent,
) (*QueryResultMeta, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*QueryResultMeta, error) {
		claimed, err := claimParent(ctx, tx)
		if err != nil {
			return nil, err
		}
		if !claimed {
			return nil, nil
		}
		childID, err := latestChildID(ctx, tx, taskID, "status IS NULL")
		if err != nil {
			return nil, err
		}
		if childID == nil {
			return nil, fmt.Errorf("task %d %w", taskID, ErrNoPendingChild)
		}
		tag, err := tx.Exec(ctx, startRunSQL, executedBy, *childID)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, fmt.Errorf("task %d child %d %w", taskID, *childID, ErrChildNotStartable)
		}
		return metaOn(ctx, tx, taskID)
	})
}

// Hook is the callback CompleteRun/FailRun/CancelRun run INSIDE the transaction that flipped the
// child, so the caller can terminalize the parent task atomically with it (INV-A6-19). A returned
// error rolls the child transition back too, keeping the two consistent. nil is the Kotlin's default
// no-op argument (`= { _, _ -> }`), which Go has no syntax for.
type Hook func(ctx context.Context, c store.Queryer, meta QueryResultMeta) error

func runHook(ctx context.Context, hook Hook, c store.Queryer, meta *QueryResultMeta) error {
	if hook == nil || meta == nil {
		return nil
	}
	return hook(ctx, c, *meta)
}

// CompleteRun flips the RUNNING child to DONE: stores the ciphertext, row count, columns,
// `executed_at` and `expires_at = now + retentionSec`, then runs the audit hook in the same
// transaction.
func (s *Store) CompleteRun(
	ctx context.Context,
	taskID int64,
	res DecryptedResult,
	retentionSec int64,
	audit Hook,
) (*QueryResultMeta, error) {
	// The plaintext is produced by the NON-escaping encoder, not json.Marshal: encoding/json's outer
	// compact pass re-escapes '<', '>' and '&' over whatever a Marshaler returns, and these bytes are
	// result data from a target. kotlinx does not escape them, so this keeps a Go-written blob
	// byte-identical to a Kotlin-written one for the same rows. (DecryptedResult.MarshalJSON also
	// keeps both lists as arrays — see its doc for why that one is a cutover requirement.)
	payload, err := marshalNoEscape(res)
	if err != nil {
		return nil, err
	}
	blob, err := s.crypto.Encrypt(payload)
	if err != nil {
		return nil, err
	}
	columnsJSON, err := marshalStringList(res.Columns)
	if err != nil {
		return nil, err
	}
	// `Instant.now()` is read ONCE, before the transaction, and used for both executed_at and
	// expires_at — so the two are exactly retentionSec apart regardless of how long the tx takes.
	now := time.Now()

	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*QueryResultMeta, error) {
		childID, err := latestChildID(ctx, tx, taskID, "status = 'RUNNING'")
		if err != nil {
			return nil, err
		}
		updated := false
		if childID != nil {
			// F16: `columns` is bound as a bare jsonb parameter here (the Kotlin's PGobject), while
			// A6's task inserts and A8's AuditStore use `$n::jsonb` casts for the same job. Two idioms
			// for one problem, both REPRODUCE — unifying them is a refactor to take after cutover, and
			// keeping them distinguishable is the point. pgx sends a Go string for a jsonb parameter as
			// raw JSON text (pgtype.JSONCodec), so the stored value is identical either way.
			tag, err := tx.Exec(ctx,
				`UPDATE query_result
				    SET status = 'DONE', ciphertext = $1, row_count = $2, columns = $3,
				        executed_at = $4, expires_at = $5, error_code = NULL
				  WHERE id = $6 AND status = 'RUNNING'`,
				blob, len(res.Rows), columnsJSON, now, now.Add(time.Duration(retentionSec)*time.Second), *childID)
			if err != nil {
				return nil, err
			}
			updated = tag.RowsAffected() > 0
		}
		var meta *QueryResultMeta
		if updated {
			if meta, err = metaOn(ctx, tx, taskID); err != nil {
				return nil, err
			}
		}
		if err := runHook(ctx, audit, tx, meta); err != nil {
			return nil, err
		}
		return meta, nil
	})
}

// FailRun flips the RUNNING child to FAILED with a stable error code and stamps
// `expires_at = now + RetentionSec` — a failed child carries no ciphertext but is still swept.
//
// onFailed runs in the SAME transaction as the flip (mirroring CompleteRun's audit hook) so the caller
// can terminalize the parent atomically; an error there rolls the child transition back too.
func (s *Store) FailRun(ctx context.Context, taskID int64, errorCode string, onFailed Hook) (*QueryResultMeta, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*QueryResultMeta, error) {
		now := time.Now()
		childID, err := latestChildID(ctx, tx, taskID, "status = 'RUNNING'")
		if err != nil {
			return nil, err
		}
		updated := false
		if childID != nil {
			tag, err := tx.Exec(ctx,
				`UPDATE query_result SET status = 'FAILED', error_code = $1, expires_at = $2 WHERE id = $3 AND status = 'RUNNING'`,
				errorCode, now.Add(time.Duration(RetentionSec)*time.Second), *childID)
			if err != nil {
				return nil, err
			}
			updated = tag.RowsAffected() > 0
		}
		var meta *QueryResultMeta
		if updated {
			if meta, err = metaOn(ctx, tx, taskID); err != nil {
				return nil, err
			}
		}
		if err := runHook(ctx, onFailed, tx, meta); err != nil {
			return nil, err
		}
		return meta, nil
	})
}

// CancelRun flips the RUNNING child to CANCELLED with `error_code = 'approval.canceled'` and stamps
// `expires_at`. It wins a late completion because both are guarded compare-and-sets on the same child:
// whichever runs second finds no RUNNING row.
func (s *Store) CancelRun(ctx context.Context, taskID int64, onCancelled Hook) (*QueryResultMeta, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (*QueryResultMeta, error) {
		now := time.Now()
		childID, err := latestChildID(ctx, tx, taskID, "status = 'RUNNING'")
		if err != nil {
			return nil, err
		}
		updated := false
		if childID != nil {
			tag, err := tx.Exec(ctx,
				`UPDATE query_result SET status = 'CANCELLED', error_code = 'approval.canceled', expires_at = $1 `+
					`WHERE id = $2 AND status = 'RUNNING'`,
				now.Add(time.Duration(RetentionSec)*time.Second), *childID)
			if err != nil {
				return nil, err
			}
			updated = tag.RowsAffected() > 0
		}
		var meta *QueryResultMeta
		if updated {
			if meta, err = metaOn(ctx, tx, taskID); err != nil {
				return nil, err
			}
		}
		if err := runHook(ctx, onCancelled, tx, meta); err != nil {
			return nil, err
		}
		return meta, nil
	})
}

// Meta reads the task's LATEST child's metadata (`ORDER BY id DESC LIMIT 1`). nil when the task has no
// child at all — a WIRE task never has one.
func (s *Store) Meta(ctx context.Context, taskID int64) (*QueryResultMeta, error) {
	return metaOn(ctx, s.db, taskID)
}

// latestChildID is the separate, unlocked select of INV-A7-8. statusClause is interpolated into the
// statement exactly as the Kotlin interpolates `$statusClause`; it is never caller data — the three
// call sites pass "status IS NULL" and "status = 'RUNNING'" as literals.
func latestChildID(ctx context.Context, c store.Queryer, taskID int64, statusClause string) (*int64, error) {
	var id int64
	err := c.QueryRow(ctx,
		"SELECT id FROM query_result WHERE task_id = $1 AND "+statusClause+" ORDER BY id DESC LIMIT 1",
		taskID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func metaOn(ctx context.Context, c store.Queryer, taskID int64) (*QueryResultMeta, error) {
	row := c.QueryRow(ctx,
		"SELECT "+metaCols+" FROM query_result WHERE task_id = $1 ORDER BY id DESC LIMIT 1", taskID)
	child, err := scanMeta(row, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &child.meta, nil
}

// childRow is one scanned `query_result` row: the wire meta, the raw expiry the meta's string was
// formatted from, and — for AccessFor — the child's own sql and ciphertext.
type childRow struct {
	meta       QueryResultMeta
	expiresAt  *time.Time
	sqlText    *string
	ciphertext []byte
}

// scanMeta reads META_COLS, and — when withPayload — the two extra columns AccessFor selects. It is
// the port of `ResultSet.toMeta()` plus AccessFor's Triple.
func scanMeta(row pgx.Row, withPayload bool) (*childRow, error) {
	var (
		out        childRow
		executedAt *time.Time
		columns    *string
	)
	dest := []any{
		&out.meta.TaskID, &out.meta.ExecutedBy, &executedAt, &out.meta.RowCount, &out.expiresAt,
		&out.meta.Status, &out.meta.ErrorCode, &columns,
	}
	if withPayload {
		dest = append(dest, &out.sqlText, &out.ciphertext)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	out.meta.ExecutedAt = instant.FormatPtr(executedAt)
	out.meta.ExpiresAt = instant.FormatPtr(out.expiresAt)
	// `json.decodeFromString(stringList, getString("columns") ?: "[]")` — a purged (NULL) columns
	// column reads back as the empty list, not as an error.
	cols, err := decodeStringList(columns)
	if err != nil {
		return nil, err
	}
	out.meta.Columns = cols
	return &out, nil
}

// AccessFor captures the latest child's meta, its OWN sql and its ciphertext in ONE read, and defers
// the decrypt (INV-A7-9 — see [ResultAccess]).
//
// The payload is handed to the lazy closure ONLY when `status == "DONE" && !expired`; anything else
// decrypts to nil so the route surfaces 409/410 rather than any bytes. An expired row triggers an
// opportunistic PurgeExpired on the way past.
func (s *Store) AccessFor(ctx context.Context, taskID int64) (*ResultAccess, error) {
	row := s.db.QueryRow(ctx,
		// Reading qr.sql in the SAME row as the ciphertext binds the view's re-decision to the
		// released bytes.
		"SELECT "+metaCols+", qr.sql, ciphertext FROM query_result qr WHERE task_id = $1 ORDER BY id DESC LIMIT 1",
		taskID)
	child, err := scanMeta(row, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// `expired = meta.expiresAt != null && Instant.parse(meta.expiresAt).isBefore(Instant.now())`.
	// The Kotlin re-parses the string it has just formatted; comparing the scanned timestamp instead
	// is the same test, because TIMESTAMPTZ is microsecond-resolution and instant.Format is lossless
	// at that resolution — no value can straddle the two forms.
	expired := child.expiresAt != nil && child.expiresAt.Before(time.Now())
	if expired {
		if _, err := s.PurgeExpired(ctx); err != nil {
			return nil, err
		}
	}

	var payload []byte
	if child.meta.Status != nil && *child.meta.Status == "DONE" && !expired {
		payload = child.ciphertext
	}
	return &ResultAccess{
		Meta: child.meta,
		SQL:  child.sqlText,
		decrypt: func() (*DecryptedResult, error) {
			if payload == nil {
				return nil, nil
			}
			plain, err := s.crypto.Decrypt(payload)
			if err != nil {
				return nil, err
			}
			var out DecryptedResult
			if err := json.Unmarshal(plain, &out); err != nil {
				return nil, err
			}
			return &out, nil
		},
	}, nil
}

// PurgeExpired drops the decryptable PAYLOAD (ciphertext, row_count, columns) and clears expires_at,
// but KEEPS the child row and its sql/sql_hash/status/error_code/executed_* for durable audit and web
// preview. A purged row still exists yet reads back with no payload (AccessFor's Decrypted is nil →
// the route returns 410).
//
// 🔒 INV-A7-10 — clearing `expires_at` is what makes the row fall out of this sweep's own WHERE, so it
// is not reprocessed. It is also why the A1 sweep must run [Store.PurgeExpiredEditorChildren] FIRST:
// this statement NULLs expires_at on every expired child including the editor ones, and an editor
// sweep ordered after it would never match again (A1 INV-A1-5).
func (s *Store) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx,
		"UPDATE query_result SET ciphertext = NULL, row_count = NULL, columns = NULL, expires_at = NULL "+
			"WHERE expires_at <= $1", time.Now())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PurgeExpiredEditorChildren GCs expired EDITOR result children by DELETING them outright — unlike
// PurgeExpired, which keeps a workflow child's row. An editor tab has no audit obligation, so its
// expired child is removed whole (INV-A7-10).
func (s *Store) PurgeExpiredEditorChildren(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx,
		"DELETE FROM query_result WHERE expires_at <= $1 AND task_id IN "+
			"(SELECT id FROM access_request WHERE creator_kind = 'EDITOR')", time.Now())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteResultsForTask drops the result child(ren) of one task outright (close-tab). Editor tabs are
// 1:child, so this removes exactly the tab's saved rows. Returns the number of rows deleted — 0 means
// already gone, i.e. idempotent.
func (s *Store) DeleteResultsForTask(ctx context.Context, taskID int64) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM query_result WHERE task_id = $1", taskID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteEditorResultsForPrincipal drops every EDITOR result child owned by principal — the
// delete-on-session-end backstop (logout, deprovision, device-mismatch, newest-wins displacement all
// funnel through PrincipalSessionStore's end seam). A workflow task's saved result is untouched.
func (s *Store) DeleteEditorResultsForPrincipal(ctx context.Context, principal string) (int64, error) {
	return s.DeleteEditorResultsForPrincipalOn(ctx, s.db, principal)
}

// DeleteEditorResultsForPrincipalOn is DeleteEditorResultsForPrincipal composed onto a caller-supplied
// handle — the session-end seam passes the connection that performed the end-write, so this delete
// joins the same transaction and commits or rolls back atomically with it (never orphaning a committed
// delete under a rolled-back deprovision teardown).
//
// 🔒 INV-A7-11 — it deletes the principal's EDITOR *tasks* (access_request), CASCADING to their
// query_result children, rather than only the children: dropping the whole task terminalizes any that
// were still EXECUTING when the session ended (a child-only delete would strand the parent EXECUTING
// until the boot reconcile) and leaves no empty editor task rows behind. Scoped
// `creator_kind = 'EDITOR' AND principal = ?` so a WORKFLOW approval is never touched.
//
// ⚠️ The returned count is therefore TASKS deleted, not children — the Kotlin's `executeUpdate()` on
// the same statement. EditorTaskStoreDbTest asserts 1 for a principal with one editor task.
func (s *Store) DeleteEditorResultsForPrincipalOn(ctx context.Context, c store.Queryer, principal string) (int64, error) {
	tag, err := c.Exec(ctx, "DELETE FROM access_request WHERE creator_kind = 'EDITOR' AND principal = $1", principal)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// marshalStringList renders a List<String> for a jsonb column. nil marshals as [], never null: the
// column is read back through decodeStringList and a null would be a different value than the Kotlin
// ever writes.
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

// decodeStringList is `json.decodeFromString(stringList, s ?: "[]")`.
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
