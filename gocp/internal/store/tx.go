package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// advisoryLockPrincipalSQL is the literal statement, with JDBC's positional `?` rewritten to pgx's
// `$1`. Nothing else about it may change — see INV-A3-4 on AdvisoryLockPrincipal.
const advisoryLockPrincipalSQL = `SELECT pg_advisory_xact_lock(hashtext($1))`

// AdvisoryLockPrincipal is the per-principal serialization primitive every teardown path shares
// (03-identity-scim.md §"Deprovision.kt"). It is the port of
// `internal fun Connection.advisoryLockPrincipal(principal: String)`.
//
// Contract: after it returns, the calling transaction holds an exclusive, transaction-scoped lock
// keyed on principal, released automatically at commit OR rollback.
//
//  1. Executes exactly `SELECT pg_advisory_xact_lock(hashtext($1))` with principal bound, and drains
//     one row.
//  2. Blocks until the lock is available. No timeout, no try variant — reproduce the absence of both.
//  3. Re-entrant within a session: a transaction already holding it acquires again for free, so
//     composing callers cannot self-deadlock.
//
// 🔒 INV-A3-3 — one serialization primitive, taken FIRST, for every principal-mutating path. Call it
// first inside a transaction, before any read or write that must not interleave with a concurrent
// teardown/re-mint for the SAME principal. Every rename, deactivate, tombstone, tombstone-release,
// credential revoke and credential mint funnels through this one lock; a second, differently-keyed
// lock would let a teardown and a mint interleave.
//
// 🔒 INV-A3-4 — the lock key must stay hashtext(<principal>), COMPUTED BY POSTGRES. It is a
// server-side expression, not a client-side hash. A Go port that hashes in-process and passes an
// integer would not serialize against a still-running Kotlin instance, and a rolling cutover would
// silently lose mutual exclusion for the whole deploy. hashtext is 32-bit, so distinct principals can
// collide — that only over-serializes (safe); the converse cannot happen. ProvisionMergeDbTest cases
// 12-13 and DeprovisionDbTest case 8 take the lock from raw SQL with this exact expression, so the
// tests pin the key.
//
// ⚠️ This must NOT be modelled as an in-process mutex: cross-instance exclusion is the entire point.
//
// c is a Queryer rather than a pgx.Tx so a store method can take the caller's handle unchanged,
// exactly as the Kotlin extension sits on Connection. That carries the Kotlin's hazard with it — a
// non-transactional handle makes the xact-scoped lock release at the end of the implicit
// single-statement transaction, i.e. immediately. REPRODUCE: the Kotlin has the same hole for an
// autoCommit Connection, and closing it here would change which call sites are correct.
func AdvisoryLockPrincipal(ctx context.Context, c Queryer, principal string) error {
	rows, err := c.Query(ctx, advisoryLockPrincipalSQL, principal)
	if err != nil {
		return err
	}
	// The Kotlin is `executeQuery().use { it.next() }` — advance one row, then close. pgx defers most
	// execution errors to Next/Close, so the error check has to come after Close, not from Query.
	rows.Next()
	rows.Close()
	return rows.Err()
}

// InTx runs body on a fresh connection inside a committed transaction. It is the port of
// `internal inline fun <T> DataSource.inTx(body: (Connection) -> T): T`
// (03-identity-scim.md §"Deprovision.kt").
//
//  1. Takes a connection and begins a transaction.
//  2. Runs body, commits, returns its value.
//  3. Any error ⇒ rollback, and the error is returned unwrapped so callers can still match it with
//     errors.As — IsUniqueViolation is applied to exactly this error at four SCIM sites.
//
// Kotlin's step 4 ("finally restores autoCommit = true before the connection returns to the pool")
// has no Go analogue: pgx has no per-connection autocommit flag, the transaction state lives in the
// pgx.Tx, and pgxpool resets the connection on release. OMIT — a non-observable JVM artifact, per
// 03-identity-scim.md's own "Go shape" note.
//
// The Kotlin catches Exception, so a JVM Error would skip rollback and only hit the finally. The
// deferred Rollback here also fires on a panic, which is strictly safer and is the only sane
// behaviour for a pooled connection; recorded as a deliberate divergence.
func InTx[T any](ctx context.Context, db Beginner, body func(context.Context, pgx.Tx) (T, error)) (T, error) {
	var zero T
	tx, err := db.Begin(ctx)
	if err != nil {
		return zero, err
	}
	// Safe after a successful Commit: pgx documents Rollback on a closed Tx as returning ErrTxClosed
	// and nothing else, which is why `defer tx.Rollback` is its idiom.
	defer func() { _ = tx.Rollback(ctx) }()

	out, err := body(ctx, tx)
	if err != nil {
		return zero, err
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	return out, nil
}

// InTxDo is InTx for a body with no return value — the Kotlin's `inTx { … }` at type Unit. Go
// generics cannot infer T from a body that returns only an error, and `InTx[struct{}]` at every
// void call site is noise.
func InTxDo(ctx context.Context, db Beginner, body func(context.Context, pgx.Tx) error) error {
	_, err := InTx(ctx, db, func(ctx context.Context, tx pgx.Tx) (struct{}, error) {
		return struct{}{}, body(ctx, tx)
	})
	return err
}

// IsUniqueViolation reports whether err is a Postgres unique-violation. It is the port of
// `SQLException.isUniqueViolation()` (Users.kt:890), whose whole body is `sqlState == "23505"`.
//
// 03-identity-scim.md:878 — "Note 23503 (foreign-key violation) is NOT matched — see F29." That is
// REPRODUCE, not an oversight to fix. F29 (03-identity-scim.md:1476) records the consequence: a SCIM
// membership id that is non-numeric is silently dropped by toLongOrNull, while one that is numeric
// but nonexistent raises 23503, which this predicate does not match and which on POST is raised
// outside the try — two different wrong answers for one class of bad input. Adding a 23503 arm here
// would change an observable status code, so this package deliberately ships no such helper.
//
// F39 also records that the Kotlin has THREE copies of this SQLSTATE check (Users.kt:890,
// ManagementServices.kt:726 inside `unique(resource, name)`, ManagementServices.kt:505 inline in
// PolicyManagementService). The duplication is not observable, so A11 may call this one; that is the
// only part of F39 the port is allowed to collapse.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
