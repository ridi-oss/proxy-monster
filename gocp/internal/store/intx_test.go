package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeTx implements just the two methods InTx drives. The embedded pgx.Tx is nil, so any other
// method would panic — which is the point: InTx must not touch anything else.
type fakeTx struct {
	pgx.Tx
	commits   int
	rollbacks int
	commitErr error
}

func (f *fakeTx) Commit(context.Context) error   { f.commits++; return f.commitErr }
func (f *fakeTx) Rollback(context.Context) error { f.rollbacks++; return nil }

type fakeBeginner struct {
	tx       *fakeTx
	beginErr error
	begins   int
}

func (f *fakeBeginner) Begin(context.Context) (pgx.Tx, error) {
	f.begins++
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return f.tx, nil
}

// Kotlin: `inTx` runs body, commits, returns its value.
func TestInTxCommitsOnSuccess(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}

	got, err := InTx(context.Background(), db, func(context.Context, pgx.Tx) (int, error) {
		return 42, nil
	})
	if err != nil {
		t.Fatalf("InTx: %v", err)
	}
	if got != 42 {
		t.Errorf("InTx returned %d, want the body's value 42", got)
	}
	if tx.commits != 1 {
		t.Errorf("commits = %d, want 1", tx.commits)
	}
	// The deferred Rollback still fires after a successful Commit. pgx documents that as returning
	// ErrTxClosed and nothing else, which is why `defer tx.Rollback` is its idiom.
	if tx.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1 (the no-op deferred rollback pgx documents as safe)", tx.rollbacks)
	}
}

// Kotlin: any exception ⇒ rollback(), rethrow.
func TestInTxRollsBackAndReturnsTheBodyError(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}
	boom := errors.New("boom")

	got, err := InTx(context.Background(), db, func(context.Context, pgx.Tx) (int, error) {
		return 7, boom
	})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the body's error", err)
	}
	if got != 0 {
		t.Errorf("InTx returned %d on failure, want the zero value", got)
	}
	if tx.commits != 0 {
		t.Errorf("commits = %d, want 0", tx.commits)
	}
	if tx.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1", tx.rollbacks)
	}
}

// The body's error is returned UNWRAPPED so callers can still classify it. IsUniqueViolation is
// applied to exactly this error at four SCIM sites (Scim.kt:380, 428, 503, 540), and wrapping it in
// a store-local error type would break every one of them.
func TestInTxPreservesSQLSTATEClassification(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}
	dup := &pgconn.PgError{Code: "23505"}

	err := InTxDo(context.Background(), db, func(context.Context, pgx.Tx) error { return dup })
	if !IsUniqueViolation(err) {
		t.Errorf("InTxDo lost the 23505 classification: %v", err)
	}
}

func TestInTxPropagatesCommitFailure(t *testing.T) {
	commitBoom := errors.New("commit failed")
	tx := &fakeTx{commitErr: commitBoom}
	db := &fakeBeginner{tx: tx}

	if _, err := InTx(context.Background(), db, func(context.Context, pgx.Tx) (int, error) {
		return 1, nil
	}); !errors.Is(err, commitBoom) {
		t.Errorf("err = %v, want the commit error", err)
	}
	if tx.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1 after a failed commit", tx.rollbacks)
	}
}

func TestInTxPropagatesBeginFailure(t *testing.T) {
	beginBoom := errors.New("pool exhausted")
	db := &fakeBeginner{beginErr: beginBoom}

	if _, err := InTx(context.Background(), db, func(context.Context, pgx.Tx) (int, error) {
		t.Error("body must not run when Begin fails")
		return 0, nil
	}); !errors.Is(err, beginBoom) {
		t.Errorf("err = %v, want the begin error", err)
	}
}

// Deliberate divergence, recorded rather than hidden: Kotlin's inTx catches Exception, so a JVM
// Error would skip rollback() and only hit the finally. Go's deferred rollback also fires on a
// panic. That is strictly safer and the only sane behaviour for a pooled connection — a panicking
// handler must not return a connection to the pool with an open transaction.
func TestInTxRollsBackOnPanic(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic must propagate, not be swallowed")
			}
		}()
		_, _ = InTx(context.Background(), db, func(context.Context, pgx.Tx) (int, error) {
			panic("handler blew up")
		})
	}()

	if tx.commits != 0 {
		t.Errorf("commits = %d, want 0", tx.commits)
	}
	if tx.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1", tx.rollbacks)
	}
}

func TestInTxDoReturnsNilOnSuccess(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}
	if err := InTxDo(context.Background(), db, func(context.Context, pgx.Tx) error { return nil }); err != nil {
		t.Fatalf("InTxDo: %v", err)
	}
	if tx.commits != 1 {
		t.Errorf("commits = %d, want 1", tx.commits)
	}
}
