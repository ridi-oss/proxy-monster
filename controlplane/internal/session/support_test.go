package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// The DB-backed support for A4's session suites. It leans on internal/dbtest for the shared
// container and the fresh migrated database; what lives here is only what these suites need on top.
//
// The Kotlin suites share one database per class through @BeforeAll. internal/dbtest hands out a
// fresh migrated database per call and Go has no PER_CLASS lifecycle, so each case builds its own.
// That is a divergence in fixture LIFETIME, not in what is asserted, and it is strictly stronger:
// no case can pass because a sibling left the table in a convenient state.

const (
	principalA = "alice@example.com"
	principalB = "bob@example.com"
	deviceA    = "device-a"
	deviceB    = "device-b"
)

// testKey is the fixed 32-byte AES key ResultCryptoTest uses, so a ciphertext produced here is
// comparable with A7's suites.
var testKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}()

// endCall is one invocation of the end seam.
type endCall struct {
	Principal string
	// InTx records whether the callback ran on a pgx.Tx (the caller's transaction) rather than on a
	// pooled autocommit connection. INV-A4-30's whole point is that a caller-supplied handle is used
	// unchanged, so the test can observe it.
	InTx bool
}

type fixture struct {
	t     testing.TB
	ctx   context.Context
	db    *store.Db
	store *session.Store

	// ends records every end-seam invocation, in order.
	ends []endCall
	// seamErr, when non-nil, is returned by the seam — for asserting that a failed cleanup aborts
	// the end-write rather than committing half of it.
	seamErr error
}

type fixtureOpts struct {
	// NoCrypto builds the store with a nil Crypto — INV-A4-14's "no key means no persistence".
	NoCrypto bool
	// IdleSeconds / SlideSeconds override the constructor defaults (900 / 120). A suite that wants
	// to observe the slide throttle needs a slide floor it can cross without sleeping for two
	// minutes.
	IdleSeconds  int64
	SlideSeconds int64
	// NoSeam omits the end callback entirely, which is the shipped default until A1 wires A7's two
	// cleanups into it.
	NoSeam bool
}

func newFixture(t testing.TB, opts fixtureOpts) *fixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	f := &fixture{t: t, ctx: context.Background(), db: db}

	// The stand-in for A7's `query_result` editor rows. A7's QueryResultStore is ported but its
	// `deleteEditorResultsForPrincipal` is not, and `query_result` needs an `access_request` parent
	// row per insert — which would put A6/A7 fixture setup in the middle of an A4 assertion. A
	// one-column table exercises the ONE property these cases are about: whether the cleanup write
	// composes into, and rolls back with, the end-write's transaction.
	//
	//	TODO(A7): re-point the seam at queryResultStore.deleteEditorResultsForPrincipal and delete
	//	          this table. A fixture with its own notion of "editor result" is a second definition.
	if _, err := db.Pool.Exec(f.ctx, `CREATE TABLE test_editor_result (principal TEXT NOT NULL)`); err != nil {
		t.Fatalf("create test_editor_result: %v", err)
	}

	var crypto session.Crypto
	if !opts.NoCrypto {
		c, err := result.NewCrypto(testKey)
		if err != nil {
			t.Fatalf("result.NewCrypto: %v", err)
		}
		crypto = c
	}
	storeOpts := session.Options{
		Crypto:                 crypto,
		WebSessionIdleSeconds:  opts.IdleSeconds,
		WebSessionSlideSeconds: opts.SlideSeconds,
	}
	if !opts.NoSeam {
		storeOpts.OnWebSessionEnded = func(ctx context.Context, principal string, c store.Queryer) error {
			_, isTx := c.(pgx.Tx)
			f.ends = append(f.ends, endCall{Principal: principal, InTx: isTx})
			if f.seamErr != nil {
				return f.seamErr
			}
			// The cleanup A1 wires here: drop the principal's saved editor results, ON THE HANDLE THE
			// END-WRITE USED. Running it on f.db.Pool instead would commit independently and defeat
			// INV-A4-30 — which is exactly what TestDeprovisionComposedCleanupRollsBack proves.
			_, err := c.Exec(ctx, `DELETE FROM test_editor_result WHERE principal = $1`, principal)
			return err
		}
	}
	f.store = session.NewStore(db.Pool, storeOpts)
	return f
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (f *fixture) scalarInt64(sql string, args ...any) int64 {
	f.t.Helper()
	var out int64
	if err := f.db.Pool.QueryRow(f.ctx, sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("scalar %q: %v", sql, err)
	}
	return out
}

// mintWeb is MintWeb with the error fataled and the two common optionals defaulted.
func (f *fixture) mintWeb(principal string, deviceID *string, absolute, idle int64) int64 {
	f.t.Helper()
	id, err := f.store.MintWeb(f.ctx, nil, session.MintWebInput{
		Principal:       principal,
		AbsoluteSeconds: absolute,
		IdleSeconds:     idle,
		DeviceID:        deviceID,
	})
	if err != nil {
		f.t.Fatalf("MintWeb(%s): %v", principal, err)
	}
	return id
}

func (f *fixture) resolveWeb(id int64, deviceID *string) *session.WebRow {
	f.t.Helper()
	row, err := f.store.ResolveWeb(f.ctx, id, deviceID)
	if err != nil {
		f.t.Fatalf("ResolveWeb(%d): %v", id, err)
	}
	return row
}

func (f *fixture) touchWeb(id int64, deviceID *string) *session.WebRow {
	f.t.Helper()
	row, err := f.store.TouchWeb(f.ctx, id, deviceID)
	if err != nil {
		f.t.Fatalf("TouchWeb(%d): %v", id, err)
	}
	return row
}

// createDaemon is Create with the error fataled.
func (f *fixture) createDaemon(principal string, handle, refreshToken *string, window float64, ttl int64) session.CreatedDaemon {
	f.t.Helper()
	out, err := f.store.Create(f.ctx, nil, principal, handle, refreshToken, window, ttl)
	if err != nil {
		f.t.Fatalf("Create(%s): %v", principal, err)
	}
	return out
}

// endedReason reads `ended_reason` straight from the table, for rows [session.Store.WebEndedReason]
// deliberately hides (daemon rows).
func (f *fixture) rawEndedReason(id int64) *string {
	f.t.Helper()
	var reason *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT ended_reason FROM principal_session WHERE id = $1`, id).Scan(&reason); err != nil {
		f.t.Fatalf("read ended_reason(%d): %v", id, err)
	}
	return reason
}

func (f *fixture) livenessStatus(id int64) string {
	f.t.Helper()
	var status string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT liveness_status FROM principal_session WHERE id = $1`, id).Scan(&status); err != nil {
		f.t.Fatalf("read liveness_status(%d): %v", id, err)
	}
	return status
}

// liveWebRows counts the principal's live web rows — INV-A4-17's postcondition.
func (f *fixture) liveWebRows(principal string) int64 {
	f.t.Helper()
	return f.scalarInt64(
		`SELECT count(*) FROM principal_session WHERE principal = $1 AND kind = 'WEB' AND ended_at IS NULL`,
		principal)
}

// holdPrincipalLock takes the SAME advisory lock MintWeb and RenewLocked take, from an independent
// connection, and holds it until the returned release func is called.
//
// 🔒 It uses the literal `pg_advisory_xact_lock(hashtext(<principal>))` expression rather than
// store.AdvisoryLockPrincipal, so the test pins the KEY as well as the behaviour: a port that hashed
// in-process and passed an integer would not serialize against this (INV-A3-4).
func (f *fixture) holdPrincipalLock(principal string) (release func()) {
	f.t.Helper()
	tx, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		f.t.Fatalf("begin lock holder: %v", err)
	}
	if _, err := tx.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, principal); err != nil {
		_ = tx.Rollback(f.ctx)
		f.t.Fatalf("take advisory lock: %v", err)
	}
	return func() { _ = tx.Rollback(f.ctx) }
}

func ptr[T any](v T) *T { return &v }

// approxEqual reports whether two instants are within tolerance — for deadline assertions that must
// tolerate the statement's own execution time but not a whole missing window.
func approxEqual(a, b time.Time, tolerance time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= tolerance
}
