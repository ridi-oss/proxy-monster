package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// Port of RenewalWindowTest.kt (330 LOC, 12 cases, DB + route) — 04-auth-session-tokens.md §4.12.
//
// ⚠️ SCOPE. The Kotlin suite drives `POST /auth/session/renew` through testApplication. This file
// holds the nine STORE-level cases, against [session.RenewLocked] and its inputs.
//
// The TODO this note used to carry — cases 2, 3 and 4, the route's THREE distinct 401 codes
// (auth.missing_renewal_token / common.unauthenticated / auth.session_window_expired) — is
// DISCHARGED: `sessionRenewRoutes` is ported ([session.RenewRoutes], renewroutes.go) and
// renewroutes_db_test.go asserts all three, plus cases 1 and 5-10 re-run END TO END through the
// route over the real token store and the real identity teardown.
//
// The two files are not redundant. The store cases pin RenewLocked's own behaviour and stay
// meaningful if the route is rewritten; the route cases pin that the route CALLS it, with SESSION,
// an empty role snapshot, the row's TTL and the locked connection. Nine green store cases plus a
// route that forgot to call RenewLocked is a fleet renewing deprovisioned credentials.
//
// Cases 11 and 12 (the advisory-lock serialization) stay here only: they are already deterministic
// at this level, and re-running them over HTTP would add a goroutine and prove nothing new.
// ---------------------------------------------------------------------------------------------

// renewInputs is the pair RenewLocked takes. Split out so each case states only what it varies.
type renewInputs struct {
	deactivated map[string]bool
	minted      int
}

func (r *renewInputs) isDeactivated(_ context.Context, principal string, _ store.Queryer) (bool, error) {
	return r.deactivated[principal], nil
}

// mint stands in for `tokenStore.issue(SESSION, principal, emptyList(), name=null, ttl =
// fresh.ttlSeconds, c)`. It returns the TTL it was handed so the case can assert INV-A4-33 — the
// renewed token's TTL comes from the ROW, not from anything the caller supplied.
func (r *renewInputs) mint(_ context.Context, fresh session.DaemonRow, _ store.Queryer) (int64, error) {
	r.minted++
	return fresh.TTLSeconds, nil
}

// Case 1 — renew with the correct bearer secret inside the window mints a fresh token, and
// INV-A4-33: the TTL comes from the row.
// KT: RenewalWindowTest.kt#renew with the correct bearer secret inside the window mints a fresh token
func TestRenewInsideTheWindowMintsWithTheRowsTTL(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	created := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 777)

	row, err := f.store.GetByRenewalTokenHash(f.ctx, session.SHA256Hex(created.RenewalToken))
	if err != nil || row == nil {
		t.Fatalf("GetByRenewalTokenHash: %v, %v", row, err)
	}
	in := &renewInputs{}
	got, err := session.RenewLocked(f.ctx, f.store, *row, in.isDeactivated, in.mint)
	if err != nil {
		t.Fatalf("RenewLocked: %v", err)
	}
	if got == nil {
		t.Fatal("a renewal inside the window with the correct secret was refused")
	}
	if *got != 777 {
		t.Errorf("🔒 INV-A4-33 BROKEN: the renewed token's ttl = %d, want the ROW's 777. Renewal must "+
			"not lengthen a token beyond what pmon asked for at device-start.", *got)
	}
}

// Cases 5, 6, 7 — 🔒 renew is refused after the window closed (INV-A4-27, INV-A4-32), for a
// deprovisioned principal, and for a liveness-INACTIVE session — each "even with the correct secret"
// and "even inside the window".
func TestRenewIsRefusedOnEveryFailClosedCheck(t *testing.T) {
	t.Run("case 5: the window closed", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{})
		created := f.createDaemon(principalA, ptr("h"), nil, 3600, 600)
		f.exec(`UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = $1`, created.Row.ID)
		assertRefused(t, f, created, &renewInputs{})
	})
	t.Run("case 6: the principal is deprovisioned", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{})
		created := f.createDaemon(principalA, ptr("h"), nil, 3600, 600)
		assertRefused(t, f, created, &renewInputs{deactivated: map[string]bool{principalA: true}})
	})
	t.Run("case 7: liveness is INACTIVE", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{})
		created := f.createDaemon(principalA, ptr("h"), nil, 3600, 600)
		if err := f.store.MarkCheck(f.ctx, nil, created.Row.ID, session.LivenessInactive); err != nil {
			t.Fatalf("MarkCheck: %v", err)
		}
		assertRefused(t, f, created, &renewInputs{})
	})
	t.Run("the row vanished", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{})
		created := f.createDaemon(principalA, ptr("h"), nil, 3600, 600)
		f.exec(`DELETE FROM principal_session WHERE id = $1`, created.Row.ID)
		assertRefused(t, f, created, &renewInputs{})
	})
}

// assertRefused runs RenewLocked against a row the store has already invalidated somehow, using the
// PRE-INVALIDATION row value on purpose.
//
// 🔒 INV-A4-31 — the pre-lock row handed in by the route is ONLY an identifier carrier; none of its
// field values are trusted. Passing a stale row that still says ACTIVE and in-window is exactly what
// proves the re-read happens.
func assertRefused(t *testing.T, f *fixture, created session.CreatedDaemon, in *renewInputs) {
	t.Helper()
	got, err := session.RenewLocked(f.ctx, f.store, created.Row, in.isDeactivated, in.mint)
	if err != nil {
		t.Fatalf("RenewLocked: %v", err)
	}
	if got != nil {
		t.Fatalf("🔒 INV-A4-31 BROKEN: renewal succeeded (%v) against a stale row. Every fail-closed "+
			"check must be re-run UNDER THE LOCK against a FRESH read, never against the caller's "+
			"copy.", *got)
	}
	if in.minted != 0 {
		t.Errorf("the mint ran %d times on a refused renewal", in.minted)
	}
}

// Cases 8, 9 — 🔒 an authoritative principal deprovision refuses renewal on EVERY sibling session
// (INV-A4-29), and 🔒 a deprovision-then-reactivate cannot resurrect the old renewal secret because
// the WINDOW stays closed.
func TestDeprovisionRefusesEverySiblingAndSurvivesReactivation(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	one := f.createDaemon(principalA, ptr("h-1"), nil, 3600, 600)
	two := f.createDaemon(principalA, ptr("h-2"), nil, 3600, 600)

	if _, err := f.store.DeactivateAllForPrincipal(f.ctx, nil, principalA); err != nil {
		t.Fatalf("DeactivateAllForPrincipal: %v", err)
	}
	// Case 8 — EVERY sibling is refused, not only the one the sweep happened to look at. Otherwise
	// the untouched siblings' renewal secrets keep minting fresh tokens.
	for i, created := range []session.CreatedDaemon{one, two} {
		in := &renewInputs{}
		got, err := session.RenewLocked(f.ctx, f.store, created.Row, in.isDeactivated, in.mint)
		if err != nil {
			t.Fatalf("RenewLocked(sibling %d): %v", i, err)
		}
		if got != nil {
			t.Errorf("🔒 INV-A4-29 BROKEN: sibling session %d still renews after a principal "+
				"deprovision (ttl %d)", i, *got)
		}
	}

	// Case 9 — a later REACTIVATION (liveness back to ACTIVE) does not resurrect it, because the
	// deprovision also dropped absolute_expires_at to now(): the WINDOW check fails independently of
	// the liveness check. That is what makes the deprovision durable rather than merely paused.
	if err := f.store.MarkCheck(f.ctx, nil, one.Row.ID, session.LivenessActive); err != nil {
		t.Fatalf("MarkCheck(reactivate): %v", err)
	}
	if status := f.livenessStatus(one.Row.ID); status != session.LivenessActive {
		t.Fatalf("setup: reactivation did not take (status %q)", status)
	}
	in := &renewInputs{}
	got, err := session.RenewLocked(f.ctx, f.store, one.Row, in.isDeactivated, in.mint)
	if err != nil {
		t.Fatalf("RenewLocked after reactivation: %v", err)
	}
	if got != nil {
		t.Errorf("🔒 INV-A4-29 BROKEN: a reactivated principal's OLD renewal secret minted a token "+
			"(ttl %d). Dropping absolute_expires_at to now() is what makes the deprovision durable.", *got)
	}
}

// Cases 10, 11, 12 — 🔒 the serialization properties. Renewal takes the SAME per-principal advisory
// lock every teardown path takes, so a renew blocks behind a concurrent holder and then observes its
// COMMITTED state (INV-A4-31).
//
// The Kotlin's case 10 ("renew mints under the lock, so an immediately-following teardown sweeps up
// the just-minted token") and case 12 ("revokeActiveCredentials itself blocks behind a concurrent
// holder of the SAME principal's advisory lock") are both statements about that one lock. Case 12 is
// A3's `revokeActiveCredentials`, which is not ported; what IS asserted here is the half this package
// owns — that RenewLocked genuinely serializes on it, and that a teardown committed during the wait
// is what the fresh read sees.
//
// ⚠️ The note above is now out of date on ONE point: `revokeActiveCredentials` IS ported
// (internal/identity.Credentials), so case 12 has its own test —
// TestRevokeActiveCredentialsBlocksBehindTheSamePrincipalLock in renewroutes_db_test.go, which is
// where the real teardown is already wired.
// KT: RenewalWindowTest.kt#a renew blocks behind a concurrent holder of the SAME principal's advisory lock, then observes its committed state
func TestRenewBlocksBehindTheSamePrincipalLockAndObservesCommittedState(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	created := f.createDaemon(principalA, ptr("h-1"), nil, 3600, 600)

	// A concurrent holder of the SAME lock, which then deprovisions the principal and commits.
	tx, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin teardown: %v", err)
	}
	if err := store.AdvisoryLockPrincipal(f.ctx, tx, principalA); err != nil {
		t.Fatalf("take the lock: %v", err)
	}

	in := &renewInputs{}
	type result struct {
		ttl *int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		got, err := session.RenewLocked(context.Background(), f.store, created.Row, in.isDeactivated, in.mint)
		done <- result{got, err}
	}()

	// The renew must be BLOCKED — the lock is taken before the re-read, so it cannot have seen
	// anything yet.
	select {
	case r := <-done:
		_ = tx.Rollback(f.ctx)
		t.Fatalf("🔒 INV-A4-31 BROKEN: RenewLocked completed (%v, %v) while another connection held "+
			"the principal's advisory lock. Authoritative deprovisioning takes the SAME lock; without "+
			"the wait a teardown can slip between the check and the mint.", r.ttl, r.err)
	case <-time.After(1500 * time.Millisecond):
	}

	// The teardown closes the window and COMMITS, releasing the lock.
	if _, err := f.store.DeactivateAllForPrincipal(f.ctx, tx, principalA); err != nil {
		_ = tx.Rollback(f.ctx)
		t.Fatalf("DeactivateAllForPrincipal(tx): %v", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatalf("commit teardown: %v", err)
	}

	var r result
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("RenewLocked never completed after the lock was released")
	}
	if r.err != nil {
		t.Fatalf("RenewLocked: %v", r.err)
	}
	// It observed the teardown's COMMITTED state, not the state it started from.
	if r.ttl != nil {
		t.Errorf("🔒 INV-A4-31 BROKEN: the renew minted (ttl %d) after waiting out a teardown that "+
			"committed during the wait. The re-read under the lock is what makes the ordering "+
			"total: the teardown either commits BEFORE the re-read (this case) or tears down AFTER "+
			"the renew commits.", *r.ttl)
	}
	if in.minted != 0 {
		t.Errorf("the mint ran %d times behind a committed teardown", in.minted)
	}
}

// 🔒 INV-A4-32 — withinWindowOn uses clock_timestamp(), not now(), and the reason is the lock wait.
//
// This is the mirror image of INV-A4-16 and it is INVISIBLE to any test that does not hold the lock:
// a window that expires DURING the wait must read as closed. With `now()` — frozen at the enclosing
// transaction's first statement, which is the lock acquisition — it would still read as open.
func TestRenewSeesAWindowThatExpiredDuringTheLockWait(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// A window that closes ~1s from now, well inside the lock hold below.
	created := f.createDaemon(principalA, ptr("h-1"), nil, 1, 600)
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || !within {
		t.Fatalf("setup: the window is not open (%v, %v)", within, err)
	}

	release := f.holdPrincipalLock(principalA)
	in := &renewInputs{}
	done := make(chan *int64, 1)
	go func() {
		got, err := session.RenewLocked(context.Background(), f.store, created.Row, in.isDeactivated, in.mint)
		if err != nil {
			t.Errorf("RenewLocked: %v", err)
		}
		done <- got
	}()
	// Hold past the window's expiry, so the renewal's transaction STARTED while the window was open
	// and the lock is released after it closed.
	time.Sleep(2500 * time.Millisecond)
	release()

	select {
	case got := <-done:
		if got != nil {
			t.Errorf("🔒 INV-A4-32 BROKEN: a renewal minted (ttl %d) against a window that expired "+
				"DURING its lock wait. `now()` is frozen at the transaction's first statement — the "+
				"lock acquisition — so it reflects a moment BEFORE the wait. Use clock_timestamp().", *got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("RenewLocked never completed")
	}
}
