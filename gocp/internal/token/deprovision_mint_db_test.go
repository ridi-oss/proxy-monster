package token_test

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// ---------------------------------------------------------------------------------------------
// `DeprovisionDbTest.kt` case 8 — the TOCTOU half of INV-A3-7 / INV-A4-58, which the store's own
// TestMintForActivePrincipalLockedRefusesADeprovisionedPrincipal does NOT cover.
//
// That test deactivates FIRST and then mints, so it proves the check exists. The Kotlin case proves
// something strictly stronger and entirely different: the mint and the teardown SERIALIZE on the same
// per-principal advisory lock, so a mint already in flight when a deprovision commits still observes
// the deactivation. A single-shot "read active, then insert" passes the existing test and fails this
// one — it would read active=true from its own pre-teardown snapshot and hand out a credential that
// outlives the deprovisioning.
// ---------------------------------------------------------------------------------------------

// 🔒 TestMintForActivePrincipalLockedBlocksBehindAConcurrentTeardownAndThenRefuses is the port of
// `mintForActivePrincipalLocked refuses when a concurrent teardown deactivates first`.
//
// The Kotlin's three steps, in order:
//
//  1. sanity — an ACTIVE principal mints, and the token VALIDATES (not merely "a row appeared");
//  2. a second connection takes `pg_advisory_xact_lock(hashtext(principal))` and commits `active =
//     FALSE` while a mint is in flight. The mint must still be blocked after ~300 ms — asserted, since
//     that is the only observation that distinguishes "took the lock" from "raced ahead";
//  3. once the teardown commits and releases, the mint observes the committed deactivation and mints
//     NOTHING — nil, and no row.
//
// The lock is taken with the LITERAL expression rather than store.AdvisoryLockPrincipal so the test
// pins the KEY as well as the behaviour: a port that hashed client-side, or keyed on the id, would
// sail past a helper-based holder while deadlocking against the real Kotlin control plane mid-cutover.
// KT: DeprovisionDbTest.kt#mintForActivePrincipalLocked refuses when a concurrent teardown deactivates first
func TestMintForActivePrincipalLockedBlocksBehindAConcurrentTeardownAndThenRefuses(t *testing.T) {
	f := newFixture(t)
	users := identity.NewUserGroupStore(f.db.Pool)
	seed := dbtest.NewSeed(t, f.db)
	const principal = "mint-toctou@example.com"
	seed.User(principal)

	mint := func(ctx context.Context) (*token.Issued, error) {
		return token.MintForActivePrincipalLocked(ctx, f.db.Pool, users, principal,
			func(ctx context.Context, c store.Queryer) (token.Issued, error) {
				return f.store.Issue(ctx, c, token.KindUser, principal, nil, nil, oneDay)
			})
	}

	// ---- 1. sanity: an active principal mints, and the minted token validates.
	ok, err := mint(f.ctx)
	if err != nil {
		t.Fatalf("mint(active): %v", err)
	}
	if ok == nil {
		t.Fatal("an ACTIVE principal was refused a credential")
	}
	if id, err := f.store.Validate(f.ctx, ok.Token); err != nil || id == nil {
		t.Fatalf("the minted token does not validate: %v, %v", id, err)
	}

	// ---- 2. a concurrent teardown holds the principal's advisory lock and commits active=false.
	holder, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()
	if _, err := holder.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, principal); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}
	if _, err := holder.Exec(f.ctx,
		`UPDATE app_user SET active = FALSE WHERE principal = $1`, principal); err != nil {
		t.Fatalf("uncommitted deactivate: %v", err)
	}

	before := f.countTokens()
	type result struct {
		out *token.Issued
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := mint(context.Background())
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("the mint completed (%v, %v) while another transaction held the principal's advisory "+
			"lock — it did not block, so it can race ahead of a teardown", r.out, r.err)
	case <-time.After(300 * time.Millisecond):
		// Blocked, as required.
	}

	if err := holder.Commit(f.ctx); err != nil {
		t.Fatalf("commit the teardown: %v", err)
	}

	// ---- 3. having acquired the lock, the mint observes the COMMITTED deactivation and mints nothing.
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("mint after the lock was released: %v", r.err)
		}
		if r.out != nil {
			t.Fatalf("🔒 INV-A3-7 BROKEN: the locked mint issued %+v after a teardown committed "+
				"active=false — the credential outlives the deprovisioning", *r.out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the mint never completed after the lock was released")
	}
	if after := f.countTokens(); after != before {
		t.Errorf("token count went %d → %d; a refused mint must leave NO row", before, after)
	}
}
