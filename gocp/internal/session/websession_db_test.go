package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// Port of PrincipalSessionStoreDbTest.kt (498 LOC, 9 cases, DB) — 04-auth-session-tokens.md §4.3.
// ---------------------------------------------------------------------------------------------

// Case 1 — "web session lifecycle separates validation from idle touch without moving the absolute
// cap" (INV-A4-20, INV-A4-21, INV-A4-22).
//
// The walk is mint → resolve → first-touch → throttled-touch → backdated → slid → end, and the
// absolute cap is asserted byte-identical across the entire lifecycle.
//
// The Kotlin case brackets that walk with two things this test used to leave out, both of which are
// part of "the lifecycle": the SHAPE of a freshly minted WEB row (the four daemon-only columns are
// NULL and the refresh token is at rest as ciphertext) and the END (`endWeb` is a one-shot that flips
// liveness and stamps a reason). They are asserted at the two ends below.
// KT: PrincipalSessionStoreDbTest.kt#web session lifecycle separates validation from idle touch without moving the absolute cap
func TestWebSessionLifecycleSeparatesValidationFromIdleTouch(t *testing.T) {
	// A 5-second slide floor, so the throttle can be crossed by backdating rather than by sleeping.
	f := newFixture(t, fixtureOpts{IdleSeconds: 900, SlideSeconds: 5})
	id, err := f.store.MintWeb(f.ctx, nil, session.MintWebInput{
		Principal: principalA, AbsoluteSeconds: 7200, IdleSeconds: 900,
		DeviceID: ptr(deviceA), RefreshToken: ptr("refresh-secret"),
	})
	if err != nil {
		t.Fatalf("MintWeb: %v", err)
	}

	// 🔒 THE MINT SHAPE. One table holds both kinds, and a WEB row is defined as much by what it does
	// NOT carry as by what it does: no handle, no ttl_seconds and no renewal_token_hash, because those
	// three are what make a DAEMON row renewable by bearer secret. A mint that filled any of them would
	// hand a browser session a renewal path.
	var (
		kind        string
		handle      *string
		ttlSeconds  *int64
		renewalHash *string
		liveness    string
		refreshEnc  []byte
		deviceID    *string
		absOffset   float64
		idleOffset  float64
		lastSeen    *time.Time
	)
	if err := f.db.Pool.QueryRow(f.ctx, `
		SELECT kind, handle, ttl_seconds, renewal_token_hash, liveness_status, refresh_token_enc,
		       device_id,
		       extract(epoch from (absolute_expires_at - created_at)),
		       extract(epoch from (idle_expires_at - created_at)),
		       last_seen_at
		  FROM principal_session WHERE id = $1`, id,
	).Scan(&kind, &handle, &ttlSeconds, &renewalHash, &liveness, &refreshEnc, &deviceID,
		&absOffset, &idleOffset, &lastSeen); err != nil {
		t.Fatalf("read the minted row: %v", err)
	}
	if kind != session.KindWeb {
		t.Errorf("kind = %q, want WEB", kind)
	}
	if handle != nil || ttlSeconds != nil || renewalHash != nil {
		t.Errorf("a WEB row carries handle=%v ttl_seconds=%v renewal_token_hash=%v; all three are "+
			"DAEMON-only and filling any of them gives a browser session a renewal secret",
			handle, ttlSeconds, renewalHash)
	}
	if liveness != session.LivenessActive {
		t.Errorf("liveness_status = %q, want ACTIVE", liveness)
	}
	if deviceID == nil || *deviceID != deviceA {
		t.Errorf("device_id = %v, want the pm_did %q", deviceID, deviceA)
	}
	if lastSeen != nil {
		t.Errorf("last_seen_at = %v on a fresh mint; it is stamped by the first TouchWeb, not by mint", *lastSeen)
	}
	// The two deadlines are computed off the row's OWN created_at, so the arithmetic is checked
	// against the database clock rather than the process one.
	if absOffset < 7199 || absOffset > 7201 {
		t.Errorf("absolute_expires_at - created_at = %.3fs, want 7200", absOffset)
	}
	if idleOffset < 899 || idleOffset > 901 {
		t.Errorf("idle_expires_at - created_at = %.3fs, want 900", idleOffset)
	}
	// 🔒 INV-A4-14 — the IdP refresh token is at rest as CIPHERTEXT and decrypts back.
	if len(refreshEnc) == 0 {
		t.Fatal("refresh_token_enc is NULL despite a configured key")
	}
	if string(refreshEnc) == "refresh-secret" {
		t.Fatal("🔒 INV-A4-14 BROKEN: the WEB row's refresh token is at rest in PLAINTEXT")
	}
	if got, err := f.store.WebRefreshToken(f.ctx, id); err != nil || got == nil || *got != "refresh-secret" {
		t.Errorf("the stored refresh token decrypts to %v, %v; want \"refresh-secret\"", got, err)
	}

	minted := f.resolveWeb(id, ptr(deviceA))
	if minted == nil {
		t.Fatal("a just-minted session did not resolve")
	}
	// The resolved row identifies its OWN principal — the value every gate downstream authorizes as.
	// A resolve that returned the right clocks off the wrong row would pass every deadline assertion
	// below.
	if minted.Principal != principalA {
		t.Errorf("the resolved session's principal = %q, want %q", minted.Principal, principalA)
	}
	absolute, idle := minted.AbsoluteExpiresAt, minted.IdleExpiresAt

	// 🔒 INV-A4-20 — resolution NEVER extends idle. Repeated resolves leave both deadlines
	// byte-identical, and write nothing at all.
	for i := 0; i < 3; i++ {
		again := f.resolveWeb(id, ptr(deviceA))
		if again == nil {
			t.Fatal("a live session stopped resolving")
		}
		if !again.IdleExpiresAt.Equal(idle) {
			t.Fatalf("ResolveWeb moved idle_expires_at %v → %v; only TouchWeb may", idle, again.IdleExpiresAt)
		}
		if !again.AbsoluteExpiresAt.Equal(absolute) {
			t.Fatalf("ResolveWeb moved absolute_expires_at %v → %v", absolute, again.AbsoluteExpiresAt)
		}
	}
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT last_seen_at FROM principal_session WHERE id = $1`, id).Scan(&lastSeen); err != nil {
		t.Fatalf("read last_seen_at: %v", err)
	}
	if lastSeen != nil {
		t.Errorf("ResolveWeb stamped last_seen_at = %v; resolution writes NOTHING", *lastSeen)
	}

	// First touch: last_seen_at is NULL, so the throttle's `IS NULL` arm lets the slide through.
	firstTouch := f.touchWeb(id, ptr(deviceA))
	if firstTouch == nil {
		t.Fatal("the first TouchWeb did not resolve")
	}
	if !firstTouch.IdleExpiresAt.After(idle) {
		t.Errorf("the first touch did not extend idle: %v → %v", idle, firstTouch.IdleExpiresAt)
	}
	// 🔒 INV-A4-22 — the absolute cap is not in the SET list and can NEVER move.
	if !firstTouch.AbsoluteExpiresAt.Equal(absolute) {
		t.Errorf("🔒 INV-A4-22 BROKEN: TouchWeb moved absolute_expires_at %v → %v. Idle is a "+
			"convenience; absolute is the security bound.", absolute, firstTouch.AbsoluteExpiresAt)
	}
	slidIdle := firstTouch.IdleExpiresAt
	firstSeen := f.scalarInt64(`SELECT extract(epoch from last_seen_at)::bigint FROM principal_session WHERE id = $1`, id)

	// 🔒 INV-A4-21 — inside the slide floor the UPDATE matches zero rows, so BOTH the deadline and
	// last_seen_at are unchanged; the subsequent resolve still succeeds, so the caller sees success.
	throttled := f.touchWeb(id, ptr(deviceA))
	if throttled == nil {
		t.Fatal("a throttled touch must still return the (unmoved) session")
	}
	if !throttled.IdleExpiresAt.Equal(slidIdle) {
		t.Errorf("🔒 INV-A4-21 BROKEN: a touch inside the %ds slide floor moved idle %v → %v. The "+
			"throttle must live in the WHERE clause, not in Go.", 5, slidIdle, throttled.IdleExpiresAt)
	}
	if got := f.scalarInt64(`SELECT extract(epoch from last_seen_at)::bigint FROM principal_session WHERE id = $1`, id); got != firstSeen {
		t.Errorf("a throttled touch rewrote last_seen_at (%d → %d)", firstSeen, got)
	}

	// Backdate last_seen_at past the floor, and the next touch slides again.
	f.exec(`UPDATE principal_session SET last_seen_at = now() - interval '1 hour' WHERE id = $1`, id)
	slid := f.touchWeb(id, ptr(deviceA))
	if slid == nil {
		t.Fatal("a backdated touch did not resolve")
	}
	if !slid.IdleExpiresAt.After(slidIdle) {
		t.Errorf("a touch past the slide floor did not extend idle: %v → %v", slidIdle, slid.IdleExpiresAt)
	}
	if !slid.AbsoluteExpiresAt.Equal(absolute) {
		t.Errorf("the absolute cap moved across the whole lifecycle: %v → %v", absolute, slid.AbsoluteExpiresAt)
	}

	// 🔒 THE END OF THE LIFECYCLE. endWeb is a ONE-SHOT: it reports true once, the row stops resolving,
	// a repeat reports false (so a double logout is not a second state change), and the row is left with
	// ended_at, its reason, and liveness INACTIVE. Reporting true twice would make every idempotent
	// caller — the sweep, SCIM deactivate, /auth/logout — believe it ended something it did not.
	ended, err := f.store.EndWeb(f.ctx, nil, id, session.EndedSignedOut)
	if err != nil || !ended {
		t.Fatalf("EndWeb = %v, %v; want true", ended, err)
	}
	if f.resolveWeb(id, ptr(deviceA)) != nil {
		t.Error("an ENDED row still resolves")
	}
	if again, err := f.store.EndWeb(f.ctx, nil, id, session.EndedSignedOut); err != nil || again {
		t.Errorf("a repeat EndWeb = %v, %v; want false", again, err)
	}
	var endedAt *time.Time
	var endedReason *string
	var endedLiveness string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT ended_at, ended_reason, liveness_status FROM principal_session WHERE id = $1`, id,
	).Scan(&endedAt, &endedReason, &endedLiveness); err != nil {
		t.Fatalf("read the ended row: %v", err)
	}
	if endedAt == nil {
		t.Error("ended_at was not stamped")
	}
	if endedReason == nil || *endedReason != session.EndedSignedOut {
		t.Errorf("ended_reason = %v, want SIGNED_OUT", endedReason)
	}
	if endedLiveness != session.LivenessInactive {
		t.Errorf("liveness_status = %q after EndWeb, want INACTIVE", endedLiveness)
	}
}

// Case 2 — 🔒 "newest web session displaces only same-principal web siblings" (INV-A4-17).
// KT: PrincipalSessionStoreDbTest.kt#newest web session displaces only same-principal web siblings
func TestNewestWebSessionDisplacesOnlySameprincipalWebSiblings(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	old := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	otherPrincipal := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	// TWO DAEMON rows for the SAME principal, as the Kotlin seeds: newest-wins must not touch either,
	// and one row could be spared by an off-by-one `LIMIT`-shaped implementation while a second is not.
	daemonA := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	daemonB := f.createDaemon(principalA, ptr("handle-2"), nil, 3600, 600)

	fresh := f.mintWeb(principalA, ptr(deviceA), 7200, 900)

	if reason := f.rawEndedReason(old); reason == nil || *reason != session.EndedDisplaced {
		t.Errorf("the prior web session's ended_reason = %v, want DISPLACED", reason)
	}
	if got := f.livenessStatus(old); got != session.LivenessInactive {
		t.Errorf("a displaced row's liveness_status = %q, want INACTIVE", got)
	}
	// ...and it is a real revocation, not just a label: the displaced row stops resolving even from
	// the browser it was bound to. A mint that wrote the reason without stamping `ended_at` would pass
	// the two assertions above and leave the old cookie live.
	if row := f.resolveWeb(old, ptr(deviceA)); row != nil {
		t.Errorf("a DISPLACED row still resolves (%+v); newest-wins must revoke, not merely annotate", row)
	}
	// The new row must NOT have ended itself — that is what `id <> new` is for.
	if reason := f.rawEndedReason(fresh); reason != nil {
		t.Errorf("🔒 the mint ended ITSELF (reason %q); the displacement must exclude the new id", *reason)
	}
	survivor := f.resolveWeb(fresh, ptr(deviceA))
	if survivor == nil {
		t.Fatal("the freshly minted session does not resolve")
	}
	if survivor.Principal != principalA {
		t.Errorf("the surviving row resolves as %q, want %q", survivor.Principal, principalA)
	}
	// Another principal's web row is untouched — and still RESOLVES, which is the property a
	// principal-blind `UPDATE … WHERE kind='WEB'` would break.
	if reason := f.rawEndedReason(otherPrincipal); reason != nil {
		t.Errorf("another principal's web session was displaced (reason %q)", *reason)
	}
	bystander := f.resolveWeb(otherPrincipal, ptr(deviceB))
	if bystander == nil || bystander.Principal != principalB {
		t.Errorf("the bystander principal's session = %+v; %s's re-login must not end %s's",
			bystander, principalA, principalB)
	}
	// The sibling DAEMON rows are untouched — the scope is (principal, kind='WEB').
	for _, daemon := range []session.CreatedDaemon{daemonA, daemonB} {
		id := daemon.Row.ID
		if reason := f.rawEndedReason(id); reason != nil {
			t.Errorf("a sibling DAEMON row was displaced (reason %q); newest-wins is WEB-only", *reason)
		}
		if got := f.livenessStatus(id); got != session.LivenessActive {
			t.Errorf("a sibling DAEMON row's liveness went to %q on a web mint", got)
		}
		row, err := f.store.GetByID(f.ctx, id)
		if err != nil {
			t.Fatalf("GetByID(%d): %v", id, err)
		}
		if row == nil {
			t.Fatalf("the sibling DAEMON row %d disappeared on a web mint", id)
		}
		if !row.SessionExpiresAt.After(time.Now()) {
			t.Errorf("the sibling DAEMON row's window closed (absolute_expires_at = %v, now %v); a web "+
				"mint must not expire a daemon session", row.SessionExpiresAt, time.Now())
		}
	}
	// …and the principal is therefore STILL in-window, which is what pmon reads.
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || !within {
		t.Errorf("WithinWindow(%s) = %v, %v after a web re-login; the daemon window must survive it",
			principalA, within, err)
	}
	// The postcondition INV-A4-17 states.
	if n := f.liveWebRows(principalA); n != 1 {
		t.Errorf("%d live web rows for %s after a re-login, want exactly 1", n, principalA)
	}
}

// Case 3 — "the session-end seam invokes the editor-cleanup callback on every ending path"
// (INV-A4-18, INV-A4-23, INV-A4-30), plus INV-A4-23's "a no-op end fires nothing".
// KT: PrincipalSessionStoreDbTest.kt#the session-end seam invokes the editor-cleanup callback on every ending path
func TestSessionEndSeamFiresOnEveryEndingPath(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// Path 1 — displacement inside MintWeb (INV-A4-18).
	f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if len(f.ends) != 0 {
		t.Fatalf("the first mint displaced nothing but fired the seam %d times", len(f.ends))
	}
	second := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if len(f.ends) != 1 || f.ends[0].Principal != principalA {
		t.Fatalf("displacement did not fire the end seam exactly once: %+v", f.ends)
	}
	if !f.ends[0].InTx {
		t.Error("🔒 INV-A4-18 BROKEN: the displacement seam did not run on the mint's own transaction, " +
			"so a rolled-back mint would leave the cleanup committed")
	}

	// Path 2 — EndWeb.
	f.ends = nil
	ok, err := f.store.EndWeb(f.ctx, nil, second, session.EndedSignedOut)
	if err != nil || !ok {
		t.Fatalf("EndWeb = %v, %v; want true", ok, err)
	}
	if len(f.ends) != 1 {
		t.Fatalf("EndWeb fired the seam %d times, want 1", len(f.ends))
	}

	// 🔒 A NO-OP end fires NOTHING, and preserves the FIRST reason. A session ended DISPLACED must
	// not be relabelled SIGNED_OUT by a later logout, or INV-A4-3's UX inverts.
	f.ends = nil
	ok, err = f.store.EndWeb(f.ctx, nil, second, session.EndedDeactivated)
	if err != nil {
		t.Fatalf("repeat EndWeb: %v", err)
	}
	if ok {
		t.Error("a repeat end reported a transition; the `ended_at IS NULL` guard makes it idempotent")
	}
	if len(f.ends) != 0 {
		t.Errorf("a no-op end fired the seam %d times", len(f.ends))
	}
	if reason := f.rawEndedReason(second); reason == nil || *reason != session.EndedSignedOut {
		t.Errorf("the reason was relabelled to %v; first-reason-wins", reason)
	}

	// Path 3 — EndAllWebForPrincipal (INV-A4-30).
	f.ends = nil
	third := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	n, err := f.store.EndAllWebForPrincipal(f.ctx, nil, principalA, session.EndedDeactivated)
	if err != nil {
		t.Fatalf("EndAllWebForPrincipal: %v", err)
	}
	if n != 1 {
		t.Errorf("EndAllWebForPrincipal ended %d rows, want 1", n)
	}
	if len(f.ends) != 1 {
		t.Errorf("EndAllWebForPrincipal fired the seam %d times, want 1", len(f.ends))
	}
	if reason := f.rawEndedReason(third); reason == nil || *reason != session.EndedDeactivated {
		t.Errorf("EndAllWebForPrincipal wrote reason %v, want DEACTIVATED", reason)
	}
	// Bulk end with nothing live: 0 rows, no callback.
	f.ends = nil
	if n, err = f.store.EndAllWebForPrincipal(f.ctx, nil, principalA, session.EndedDeactivated); err != nil || n != 0 {
		t.Errorf("idempotent bulk end = %d, %v; want 0", n, err)
	}
	if len(f.ends) != 0 {
		t.Errorf("a bulk end that ended nothing fired the seam %d times", len(f.ends))
	}

	// Path 4 — EndWebBySessionKey, the logout path (INV-A4-7).
	f.ends = nil
	fourth := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if err := f.store.LinkWebSessionKey(f.ctx, fourth, "tracker-1"); err != nil {
		t.Fatalf("LinkWebSessionKey: %v", err)
	}
	ok, err = f.store.EndWebBySessionKey(f.ctx, "tracker-1", session.EndedSignedOut)
	if err != nil || !ok {
		t.Fatalf("EndWebBySessionKey = %v, %v; want true", ok, err)
	}
	if len(f.ends) != 1 {
		t.Errorf("EndWebBySessionKey fired the seam %d times, want 1", len(f.ends))
	}
}

// Case 4 — 🔒 "deprovision-composed cleanup rolls back with an aborted teardown transaction"
// (INV-A4-30). The regression test: abort the tx after the end, and assert the editor result AND the
// live session both survive.
// KT: PrincipalSessionStoreDbTest.kt#deprovision-composed cleanup rolls back with an aborted teardown transaction
func TestDeprovisionComposedCleanupRollsBackWithAnAbortedTeardown(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	id := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	f.exec(`INSERT INTO test_editor_result (principal) VALUES ($1)`, principalA)

	// A teardown transaction that bulk-ends the principal's web sessions and then ABORTS.
	tx, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin teardown: %v", err)
	}
	n, err := f.store.EndAllWebForPrincipal(f.ctx, tx, principalA, session.EndedDeactivated)
	if err != nil {
		t.Fatalf("EndAllWebForPrincipal(tx): %v", err)
	}
	if n != 1 {
		t.Fatalf("the teardown ended %d rows, want 1", n)
	}
	if len(f.ends) != 1 || !f.ends[0].InTx {
		t.Fatalf("the seam did not run on the caller's transaction: %+v", f.ends)
	}
	// Inside the transaction, both writes are visible.
	var remaining int64
	if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM test_editor_result WHERE principal = $1`, principalA).Scan(&remaining); err != nil {
		t.Fatalf("count inside tx: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("the cleanup did not run on the teardown's connection (%d rows still visible inside it)", remaining)
	}
	// ...and a later statement aborts the whole teardown.
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// 🔒 Both halves must be back. A cleanup committed on its own connection would have deleted the
	// editor result while the rollback kept the session alive — a session with no results, which is
	// the exact orphan INV-A4-30 exists to prevent.
	if got := f.scalarInt64(`SELECT count(*) FROM test_editor_result WHERE principal = $1`, principalA); got != 1 {
		t.Errorf("🔒 INV-A4-30 BROKEN: the editor result was deleted by an ABORTED teardown "+
			"(%d rows survive, want 1). The cleanup must compose onto the caller's connection.", got)
	}
	if f.resolveWeb(id, ptr(deviceA)) == nil {
		t.Error("the session did not survive the aborted teardown")
	}
	if n := f.liveWebRows(principalA); n != 1 {
		t.Errorf("%d live web rows after a rolled-back teardown, want 1", n)
	}

	// 🔒 THE OTHER HALF OF ATOMICITY, and the one that proves the rollback above was not a cleanup that
	// simply never ran: a COMMITTED teardown removes BOTH. Without this arm a seam wired to a no-op
	// would satisfy every assertion so far.
	f.ends = nil
	committed, err := f.db.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin the committed teardown: %v", err)
	}
	if n, err := f.store.EndAllWebForPrincipal(f.ctx, committed, principalA, session.EndedDeactivated); err != nil || n != 1 {
		t.Fatalf("EndAllWebForPrincipal(committed) = %d, %v; want 1", n, err)
	}
	if err := committed.Commit(f.ctx); err != nil {
		t.Fatalf("commit the teardown: %v", err)
	}
	if got := f.scalarInt64(`SELECT count(*) FROM test_editor_result WHERE principal = $1`, principalA); got != 0 {
		t.Errorf("a COMMITTED teardown left %d editor result(s); the composed cleanup must persist with it", got)
	}
	if n := f.liveWebRows(principalA); n != 0 {
		t.Errorf("%d live web rows after a committed teardown, want 0", n)
	}
	if len(f.ends) != 1 || !f.ends[0].InTx {
		t.Errorf("the committed teardown's seam calls = %+v, want exactly one on the caller's tx", f.ends)
	}
}

// Case 5 — 🔒 "device mismatch ends a live web row permanently without sliding idle" (INV-A4-19, all
// three sub-cases), and F35's absent-cookie sub-case in particular.
// KT: PrincipalSessionStoreDbTest.kt#device mismatch ends a live web row permanently without sliding idle
func TestDeviceMismatchEndsALiveWebRowPermanentlyWithoutSlidingIdle(t *testing.T) {
	cases := []struct {
		name      string
		stored    *string
		presented *string
	}{
		{"(a) a DIFFERENT pm_did", ptr(deviceA), ptr(deviceB)},
		// 🔒 F35 — the sub-case whose reason exists ONLY in Kotlin test comments: "a stolen
		// pm_session replayed without a pm_did is exactly what device-binding defends against, so an
		// absent device can never be treated as a wildcard match."
		{"(b) NO pm_did at all — an absent device is a MISMATCH, never a wildcard", ptr(deviceA), nil},
		{"(c) a NULL device_id in the database (a pre-binding legacy row)", nil, ptr(deviceA)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, fixtureOpts{})
			id := f.mintWeb(principalA, tc.stored, 7200, 900)

			// The row is LIVE going in, so the ending below is caused by the mismatch and not by the
			// fixture. (Sub-case (c) stores NULL, which is itself a mismatch, so only the two rows with
			// a stored device can be resolved first.)
			if tc.stored != nil {
				if row := f.resolveWeb(id, tc.stored); row == nil {
					t.Fatal("the freshly minted row did not resolve for its own device")
				}
			}
			// The idle deadline before the mismatch, read straight from the table so the assertion
			// does not depend on the resolve that is under test.
			idleBefore := f.scalarInt64(`SELECT extract(epoch from idle_expires_at)::bigint FROM principal_session WHERE id = $1`, id)

			if row, err := f.store.ResolveWeb(f.ctx, id, tc.presented); err != nil || row != nil {
				t.Fatalf("ResolveWeb = %v, %v; a device mismatch must resolve to nothing", row, err)
			}
			// TERMINAL: the row is ended with DEVICE_BIND_MISMATCH...
			reason := f.rawEndedReason(id)
			if reason == nil || *reason != session.EndedDeviceBindMismatch {
				t.Fatalf("🔒 INV-A4-19 BROKEN: ended_reason = %v, want DEVICE_BIND_MISMATCH. A mismatch "+
					"is not merely a rejection — it KILLS the session, which is what turns a silent "+
					"theft into a visible, self-reported event.", reason)
			}
			// ...and the liveness column follows, which is what the admin session list renders. A reason
			// stamped without flipping liveness leaves the row reading ACTIVE in the console.
			if got := f.livenessStatus(id); got != session.LivenessInactive {
				t.Errorf("liveness_status = %q after a device mismatch, want INACTIVE", got)
			}
			// ...so even the CORRECTLY-bound browser cannot resurrect it.
			if tc.stored != nil {
				if row, err := f.store.ResolveWeb(f.ctx, id, tc.stored); err != nil || row != nil {
					t.Errorf("the correctly-bound device resurrected an ended session: %v, %v", row, err)
				}
			}
			// And the mismatch did NOT slide idle.
			idleAfter := f.scalarInt64(`SELECT extract(epoch from idle_expires_at)::bigint FROM principal_session WHERE id = $1`, id)
			if idleAfter != idleBefore {
				t.Errorf("a device mismatch moved idle_expires_at (%d → %d)", idleBefore, idleAfter)
			}
			// The wire reason A1 reports is bind_mismatch, not expired.
			stored, err := f.store.WebEndedReason(f.ctx, id)
			if err != nil {
				t.Fatalf("WebEndedReason: %v", err)
			}
			if got := session.WireReason(stored); got != session.WireReasonBindMismatch {
				t.Errorf("WireReason = %q, want %q — the console must say \"this browser is not the "+
					"one that signed in\", not \"your session ran out\"", got, session.WireReasonBindMismatch)
			}
		})
	}
}

// Case 6 — 🔒 "resolve web requires both live clocks and excludes daemon rows" (INV-A4-13,
// INV-A4-20).
// KT: PrincipalSessionStoreDbTest.kt#resolve web requires both live clocks and excludes daemon rows
func TestResolveWebRequiresBothLiveClocksAndExcludesDaemonRows(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// 🔒 INV-A4-13 — a DAEMON row is not resolvable as a web session. Dropping the kind predicate
	// here would make one resolvable with a NULL device binding, i.e. INV-A4-19's wildcard hole.
	daemon := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	if row, err := f.store.ResolveWeb(f.ctx, daemon.Row.ID, ptr(deviceA)); err != nil || row != nil {
		t.Fatalf("🔒 INV-A4-13 BROKEN: a DAEMON row resolved as a web session (%v, %v)", row, err)
	}
	// ...and it was not ended by the attempt either: no row matched, so nothing was written.
	if reason := f.rawEndedReason(daemon.Row.ID); reason != nil {
		t.Errorf("a failed web resolve wrote ended_reason %q onto a daemon row", *reason)
	}

	const idleEpoch = `SELECT extract(epoch from idle_expires_at)::bigint FROM principal_session WHERE id = $1`

	// The idle clock alone can kill it.
	idleDead := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	f.exec(`UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, idleDead)
	idleDeadDeadline := f.scalarInt64(idleEpoch, idleDead)
	if row, err := f.store.ResolveWeb(f.ctx, idleDead, ptr(deviceA)); err != nil || row != nil {
		t.Errorf("a row past its IDLE deadline resolved (%v, %v)", row, err)
	}
	// 🔒 INV-A4-20 — an expired clock never slides back to life, and the failed resolve wrote nothing.
	if got := f.scalarInt64(idleEpoch, idleDead); got != idleDeadDeadline {
		t.Errorf("the failed resolve moved idle_expires_at (%d → %d); an EXPIRED idle clock must never "+
			"slide back to life", idleDeadDeadline, got)
	}
	if reason := f.rawEndedReason(idleDead); reason != nil {
		t.Errorf("a no-row resolve ended the row (reason %q); it must write NOTHING", *reason)
	}

	// The absolute clock alone can kill it, even with idle wide open.
	absDead := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	f.exec(`UPDATE principal_session
	           SET absolute_expires_at = now() - interval '1 second',
	               idle_expires_at = now() + interval '1 hour'
	         WHERE id = $1`, absDead)
	absDeadIdle := f.scalarInt64(idleEpoch, absDead)
	if row, err := f.store.ResolveWeb(f.ctx, absDead, ptr(deviceB)); err != nil || row != nil {
		t.Errorf("a row past its ABSOLUTE cap resolved with idle still open (%v, %v)", row, err)
	}
	// Its idle clock is wide open, so this is the arm where a resolve that slid FIRST and filtered
	// second would leave a visible trace.
	if got := f.scalarInt64(idleEpoch, absDead); got != absDeadIdle {
		t.Errorf("a resolve past the ABSOLUTE cap moved idle_expires_at (%d → %d); an expired absolute "+
			"clock must never slide idle", absDeadIdle, got)
	}
	// An ended row stays unresolvable.
	ended := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if _, err := f.store.EndWeb(f.ctx, nil, ended, session.EndedSignedOut); err != nil {
		t.Fatalf("EndWeb: %v", err)
	}
	if row, err := f.store.ResolveWeb(f.ctx, ended, ptr(deviceA)); err != nil || row != nil {
		t.Errorf("an ended row resolved (%v, %v)", row, err)
	}
}

// Case 7 — "web ended reason is returned only for web rows", including `assertNull(webEndedReason(-1))`.
// KT: PrincipalSessionStoreDbTest.kt#web ended reason is returned only for web rows
func TestWebEndedReasonIsReturnedOnlyForWebRows(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// A nonexistent id.
	if reason, err := f.store.WebEndedReason(f.ctx, -1); err != nil || reason != nil {
		t.Errorf("WebEndedReason(-1) = %v, %v; want nil", reason, err)
	}
	// A DAEMON row, even one that has been ended by hand: the `kind='WEB'` predicate hides it.
	daemon := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	f.exec(`UPDATE principal_session SET ended_at = now(), ended_reason = 'SIGNED_OUT' WHERE id = $1`, daemon.Row.ID)
	if reason, err := f.store.WebEndedReason(f.ctx, daemon.Row.ID); err != nil || reason != nil {
		t.Errorf("WebEndedReason returned %v for a DAEMON row; the reason surface is web-only", reason)
	}
	// A LIVE web row: ended_reason is NULL, so nil — which is what makes A1's "expired" fallback the
	// answer for a row that merely ran past a deadline (INV-A4-3).
	live := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	reason, err := f.store.WebEndedReason(f.ctx, live)
	if err != nil || reason != nil {
		t.Errorf("WebEndedReason on a live row = %v, %v; want nil", reason, err)
	}
	if got := session.WireReason(reason); got != session.WireReasonNone {
		t.Errorf("WireReason(nil) = %q, want %q", got, session.WireReasonNone)
	}
	// An ended web row returns its reason.
	if _, err := f.store.EndWeb(f.ctx, nil, live, session.EndedGroupRevoked); err != nil {
		t.Fatalf("EndWeb: %v", err)
	}
	reason, err = f.store.WebEndedReason(f.ctx, live)
	if err != nil || reason == nil || *reason != session.EndedGroupRevoked {
		t.Fatalf("WebEndedReason = %v, %v; want GROUP_REVOKED", reason, err)
	}
	// 🔒 INV-A4-3 — GROUP_REVOKED is NOT surfaced to the browser. It collapses to "expired", which is
	// what keeps the disclosure surface closed.
	if got := session.WireReason(reason); got != session.WireReasonExpired {
		t.Errorf("WireReason(GROUP_REVOKED) = %q, want %q — a port that leaks the stored reason to an "+
			"unauthenticated caller changes the disclosure surface", got, session.WireReasonExpired)
	}
}

// Case 8 — 🔒 "web mint waits for the principal lock and leaves exactly one active web row"
// (INV-A4-16, INV-A4-17). THE SINGLE MOST VALUABLE TEST IN THE AREA.
//
// It holds the principal advisory lock from another connection for ~2 s and then asserts the delayed
// mint's deadlines are FULL-DURATION MEASURED FROM COMPLETION. A `now()`-based implementation passes
// every other case in this file and fails only this one, because `now()` is frozen at the
// transaction's first statement — which is the lock acquisition, i.e. BEFORE the wait.
// KT: PrincipalSessionStoreDbTest.kt#web mint waits for the principal lock and leaves exactly one active web row
func TestWebMintWaitsForThePrincipalLockAndLeavesExactlyOneActiveWebRow(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	const (
		hold      = 2 * time.Second
		absolute  = int64(7200)
		idle      = int64(900)
		tolerance = 1500 * time.Millisecond
	)

	// 🔒 A PRIOR LIVE WEB ROW, so the "leaves exactly ONE active web row" half of the title has
	// something to be about. Without it the row count is 1 by construction and the assertion at the end
	// is vacuous: newest-wins displacement could be entirely broken and this case would still pass.
	// The Kotlin mints `serialized-first` before taking the lock for exactly this reason.
	first := f.mintWeb(principalA, ptr(deviceB), 7200, 900)

	release := f.holdPrincipalLock(principalA)

	type mintResult struct {
		id  int64
		err error
	}
	done := make(chan mintResult, 1)
	go func() {
		id, err := f.store.MintWeb(context.Background(), nil, session.MintWebInput{
			Principal:       principalA,
			AbsoluteSeconds: absolute,
			IdleSeconds:     idle,
			DeviceID:        ptr(deviceA),
		})
		done <- mintResult{id, err}
	}()

	// The mint must still be blocked on the lock.
	select {
	case r := <-done:
		release()
		t.Fatalf("MintWeb completed while the principal lock was held (id %d, err %v); the advisory "+
			"lock must be the FIRST statement", r.id, r.err)
	case <-time.After(hold):
	}
	release()

	var res mintResult
	select {
	case res = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("MintWeb never completed after the lock was released")
	}
	if res.err != nil {
		t.Fatalf("MintWeb: %v", res.err)
	}

	// 🔒 INV-A4-16 — the deadlines are measured from the clock read taken AFTER the wait. Compared
	// against the DATABASE's clock, never the process's, so this asserts nothing about CP/DB skew.
	var (
		created, absoluteAt, idleAt, dbNow time.Time
	)
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT created_at, absolute_expires_at, idle_expires_at, clock_timestamp()
		     FROM principal_session WHERE id = $1`, res.id).Scan(&created, &absoluteAt, &idleAt, &dbNow); err != nil {
		t.Fatalf("read the minted row: %v", err)
	}
	if !approxEqual(idleAt, dbNow.Add(time.Duration(idle)*time.Second), tolerance) {
		t.Errorf("🔒 INV-A4-16 BROKEN: idle_expires_at is %v, but a full %ds window from the mint's "+
			"completion (%v) would be %v. A now()-based implementation mints the deadline from BEFORE "+
			"the %v lock wait, so the session it just created 401s.",
			idleAt, idle, dbNow, dbNow.Add(time.Duration(idle)*time.Second), hold)
	}
	if !approxEqual(absoluteAt, dbNow.Add(time.Duration(absolute)*time.Second), tolerance) {
		t.Errorf("absolute_expires_at = %v, want ~%v (full duration from completion)",
			absoluteAt, dbNow.Add(time.Duration(absolute)*time.Second))
	}
	// One CTE reading shares the instant across all three columns, so the row is internally
	// consistent: both deadlines are exactly their window past created_at.
	if idleAt.Sub(created) != time.Duration(idle)*time.Second {
		t.Errorf("idle_expires_at - created_at = %v, want exactly %ds; the three timestamps must come "+
			"from ONE clock_timestamp() reading shared across all three columns", idleAt.Sub(created), idle)
	}
	if absoluteAt.Sub(created) != time.Duration(absolute)*time.Second {
		t.Errorf("absolute_expires_at - created_at = %v, want exactly %ds", absoluteAt.Sub(created), absolute)
	}
	// And it resolves — the failure a now()-based mint produces is a session that 401s immediately.
	if f.resolveWeb(res.id, ptr(deviceA)) == nil {
		t.Error("the session minted behind the lock does not resolve; its idle deadline was minted in the past")
	}
	// 🔒 INV-A4-17 — a mint that waited on the lock still displaces the sibling it found when it woke
	// up. A displacement computed BEFORE the wait (or skipped because the wait looked like a retry)
	// would leave two live rows for one principal.
	if reason := f.rawEndedReason(first); reason == nil || *reason != session.EndedDisplaced {
		t.Errorf("the pre-existing web row's ended_reason = %v, want DISPLACED; a lock-delayed mint must "+
			"still displace its sibling", reason)
	}
	if row := f.resolveWeb(first, ptr(deviceB)); row != nil {
		t.Errorf("the displaced row still resolves after a lock-delayed mint: %+v", row)
	}
	// 🔒 INV-A4-17's postcondition, asserted directly — and now non-vacuous, because two web rows
	// exist for this principal.
	if n := f.liveWebRows(principalA); n != 1 {
		t.Errorf("%d live web rows, want exactly 1", n)
	}
}

// Case 9 — 🔒 "web refresh token is omitted when encryption is unavailable" (INV-A4-14).
// KT: PrincipalSessionStoreDbTest.kt#web refresh token is omitted when encryption is unavailable
func TestWebRefreshTokenIsOmittedWhenEncryptionIsUnavailable(t *testing.T) {
	const secret = "idp-refresh-token"

	// With crypto: the ciphertext is stored, the plaintext is NOT, and the round trip works.
	withCrypto := newFixture(t, fixtureOpts{})
	id, err := withCrypto.store.MintWeb(withCrypto.ctx, nil, session.MintWebInput{
		Principal: principalA, RefreshToken: ptr(secret),
		AbsoluteSeconds: 7200, IdleSeconds: 900, DeviceID: ptr(deviceA),
	})
	if err != nil {
		t.Fatalf("MintWeb: %v", err)
	}
	var enc []byte
	if err := withCrypto.db.Pool.QueryRow(withCrypto.ctx,
		`SELECT refresh_token_enc FROM principal_session WHERE id = $1`, id).Scan(&enc); err != nil {
		t.Fatalf("read refresh_token_enc: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("the refresh token was not persisted at all despite a configured key")
	}
	if string(enc) == secret {
		t.Fatal("🔒 INV-A4-14 BROKEN: the refresh token is at rest in PLAINTEXT")
	}
	got, err := withCrypto.store.WebRefreshToken(withCrypto.ctx, id)
	if err != nil || got == nil || *got != secret {
		t.Fatalf("WebRefreshToken = %v, %v; want %q", got, err, secret)
	}

	// 🔒 INV-A4-24 — an ENDED row yields nothing, so a credential is never minted off an
	// authentication that was just invalidated.
	if _, err := withCrypto.store.EndWeb(withCrypto.ctx, nil, id, session.EndedIdpRejected); err != nil {
		t.Fatalf("EndWeb: %v", err)
	}
	if got, err = withCrypto.store.WebRefreshToken(withCrypto.ctx, id); err != nil || got != nil {
		t.Errorf("🔒 INV-A4-24 BROKEN: WebRefreshToken returned %v for an ENDED session", got)
	}

	// Without crypto: the token is DROPPED, not stored. The column stays NULL.
	noCrypto := newFixture(t, fixtureOpts{NoCrypto: true})
	id2, err := noCrypto.store.MintWeb(noCrypto.ctx, nil, session.MintWebInput{
		Principal: principalA, RefreshToken: ptr(secret),
		AbsoluteSeconds: 7200, IdleSeconds: 900, DeviceID: ptr(deviceA),
	})
	if err != nil {
		t.Fatalf("MintWeb(no crypto): %v", err)
	}
	var enc2 []byte
	if err := noCrypto.db.Pool.QueryRow(noCrypto.ctx,
		`SELECT refresh_token_enc FROM principal_session WHERE id = $1`, id2).Scan(&enc2); err != nil {
		t.Fatalf("read refresh_token_enc: %v", err)
	}
	if enc2 != nil {
		t.Errorf("🔒 INV-A4-14 BROKEN: with no PM_RESULT_KEY the column holds %d bytes. No key means "+
			"the token is DROPPED, never stored — not even in plaintext.", len(enc2))
	}
	// The session itself still works: silent renewal and the window are unaffected.
	if noCrypto.resolveWeb(id2, ptr(deviceA)) == nil {
		t.Error("a session minted without a result key does not resolve; only the refresh token is dropped")
	}
	if got, err = noCrypto.store.WebRefreshToken(noCrypto.ctx, id2); err != nil || got != nil {
		t.Errorf("WebRefreshToken with no crypto = %v, %v; want nil", got, err)
	}
}

// A seam that FAILS must abort the end-write rather than commit half of it. Kotlin's callback returns
// Unit and would have thrown out of the same `.use` block; Go's returns an error, so the divergence
// is asserted rather than assumed. See [session.EndSeam].
func TestAFailingEndSeamAbortsTheEndWrite(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	id := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	f.seamErr = errors.New("editor-result cleanup failed")

	err := store.InTxDo(f.ctx, f.db.Pool, func(ctx context.Context, tx pgx.Tx) error {
		_, err := f.store.EndWeb(ctx, tx, id, session.EndedSignedOut)
		return err
	})
	if err == nil {
		t.Fatal("a failing end seam did not surface an error")
	}
	// The end-write rolled back with it: the session is still live.
	if f.resolveWeb(id, ptr(deviceA)) == nil {
		t.Error("the session was ended even though its cleanup failed; the two must be atomic")
	}
}
