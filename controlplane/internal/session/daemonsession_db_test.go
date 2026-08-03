package session_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
)

// ---------------------------------------------------------------------------------------------
// Port of DaemonSessionStoreDbTest.kt (346 LOC, 17 cases, DB) — 04-auth-session-tokens.md §4.1.
//
// Cases are grouped where the Kotlin's assertions overlap; every one of the 17 named behaviours is
// asserted, and the case number is cited on each block.
// ---------------------------------------------------------------------------------------------

// Cases 1-3 — create round-trips, encrypts the refresh token at rest (INV-A4-14), never persists it
// without a key, and round-trips a nil token as NULL (a device flow without offline_access).
func TestDaemonCreateRoundTripsAndEncryptsAtRest(t *testing.T) {
	const secret = "idp-refresh"

	// Case 1 — with crypto.
	f := newFixture(t, fixtureOpts{})
	created := f.createDaemon(principalA, ptr("handle-1"), ptr(secret), 3600, 600)

	if created.RenewalToken == "" {
		t.Fatal("Create returned no renewal token; the plaintext pmr_ secret is visible ONLY here")
	}
	if len(created.RenewalToken) != len(session.RenewalTokenPrefix)+43 {
		t.Errorf("renewal token %q is not pmr_ + base64url-nopad(32 bytes)", created.RenewalToken)
	}
	row := created.Row
	if row.Principal != principalA || row.Handle == nil || *row.Handle != "handle-1" {
		t.Errorf("Create read back %+v, want principal %s / handle handle-1", row, principalA)
	}
	if row.TTLSeconds != 600 {
		t.Errorf("ttl_seconds = %d, want 600 — the wire SESSION token TTL pmon asked for", row.TTLSeconds)
	}
	if row.LivenessStatus != session.LivenessActive {
		t.Errorf("liveness_status = %q, want ACTIVE", row.LivenessStatus)
	}
	// 🔒 INV-A4-14 — ciphertext at rest, never the plaintext.
	if len(row.RefreshTokenEnc) == 0 {
		t.Fatal("the refresh token was not persisted despite a configured key")
	}
	if string(row.RefreshTokenEnc) == secret {
		t.Fatal("🔒 INV-A4-14 BROKEN: the refresh token is at rest in PLAINTEXT")
	}
	got, err := f.store.DecryptRefreshRow(row)
	if err != nil || got == nil || *got != secret {
		t.Fatalf("DecryptRefresh = %v, %v; want %q", got, err, secret)
	}
	// 🔒 The renewal secret is stored ONLY as its hash — never in plaintext, and the hash is
	// computed in-process (never by a SQL digest() call, which would put the secret into
	// pg_stat_statements).
	var storedHash *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT renewal_token_hash FROM principal_session WHERE id = $1`, row.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read renewal_token_hash: %v", err)
	}
	if storedHash == nil || *storedHash != session.SHA256Hex(created.RenewalToken) {
		t.Fatalf("renewal_token_hash = %v, want sha256hex of the plaintext secret", storedHash)
	}
	if *storedHash == created.RenewalToken {
		t.Fatal("the renewal secret is at rest in PLAINTEXT")
	}
	// A daemon row has NO idle deadline and NO device binding — the shape half of INV-A4-13.
	var idle, device *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT idle_expires_at::text, device_id FROM principal_session WHERE id = $1`, row.ID).Scan(&idle, &device); err != nil {
		t.Fatalf("read daemon shape: %v", err)
	}
	if idle != nil || device != nil {
		t.Errorf("a DAEMON row carries idle_expires_at=%v device_id=%v; both must be NULL", idle, device)
	}

	// Case 2 — 🔒 no crypto configured means the refresh token is never persisted, not even plaintext.
	noCrypto := newFixture(t, fixtureOpts{NoCrypto: true})
	dropped := noCrypto.createDaemon(principalA, ptr("handle-2"), ptr(secret), 3600, 600)
	if dropped.Row.RefreshTokenEnc != nil {
		t.Errorf("🔒 INV-A4-14 BROKEN: with no key the column holds %d bytes; the token must be "+
			"DROPPED, not stored", len(dropped.Row.RefreshTokenEnc))
	}
	// The session and its window still work — the degradation is confined to the liveness recheck.
	if within, err := noCrypto.store.WithinWindow(noCrypto.ctx, principalA); err != nil || !within {
		t.Errorf("WithinWindow = %v, %v after a keyless create; the window is unaffected", within, err)
	}

	// Case 3 — no refresh token at all round-trips as nil.
	none := f.createDaemon(principalB, ptr("handle-3"), nil, 3600, 600)
	if none.Row.RefreshTokenEnc != nil {
		t.Errorf("a create with no refresh token stored %d bytes", len(none.Row.RefreshTokenEnc))
	}
	if got, err := f.store.DecryptRefreshRow(none.Row); err != nil || got != nil {
		t.Errorf("DecryptRefresh over a NULL blob = %v, %v; want nil", got, err)
	}
}

// Cases 4, 5, 13 — getByHandle finds the exact session; getByPrincipal returns the MOST RECENT;
// 🔒 getByRenewalTokenHash resolves by the hashed bearer secret and by nothing else (INV-A4-26).
func TestDaemonLookups(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	first := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	second := f.createDaemon(principalA, ptr("handle-2"), nil, 3600, 900)
	otherPrincipal := f.createDaemon(principalB, ptr("handle-3"), nil, 3600, 600)

	// Case 4.
	got, err := f.store.GetByHandle(f.ctx, "handle-1")
	if err != nil || got == nil || got.ID != first.Row.ID {
		t.Fatalf("GetByHandle(handle-1) = %v, %v; want row %d", got, err, first.Row.ID)
	}
	if got, err = f.store.GetByHandle(f.ctx, "nope"); err != nil || got != nil {
		t.Errorf("GetByHandle(nope) = %v, %v; want nil", got, err)
	}

	// Case 5 — "a principal may be logged in from more than one daemon", so this is the most recent.
	if got, err = f.store.GetByPrincipal(f.ctx, principalA); err != nil || got == nil || got.ID != second.Row.ID {
		t.Fatalf("GetByPrincipal = %v, %v; want the MOST RECENT row %d", got, err, second.Row.ID)
	}
	if got, err = f.store.GetByPrincipal(f.ctx, "nobody@example.com"); err != nil || got != nil {
		t.Errorf("GetByPrincipal(nobody) = %v, %v; want nil", got, err)
	}

	// Case 13 — 🔒 INV-A4-26. "Never look this up by a caller-supplied principal/handle; that was the
	// unauthenticated-renewal flaw."
	hash := session.SHA256Hex(first.RenewalToken)
	if got, err = f.store.GetByRenewalTokenHash(f.ctx, hash); err != nil || got == nil || got.ID != first.Row.ID {
		t.Fatalf("GetByRenewalTokenHash = %v, %v; want row %d", got, err, first.Row.ID)
	}
	// A wrong hash finds nothing — including the RAW secret, which must never match the column.
	for _, wrong := range []string{session.SHA256Hex("pmr_wrong"), first.RenewalToken, "", "deadbeef"} {
		if got, err = f.store.GetByRenewalTokenHash(f.ctx, wrong); err != nil || got != nil {
			t.Errorf("GetByRenewalTokenHash(%q) resolved to %v; only the SHA-256 of the real secret may", wrong, got)
		}
	}
	_ = otherPrincipal
}

// Cases 6, 7, 17 — withinWindow is true right after create and false once the window has passed
// (INV-A4-27); 🔒 false, fail-closed, for a principal with no session at all; 🔒 and it ignores a
// still-open WEB row once the daemon window has closed (INV-A4-13).
func TestWithinWindow(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// Case 7 — NO ROW ⇒ false. Fail-closed.
	if within, err := f.store.WithinWindow(f.ctx, "nobody@example.com"); err != nil || within {
		t.Errorf("🔒 WithinWindow for a principal with no session = %v, %v; want false (fail-closed)", within, err)
	}

	// Case 6.
	created := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || !within {
		t.Fatalf("WithinWindow right after create = %v, %v; want true", within, err)
	}
	f.exec(`UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = $1`, created.Row.ID)
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || within {
		t.Fatalf("WithinWindow after the window passed = %v, %v; want false", within, err)
	}

	// Case 17 — 🔒 INV-A4-13. A still-open WEB row must not keep a closed daemon window alive.
	f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || within {
		t.Errorf("🔒 INV-A4-13 BROKEN: a live WEB row made the closed DAEMON renewal window read as "+
			"open (%v, %v). Dropping the kind predicate here revives every expired daemon login.", within, err)
	}
}

// Cases 8, 9 — markCheck stamps last_idp_check_at and the liveness status, and 🔒 its connection
// overload preserves an ENDED row's status (INV-A4-28).
func TestMarkCheckStampsWithoutResurrectingAnEndedRow(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// Case 8 — a live daemon row.
	created := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	if err := f.store.MarkCheck(f.ctx, nil, created.Row.ID, session.LivenessInactive); err != nil {
		t.Fatalf("MarkCheck: %v", err)
	}
	got, err := f.store.GetByID(f.ctx, created.Row.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID: %v, %v", got, err)
	}
	if got.LastIdpCheckAt == nil {
		t.Error("MarkCheck did not stamp last_idp_check_at")
	}
	if got.LivenessStatus != session.LivenessInactive {
		t.Errorf("liveness_status = %q, want INACTIVE", got.LivenessStatus)
	}

	// Case 9 — 🔒 INV-A4-28. The sweep's Active branch calls MarkCheck(ACTIVE) AFTER possibly having
	// ended every web session for a zero-role principal. Without the CASE guard that write flips the
	// just-ended row back to ACTIVE.
	web := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if _, err := f.store.EndWeb(f.ctx, nil, web, session.EndedGroupRevoked); err != nil {
		t.Fatalf("EndWeb: %v", err)
	}
	if err := f.store.MarkCheck(f.ctx, nil, web, session.LivenessActive); err != nil {
		t.Fatalf("MarkCheck(ended row): %v", err)
	}
	if status := f.livenessStatus(web); status != session.LivenessInactive {
		t.Errorf("🔒 INV-A4-28 BROKEN: stamping a check on an ENDED row flipped its liveness back to "+
			"%q. The CASE WHEN ended_at IS NULL guard is what stops the sweep resurrecting the row it "+
			"just ended.", status)
	}
	// The stamp itself still happened — MarkCheck has NO kind filter and covers both kinds.
	var checked *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT last_idp_check_at::text FROM principal_session WHERE id = $1`, web).Scan(&checked); err != nil {
		t.Fatalf("read last_idp_check_at: %v", err)
	}
	if checked == nil {
		t.Error("MarkCheck did not stamp a WEB row; the statement deliberately has no kind filter")
	}
}

// Case 10 — staleSessions returns live stale daemon AND web rows and excludes fresh, ended or
// expired rows. The include/exclude matrix, enumerated.
func TestStaleSessionsIncludeExcludeMatrix(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// INCLUDED: a never-checked daemon row (last_idp_check_at IS NULL).
	neverChecked := f.createDaemon(principalA, ptr("h-never"), nil, 3600, 600)
	// INCLUDED: a stale-checked daemon row.
	stale := f.createDaemon(principalA, ptr("h-stale"), nil, 3600, 600)
	f.exec(`UPDATE principal_session SET last_idp_check_at = now() - interval '1 hour' WHERE id = $1`, stale.Row.ID)
	// EXCLUDED: a FRESHLY checked daemon row.
	fresh := f.createDaemon(principalA, ptr("h-fresh"), nil, 3600, 600)
	f.exec(`UPDATE principal_session SET last_idp_check_at = now() WHERE id = $1`, fresh.Row.ID)
	// EXCLUDED: an EXPIRED daemon row.
	expired := f.createDaemon(principalB, ptr("h-expired"), nil, 3600, 600)
	f.exec(`UPDATE principal_session SET absolute_expires_at = now() - interval '1 second' WHERE id = $1`, expired.Row.ID)

	// INCLUDED: a live never-checked WEB row — the only query that spans both kinds.
	liveWeb := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	// EXCLUDED: an ENDED web row.
	endedWeb := f.mintWeb("carol@example.com", ptr(deviceA), 7200, 900)
	if _, err := f.store.EndWeb(f.ctx, nil, endedWeb, session.EndedSignedOut); err != nil {
		t.Fatalf("EndWeb: %v", err)
	}
	// EXCLUDED: a web row past its IDLE deadline (absolute still open).
	idleDeadWeb := f.mintWeb("dave@example.com", ptr(deviceA), 7200, 900)
	f.exec(`UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, idleDeadWeb)

	got, err := f.store.StaleSessions(f.ctx, 60)
	if err != nil {
		t.Fatalf("StaleSessions: %v", err)
	}
	seen := map[int64]string{}
	for _, c := range got {
		seen[c.ID] = c.Kind
	}
	for _, want := range []struct {
		id   int64
		kind string
		why  string
	}{
		{neverChecked.Row.ID, session.KindDaemon, "a never-checked row (NULL) must be INCLUDED"},
		{stale.Row.ID, session.KindDaemon, "a stale-checked daemon row must be INCLUDED"},
		{liveWeb, session.KindWeb, "a live stale WEB row must be INCLUDED — this is the only query spanning both kinds"},
	} {
		if kind, ok := seen[want.id]; !ok {
			t.Errorf("row %d missing from StaleSessions: %s", want.id, want.why)
		} else if kind != want.kind {
			t.Errorf("row %d came back as kind %q, want %q", want.id, kind, want.kind)
		}
	}
	for _, notWant := range []struct {
		id  int64
		why string
	}{
		{fresh.Row.ID, "a freshly-checked row is not stale"},
		{expired.Row.ID, "an EXPIRED daemon row — the sweep must not resurrect or re-warn about a dead session"},
		{endedWeb, "an ENDED web row"},
		{idleDeadWeb, "a web row past its idle deadline"},
	} {
		if _, ok := seen[notWant.id]; ok {
			t.Errorf("row %d was returned by StaleSessions: %s", notWant.id, notWant.why)
		}
	}
}

// Cases 11, 12 — updateRefresh rotates the stored ciphertext, and 🔒 is a NO-OP when no crypto is
// configured (INV-A4-14): it neither stores plaintext nor NULLs the column.
func TestUpdateRefresh(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	created := f.createDaemon(principalA, ptr("handle-1"), ptr("first"), 3600, 600)

	if err := f.store.UpdateRefresh(f.ctx, created.Row.ID, "second"); err != nil {
		t.Fatalf("UpdateRefresh: %v", err)
	}
	got, err := f.store.GetByID(f.ctx, created.Row.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID: %v, %v", got, err)
	}
	pt, err := f.store.DecryptRefreshRow(*got)
	if err != nil || pt == nil || *pt != "second" {
		t.Fatalf("the rotated token decrypts to %v, %v; want \"second\"", pt, err)
	}
	if string(got.RefreshTokenEnc) == string(created.Row.RefreshTokenEnc) {
		t.Error("the ciphertext did not change; a per-blob random IV alone should have moved it")
	}

	// Case 12 — no crypto: early return, column untouched.
	noCrypto := newFixture(t, fixtureOpts{NoCrypto: true})
	row := noCrypto.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	if err := noCrypto.store.UpdateRefresh(noCrypto.ctx, row.Row.ID, "anything"); err != nil {
		t.Fatalf("UpdateRefresh(no crypto): %v", err)
	}
	after, err := noCrypto.store.GetByID(noCrypto.ctx, row.Row.ID)
	if err != nil || after == nil {
		t.Fatalf("GetByID: %v, %v", after, err)
	}
	if after.RefreshTokenEnc != nil {
		t.Errorf("🔒 UpdateRefresh wrote %d bytes with no key configured; it must be a no-op",
			len(after.RefreshTokenEnc))
	}
}

// Cases 14, 15 — 🔒 deactivateAllForPrincipal closes EVERY in-window session for the principal and
// marks them INACTIVE (INV-A4-29); 🔒 daemon lookups stay isolated while liveness operations cover
// web rows (INV-A4-13). Plus closeDaemonWindow's deliberate asymmetry.
func TestDeactivateAllForPrincipal(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// Two daemon sessions for one principal: "multiple machines / re-logins". A sweep that finds ONE
	// inactive must tear down every sibling, else the untouched siblings' renewal secrets keep
	// minting fresh tokens.
	one := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)
	two := f.createDaemon(principalA, ptr("handle-2"), nil, 3600, 600)
	survivor := f.createDaemon(principalB, ptr("handle-3"), nil, 3600, 600)
	// A live WEB row for the same principal — deactivateAllForPrincipal is DAEMON-scoped and must
	// leave it alone. Ending web sessions is endAllWebForPrincipal's job.
	web := f.mintWeb(principalA, ptr(deviceA), 7200, 900)

	n, err := f.store.DeactivateAllForPrincipal(f.ctx, nil, principalA)
	if err != nil {
		t.Fatalf("DeactivateAllForPrincipal: %v", err)
	}
	if n != 2 {
		t.Errorf("DeactivateAllForPrincipal closed %d windows, want 2 (every daemon session)", n)
	}
	for _, id := range []int64{one.Row.ID, two.Row.ID} {
		if status := f.livenessStatus(id); status != session.LivenessInactive {
			t.Errorf("row %d liveness = %q, want INACTIVE", id, status)
		}
	}
	// 🔒 The closure is DURABLE: absolute_expires_at dropped to now(), so a later renew fails its
	// WINDOW check too, and stays failed across a later reactivation.
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || within {
		t.Errorf("🔒 INV-A4-29 BROKEN: the renewal window is still open after a deprovision (%v, %v)", within, err)
	}
	// Idempotent, by the `> now()` predicate.
	if again, err := f.store.DeactivateAllForPrincipal(f.ctx, nil, principalA); err != nil || again != 0 {
		t.Errorf("second DeactivateAllForPrincipal = %d, %v; want 0", again, err)
	}
	// 🔒 INV-A4-13 — another principal's daemon session survives...
	if within, err := f.store.WithinWindow(f.ctx, principalB); err != nil || !within {
		t.Errorf("another principal's window was closed (%v, %v)", within, err)
	}
	// ...and this principal's WEB row is untouched by the DAEMON-scoped statement.
	if f.resolveWeb(web, ptr(deviceA)) == nil {
		t.Error("a DAEMON-scoped deactivate ended a WEB session; the kind predicate is the boundary")
	}
	_ = survivor

	// closeDaemonWindow — the same UPDATE scoped to ONE row. The asymmetry is deliberate: an IdP
	// rejection of one refresh token is evidence about THAT TOKEN, not about the account, so it must
	// not cascade to siblings.
	g := newFixture(t, fixtureOpts{})
	a := g.createDaemon(principalA, ptr("h-a"), nil, 3600, 600)
	b := g.createDaemon(principalA, ptr("h-b"), nil, 3600, 600)
	if n, err = g.store.CloseDaemonWindow(g.ctx, a.Row.ID); err != nil || n != 1 {
		t.Fatalf("CloseDaemonWindow = %d, %v; want 1", n, err)
	}
	if status := g.livenessStatus(a.Row.ID); status != session.LivenessInactive {
		t.Errorf("the closed row's liveness = %q, want INACTIVE", status)
	}
	if status := g.livenessStatus(b.Row.ID); status != session.LivenessActive {
		t.Errorf("🔒 CloseDaemonWindow cascaded to a sibling row (liveness %q). One rejected refresh "+
			"token is not evidence about the account.", status)
	}
	// The sibling is still the most recent row, so the principal's window is still open.
	if within, err := g.store.WithinWindow(g.ctx, principalA); err != nil || !within {
		t.Errorf("WithinWindow = %v, %v after closing ONE of two daemon rows; want true", within, err)
	}
}

// Case 16 — endAllWebForPrincipal ends only LIVE WEB rows for ONE principal, and is idempotent.
func TestEndAllWebForPrincipalIsScopedAndIdempotent(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// Two web rows for one principal. Newest-wins already ended the first, so only ONE is live —
	// which is itself the postcondition, and it makes "only live rows" observable.
	first := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	second := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	otherWeb := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	daemon := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)

	n, err := f.store.EndAllWebForPrincipal(f.ctx, nil, principalA, session.EndedDeactivated)
	if err != nil {
		t.Fatalf("EndAllWebForPrincipal: %v", err)
	}
	if n != 1 {
		t.Errorf("EndAllWebForPrincipal ended %d rows, want 1 (only the LIVE one)", n)
	}
	// The already-displaced row keeps its FIRST reason.
	if reason := f.rawEndedReason(first); reason == nil || *reason != session.EndedDisplaced {
		t.Errorf("the already-ended row's reason became %v; first-reason-wins", reason)
	}
	if reason := f.rawEndedReason(second); reason == nil || *reason != session.EndedDeactivated {
		t.Errorf("the live row's reason = %v, want DEACTIVATED", reason)
	}
	// Idempotent.
	if again, err := f.store.EndAllWebForPrincipal(f.ctx, nil, principalA, session.EndedDeactivated); err != nil || again != 0 {
		t.Errorf("second EndAllWebForPrincipal = %d, %v; want 0", again, err)
	}
	// Scoped: another principal's web row and this principal's DAEMON row are untouched.
	if f.resolveWeb(otherWeb, ptr(deviceB)) == nil {
		t.Error("another principal's web session was ended")
	}
	if status := f.livenessStatus(daemon.Row.ID); status != session.LivenessActive {
		t.Errorf("a DAEMON row's liveness went to %q on a WEB-scoped bulk end", status)
	}
	if within, err := f.store.WithinWindow(f.ctx, principalA); err != nil || !within {
		t.Errorf("the daemon renewal window closed on a WEB-scoped bulk end (%v, %v)", within, err)
	}
}

// TestRenewalHashMatchesTokenHash pins the property the deliberate hash duplication rests on.
//
// DaemonSession.sha256Hex and Tokens.tokenHash are two implementations of one algorithm, kept
// separate on purpose ("that's a different part's file; this store persists its own hashed secret in
// its own column"). The Go port keeps both. The only thing anything depends on is that the VALUES
// agree — INV-A4-53's single-definition rule is about token.Hash's OTHER consumer, A7's requester-IP
// registry, not about this one.
func TestRenewalHashIsPlainSHA256Hex(t *testing.T) {
	// Computed OUTSIDE Go, so this is an independent oracle rather than the implementation checking
	// itself: `printf 'pmr_abc' | shasum -a 256`.
	const want = "d6743907f8d43a1bbf948f2264298a7ebbd80d77345092846c7f0839a9ef2971"
	got := session.SHA256Hex("pmr_abc")
	if len(got) != 64 {
		t.Fatalf("SHA256Hex produced %d hex chars, want 64", len(got))
	}
	if got != want {
		t.Errorf("SHA256Hex(\"pmr_abc\") = %s, want %s", got, want)
	}
	// And the two hashers agree, which is the only property anything depends on. token.Hash is not
	// imported here (that would couple the packages the Kotlin deliberately keeps apart); the shared
	// value is asserted against the same external oracle instead — internal/token's
	// TestHashIsPlainSHA256Hex asserts the other half.
}
