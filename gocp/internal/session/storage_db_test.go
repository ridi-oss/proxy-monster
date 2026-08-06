package session_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/session"
)

// webTimes is PrincipalSessionStorageDbTest.kt's private `webTimes(id)` helper: the pair
// (idle_expires_at, last_seen_at) the Kotlin asserts UNCHANGED across a session-key read. last_seen_at
// is nullable, so it comes back as a pointer.
func storageWebTimes(f *fixture, id int64) (time.Time, *time.Time) {
	f.t.Helper()
	var idle time.Time
	var lastSeen *time.Time
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT idle_expires_at, last_seen_at FROM principal_session WHERE id = $1`, id).
		Scan(&idle, &lastSeen); err != nil {
		f.t.Fatalf("read web times(%d): %v", id, err)
	}
	return idle, lastSeen
}

func sameNullableTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// ---------------------------------------------------------------------------------------------
// Port of PrincipalSessionStorageDbTest.kt (116 LOC, 4 cases, DB) — 04-auth-session-tokens.md §4.4,
// and PrincipalSessionSchemaDbTest.kt (65 LOC, 1 case) — §4.5.
//
// There is no Ktor SessionStorage in Go, so the Kotlin's write/read/invalidate trio is the explicit
// three-function seam [session.Store.LinkWebSessionKey] / [session.Store.WebIDBySessionKey] /
// [session.Store.EndWebBySessionKey], invoked from the cookie middleware at the same three moments.
// ---------------------------------------------------------------------------------------------

// Case 1 — "write links a web row and steals a reused key from its prior holder" (INV-A4-25).
// KT: PrincipalSessionStorageDbTest.kt#write links a web row and steals a reused key from its prior holder
func TestLinkWebSessionKeyStealsAReusedKeyFromItsPriorHolder(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	first := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	second := f.mintWeb(principalB, ptr(deviceB), 7200, 900)

	if err := f.store.LinkWebSessionKey(f.ctx, first, "tracker-1"); err != nil {
		t.Fatalf("LinkWebSessionKey(first): %v", err)
	}
	got, err := f.store.WebIDBySessionKey(f.ctx, "tracker-1")
	if err != nil || got != first {
		t.Fatalf("WebIDBySessionKey = %d, %v; want %d", got, err, first)
	}

	// 🔒 INV-A4-25 — the STEAL must precede the CLAIM, in ONE transaction.
	// `idx_principal_session_session_key` is a PARTIAL UNIQUE index, so claiming before releasing
	// would violate it — the failure mode of a wrong implementation is a 23505, not a wrong answer.
	if err := f.store.LinkWebSessionKey(f.ctx, second, "tracker-1"); err != nil {
		t.Fatalf("🔒 INV-A4-25 BROKEN: re-linking a reused tracker id failed (%v). The prior holder's "+
			"key must be NULLed BEFORE the new row claims it, in one transaction.", err)
	}
	if got, err = f.store.WebIDBySessionKey(f.ctx, "tracker-1"); err != nil || got != second {
		t.Fatalf("after the steal WebIDBySessionKey = %d, %v; want %d", got, err, second)
	}
	// The prior holder kept its row and lost only the key.
	var key *string
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT session_key FROM principal_session WHERE id = $1`, first).Scan(&key); err != nil {
		t.Fatalf("read session_key: %v", err)
	}
	if key != nil {
		t.Errorf("the prior holder still holds session_key %q", *key)
	}
	if f.resolveWeb(first, ptr(deviceA)) == nil {
		t.Error("the steal ended the prior holder's session; it only releases the key")
	}
	// Re-linking the SAME row to the SAME key is a no-op, not a violation.
	if err := f.store.LinkWebSessionKey(f.ctx, second, "tracker-1"); err != nil {
		t.Errorf("re-linking a row to the key it already holds failed: %v", err)
	}
}

// Case 2 — 🔒 "read returns live, ended AND expired refs without changing idle state" (INV-A4-12).
//
// This is the case a "harmless optimization" breaks. Adding `AND ended_at IS NULL` to the lookup
// would make webSession() never learn the sessionId for a terminated row, FAILED_WEB_SESSION would
// stay unset, and every displaced or bind-mismatched session would report "none" instead of its real
// reason — INV-A4-3's entire UX.
// KT: PrincipalSessionStorageDbTest.kt#read returns live ended and expired refs without changing idle state
func TestWebIDBySessionKeyReturnsEndedAndExpiredRefs(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// Live.
	live := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if err := f.store.LinkWebSessionKey(f.ctx, live, "k-live"); err != nil {
		t.Fatalf("link: %v", err)
	}
	// The Kotlin's `webTimes(id)` is the PAIR (idle_expires_at, last_seen_at), asserted UNCHANGED
	// across the read — so both clocks are compared here, at full timestamp precision rather than
	// truncated to whole seconds. A lookup that stamped last_seen_at would make the key read count as
	// activity, which is the other half of "without changing idle state".
	idleBefore, seenBefore := storageWebTimes(f, live)
	if got, err := f.store.WebIDBySessionKey(f.ctx, "k-live"); err != nil || got != live {
		t.Fatalf("live lookup = %d, %v", got, err)
	}
	// It does NOT slide idle: request-time resolution owns liveness, not the key lookup.
	idleAfter, seenAfter := storageWebTimes(f, live)
	if !idleAfter.Equal(idleBefore) {
		t.Errorf("the key lookup slid idle_expires_at (%s → %s)", idleBefore, idleAfter)
	}
	if !sameNullableTime(seenBefore, seenAfter) {
		t.Errorf("the key lookup stamped last_seen_at (%v → %v)", seenBefore, seenAfter)
	}

	// ENDED — the case that matters.
	ended := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	if err := f.store.LinkWebSessionKey(f.ctx, ended, "k-ended"); err != nil {
		t.Fatalf("link: %v", err)
	}
	if _, err := f.store.EndWeb(f.ctx, nil, ended, session.EndedDisplaced); err != nil {
		t.Fatalf("EndWeb: %v", err)
	}
	got, err := f.store.WebIDBySessionKey(f.ctx, "k-ended")
	if err != nil || got != ended {
		t.Fatalf("🔒 INV-A4-12 BROKEN: an ENDED row is no longer reachable by session key (%d, %v). "+
			"Adding `AND ended_at IS NULL` here silently destroys the whole ended-reason UX — every "+
			"displaced session would report \"none\" instead of \"displaced\".", got, err)
	}
	// ...and the reason is therefore still reportable, which is the point.
	reason, err := f.store.WebEndedReason(f.ctx, got)
	if err != nil || reason == nil || session.WireReason(reason) != session.WireReasonDisplaced {
		t.Errorf("the ended row's wire reason = %v/%q, want displaced", reason, session.WireReason(reason))
	}

	// EXPIRED (never explicitly ended, both clocks run out).
	expired := f.mintWeb("carol@example.com", ptr(deviceA), 7200, 900)
	if err := f.store.LinkWebSessionKey(f.ctx, expired, "k-expired"); err != nil {
		t.Fatalf("link: %v", err)
	}
	f.exec(`UPDATE principal_session SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, expired)
	if got, err = f.store.WebIDBySessionKey(f.ctx, "k-expired"); err != nil || got != expired {
		t.Fatalf("an EXPIRED row is no longer reachable by session key (%d, %v)", got, err)
	}

	// An unknown key is the Ktor "no session" contract — a sentinel, not a zero id.
	if _, err = f.store.WebIDBySessionKey(f.ctx, "k-unknown"); !errors.Is(err, session.ErrUnknownWebSessionKey) {
		t.Errorf("an unknown key returned %v, want ErrUnknownWebSessionKey", err)
	}
}

// Case 3 — 🔒 "invalidate signs out only active rows and preserves an existing terminal reason"
// (INV-A4-23).
//
// This also closes §4.17 coverage gap 7: the interaction that matters most — a DISPLACED row later
// logged out must KEEP DISPLACED — which no Kotlin case covers.
// KT: PrincipalSessionStorageDbTest.kt#invalidate signs out only active rows and preserves an existing terminal reason
func TestEndWebBySessionKeySignsOutOnlyActiveRowsAndPreservesATerminalReason(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	live := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	if err := f.store.LinkWebSessionKey(f.ctx, live, "k-live"); err != nil {
		t.Fatalf("link: %v", err)
	}
	ok, err := f.store.EndWebBySessionKey(f.ctx, "k-live", session.EndedSignedOut)
	if err != nil || !ok {
		t.Fatalf("EndWebBySessionKey = %v, %v; want true", ok, err)
	}
	if reason := f.rawEndedReason(live); reason == nil || *reason != session.EndedSignedOut {
		t.Errorf("logout wrote reason %v, want SIGNED_OUT", reason)
	}
	// Idempotent: a second invalidate is a no-op.
	if ok, err = f.store.EndWebBySessionKey(f.ctx, "k-live", session.EndedSignedOut); err != nil || ok {
		t.Errorf("a repeat invalidate = %v, %v; want false", ok, err)
	}

	// 🔒 The interaction: a row already ended DISPLACED, then logged out, KEEPS DISPLACED. If a
	// later logout could relabel it, the console would say "your session ran out" when what actually
	// happened was "someone signed in elsewhere" — INV-A4-3 inverted.
	displaced := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	if err = f.store.LinkWebSessionKey(f.ctx, displaced, "k-displaced"); err != nil {
		t.Fatalf("link: %v", err)
	}
	f.mintWeb(principalB, ptr(deviceB), 7200, 900) // newest-wins ends the first
	if reason := f.rawEndedReason(displaced); reason == nil || *reason != session.EndedDisplaced {
		t.Fatalf("setup: the row was not displaced (%v)", reason)
	}
	if ok, err = f.store.EndWebBySessionKey(f.ctx, "k-displaced", session.EndedSignedOut); err != nil || ok {
		t.Errorf("logging out an already-displaced row reported a transition (%v, %v)", ok, err)
	}
	reason := f.rawEndedReason(displaced)
	if reason == nil || *reason != session.EndedDisplaced {
		t.Errorf("🔒 a DISPLACED row was relabelled to %v by a later logout. First-reason-wins is what "+
			"keeps \"someone signed in elsewhere\" from degrading into \"your session ran out\".", reason)
	}
}

// Case 4 — 🔒 "daemon rows cannot be linked or reached through web session keys" (INV-A4-13).
// KT: PrincipalSessionStorageDbTest.kt#daemon rows cannot be linked or reached through web session keys
func TestDaemonRowsCannotBeLinkedOrReachedThroughWebSessionKeys(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	daemon := f.createDaemon(principalA, ptr("handle-1"), nil, 3600, 600)

	// The link statement is `kind='WEB'`-scoped, so linking a daemon row is a silent no-op.
	if err := f.store.LinkWebSessionKey(f.ctx, daemon.Row.ID, "k-daemon"); err != nil {
		t.Fatalf("LinkWebSessionKey(daemon): %v", err)
	}
	var key *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT session_key FROM principal_session WHERE id = $1`, daemon.Row.ID).Scan(&key); err != nil {
		t.Fatalf("read session_key: %v", err)
	}
	if key != nil {
		t.Errorf("🔒 INV-A4-13 BROKEN: a DAEMON row was given session_key %q. A daemon row has no "+
			"device binding, so reaching it through a web session key is INV-A4-19's wildcard hole.", *key)
	}
	if _, err := f.store.WebIDBySessionKey(f.ctx, "k-daemon"); !errors.Is(err, session.ErrUnknownWebSessionKey) {
		t.Errorf("a daemon row was reachable through a web session key (%v)", err)
	}

	// Even a key written directly onto the daemon row stays unreachable and un-endable through the
	// web seam — the predicate is on every statement, not only the link.
	f.exec(`UPDATE principal_session SET session_key = 'k-forced' WHERE id = $1`, daemon.Row.ID)
	if _, err := f.store.WebIDBySessionKey(f.ctx, "k-forced"); !errors.Is(err, session.ErrUnknownWebSessionKey) {
		t.Errorf("a DAEMON row with a session_key was reachable through the web lookup (%v)", err)
	}
	ok, err := f.store.EndWebBySessionKey(f.ctx, "k-forced", session.EndedSignedOut)
	if err != nil || ok {
		t.Errorf("a DAEMON row was ended through the web session-key path (%v, %v)", ok, err)
	}
	if f.rawEndedReason(daemon.Row.ID) != nil {
		t.Error("a DAEMON row was ended by the web logout path")
	}
}

// ---------------------------------------------------------------------------------------------
// Port of PrincipalSessionSchemaDbTest.kt (65 LOC, 1 case, DB) — §4.5.
// ---------------------------------------------------------------------------------------------

// "the session table carries its indexes and a partial-unique session key" (INV-A4-25).
//
// The PARTIAL-ness is the load-bearing half: `WHERE session_key IS NOT NULL`. Without it, the second
// row to have its key NULLed by a steal would collide with the first on a NULL value — and every
// re-login after the first would fail with a 23505 that looks like a race rather than a schema bug.
// KT: PrincipalSessionSchemaDbTest.kt#the session table carries its indexes and a partial-unique session key
func TestSessionTableCarriesItsIndexesAndAPartialUniqueSessionKey(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	want := map[string]string{
		"idx_principal_session_principal":    "",
		"idx_principal_session_handle":       "",
		"idx_principal_session_renewal_hash": "",
		"idx_principal_session_active":       "",
		"idx_principal_session_session_key":  "",
	}
	rows, err := f.db.Pool.Query(f.ctx,
		`SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'principal_session'`)
	if err != nil {
		t.Fatalf("read pg_indexes: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatalf("scan pg_indexes: %v", err)
		}
		if _, ok := want[name]; ok {
			want[name] = def
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate pg_indexes: %v", err)
	}
	for name, def := range want {
		if def == "" {
			t.Errorf("index %s is missing from principal_session", name)
		}
	}

	sessionKeyDef := want["idx_principal_session_session_key"]
	if sessionKeyDef != "" {
		if !strings.Contains(sessionKeyDef, "UNIQUE") {
			t.Errorf("idx_principal_session_session_key is not UNIQUE: %s", sessionKeyDef)
		}
		if !strings.Contains(sessionKeyDef, "session_key IS NOT NULL") {
			t.Errorf("🔒 INV-A4-25 BROKEN: idx_principal_session_session_key is not PARTIAL (%s). A "+
				"full unique index would collide every row whose key was NULLed by a steal.", sessionKeyDef)
		}
	}
	// The active-session index is partial too — `WHERE ended_at IS NULL`.
	if def := want["idx_principal_session_active"]; def != "" && !strings.Contains(def, "ended_at IS NULL") {
		t.Errorf("idx_principal_session_active is not scoped to live rows: %s", def)
	}

	// The behavioural proof the partial index buys, and the Kotlin's own two: TWO rows coexisting on a
	// NULL session_key (PrincipalSessionSchemaDbTest.kt:46-48 asserts the count is exactly 2 for its two
	// freshly-created daemon rows), and a duplicate non-NULL key being REFUSED (its assertFails at
	// :59-61). Asserting the index DEFINITION says UNIQUE is not the same as watching Postgres enforce
	// it, so both are stated.
	firstDaemon := f.createDaemon("first@example.com", nil, nil, 7200, 60)
	secondDaemon := f.createDaemon("second@example.com", nil, nil, 7200, 60)
	if secondDaemon.Row.ID <= firstDaemon.Row.ID {
		t.Errorf("ids are not monotonic: second=%d, first=%d", secondDaemon.Row.ID, firstDaemon.Row.ID)
	}
	if n := f.scalarInt64(`SELECT count(*) FROM principal_session WHERE session_key IS NULL`); n != 2 {
		t.Errorf("rows holding a NULL session_key = %d, want 2 — two keyless sessions must coexist "+
			"under the PARTIAL unique index", n)
	}

	a := f.mintWeb(principalA, ptr(deviceA), 7200, 900)
	b := f.mintWeb(principalB, ptr(deviceB), 7200, 900)
	if err := f.store.LinkWebSessionKey(f.ctx, a, "k"); err != nil {
		t.Fatalf("link a: %v", err)
	}
	if err := f.store.LinkWebSessionKey(f.ctx, b, "k"); err != nil {
		t.Fatalf("link b (the steal): %v", err)
	}
	if n := f.scalarInt64(`SELECT count(*) FROM principal_session WHERE session_key IS NULL`); n < 1 {
		t.Error("no row holds a NULL session_key after a steal; the steal did not release it")
	}

	// Two sessions must not share one session_key — written straight onto the table, bypassing the
	// store, so it is the INDEX that refuses rather than the steal-then-claim statement. The positive
	// control first: the same statement with a FREE key succeeds, so the failure below is the unique
	// index and not a broken write.
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE principal_session SET session_key = 'k-free' WHERE id = $1`, a); err != nil {
		t.Fatalf("control: writing an unused session_key must succeed: %v", err)
	}
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE principal_session SET session_key = 'k' WHERE id = $1`, a); err == nil {
		t.Error("🔒 INV-A4-25 BROKEN: two rows were allowed to share the session_key 'k' — a stolen " +
			"tracker id would then resolve to two sessions")
	}
}
