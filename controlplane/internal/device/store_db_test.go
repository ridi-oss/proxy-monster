package device

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// Port of DeviceLoginStoreDbTest.kt cases 1-6 — the store round-trips.
//
// ORACLE: control-plane/src/test/kotlin/.../DeviceLoginStoreDbTest.kt, read this session.
//
// ⚠️ The Kotlin suite's case 7 ("the verification URL points at the web console origin") asserts on
// `Config.webBaseUrl` and touches no device code at all; it belongs to internal/config, which already
// covers WebBaseURL. What IS device behaviour — that Start BUILDS its URL from WebBaseURL rather than
// from the CP's own origin — is asserted in routes_db_test.go's TestStart_VerificationURIIsTheWebOrigin.

func newStore(t *testing.T) (*LoginStore, context.Context) {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return NewLoginStore(db.Pool, nil), context.Background()
}

func mustCreate(t *testing.T, s *LoginStore, ctx context.Context, handle string, deviceCode *string,
	intervalSec int, ttl int64, expiresAt time.Time, userCode *string) *LoginRow {
	t.Helper()
	row, err := s.Create(ctx, handle, deviceCode, intervalSec, ttl, expiresAt, userCode)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return row
}

func mustHandle(t *testing.T, s *LoginStore) string {
	t.Helper()
	h, err := s.NewHandle()
	if err != nil {
		t.Fatalf("NewHandle: %v", err)
	}
	return h
}

// --- Case 1 · `create then get round-trips a pending row`
func TestStore_CreateThenGetRoundTrips(t *testing.T) {
	s, ctx := newStore(t)
	handle := mustHandle(t, s)

	row := mustCreate(t, s, ctx, handle, types.Ptr("dc-1"), 5, 3600, time.Now().Add(600*time.Second), nil)
	if row.Handle != handle {
		t.Errorf("handle = %q, want %q", row.Handle, handle)
	}
	if row.DeviceCode == nil || *row.DeviceCode != "dc-1" {
		t.Errorf("deviceCode = %v", row.DeviceCode)
	}
	if row.Status != StatusPending {
		t.Errorf("status = %q, want PENDING", row.Status)
	}
	if row.Principal != nil {
		t.Errorf("principal = %q, want nil on a fresh row", *row.Principal)
	}

	fetched, err := s.Get(ctx, handle)
	if err != nil || fetched == nil {
		t.Fatalf("Get = %v, %v", fetched, err)
	}
	if fetched.ID != row.ID {
		t.Errorf("id = %d, want %d", fetched.ID, row.ID)
	}
	if fetched.IntervalSec != 5 {
		t.Errorf("intervalSec = %d, want 5", fetched.IntervalSec)
	}
	if fetched.TTLSeconds != 3600 {
		t.Errorf("ttlSeconds = %d, want 3600", fetched.TTLSeconds)
	}
}

// --- Case 2 · `unknown handle is absent`
func TestStore_UnknownHandleIsAbsent(t *testing.T) {
	s, ctx := newStore(t)
	row, err := s.Get(ctx, "no-such-handle")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row != nil {
		t.Fatalf("Get = %+v, want nil — an unknown handle is absent, not an error", row)
	}
}

// --- Case 3 · `a login is retrievable by its user_code and a fresh one is well-formed`
func TestStore_RetrievableByUserCodeAndWellFormed(t *testing.T) {
	s, ctx := newStore(t)
	handle := mustHandle(t, s)
	userCode, err := s.NewUserCode()
	if err != nil {
		t.Fatalf("NewUserCode: %v", err)
	}
	if !regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`).MatchString(userCode) {
		t.Fatalf("user_code is XXXX-XXXX from the unambiguous alphabet, got %q", userCode)
	}
	mustCreate(t, s, ctx, handle, nil, 2, 3600, time.Now().Add(600*time.Second), &userCode)

	byCode, err := s.GetByUserCode(ctx, userCode)
	if err != nil || byCode == nil {
		t.Fatalf("GetByUserCode = %v, %v", byCode, err)
	}
	if byCode.Handle != handle {
		t.Errorf("handle = %q, want %q — the page looks the handle up by the human user_code", byCode.Handle, handle)
	}
	if byCode.UserCode == nil || *byCode.UserCode != userCode {
		t.Errorf("userCode = %v", byCode.UserCode)
	}

	unknown, err := s.GetByUserCode(ctx, "NOPE-NOPE")
	if err != nil {
		t.Fatalf("GetByUserCode: %v", err)
	}
	if unknown != nil {
		t.Error("an unknown user_code must be absent")
	}
}

// --- Case 4 🔒 · `markApproved sets status and principal, only once` (INV-A4-42)
func TestStore_MarkApprovedOnlyOnce(t *testing.T) {
	s, ctx := newStore(t)
	handle := mustHandle(t, s)
	mustCreate(t, s, ctx, handle, types.Ptr("dc-2"), 5, 3600, time.Now().Add(600*time.Second), nil)

	ok, err := s.MarkApproved(ctx, handle, "alice@example.com", nil)
	if err != nil || !ok {
		t.Fatalf("MarkApproved = %v, %v", ok, err)
	}
	row, _ := s.Get(ctx, handle)
	if row.Status != StatusApproved {
		t.Errorf("status = %q, want APPROVED", row.Status)
	}
	if row.Principal == nil || *row.Principal != "alice@example.com" {
		t.Errorf("principal = %v", row.Principal)
	}

	// Re-approving an already-approved row is a no-op — "a second IdP exchange for the same handle
	// must not silently switch the winning principal."
	ok, err = s.MarkApproved(ctx, handle, "mallory@example.com", nil)
	if err != nil {
		t.Fatalf("MarkApproved: %v", err)
	}
	if ok {
		t.Fatal("MarkApproved returned true for an already-APPROVED row — the CAS is the truth")
	}
	row, _ = s.Get(ctx, handle)
	if row.Principal == nil || *row.Principal != "alice@example.com" {
		t.Fatalf("principal = %v, want the FIRST approver to win", row.Principal)
	}
}

// --- Case 5 🔒 · `markApproved refuses an expired handle` (INV-A4-42)
func TestStore_MarkApprovedRefusesAnExpiredHandle(t *testing.T) {
	s, ctx := newStore(t)
	handle := mustHandle(t, s)
	mustCreate(t, s, ctx, handle, types.Ptr("dc-3"), 5, 3600, time.Now().Add(-time.Second), nil)

	ok, err := s.MarkApproved(ctx, handle, "alice@example.com", nil)
	if err != nil {
		t.Fatalf("MarkApproved: %v", err)
	}
	if ok {
		t.Fatal("an expired handle must not be approvable")
	}
	row, _ := s.Get(ctx, handle)
	if row.Status != StatusPending {
		t.Errorf("status = %q, want it left PENDING", row.Status)
	}
}

// --- Case 6 · `purgeExpired removes only expired rows`
func TestStore_PurgeExpiredRemovesOnlyExpiredRows(t *testing.T) {
	s, ctx := newStore(t)
	live, dead := mustHandle(t, s), mustHandle(t, s)
	mustCreate(t, s, ctx, live, nil, 5, 3600, time.Now().Add(600*time.Second), nil)
	mustCreate(t, s, ctx, dead, nil, 5, 3600, time.Now().Add(-time.Second), nil)

	n, err := s.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n < 1 {
		t.Fatalf("PurgeExpired removed %d rows, want at least 1", n)
	}
	if row, _ := s.Get(ctx, dead); row != nil {
		t.Error("the expired row survived the purge")
	}
	if row, _ := s.Get(ctx, live); row == nil {
		t.Error("the live row was purged")
	}
}

// --- 🔒 INV-A4-43 · `consume` is the one-time claim.
//
// "Returns true only for the single caller that wins the transition; false for any replay/race on an
// already-consumed (or never-approved / expired) handle."
func TestStore_ConsumeIsAOneTimeClaim(t *testing.T) {
	s, ctx := newStore(t)

	t.Run("only the winner gets true", func(t *testing.T) {
		handle := mustHandle(t, s)
		mustCreate(t, s, ctx, handle, nil, 5, 3600, time.Now().Add(600*time.Second), nil)
		if _, err := s.MarkApproved(ctx, handle, "alice@example.com", nil); err != nil {
			t.Fatal(err)
		}
		first, err := s.Consume(ctx, handle)
		if err != nil || !first {
			t.Fatalf("first Consume = %v, %v", first, err)
		}
		second, err := s.Consume(ctx, handle)
		if err != nil {
			t.Fatal(err)
		}
		if second {
			t.Fatal("a replayed Consume won too — the handle would become an unbounded credential minter")
		}
		row, _ := s.Get(ctx, handle)
		if row.Status != StatusConsumed {
			t.Errorf("status = %q, want CONSUMED", row.Status)
		}
	})

	t.Run("a never-approved handle cannot be consumed", func(t *testing.T) {
		handle := mustHandle(t, s)
		mustCreate(t, s, ctx, handle, nil, 5, 3600, time.Now().Add(600*time.Second), nil)
		if ok, _ := s.Consume(ctx, handle); ok {
			t.Fatal("a PENDING handle must not be consumable")
		}
	})

	t.Run("an expired APPROVED handle cannot be consumed", func(t *testing.T) {
		handle := mustHandle(t, s)
		// Approve while live, then expire the row out from under it.
		mustCreate(t, s, ctx, handle, nil, 5, 3600, time.Now().Add(600*time.Second), nil)
		if _, err := s.MarkApproved(ctx, handle, "alice@example.com", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(ctx, `UPDATE device_login SET expires_at = now() - interval '1 second' WHERE handle = $1`, handle); err != nil {
			t.Fatal(err)
		}
		if ok, _ := s.Consume(ctx, handle); ok {
			t.Fatal("an expired handle must not be consumable")
		}
	})
}

// --- 🔒 INV-A4-14 · the refresh token is encrypted at rest, and with NO key it is not persisted at
// all — not even in plaintext.
func TestStore_RefreshTokenEncryptionAndTheNoKeyCase(t *testing.T) {
	db, _ := dbtest.MigratedStore(t)
	ctx := context.Background()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypto, err := result.NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with a key it round-trips and the column is NOT the plaintext", func(t *testing.T) {
		s := NewLoginStore(db.Pool, crypto)
		handle := mustHandle(t, s)
		mustCreate(t, s, ctx, handle, nil, 5, 3600, time.Now().Add(600*time.Second), nil)
		if _, err := s.MarkApproved(ctx, handle, "alice@example.com", types.Ptr("the-refresh-secret")); err != nil {
			t.Fatal(err)
		}
		row, _ := s.Get(ctx, handle)
		if row.RefreshTokenEnc == nil {
			t.Fatal("refresh_token_enc is NULL, want ciphertext")
		}
		if strings.Contains(string(row.RefreshTokenEnc), "the-refresh-secret") {
			t.Fatal("the refresh token is on disk in plaintext")
		}
		got, err := s.DecryptRefresh(row)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || *got != "the-refresh-secret" {
			t.Fatalf("DecryptRefresh = %v, want the-refresh-secret", got)
		}
	})

	t.Run("with NO key nothing is persisted", func(t *testing.T) {
		s := NewLoginStore(db.Pool, nil)
		handle := mustHandle(t, s)
		mustCreate(t, s, ctx, handle, nil, 5, 3600, time.Now().Add(600*time.Second), nil)
		if _, err := s.MarkApproved(ctx, handle, "alice@example.com", types.Ptr("the-refresh-secret")); err != nil {
			t.Fatal(err)
		}
		row, _ := s.Get(ctx, handle)
		if row.RefreshTokenEnc != nil {
			t.Fatalf("refresh_token_enc = %q with no key configured — INV-A4-14 says NULL, never plaintext",
				row.RefreshTokenEnc)
		}
		got, err := s.DecryptRefresh(row)
		if err != nil || got != nil {
			t.Fatalf("DecryptRefresh = %v, %v; want nil, nil", got, err)
		}
	})
}

// --- · `normalizeUserCode` folds a human-typed code back to the stored form (RFC 8628 §6.1).
func TestNormalizeUserCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"wdjbmjht", "WDJB-MJHT"},
		{"WDJB-MJHT", "WDJB-MJHT"},
		{"wdjb mjht", "WDJB-MJHT"},
		{"w-d-j-b-m-j-h-t", "WDJB-MJHT"},
		// ⚠️ NOT length-clamped: a short input stays short and simply matches nothing.
		{"WDJB", "WDJB"},
		{"", ""},
		// Ambiguous characters are not in the alphabet, so they are STRIPPED rather than mapped —
		// "WDJB0MJHT" loses the 0 and becomes a valid-looking 8-character code.
		{"WDJB0MJHT", "WDJB-MJHT"},
		// 9 surviving characters is not 8, so no hyphen is inserted.
		{"WDJBMJHTX", "WDJBMJHTX"},
	}
	for _, tc := range cases {
		if got := NormalizeUserCode(tc.in); got != tc.want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- · `GetByUserCode` normalises its argument, so a lowercase unhyphenated code finds the row.
func TestStore_GetByUserCodeNormalises(t *testing.T) {
	s, ctx := newStore(t)
	handle := mustHandle(t, s)
	code := "WDJB-MJHT"
	mustCreate(t, s, ctx, handle, nil, 2, 3600, time.Now().Add(600*time.Second), &code)

	for _, typed := range []string{"WDJB-MJHT", "wdjbmjht", "wdjb-mjht", "WDJB MJHT"} {
		row, err := s.GetByUserCode(ctx, typed)
		if err != nil {
			t.Fatalf("GetByUserCode(%q): %v", typed, err)
		}
		if row == nil || row.Handle != handle {
			t.Errorf("GetByUserCode(%q) did not find the row", typed)
		}
	}
}

// --- 🔒 · handle and user-code shape: 192-bit handle, 8 unambiguous characters, no 0/O/1/I/L.
func TestStore_HandleAndUserCodeShape(t *testing.T) {
	s, _ := newStore(t)

	handle := mustHandle(t, s)
	if !strings.HasPrefix(handle, HandlePrefix) {
		t.Errorf("handle = %q, want the dvc_ prefix", handle)
	}
	// 24 random bytes, base64url-nopad = 32 characters.
	if got := len(strings.TrimPrefix(handle, HandlePrefix)); got != 32 {
		t.Errorf("handle body is %d chars, want 32 (24 bytes = 192 bits)", got)
	}

	// The alphabet excludes 0, O, 1, I and L, "because a human reads this code off the CP
	// verification page". Drawing many codes makes an accidental inclusion visible.
	seen := map[byte]bool{}
	for i := 0; i < 200; i++ {
		code, err := s.NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("user_code = %q, want XXXX-XXXX", code)
		}
		for j := 0; j < len(code); j++ {
			if code[j] == '-' {
				continue
			}
			if strings.IndexByte(UserCodeAlphabet, code[j]) < 0 {
				t.Fatalf("user_code %q contains %q, which is outside the alphabet", code, code[j])
			}
			seen[code[j]] = true
		}
	}
	for _, ambiguous := range []byte{'0', 'O', '1', 'I', 'L'} {
		if seen[ambiguous] {
			t.Errorf("the ambiguous character %q was drawn", ambiguous)
		}
	}
	// 200 codes = 1600 draws over a 31-character alphabet; every character should appear. This is
	// the guard against a modulo-biased index that silently never reaches the tail.
	if len(seen) != len(UserCodeAlphabet) {
		t.Errorf("only %d of %d alphabet characters were ever drawn — check for modulo bias",
			len(seen), len(UserCodeAlphabet))
	}
}

// --- · `createPending` produces a PENDING row with both identifiers set.
func TestStore_CreatePending(t *testing.T) {
	s, ctx := newStore(t)
	row, err := s.CreatePending(ctx, PollIntervalSeconds, 3600, time.Now().Add(600*time.Second))
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	if row.Status != StatusPending {
		t.Errorf("status = %q", row.Status)
	}
	if row.UserCode == nil || *row.UserCode == "" {
		t.Fatal("createPending must always set a user_code")
	}
	if row.DeviceCode != nil {
		t.Errorf("deviceCode = %q — INV-A4-44: the CP never runs the RFC 8628 client side", *row.DeviceCode)
	}
	if row.IntervalSec != PollIntervalSeconds {
		t.Errorf("intervalSec = %d, want %d", row.IntervalSec, PollIntervalSeconds)
	}

	// The unique index on user_code is what makes the retry loop necessary; prove it exists by
	// hitting it directly.
	dup := mustHandle(t, s)
	_, err = s.Create(ctx, dup, nil, 2, 3600, time.Now().Add(600*time.Second), row.UserCode)
	if err == nil {
		t.Fatal("a duplicate user_code must violate idx_device_login_user_code")
	}
}
