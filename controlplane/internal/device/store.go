package device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// The three `device_login.status` values. ⚠️ `V6__sessions.sql:21` still documents only
// `PENDING | APPROVED`; the CONSUMED state was added with the one-time-mint claim and the migration
// comment was never updated. Stale comment, candidate finding — the field comment on
// DeviceAuth.kt:78 has the correct set.
const (
	// StatusPending is the state a row is created in and the only state markApproved accepts.
	StatusPending = "PENDING"
	// StatusApproved means a browser session approved it; the only state consume accepts.
	StatusApproved = "APPROVED"
	// StatusConsumed means the one-time mint already happened.
	StatusConsumed = "CONSUMED"
)

// UserCodeAlphabet is `USER_CODE_ALPHABET` (DeviceAuth.kt:96) — 31 characters with NO ambiguous
// 0/O, 1/I/L, "because a human reads this code off the CP verification page".
//
// Entropy is 31⁸ ≈ 39.6 bits (the Kotlin doc says "~40 bits"). Quoted from DeviceAuth.kt:112-116 on
// why that is enough: the code is "short-lived and single-use, so it is safe to show a human even
// though it is the page's approval key."
const UserCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// HandlePrefix is the `dvc_` on `newHandle()`'s output.
const HandlePrefix = "dvc_"

// LoginRow is `data class DeviceLoginRow` (DeviceAuth.kt:62-75).
//
// Column ↔ field names differ in four places (user_code, device_code, interval_sec,
// refresh_token_enc); both timestamps are NOT NULL in V6 so neither is a pointer here.
type LoginRow struct {
	ID       int64
	Handle   string
	UserCode *string
	// DeviceCode is the IdP's device_code.
	//
	// 🔒 INV-A4-41 — it NEVER leaves the server, and pmon only ever sees the opaque Handle. Keeping
	// the two identifiers distinct (V6__sessions.sql:12-14) is why the polling secret never rides in
	// a browser URL. In practice this is always NULL: see the package doc on INV-A4-44.
	DeviceCode      *string
	IntervalSec     int
	TTLSeconds      int64
	Status          string
	Principal       *string
	RefreshTokenEnc []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// LoginStore is `class DeviceLoginStore(dataSource, crypto: ResultCrypto? = null)`
// (DeviceAuth.kt:85-90).
//
// crypto is nil when PM_RESULT_KEY is unset. 🔒 INV-A4-14 — no key means the IdP refresh token is
// NEVER PERSISTED, not even in plaintext; [LoginStore.MarkApproved] simply stores NULL and the daemon
// session minted at poll ends up with no liveness path.
type LoginStore struct {
	db     store.DB
	crypto *result.Crypto
}

// NewLoginStore wires the store. crypto may be nil.
func NewLoginStore(db store.DB, crypto *result.Crypto) *LoginStore {
	return &LoginStore{db: db, crypto: crypto}
}

// selectColumns is the one column list every read shares, in the Kotlin's order.
const selectColumns = `id, handle, user_code, device_code, interval_sec, ttl_seconds, status,
                       principal, refresh_token_enc, created_at, expires_at`

// NewHandle is `fun newHandle(): String` (DeviceAuth.kt:104-107) — `"dvc_" +
// base64url-nopad(24 bytes)`, i.e. 192 bits. "The only device-login identifier pmon ever sees."
func (s *LoginStore) NewHandle() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("device: CSPRNG read failed: %w", err)
	}
	return HandlePrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewUserCode is `fun newUserCode(): String` (DeviceAuth.kt:117-122) — 8 alphabet characters with a
// hyphen after the 4th, i.e. `XXXX-XXXX`.
//
// Kotlin uses `SecureRandom.nextInt(31)`, which is UNIFORM: java.util.Random.nextInt(bound) rejects
// the biased tail rather than taking a modulo. randomAlphabetIndex reproduces that with the same
// rejection idea, because a modulo of a random byte over 31 would over-weight the first 8 characters
// (256 = 8×31 + 8) — a measurable entropy loss on a ~40-bit approval key.
func (s *LoginStore) NewUserCode() (string, error) {
	var b strings.Builder
	b.Grow(9)
	for i := 0; i < 8; i++ {
		if i == 4 {
			b.WriteByte('-')
		}
		idx, err := randomAlphabetIndex()
		if err != nil {
			return "", err
		}
		b.WriteByte(UserCodeAlphabet[idx])
	}
	return b.String(), nil
}

// randomAlphabetIndex draws a uniform index into [UserCodeAlphabet] by rejection sampling.
func randomAlphabetIndex() (int, error) {
	n := byte(len(UserCodeAlphabet))
	// The largest multiple of n that fits in a byte; anything at or above it is rejected.
	limit := byte(256 / int(n) * int(n))
	var buf [1]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("device: CSPRNG read failed: %w", err)
		}
		if buf[0] < limit {
			return int(buf[0] % n), nil
		}
	}
}

// NormalizeUserCode is `private fun normalizeUserCode(raw)` (DeviceAuth.kt:99-102).
//
// Fold a human-typed code back to the stored form: uppercase, keep only alphabet characters (RFC 8628
// §6.1's "strip readability punctuation"), then re-insert the single hyphen when exactly 8 survive. So
// `"wdjbmjht"` and `"WDJB-MJHT"` both fold to `"WDJB-MJHT"`.
//
// ⚠️ The fold-then-reformat is NOT length-clamped: a 5-character input stays 5 characters and simply
// matches nothing. Reproduced.
func NormalizeUserCode(raw string) string {
	upper := strings.ToUpper(raw)
	var bare strings.Builder
	bare.Grow(len(upper))
	for i := 0; i < len(upper); i++ {
		if strings.IndexByte(UserCodeAlphabet, upper[i]) >= 0 {
			bare.WriteByte(upper[i])
		}
	}
	out := bare.String()
	if len(out) == 8 {
		return out[:4] + "-" + out[4:]
	}
	return out
}

// Create is `fun create(handle, deviceCode, intervalSec, ttlSeconds, expiresAt, userCode = null)`
// (DeviceAuth.kt:124-142): INSERT, then re-read by handle.
//
// ⚠️ expiresAt is stamped from the CALLER's clock (`Timestamp.from(instant)`), not from the database's
// `now()` — the only place in this area where a deadline comes from the application clock. Reproduced
// verbatim, because DeviceLoginStoreDbTest case 5 creates an already-expired row by passing
// `Instant.now().minusSeconds(1)` and a `now() - interval` rewrite would make that test express
// something different.
//
// The re-read is the Kotlin's `get(handle)!!` and is kept rather than collapsed into a RETURNING: the
// defaults V6 fills in (`status`, `created_at`) must come back from the row, and a RETURNING would
// change which of the two statements is the one that can fail.
func (s *LoginStore) Create(
	ctx context.Context, handle string, deviceCode *string, intervalSec int, ttlSeconds int64,
	expiresAt time.Time, userCode *string,
) (*LoginRow, error) {
	_, err := s.db.Exec(ctx,
		`INSERT INTO device_login (handle, user_code, device_code, interval_sec, ttl_seconds, expires_at)
		     VALUES ($1, $2, $3, $4, $5, $6)`,
		handle, userCode, deviceCode, intervalSec, ttlSeconds, expiresAt)
	if err != nil {
		return nil, err
	}
	row, err := s.Get(ctx, handle)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// Kotlin's `!!`. Unreachable unless the row vanished between two statements.
		return nil, fmt.Errorf("device: created login %q is not readable back", handle)
	}
	return row, nil
}

// Get is `fun get(handle)` (DeviceAuth.kt:144-153). A missing row is (nil, nil), never an error.
func (s *LoginStore) Get(ctx context.Context, handle string) (*LoginRow, error) {
	return scanRow(s.db.QueryRow(ctx,
		`SELECT `+selectColumns+` FROM device_login WHERE handle = $1`, handle))
}

// GetByUserCode is `fun getByUserCode(userCode)` (DeviceAuth.kt:157-166) — the same read, but the
// argument is normalised first, so the lookup is case- and punctuation-insensitive.
func (s *LoginStore) GetByUserCode(ctx context.Context, userCode string) (*LoginRow, error) {
	return scanRow(s.db.QueryRow(ctx,
		`SELECT `+selectColumns+` FROM device_login WHERE user_code = $1`, NormalizeUserCode(userCode)))
}

// createPendingAttempts is the Kotlin's `attempts >= 5` bound — five Create calls at most.
const createPendingAttempts = 5

// CreatePending is `fun createPending(intervalSec, ttlSeconds, expiresAt)` (DeviceAuth.kt:169-179):
// one handle, then up to five user codes.
//
// Quoted from DeviceAuth.kt:164-168 on the retry: "Retries the user_code on the astronomically-rare
// unique-index collision (~40 bits, minutes-long TTL) rather than surfacing a 500; the handle is
// 192-bit so it never collides."
//
// 🔒 The handle is generated ONCE, OUTSIDE the loop, and only the code is redrawn. That is why the
// retry is safe: a retry cannot leave two rows for one login, because the first attempt's INSERT is
// the one that failed.
//
// The retry predicate is SQLSTATE 23505, read from the driver's structured error via
// [store.IsUniqueViolation] — never by matching on the message text, which is locale- and
// version-dependent. Any other SQLSTATE, or the fifth failure, propagates.
func (s *LoginStore) CreatePending(
	ctx context.Context, intervalSec int, ttlSeconds int64, expiresAt time.Time,
) (*LoginRow, error) {
	handle, err := s.NewHandle()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempts := 0; attempts < createPendingAttempts; attempts++ {
		userCode, err := s.NewUserCode()
		if err != nil {
			return nil, err
		}
		row, err := s.Create(ctx, handle, nil, intervalSec, ttlSeconds, expiresAt, &userCode)
		if err == nil {
			return row, nil
		}
		if !store.IsUniqueViolation(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// MarkApproved is `fun markApproved(handle, principal, refreshToken = null): Boolean`
// (DeviceAuth.kt:186-198).
//
// 🔒 INV-A4-42 — approval is a COMPARE-AND-SET on (PENDING, unexpired), and the RETURN VALUE IS THE
// TRUTH. Quoted from DeviceAuth.kt:181-185: "A CAS on (PENDING, unexpired) — the return value is the
// truth." The route must branch on it, not assume success. DeviceLoginStoreDbTest cases 4 and 5 pin
// approve-only-once and refuse-expired: re-approving an already-APPROVED row is a no-op, so "a second
// IdP exchange for the same handle must not silently switch the winning principal."
//
// 🔒 INV-A4-14 — refreshToken is encrypted at rest, and when crypto is nil it is simply DROPPED. The
// column takes NULL rather than plaintext; there is no fallback.
func (s *LoginStore) MarkApproved(ctx context.Context, handle, principal string, refreshToken *string) (bool, error) {
	var encrypted []byte
	if refreshToken != nil && s.crypto != nil {
		var err error
		encrypted, err = s.crypto.Encrypt([]byte(*refreshToken))
		if err != nil {
			return false, fmt.Errorf("device: encrypt refresh token: %w", err)
		}
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE device_login SET status = 'APPROVED', principal = $1, refresh_token_enc = $2
		     WHERE handle = $3 AND status = 'PENDING' AND expires_at > now()`,
		principal, encrypted, handle)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DecryptRefresh is `fun decryptRefresh(row): String?` (DeviceAuth.kt:201) —
// `row.refreshTokenEnc?.let { crypto?.decrypt(it) }` as UTF-8.
//
// Nil for a debug login, for a login with no offline_access, or when no key is configured. Note the
// double safe-call: a stored ciphertext with no key today yields nil rather than an error.
func (s *LoginStore) DecryptRefresh(row *LoginRow) (*string, error) {
	if row == nil || row.RefreshTokenEnc == nil || s.crypto == nil {
		return nil, nil
	}
	plain, err := s.crypto.Decrypt(row.RefreshTokenEnc)
	if err != nil {
		return nil, fmt.Errorf("device: decrypt refresh token: %w", err)
	}
	out := string(plain)
	return &out, nil
}

// Consume is `fun consume(handle): Boolean` (DeviceAuth.kt:210-218).
//
// 🔒 INV-A4-43 — THE ONE-TIME CLAIM IS WHAT BOUNDS A DEVICE HANDLE TO EXACTLY ONE CREDENTIAL SET.
// Quoted from DeviceAuth.kt:203-209: "Returns true only for the single caller that wins the
// transition; false for any replay/race on an already-consumed (or never-approved / expired) handle.
// The poll endpoint gates minting on this, which is what makes a device handle yield EXACTLY one
// SESSION token + one `pmr_` renewal secret — without it, re-polling an approved handle re-mints a
// fresh renewal secret on every call, turning a short-lived login handle into an unbounded
// credential-minting handle."
//
// It is a single atomic UPDATE with the state in the WHERE clause, which is what makes it a race
// winner rather than a check-then-act. DeviceLoginStoreDbTest case 14 is the end-to-end regression.
func (s *LoginStore) Consume(ctx context.Context, handle string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE device_login SET status = 'CONSUMED'
		     WHERE handle = $1 AND status = 'APPROVED' AND expires_at > now()`, handle)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// PurgeExpired is `fun purgeExpired(): Int` (DeviceAuth.kt:221) — "delete every expired row;
// device-auth attempts are short-lived; nothing to keep past expiry."
//
// Backed by `idx_device_login_expires_at`. Run from A1's 60-second timer loop (App.kt:408) and nowhere
// else.
//
//	TODO(A1): wire this into the background sweep alongside the session purge.
func (s *LoginStore) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM device_login WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// scanRow is `private fun ResultSet.toRow()` (DeviceAuth.kt:225-237) plus the `if (rs.next())` its
// two callers wrap it in.
func scanRow(row pgx.Row) (*LoginRow, error) {
	var r LoginRow
	err := row.Scan(&r.ID, &r.Handle, &r.UserCode, &r.DeviceCode, &r.IntervalSec, &r.TTLSeconds,
		&r.Status, &r.Principal, &r.RefreshTokenEnc, &r.CreatedAt, &r.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}
