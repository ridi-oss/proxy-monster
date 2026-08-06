package audit

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/gocp/internal/instant"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ChainVersion is AuditCanonical.CHAIN_VERSION, re-exported from canon so nothing in this package
// re-declares it. It is stamped into audit_event.chain_version on every appended row.
const ChainVersion = canon.ChainVersion

// sha256Bytes is AuditStore.kt's SHA256_BYTES. Both the head hash read under the lock and the
// prev_hash canon.RowHash requires are exactly this wide.
const sha256Bytes = 32

// ToCanon adapts the WIRE audit event (internal/types) to the CANONICAL one (auditmon/canon).
//
// The two shapes differ in exactly two places and nowhere else:
//
//   - ts. types.AuditEvent carries it as an ISO-8601 *string (the value the proxy posted, or nil);
//     canon.AuditEvent carries the epoch-microsecond int64 that actually goes into the hash. The
//     caller supplies tsMicros because only the store knows which instant won — rec.ts when supplied,
//     time.Now() when not (INV-A8-3) — and because it must be the ALREADY-TRUNCATED value (INV-A8-2).
//   - decision. types.Decision is a validated named string; canon's is a plain string. The Kotlin
//     hashes `event.decision.name`, so this is a straight conversion of the same characters.
//
// Everything else is field-for-field. The nil-slice normalisation is not a nicety: canon.writeArray
// encodes u32be(len) and a nil slice has len 0, so it would hash identically — but reproducing
// Kotlin's emptyList() here keeps the conversion total rather than accidentally correct.
//
// 🔒 The field ORDER is canon's, not this struct literal's: canon.writeFields owns the 22-field order
// and a named-field literal cannot get it wrong. Do not "simplify" this into a positional literal.
func ToCanon(rec types.AuditEvent, tsMicros int64) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:               rec.Kind,
		TSMicros:           tsMicros,
		Principal:          rec.Principal,
		Roles:              orEmpty(rec.Roles),
		Datasource:         rec.Datasource,
		ClientAddr:         rec.ClientAddr,
		Statement:          rec.Statement,
		Decision:           string(rec.Decision),
		FailedStage:        rec.FailedStage,
		EffectiveNamespace: orEmpty(rec.EffectiveNamespace),
		MaskedColumns:      orEmpty(rec.MaskedColumns),
		PIITouched:         orEmpty(rec.PIITouched),
		LatencyMs:          rec.LatencyMs,
		Detail:             rec.Detail,
		Channel:            rec.Channel,
		ContextTags:        orEmpty(rec.ContextTags),
		AuthzAction:        rec.AuthzAction,
		AuthzResource:      rec.AuthzResource,
		Outcome:            rec.Outcome,
		RowsReturned:       rec.RowsReturned,
		BytesReturned:      rec.BytesReturned,
		DecisionID:         rec.DecisionID,
	}
}

// Canonical is AuditCanonical.canonical(event, tsMicros) over the wire type.
func Canonical(rec types.AuditEvent, tsMicros int64) []byte {
	return canon.Canonical(ToCanon(rec, tsMicros), ChainVersion)
}

// RowHash is AuditCanonical.rowHash(id, event, tsMicros, prevHash) over the wire type. prevHash must
// be exactly 32 bytes; canon enforces that (the Kotlin's `require`).
func RowHash(id int64, rec types.AuditEvent, tsMicros int64, prevHash []byte) ([]byte, error) {
	return canon.RowHash(id, ToCanon(rec, tsMicros), ChainVersion, prevHash)
}

// EpochMicros is AuditCanonical.epochMicros. Delegated rather than reimplemented.
//
// The Kotlin uses Math.multiplyExact/addExact, so an instant far enough outside the epoch to overflow
// an int64 of microseconds THROWS. Go wraps silently instead. That is unreachable through either
// caller — Postgres timestamptz tops out at 294276 AD, ~9.2e18 µs is ~292277 AD away from 1970, and
// the two are close enough that the overflow band lies outside what the column can hold — but it is a
// language-forced divergence and is recorded as one rather than papered over here, because canon is
// shared with auditmon and must not grow a control-plane-only guard.
func EpochMicros(t time.Time) int64 { return canon.EpochMicros(t) }

// TruncateToMicros is Instant.truncatedTo(ChronoUnit.MICROS).
//
// 🔒 INV-A8-2. Truncation happens BEFORE both the hash and the INSERT, so the microseconds hashed are
// the microseconds Postgres stores. Skip it and every row fails verification, which is
// indistinguishable from tampering.
//
// Go's time.Time.Truncate is deliberately NOT used: it rounds down relative to the zero time and
// strips the monotonic clock reading, which is the right answer here but for reasons that would have
// to be re-derived by every reader. Zeroing the sub-microsecond part of Nanosecond() is what Java
// does, spelled out: Instant guarantees nano ∈ [0, 1e9) and so does Go's Nanosecond(), so the integer
// division floors for every instant, pre-1970 ones included.
func TruncateToMicros(t time.Time) time.Time {
	return time.Unix(t.Unix(), int64(t.Nanosecond()/1_000)*1_000).UTC()
}

// ParseInstant is Instant.parse.
//
// Divergence, language-forced and narrow: Java's ISO_INSTANT and Go's RFC3339Nano agree on everything
// the proxy emits (`2026-07-01T01:02:03.123456789Z`, `2026-07-01T00:00:00Z`, and offset forms like
// `+09:00`), but the two grammars are not identical at the edges — Java accepts years outside
// 0000..9999 with an explicit sign, Go's layout does not. No caller can reach that band: the value is
// on its way into a timestamptz column.
//
// A parse failure is returned, not defaulted. The Kotlin throws DateTimeParseException out of insert,
// which fails the enclosing operation closed; substituting time.Now() here would silently record a
// decision at the wrong instant, and the timestamp is hashed.
func ParseInstant(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("audit: ts %q is not an ISO-8601 instant: %w", s, err)
	}
	return t, nil
}

// FormatInstant is Java's Instant.toString() — the rendering AuditStore.toRecord() puts on `ts` via
// `getTimestamp("ts")?.toInstant()?.toString()`.
//
// ⚠️ Wire-visible (08-audit.md §1, Q2). Java's ISO_INSTANT printer emits a VARIABLE-PRECISION fraction:
// none when the nanosecond field is zero, otherwise 3, 6 or 9 digits — the first of those that loses
// nothing. Go's time.RFC3339Nano is NOT the same function; it strips trailing zeros one at a time, so
// 100ms prints as `.1` where Java prints `.100`.
//
// REUSED, not reimplemented: internal/instant.Format is that renderer, and its own doc carries a
// TODO(A8) offering it to this package. A8 needs it at exactly one site (`ts`), so this is a named
// seam rather than a call to instant.Format buried inside toRecord — the invariant is A8's even though
// the function is not.
//
// AuditChainDbTest case 1 pins the composition: it feeds `2026-07-01T01:02:03.123456789Z` and asserts
// the row reads back as `2026-07-01T01:02:03.123456Z`, which needs TruncateToMicros AND this renderer.
// TestFormatInstantMatchesJavaInstantToString keeps the shared function honest from A8's side, which
// is worth having twice: if instant.Format ever drifts, A8's hash-adjacent wire contract finds out.
func FormatInstant(t time.Time) string { return instant.Format(t) }

// orEmpty is the nil-slice guard. Kotlin's List<String> is non-null, so [] is the only empty a Kotlin
// AuditEvent can hold; a Go nil slice is an artifact with no counterpart and normalising it is
// REPRODUCING emptyList(), not improving on it. Same reasoning as types.AuditEvent's MarshalJSON.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// parseKotlinInt is Kotlin's String.toIntOrNull(): base 10, an optional leading sign, and — the part
// Go's strconv.Atoi does NOT reproduce on a 64-bit platform — a value outside the 32-bit Int range is
// NOT a number, it is null.
//
// This matters at exactly one call site, CoerceLimit. `?limit=3000000000` is null to Kotlin and so
// falls back to the default 100; strconv.Atoi would parse it into a 64-bit int and coerceIn would then
// clamp it to 500. Two different observable answers for one query string.
func parseKotlinInt(s string) (int, bool) {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return int(v), true
}
