// Package instant renders a database timestamp exactly as java.time.Instant.toString() does.
//
// Every DTO the control plane puts on the wire carries its timestamps as STRINGS produced by
// `getTimestamp(col)?.toInstant()?.toString()` — AccessRequest's six, QueryResultMeta's two,
// AuditRecord's `ts`, AccessGrant's three. 06-query-decision.md:337 flags the shape: "All timestamps
// are Java Instant.toString() (variable precision) — same wire concern as A2/A8", and 08-audit.md:62
// repeats it. The formatting is therefore wire-visible, not an implementation detail, and 08-audit.md
// Q2 leaves changing it explicitly OPEN ("confirm web/ tolerates fixed-precision RFC3339 before
// changing it"). Until that question is answered the port REPRODUCEs the Java rendering.
//
// Go's time.RFC3339Nano is NOT that rendering: it strips trailing zeros one digit at a time
// (".12" is possible), while Java emits the fraction in groups of 3 or 9 digits, or not at all.
//
// TODO(A2)/TODO(A8): A2's AccessGrant-adjacent DTOs and A8's AuditStore need the same function. It
// lives in its own package rather than in internal/types so that landing it here does not edit a
// package another area is concurrently porting; fold it into whichever shared package the areas
// settle on once they are all in.
package instant

import "time"

// Format renders t the way java.time.Instant.toString() renders the same moment.
//
// Java's rule (DateTimeFormatter.ISO_INSTANT with fractionalDigits = -2), reproduced verbatim:
//
//   - always UTC, always suffixed 'Z';
//   - seconds are ALWAYS printed, even at :00 (unlike LocalDateTime.toString());
//   - the fraction is omitted when the nanosecond field is zero, and otherwise printed in whole
//     groups of three — 3 digits when the value is a whole millisecond, 6 when it is a whole
//     microsecond, 9 otherwise.
//
// PostgreSQL's TIMESTAMPTZ resolution is microseconds, so only the first three branches can be
// reached from a stored column; the 9-digit branch exists because Instant.toString() has it.
func Format(t time.Time) string {
	u := t.UTC()
	switch ns := u.Nanosecond(); {
	case ns == 0:
		// Go's layout parser reads a bare trailing "Z" as the start of "Z07:00", so the zone
		// designator is appended as a literal rather than written into the layout.
		return u.Format("2006-01-02T15:04:05") + "Z"
	case ns%1_000_000 == 0:
		return u.Format("2006-01-02T15:04:05.000") + "Z"
	case ns%1_000 == 0:
		return u.Format("2006-01-02T15:04:05.000000") + "Z"
	default:
		return u.Format("2006-01-02T15:04:05.000000000") + "Z"
	}
}

// FormatPtr is Format over a nullable column: `getTimestamp(col)?.toInstant()?.toString()`. A NULL
// timestamp stays absent from the JSON rather than becoming an empty string (INV-A1-4).
func FormatPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := Format(*t)
	return &s
}
