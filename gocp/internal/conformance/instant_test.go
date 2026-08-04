package conformance

import (
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/audit"
	"github.com/ridi-oss/proxy-monster/gocp/internal/instant"
)

// ============================================================================================
// CONTRACT 4 — timestamp rendering.
//
// ORACLE: the rule, not a fixture. `java.time.Instant.toString()` is DateTimeFormatter.ISO_INSTANT
// with fractionalDigits = -2, which emits the fraction in whole groups of 3 or 9 digits — or omits it
// entirely when the nanosecond field is zero. internal/instant's package doc states the rule and
// 06-query-decision.md:337 / 08-audit.md:62 record that the rendering is WIRE-VISIBLE, not an
// implementation detail ("All timestamps are Java Instant.toString() (variable precision) — same wire
// concern as A2/A8").
//
// One composition of it IS pinned by a Kotlin assertion: AuditChainDbTest case 1 feeds
// 2026-07-01T01:02:03.123456789Z and asserts the row reads back as 2026-07-01T01:02:03.123456Z, which
// needs micro-truncation AND this renderer (cited at internal/audit/canon.go's FormatInstant doc).
// TestTruncationThenRenderingReproducesTheKotlinRoundTrip below replays that composition end to end.
//
// WHY IT IS A CONFORMANCE CONCERN AND NOT A UNIT DETAIL: Go's time.RFC3339Nano is a DIFFERENT
// function. It strips trailing zeros ONE DIGIT AT A TIME, so it can emit `.12`, a precision Java never
// produces. Anywhere the port reaches for RFC3339Nano instead of instant.Format, the wire silently
// changes shape for every timestamp whose fraction ends in a zero — roughly a tenth of all of them,
// which is frequent enough to be noticed by a consumer and rare enough to pass a hand-written test.
// So every row below asserts BOTH what Java produces and whether RFC3339Nano happens to agree.
// ============================================================================================

// instantCase is one rendering. wantRFC3339NanoAgrees is asserted, not merely documented: the `false`
// rows ARE the reason instant.Format exists, and if a future Go release changed RFC3339Nano's
// trailing-zero handling this suite should say so rather than let the divergence quietly vanish.
type instantCase struct {
	name                  string
	nanos                 int // the sub-second field
	want                  string
	wantRFC3339NanoAgrees bool
}

// base is 2026-07-01T01:02:03Z. Every case varies only the nanosecond field, so the fraction rule is
// the only thing under test.
var instantBase = time.Date(2026, 7, 1, 1, 2, 3, 0, time.UTC)

func TestInstantFormatReproducesJavaInstantToString(t *testing.T) {
	cases := []instantCase{
		// --- boundary: NO fraction. Java omits it entirely when the nanosecond field is zero.
		{"zero fraction", 0, "2026-07-01T01:02:03Z", true},

		// --- boundary: exactly 3 digits (a whole millisecond).
		{"3 digits", 123_000_000, "2026-07-01T01:02:03.123Z", true},
		// 🔴 the trailing-zero case the brief names. .120000000 is a whole millisecond, so Java prints
		// THREE digits: .120. RFC3339Nano strips the final zero and prints .12 — a two-digit fraction
		// Java cannot emit.
		{"3 digits, trailing zero (.120000000)", 120_000_000, "2026-07-01T01:02:03.120Z", false},
		// The same failure one step further: .100000000 → Java .100, RFC3339Nano .1.
		{"3 digits, two trailing zeros (.100000000)", 100_000_000, "2026-07-01T01:02:03.100Z", false},
		// A leading zero inside the group must survive: 10ms is .010, not .10 and not .01.
		{"3 digits, leading zero (.010000000)", 10_000_000, "2026-07-01T01:02:03.010Z", false},
		{"3 digits, one millisecond (.001000000)", 1_000_000, "2026-07-01T01:02:03.001Z", true},

		// --- boundary: exactly 6 digits (a whole microsecond that is NOT a whole millisecond).
		// This is the only branch a Postgres timestamptz column can reach with a non-round value.
		{"6 digits", 123_456_000, "2026-07-01T01:02:03.123456Z", true},
		{"6 digits, trailing zero (.123450000)", 123_450_000, "2026-07-01T01:02:03.123450Z", false},
		{"6 digits, leading zeros (.000100000)", 100_000, "2026-07-01T01:02:03.000100Z", false},
		{"6 digits, one microsecond (.000001000)", 1_000, "2026-07-01T01:02:03.000001Z", true},

		// --- boundary: 9 digits (sub-microsecond precision; unreachable from a stored column, but
		// Instant.toString() has the branch and an ingest-supplied `ts` string can carry it).
		{"9 digits", 123_456_789, "2026-07-01T01:02:03.123456789Z", true},
		{"9 digits, trailing zero (.123456780)", 123_456_780, "2026-07-01T01:02:03.123456780Z", false},
		{"9 digits, one nanosecond (.000000001)", 1, "2026-07-01T01:02:03.000000001Z", true},
		{"9 digits, all nines (.999999999)", 999_999_999, "2026-07-01T01:02:03.999999999Z", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := instantBase.Add(time.Duration(c.nanos))
			if got := instant.Format(ts); got != c.want {
				t.Errorf("instant.Format = %q, want %q", got, c.want)
			}
			rfc := ts.UTC().Format(time.RFC3339Nano)
			if agrees := rfc == c.want; agrees != c.wantRFC3339NanoAgrees {
				t.Errorf("time.RFC3339Nano gave %q; agreement with Java (%q) = %v, want %v",
					rfc, c.want, agrees, c.wantRFC3339NanoAgrees)
			}
		})
	}
}

// TestRFC3339NanoIsWrongOnAtLeastOneCaseInEveryFractionGroup is a meta-assertion on the table above.
//
// Without it, a well-meaning edit could delete every disagreeing row and leave a suite that passes
// while proving nothing — the exact failure mode "never weaken a test to get green" is about. Each of
// the three fraction widths must retain at least one case where Go's own formatter is WRONG, because
// those are the only cases that distinguish instant.Format from a one-line RFC3339Nano call.
func TestRFC3339NanoIsWrongOnAtLeastOneCaseInEveryFractionGroup(t *testing.T) {
	groups := map[string]bool{"3": false, "6": false, "9": false}
	for _, c := range []struct {
		group string
		nanos int
		want  string
	}{
		{"3", 120_000_000, "2026-07-01T01:02:03.120Z"},
		{"6", 100_000, "2026-07-01T01:02:03.000100Z"},
		{"9", 123_456_780, "2026-07-01T01:02:03.123456780Z"},
	} {
		ts := instantBase.Add(time.Duration(c.nanos))
		if instant.Format(ts) != c.want {
			t.Fatalf("group %s: instant.Format = %q, want %q", c.group, instant.Format(ts), c.want)
		}
		if ts.UTC().Format(time.RFC3339Nano) != c.want {
			groups[c.group] = true
		}
	}
	for g, disagreed := range groups {
		if !disagreed {
			t.Errorf("fraction group %s: RFC3339Nano now AGREES on the discriminating case — "+
				"either Go changed or the case was neutered; do not delete it, investigate", g)
		}
	}
}

// TestInstantFormatAlwaysPrintsSecondsAndAlwaysUTC pins the two parts of ISO_INSTANT that are not
// about the fraction.
//
//   - Seconds are ALWAYS printed, even at :00. This is where Instant.toString() differs from
//     LocalDateTime.toString(), which drops a zero seconds field — an easy thing to reproduce with the
//     wrong Java method in mind.
//   - The rendering is ALWAYS UTC with a literal 'Z'. A non-UTC time.Time must be converted, not
//     rendered with its own offset: `+09:00` on an audit `ts` would be a different string for the
//     same instant, and the string is what the UI and auditmon compare.
func TestInstantFormatAlwaysPrintsSecondsAndAlwaysUTC(t *testing.T) {
	midnight := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if got, want := instant.Format(midnight), "2026-07-01T00:00:00Z"; got != want {
		t.Errorf("zero seconds: got %q, want %q — Instant.toString() always prints seconds", got, want)
	}

	seoul := time.FixedZone("KST", 9*60*60)
	local := time.Date(2026, 7, 1, 10, 2, 3, 123_000_000, seoul)
	if got, want := instant.Format(local), "2026-07-01T01:02:03.123Z"; got != want {
		t.Errorf("non-UTC input: got %q, want %q — the rendering is always UTC with a literal Z", got, want)
	}
}

// TestInstantFormatOnPreEpochInstants covers the sign boundary.
//
// Java's Instant keeps `nano` in [0, 1e9) for pre-1970 instants too (the second field carries the
// sign), and so does Go's Nanosecond(). If either had used a negative nanosecond field the fraction
// would render as a negative number of digits' worth of garbage; both do not, and this pins it on the
// one side we can execute.
func TestInstantFormatOnPreEpochInstants(t *testing.T) {
	// Apollo 11 touchdown, plus a fraction.
	ts := time.Date(1969, 7, 20, 20, 17, 40, 123_456_000, time.UTC)
	if got, want := instant.Format(ts), "1969-07-20T20:17:40.123456Z"; got != want {
		t.Errorf("pre-epoch: got %q, want %q", got, want)
	}
	if ts.Nanosecond() < 0 {
		t.Fatal("Go's Nanosecond() returned a negative value for a pre-epoch instant")
	}
}

// TestTruncationThenRenderingReproducesTheKotlinRoundTrip is the one composition an actual Kotlin
// assertion pins: AuditChainDbTest case 1 feeds `2026-07-01T01:02:03.123456789Z` and asserts the row
// reads back as `2026-07-01T01:02:03.123456Z`.
//
// Two independent rules have to hold for that to come out: INV-A8-2's truncate-to-micros BEFORE the
// hash and the INSERT, and this renderer's 6-digit branch. Either one alone gives a different answer —
// truncation without the renderer is the same string here but diverges the moment the value ends in a
// zero, and the renderer without truncation gives `.123456789Z`.
func TestTruncationThenRenderingReproducesTheKotlinRoundTrip(t *testing.T) {
	const in = "2026-07-01T01:02:03.123456789Z"
	const want = "2026-07-01T01:02:03.123456Z"

	parsed, err := audit.ParseInstant(in)
	if err != nil {
		t.Fatalf("ParseInstant(%q): %v", in, err)
	}
	if got := audit.FormatInstant(audit.TruncateToMicros(parsed)); got != want {
		t.Errorf("truncate+format = %q, want %q", got, want)
	}
	// Without truncation the renderer alone does NOT produce the pinned string — proving both rules
	// are load-bearing rather than one masking the other.
	if got := audit.FormatInstant(parsed); got == want {
		t.Error("the renderer alone reproduced the truncated string; INV-A8-2 would be untested here")
	}
}

// TestAuditFormatInstantIsTheSameFunctionAsInstantFormat guards the seam.
//
// internal/audit re-exports the renderer rather than reimplementing it (canon.go's FormatInstant), and
// A8 is the one caller whose output is hash-adjacent. If the two ever diverge — say because someone
// "optimises" one of them — the audit wire contract moves while instant's own unit tests stay green.
func TestAuditFormatInstantIsTheSameFunctionAsInstantFormat(t *testing.T) {
	for _, nanos := range []int{0, 1, 1_000, 100_000, 1_000_000, 10_000_000, 120_000_000, 123_456_780, 999_999_999} {
		ts := instantBase.Add(time.Duration(nanos))
		if a, b := audit.FormatInstant(ts), instant.Format(ts); a != b {
			t.Errorf("nanos=%d: audit.FormatInstant = %q but instant.Format = %q", nanos, a, b)
		}
	}
}

// TestFormatPtrOmitsAnAbsentTimestamp is INV-A1-4 meeting the renderer: a NULL timestamptz column
// stays ABSENT from the JSON, and must not become an empty string or the zero instant.
func TestFormatPtrOmitsAnAbsentTimestamp(t *testing.T) {
	if got := instant.FormatPtr(nil); got != nil {
		t.Errorf("FormatPtr(nil) = %q, want nil", *got)
	}
	ts := instantBase.Add(120 * time.Millisecond)
	got := instant.FormatPtr(&ts)
	if got == nil {
		t.Fatal("FormatPtr(&ts) = nil, want a rendered string")
	}
	if *got != "2026-07-01T01:02:03.120Z" {
		t.Errorf("FormatPtr = %q, want %q", *got, "2026-07-01T01:02:03.120Z")
	}
}
