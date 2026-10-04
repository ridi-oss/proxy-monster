package instant

import (
	"testing"
	"time"
)

// TestFormatMatchesJavaInstantToString pins the four branches of Instant.toString()'s fraction rule.
// The expected strings are what java.time.Instant.toString() prints for the same moments; a Go
// time.RFC3339Nano rendering would differ on two of the four (it trims trailing zeros digit by
// digit, so the millisecond case would print ".12" and the microsecond case ".000001").
func TestFormatMatchesJavaInstantToString(t *testing.T) {
	base := time.Date(2026, 8, 1, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name string
		in   time.Time
		want string
	}{
		{"no fraction", base, "2026-08-01T03:04:05Z"},
		{"whole second at :00", time.Date(2026, 8, 1, 3, 4, 0, 0, time.UTC), "2026-08-01T03:04:00Z"},
		{"milliseconds print 3 digits", base.Add(120 * time.Millisecond), "2026-08-01T03:04:05.120Z"},
		{"microseconds print 6 digits", base.Add(1 * time.Microsecond), "2026-08-01T03:04:05.000001Z"},
		{"nanoseconds print 9 digits", base.Add(1 * time.Nanosecond), "2026-08-01T03:04:05.000000001Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Format(tc.in); got != tc.want {
				t.Errorf("Format(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFormatNormalisesToUTC — Instant has no zone, so a timestamp read back in any offset renders as
// the same UTC instant.
func TestFormatNormalisesToUTC(t *testing.T) {
	zone := time.FixedZone("KST", 9*60*60)
	got := Format(time.Date(2026, 8, 1, 12, 0, 0, 0, zone))
	if want := "2026-08-01T03:00:00Z"; got != want {
		t.Errorf("Format(+09:00) = %q, want %q", got, want)
	}
}

func TestFormatPtrKeepsNullAbsent(t *testing.T) {
	if got := FormatPtr(nil); got != nil {
		t.Errorf("FormatPtr(nil) = %q, want nil", *got)
	}
	ts := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if got := FormatPtr(&ts); got == nil || *got != "2026-08-01T00:00:00Z" {
		t.Errorf("FormatPtr(%v) = %v, want 2026-08-01T00:00:00Z", ts, got)
	}
}
