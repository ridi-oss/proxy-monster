package audit

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// goldenFixtureRelPath is where AuditCanonicalGoldenTest's vectors live TODAY.
//
// ⚠️ 08-audit.md §4 and Q1 flag this as a concrete cutover task: the fixture sits under the Kotlin
// module's test resources and auditmon/canon reads it through a fixed `../../` hop. When the Kotlin
// module is deleted, BOTH readers break. The lookup below walks up from the working directory instead
// of hardcoding a depth (the same shape as dbtest's findUpwards, and for the same F9 reason), so this
// test survives a move within the repo — but the fixture still needs a language-neutral home and
// auditmon/canon/canonical_test.go:90 still needs the one-line change.
const goldenFixtureRelPath = "control-plane/src/test/resources/atrail/canonical-golden.json"

type goldenCase struct {
	Name         string           `json:"name"`
	ID           int64            `json:"id"`
	PrevHashHex  string           `json:"prevHashHex"`
	Event        types.AuditEvent `json:"event"`
	CanonicalHex string           `json:"canonicalHex"`
	RowHashHex   string           `json:"rowHashHex"`
}

type goldenFixture struct {
	DomainSep    string       `json:"domainSep"`
	ChainVersion uint32       `json:"chainVersion"`
	Cases        []goldenCase `json:"cases"`
}

func loadGolden(t *testing.T) goldenFixture {
	t.Helper()
	path := findUpwards(t, goldenFixtureRelPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", path, err)
	}
	var fx goldenFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal golden fixture %s: %v", path, err)
	}
	return fx
}

func findUpwards(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, filepath.FromSlash(rel))
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("%s not found walking up from the working directory", rel)
		}
		dir = parent
	}
}

// TestGoldenVectorsThroughTypesAuditEvent is A8 case 1 (AuditCanonicalGoldenTest) re-run through THIS
// package's conversion.
//
// auditmon/canon already asserts the same fixture against canon.AuditEvent, so what this adds is the
// only part that is genuinely new in the control plane: ToCanon. It decodes each vector into
// internal/types.AuditEvent — the wire type, with its own UnmarshalJSON, its validated Decision and
// its *string ts — converts, and demands the SAME canonical bytes and the SAME row hash.
//
// That is what makes the conversion safe to write at all. The task brief's rule was "if canon's shape
// differs from internal/types.AuditEvent, write a conversion and test it against the golden fixture —
// do not fork the format". The two shapes DO differ (ts *string vs TSMicros int64; types.Decision vs
// string), and this is the test that keeps the adapter honest: a mis-wired field — say PIITouched
// bound to MaskedColumns — changes the bytes and fails here, exactly as it would in the Kotlin.
//
// KT: AuditCanonicalGoldenTest.kt#canonical bytes and row hashes match the cross-language golden vectors
//
//	The conversion half of the split; internal/conformance TestGoldenCanonicalBytesAndRowHashes is
//	the other.
func TestGoldenVectorsThroughTypesAuditEvent(t *testing.T) {
	fx := loadGolden(t)
	// AuditCanonicalGoldenTest.kt:17 — `assertEquals("pm-audit-event", fixture.domainSep)`. The Kotlin
	// pins the literal; this pins it against the shipped constant, so a fixture regenerated with a
	// different domain separator (or a constant edited to match a bad fixture) fails here rather than
	// silently agreeing with itself.
	if fx.DomainSep != string(canon.DomainSep) {
		t.Fatalf("fixture domainSep = %q, want %q", fx.DomainSep, canon.DomainSep)
	}
	if fx.DomainSep != "pm-audit-event" {
		t.Fatalf("fixture domainSep = %q, want the cross-language literal %q", fx.DomainSep, "pm-audit-event")
	}
	if fx.ChainVersion != ChainVersion {
		t.Fatalf("fixture chainVersion = %d, want %d", fx.ChainVersion, ChainVersion)
	}
	if len(fx.Cases) != 6 {
		t.Fatalf("fixture cases = %d, want 6", len(fx.Cases))
	}

	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Event.TS == nil {
				t.Fatalf("fixture case %s has no ts", c.Name)
			}
			ts, err := ParseInstant(*c.Event.TS)
			if err != nil {
				t.Fatalf("parse ts %q: %v", *c.Event.TS, err)
			}
			tsMicros := EpochMicros(TruncateToMicros(ts))

			if got := hex.EncodeToString(Canonical(c.Event, tsMicros)); got != c.CanonicalHex {
				t.Errorf("canonical bytes:\n got  %s\n want %s", got, c.CanonicalHex)
			}

			prev, err := hex.DecodeString(c.PrevHashHex)
			if err != nil {
				t.Fatalf("decode prevHashHex: %v", err)
			}
			rowHash, err := RowHash(c.ID, c.Event, tsMicros, prev)
			if err != nil {
				t.Fatalf("RowHash: %v", err)
			}
			if got := hex.EncodeToString(rowHash); got != c.RowHashHex {
				t.Errorf("row hash:\n got  %s\n want %s", got, c.RowHashHex)
			}
		})
	}
}

// TestRowHashRejectsWrongPrevHashLength is A8 case 2 (AuditCanonicalGoldenTest) at this package's
// boundary: the 32-byte requirement survives the conversion wrapper rather than being enforced only
// inside canon. It is also the guard InsertOn leans on for a corrupted genesis head.
//
// KT: AuditCanonicalGoldenTest.kt#row hash rejects a previous hash with the wrong length
func TestRowHashRejectsWrongPrevHashLength(t *testing.T) {
	rec := types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow)
	for _, size := range []int{0, 31, 33} {
		if _, err := RowHash(1, rec, 0, make([]byte, size)); err == nil {
			t.Errorf("RowHash accepted a %d-byte prev_hash", size)
		}
	}
	if _, err := RowHash(1, rec, 0, make([]byte, sha256Bytes)); err != nil {
		t.Errorf("RowHash rejected a 32-byte prev_hash: %v", err)
	}
}

// TestTruncateToMicros pins INV-A8-2 directly: sub-microsecond nanos are dropped, and the value fed to
// EpochMicros is therefore the value Postgres stores.
func TestTruncateToMicros(t *testing.T) {
	cases := []struct {
		in       string
		wantNano int
	}{
		{"2026-07-01T01:02:03.123456789Z", 123456000},
		{"2026-07-01T01:02:03.999999999Z", 999999000},
		{"2026-07-01T01:02:03.000000001Z", 0},
		{"2026-07-01T01:02:03Z", 0},
		{"1969-07-20T20:17:40.123456789Z", 123456000}, // pre-epoch: nano is still non-negative
	}
	for _, c := range cases {
		parsed, err := ParseInstant(c.in)
		if err != nil {
			t.Fatalf("parse %s: %v", c.in, err)
		}
		got := TruncateToMicros(parsed)
		if got.Nanosecond() != c.wantNano {
			t.Errorf("TruncateToMicros(%s).Nanosecond() = %d, want %d", c.in, got.Nanosecond(), c.wantNano)
		}
		if EpochMicros(got) != EpochMicros(parsed) {
			t.Errorf("%s: truncation changed the microsecond value", c.in)
		}
	}
}

// TestFormatInstantMatchesJavaInstantToString pins the variable-precision rendering AuditStore's
// toRecord() puts on the wire. Go's time.RFC3339Nano would disagree on four of these six.
func TestFormatInstantMatchesJavaInstantToString(t *testing.T) {
	cases := []struct {
		in, want string
		// rfcAgrees records whether Go's own time.RFC3339Nano happens to produce the same string. It is
		// asserted, not just noted: the four `false` rows are the reason this function has to exist at
		// all, and if a future Go release changed RFC3339Nano's trailing-zero handling the assertion
		// would tell us rather than the difference quietly disappearing.
		rfcAgrees bool
	}{
		{"2026-07-01T01:02:03Z", "2026-07-01T01:02:03Z", true},
		{"2026-07-01T01:02:03.100000000Z", "2026-07-01T01:02:03.100Z", false},
		{"2026-07-01T01:02:03.120000000Z", "2026-07-01T01:02:03.120Z", false},
		{"2026-07-01T01:02:03.123456000Z", "2026-07-01T01:02:03.123456Z", true},
		{"2026-07-01T01:02:03.000001000Z", "2026-07-01T01:02:03.000001Z", true},
		{"2026-07-01T01:02:03.123000000Z", "2026-07-01T01:02:03.123Z", true},
		{"2026-07-01T01:02:03.000000001Z", "2026-07-01T01:02:03.000000001Z", true},
		{"2026-07-01T01:02:03.123456780Z", "2026-07-01T01:02:03.123456780Z", false},
	}
	for _, c := range cases {
		parsed, err := ParseInstant(c.in)
		if err != nil {
			t.Fatalf("parse %s: %v", c.in, err)
		}
		if got := FormatInstant(parsed); got != c.want {
			t.Errorf("FormatInstant(%s) = %s, want %s", c.in, got, c.want)
		}
		rfc := parsed.UTC().Format(time.RFC3339Nano)
		if agrees := rfc == c.want; agrees != c.rfcAgrees {
			t.Errorf("%s: RFC3339Nano gave %s (want-agrees=%v, Java says %s)", c.in, rfc, c.rfcAgrees, c.want)
		}
	}
}

// TestCoerceLimit closes 08-audit.md §4's "limit coercion bounds (0, -1, 501, non-numeric)" gap, plus
// the 32-bit edge Go gets wrong by default.
func TestCoerceLimit(t *testing.T) {
	cases := []struct {
		raw     string
		present bool
		want    int
	}{
		{"", false, 100},   // absent
		{"", true, 100},    // present but empty: not an Int
		{"abc", true, 100}, // not an Int
		{"0", true, 1},     // clamps up
		{"-1", true, 1},    // clamps up
		{"1", true, 1},
		{"100", true, 100},
		{"500", true, 500},
		{"501", true, 500},        // clamps down
		{"2147483647", true, 500}, // Int.MAX_VALUE parses, then clamps
		// 🔒 The one Go gets wrong with strconv.Atoi: 3e9 exceeds Kotlin's Int, so toIntOrNull is null
		// and the default 100 applies — NOT 500.
		{"3000000000", true, 100},
		{"9223372036854775808", true, 100}, // beyond int64 too
		{"+42", true, 42},                  // Kotlin's toIntOrNull accepts a leading '+'
		{" 42", true, 100},                 // ... but not surrounding space
		{"4_2", true, 100},                 // ... nor an underscore separator
	}
	for _, c := range cases {
		if got := CoerceLimit(c.raw, c.present); got != c.want {
			t.Errorf("CoerceLimit(%q, %v) = %d, want %d", c.raw, c.present, got, c.want)
		}
	}
}
