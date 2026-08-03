package store

import (
	"hash/crc32"
	"testing"
)

// The defining property, asserted against an INDEPENDENT computation rather than against
// FlywayChecksum's own output: the checksum is a CRC32 over the concatenated lines with the
// terminators removed, so "a\nb" hashes exactly the bytes "ab".
//
// This is what separates the implementation from the naive "CRC32 of the file's bytes", which is the
// most likely way to get D4 wrong. ⚠️ The algorithm itself is Unverified — 99-library-decisions.md §5
// records that no Flyway jar exists on this machine — so these cases pin the SHAPE described there
// and the docker-compose parity gate is still required before pointing the runner at a real database.
func TestFlywayChecksumHashesLinesWithoutTerminators(t *testing.T) {
	want := int32(crc32.ChecksumIEEE([]byte("ab")))
	if got := FlywayChecksum([]byte("a\nb")); got != want {
		t.Errorf("FlywayChecksum(\"a\\nb\") = %d, want CRC32(\"ab\") = %d", got, want)
	}
	if got := FlywayChecksum([]byte("ab")); got != want {
		t.Errorf("FlywayChecksum(\"ab\") = %d, want %d", got, want)
	}
}

// java.io.BufferedReader.readLine treats "\n", "\r" and "\r\n" as terminators and drops them, so a
// checkout with CRLF line endings must produce the same checksum a LF checkout did. Getting this
// wrong would refuse to boot every Windows-checkout deployment.
func TestFlywayChecksumIgnoresLineEndingStyle(t *testing.T) {
	want := FlywayChecksum([]byte("first\nsecond\nthird"))
	for _, in := range []string{
		"first\r\nsecond\r\nthird",
		"first\rsecond\rthird",
		"first\nsecond\nthird\n",   // a terminator at EOF adds no trailing empty line
		"first\r\nsecond\rthird\n", // mixed
	} {
		if got := FlywayChecksum([]byte(in)); got != want {
			t.Errorf("FlywayChecksum(%q) = %d, want %d", in, got, want)
		}
	}
}

// A consequence of hashing lines rather than bytes: blank lines contribute nothing, so inserting one
// does not move the checksum. Recorded as a test because it is surprising, and because it is the
// clearest single behaviour to confirm at the parity gate — if Flyway 13.0.0 disagrees here, the
// reimplementation is wrong.
func TestFlywayChecksumIsUnchangedByBlankLines(t *testing.T) {
	want := FlywayChecksum([]byte("a\nb"))
	if got := FlywayChecksum([]byte("a\n\n\nb")); got != want {
		t.Errorf("FlywayChecksum with blank lines = %d, want %d", got, want)
	}
}

// Flyway strips a byte-order mark from the first line only (BomFilter.isBom on line.charAt(0)).
func TestFlywayChecksumStripsLeadingBOM(t *testing.T) {
	want := FlywayChecksum([]byte("a\nb"))
	if got := FlywayChecksum([]byte("\xef\xbb\xbfa\nb")); got != want {
		t.Errorf("FlywayChecksum with a leading BOM = %d, want %d", got, want)
	}
	// A BOM further in is ordinary content and must NOT be stripped.
	if got := FlywayChecksum([]byte("a\n\xef\xbb\xbfb")); got == want {
		t.Error("a BOM on the second line was stripped; only the first line is BOM-filtered")
	}
}

func TestFlywayChecksumOfEmptyInput(t *testing.T) {
	if got := FlywayChecksum(nil); got != 0 {
		t.Errorf("FlywayChecksum(nil) = %d, want 0", got)
	}
	if got := FlywayChecksum([]byte("")); got != 0 {
		t.Errorf("FlywayChecksum(\"\") = %d, want 0", got)
	}
	// A file that is only a terminator has one empty line, which also hashes nothing.
	if got := FlywayChecksum([]byte("\n")); got != 0 {
		t.Errorf("FlywayChecksum(\"\\n\") = %d, want 0", got)
	}
}

// The stored column is INTEGER and Flyway's value is a Java int, so a CRC32 above 2^31 must come back
// NEGATIVE. Widening to int64 here would produce a value that never matches the stored row.
func TestFlywayChecksumIsSigned32Bit(t *testing.T) {
	// Search for an input whose CRC32 has the high bit set, then assert the port reports it signed.
	var found bool
	for i := 0; i < 1000 && !found; i++ {
		in := []byte{byte(i), byte(i >> 8)}
		raw := crc32.ChecksumIEEE(in)
		if raw <= 1<<31 {
			continue
		}
		found = true
		got := FlywayChecksum(in)
		if got >= 0 {
			t.Errorf("FlywayChecksum(%q) = %d, want the negative int32 form of %d", in, got, raw)
		}
		if uint32(got) != raw {
			t.Errorf("FlywayChecksum(%q) = %d, want the int32 reinterpretation of %d", in, got, raw)
		}
	}
	if !found {
		t.Skip("no high-bit CRC32 found in the search space")
	}
}

func TestFlywayLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a\n", []string{"a"}},
		{"a\nb", []string{"a", "b"}},
		{"a\n\nb", []string{"a", "", "b"}},
		{"\n", []string{""}},
		{"a\r\nb", []string{"a", "b"}},
		{"a\rb", []string{"a", "b"}},
		{"a\r\n", []string{"a"}},
	}
	for _, tc := range cases {
		got := flywayLines([]byte(tc.in))
		if len(got) != len(tc.want) {
			t.Errorf("flywayLines(%q) produced %d lines, want %d", tc.in, len(got), len(tc.want))
			continue
		}
		for i := range got {
			if string(got[i]) != tc.want[i] {
				t.Errorf("flywayLines(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
