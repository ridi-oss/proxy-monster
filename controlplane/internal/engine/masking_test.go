package engine

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// Port of probe/MaskingTest.kt (5 cases) and probe/BindMasksTest.kt (5 cases), MERGED WITH the Go twin's
// suite in goproxy/engine/masking_test.go.
//
// 13-engine.md §6 is explicit about which side is authoritative: "goproxy/engine/masking_test.go
// TestMasking is a table test with 11 rows, which is these 5 Kotlin methods' 8 assertions one-per-row plus
// THREE the Kotlin side lacks … The Go suite is the AUTHORITATIVE one for INV-A13-4/5." Likewise for
// binding: "Case-for-case identical to goproxy/engine/masking_test.go TestBindMasks, EXCEPT the Go suite
// adds a sixth, 'first duplicate ordinal wins' (INV-A13-9). Migrate the Go superset, not the Kotlin
// subset."
//
// So both tables below are the goproxy tables verbatim, retyped onto the control plane's own
// internal/pb.ColumnMask. They are the drift alarm for the twin this package could not import (doc.go).

func stringPointer(value string) *string { return &value }

func TestMasking(t *testing.T) {
	tests := []struct {
		name  string
		value *string
		kind  string
		want  *string
	}{
		{"last_n reveals only final four", stringPointer("900101-1234567"), "LAST_N", stringPointer("**********4567")},
		{"last_n masks short value", stringPointer("abc"), "LAST_N", stringPointer("***")},
		{"last_n masks four-character value", stringPointer("1234"), "LAST_N", stringPointer("****")},
		{"format preserving", stringPointer("010-1234-5678"), "FORMAT_PRESERVING", stringPointer("***-****-****")},
		{"fixed", stringPointer("anything"), "FIXED", stringPointer("####")},
		{"null kind", stringPointer("anything"), "NULL", nil},
		{"null input", nil, "LAST_N", nil},
		{"unknown kind", stringPointer("secret"), "WHATEVER", stringPointer("****")},
		{"last_n counts UTF-16 code units", stringPointer("😀1234"), "LAST_N", stringPointer("**1234")},
		{"format preserving keeps surrogate-pair letters", stringPointer("𐐀A1"), "FORMAT_PRESERVING", stringPointer("𐐀**")},
		{"format preserving masks Unicode 16 BMP letters", stringPointer("Ɤ-1"), "FORMAT_PRESERVING", stringPointer("*-*")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ApplyMaskKind(test.value, test.kind)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

// 🔒 INV-A13-1 — apply returns nil for EXACTLY TWO inputs. Stated separately from the table because the
// whole point is that a caller must branch on the KIND, not on the result: collapsing this to
// `ApplyMaskKind(v, kind) ?? v` falls a NULL-redacted cell back to the CLEARTEXT value (A7's INV-A7-15).
func TestApplyMaskKindReturnsNilOnlyForANilValueOrTheNullKind(t *testing.T) {
	if got := ApplyMaskKind(nil, "FIXED"); got != nil {
		t.Errorf("a nil value must stay nil regardless of kind, got %q", *got)
	}
	if got := ApplyMaskKind(stringPointer("secret"), "NULL"); got != nil {
		t.Errorf("kind NULL is a FULL REDACTION and must be nil, got %q", *got)
	}
	// Every other kind, recognized or not, returns a non-nil masked rendering — which is what makes
	// "result == nil" a usable signal for "redacted" and nothing else.
	for _, kind := range []string{"FIXED", "LAST_N", "FORMAT_PRESERVING", "WHATEVER", "", "null", "Null"} {
		got := ApplyMaskKind(stringPointer("secret"), kind)
		if got == nil {
			t.Errorf("kind %q unexpectedly redacted to nil — only the exact string \"NULL\" may", kind)
		}
	}
}

// 🔒 INV-A13-2 + F21/F79 — mask_fn.kind is a bare TEXT column with NO CHECK constraint, so an
// unrecognised kind REACHES this arm in production: an admin can store any string through
// POST /api/mask-fns. The "****" default is therefore a SECURITY DEFAULT, not dead code — it fails
// closed rather than passing cleartext through when a typo in an admin form would otherwise silently
// disable a mask. Pinned so nobody "cleans up" the default arm into a passthrough or an error.
func TestUnrecognisedMaskKindMasksFullyRatherThanLeakingCleartext(t *testing.T) {
	for _, kind := range []string{
		"WHATEVER",          // BindMasksTest's own unknown kind
		"",                  // an empty kind column
		"redact",            // goproxy's TestRowMasker uses this lower-case spelling
		"last_n",            // right vocabulary, WRONG CASE — the switch is case-SENSITIVE
		"FIXED ",            // a trailing space from an admin form
		"FORMAT-PRESERVING", // a hyphen instead of an underscore
		"DROP TABLE users;", // arbitrary operator input; the column accepts it
	} {
		got := ApplyMaskKind(stringPointer("900101-1234567"), kind)
		if got == nil {
			t.Fatalf("kind %q: must not redact to nil (only kind \"NULL\" may)", kind)
		}
		if *got != "****" {
			t.Errorf("kind %q: got %q, want \"****\" — an unrecognised kind must mask FULLY", kind, *got)
		}
		if *got == "900101-1234567" {
			t.Errorf("kind %q: cleartext passed through", kind)
		}
	}
}

// INV-A13-4 — the JDK 24 Character.isLetterOrDigit parity set, and the deliberate supplementary-letter
// gap. Migrated from goproxy/engine/masking_test.go verbatim.
func TestKotlinCharLetterOrDigitUnicode16Parity(t *testing.T) {
	for _, r := range []rune{0x1c89, 0x1c8a, 0xa7cb, 0xa7cc, 0xa7cd, 0xa7da, 0xa7db, 0xa7dc} {
		if !isKotlinCharLetterOrDigit(r) {
			t.Errorf("isKotlinCharLetterOrDigit(%U) = false, want true", r)
		}
	}
	if isKotlinCharLetterOrDigit(0x10400) {
		t.Error("supplementary letter must remain two non-letter Kotlin Char surrogate halves")
	}
}

// The UTF-16 code-unit requirement 13-engine.md calls out for the port, stated as its own case: a naive
// Go implementation over runes gets a DIFFERENT answer for every one of these, and the difference is
// observable in what a viewer sees.
func TestMaskingCountsUTF16CodeUnitsNotRunes(t *testing.T) {
	for _, tc := range []struct {
		name, value, kind, want string
		runeAnswer              string // what len([]rune(...)) would have produced — must NOT match
	}{
		{
			name: "emoji is two starred units", value: "😀1234", kind: "LAST_N",
			want: "**1234", runeAnswer: "*1234",
		},
		{
			name: "CJK extension B ideograph is two starred units", value: "𠀋1234", kind: "LAST_N",
			want: "**1234", runeAnswer: "*1234",
		},
		{
			name: "BMP CJK is ONE unit, so it agrees with the rune count", value: "한국어1234", kind: "LAST_N",
			want: "***1234", runeAnswer: "***1234",
		},
		{
			name: "a value of four code units in two runes is fully masked", value: "😀😀", kind: "LAST_N",
			want: "****", runeAnswer: "**",
		},
		{
			name: "surrogate halves are not letters, so they survive FORMAT_PRESERVING", value: "𐐀A1",
			kind: "FORMAT_PRESERVING", want: "𐐀**", runeAnswer: "***",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyMaskKind(stringPointer(tc.value), tc.kind)
			if got == nil {
				t.Fatal("unexpected nil")
			}
			if *got != tc.want {
				t.Errorf("got %q, want %q", *got, tc.want)
			}
			if tc.want != tc.runeAnswer && *got == tc.runeAnswer {
				t.Errorf("got the RUNE-counted answer %q — this is the naive-port bug INV-A13-4 warns about", *got)
			}
		})
	}
}

func TestBindMasks(t *testing.T) {
	tests := []struct {
		name        string
		masks       []*pb.ColumnMask
		columnCount int
		wantByIndex map[int]string
		wantUnbound []*pb.ColumnMask
	}{
		{
			name:        "ordinal binds",
			masks:       []*pb.ColumnMask{{Column: "rrn", Kind: "FIXED", Ordinal: proto.Int32(1)}},
			columnCount: 2,
			wantByIndex: map[int]string{1: "FIXED"},
		},
		{
			// 🔒 INV-A13-6: "EXPR$0" is a name that can never match a catalog column. It binds anyway,
			// because binding is by POSITION — name binding was the fail-open bug.
			name:        "name is ignored",
			masks:       []*pb.ColumnMask{{Column: "EXPR$0", Kind: "LAST_N", Ordinal: proto.Int32(0)}},
			columnCount: 1,
			wantByIndex: map[int]string{0: "LAST_N"},
		},
		{
			name:        "out of range ordinal is unbound",
			masks:       []*pb.ColumnMask{{Column: "rrn", Kind: "FIXED", Ordinal: proto.Int32(5)}},
			columnCount: 2,
			wantByIndex: map[int]string{},
			wantUnbound: []*pb.ColumnMask{{Column: "rrn", Kind: "FIXED", Ordinal: proto.Int32(5)}},
		},
		{
			// Ordinal nil = proto explicit-presence absent. Must be reported unbound, NOT silently bound
			// to result column 0 (which would mask the wrong column and leak the intended-masked one).
			name:        "absent ordinal is unbound (never binds to result column 0)",
			masks:       []*pb.ColumnMask{{Column: "rrn", Kind: "FIXED"}},
			columnCount: 2,
			wantByIndex: map[int]string{},
			wantUnbound: []*pb.ColumnMask{{Column: "rrn", Kind: "FIXED"}},
		},
		{
			name: "multiple ordinals bind",
			masks: []*pb.ColumnMask{
				{Column: "rrn", Kind: "FIXED", Ordinal: proto.Int32(0)},
				{Column: "email", Kind: "LAST_N", Ordinal: proto.Int32(2)},
			},
			columnCount: 3,
			wantByIndex: map[int]string{0: "FIXED", 2: "LAST_N"},
		},
		{
			// INV-A13-9: putIfAbsent keeps the EARLIEST mask for an ordinal; the later one is silently
			// dropped — neither applied nor surfaced in Unbound, so AllBound stays true. Untested on the
			// Kotlin side; the Go twin does test it, so it comes across with the Go superset.
			name: "first duplicate ordinal wins",
			masks: []*pb.ColumnMask{
				{Column: "first", Kind: "FIXED", Ordinal: proto.Int32(0)},
				{Column: "second", Kind: "LAST_N", Ordinal: proto.Int32(0)},
			},
			columnCount: 1,
			wantByIndex: map[int]string{0: "FIXED"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := BindMasks(test.masks, test.columnCount)
			if !reflect.DeepEqual(binding.ByIndex, test.wantByIndex) {
				t.Fatalf("ByIndex got %#v, want %#v", binding.ByIndex, test.wantByIndex)
			}
			if len(binding.Unbound) != len(test.wantUnbound) {
				t.Fatalf("Unbound got %d entries, want %d", len(binding.Unbound), len(test.wantUnbound))
			}
			for i := range test.wantUnbound {
				if !proto.Equal(binding.Unbound[i], test.wantUnbound[i]) {
					t.Fatalf("Unbound[%d] got %v, want %v", i, binding.Unbound[i], test.wantUnbound[i])
				}
			}
			if got, want := binding.AllBound(), len(test.wantUnbound) == 0; got != want {
				t.Fatalf("AllBound got %v, want %v", got, want)
			}
		})
	}
}

// 🔒 INV-A13-7, stated separately because it is "the single easiest mistake in the whole area" in Go:
// GetOrdinal() returns 0 for a nil pointer, so a port that used it would bind a malformed or omitted mask
// to result column 0 — masking a column that needed no mask and leaving the intended one cleartext.
func TestAbsentOrdinalNeverBindsToColumnZero(t *testing.T) {
	absent := &pb.ColumnMask{Column: "rrn", Kind: "FIXED"} // Ordinal is nil
	if absent.GetOrdinal() != 0 {
		t.Fatal("precondition: GetOrdinal() returns 0 for an absent ordinal — that is the trap")
	}
	binding := BindMasks([]*pb.ColumnMask{absent}, 3)
	if _, bound := binding.ByIndex[0]; bound {
		t.Fatal("an ABSENT ordinal bound to result column 0 — this masks the wrong column and leaks the intended one")
	}
	if binding.AllBound() {
		t.Fatal("an absent ordinal must be reported unbound so the caller fails closed")
	}
	// A legitimate ordinal 0 still binds — presence, not value, is what distinguishes them.
	binding = BindMasks([]*pb.ColumnMask{{Column: "rrn", Kind: "FIXED", Ordinal: proto.Int32(0)}}, 3)
	if binding.ByIndex[0] != "FIXED" || !binding.AllBound() {
		t.Fatalf("a legitimate ordinal 0 must bind, got %+v", binding)
	}
}

// 🔒 INV-A13-8 — "bindMasks with resultColumnCount == 0 (everything unbound) is untested", 13-engine.md
// §6. With no live result columns every ordinal is out of range, so every mask is unbound and the caller
// must fail closed.
func TestBindMasksWithNoResultColumnsLeavesEverythingUnbound(t *testing.T) {
	masks := []*pb.ColumnMask{
		{Column: "a", Kind: "FIXED", Ordinal: proto.Int32(0)},
		{Column: "b", Kind: "LAST_N", Ordinal: proto.Int32(1)},
	}
	binding := BindMasks(masks, 0)
	if len(binding.ByIndex) != 0 {
		t.Errorf("ByIndex got %v, want empty", binding.ByIndex)
	}
	if len(binding.Unbound) != 2 {
		t.Errorf("Unbound got %d, want 2", len(binding.Unbound))
	}
	if binding.AllBound() {
		t.Error("AllBound must be false — every required mask must bind, else DENY")
	}
	// A NEGATIVE ordinal is likewise unbound. Kotlin's `m.ordinal in 0 until count` includes the lower
	// bound, which the Go port reproduces with an explicit >= 0 test.
	binding = BindMasks([]*pb.ColumnMask{{Column: "a", Kind: "FIXED", Ordinal: proto.Int32(-1)}}, 4)
	if len(binding.ByIndex) != 0 || binding.AllBound() {
		t.Errorf("a negative ordinal must be unbound, got %+v", binding)
	}
	// And an empty mask list is trivially all-bound — the caller applies nothing and denies nothing.
	binding = BindMasks(nil, 0)
	if !binding.AllBound() {
		t.Error("no masks means nothing failed to bind")
	}
}

// takeUTF16 backs the fail-closed detail truncation in catalogapi.go, where Kotlin's `.take(150)` counts
// UTF-16 code units and the Go probe's own truncateDetail counts runes (F28).
func TestTakeUTF16CountsCodeUnits(t *testing.T) {
	if got := takeUTF16("abc", 10); got != "abc" {
		t.Errorf("a short string is returned unchanged, got %q", got)
	}
	if got := takeUTF16("abcdef", 3); got != "abc" {
		t.Errorf("got %q, want %q", got, "abc")
	}
	// One emoji is TWO code units, so take(2) keeps exactly it and take(3) adds one more unit.
	if got := takeUTF16("😀ab", 2); got != "😀" {
		t.Errorf("got %q, want the whole surrogate pair", got)
	}
	if got := takeUTF16("😀ab", 3); got != "😀a" {
		t.Errorf("got %q, want %q", got, "😀a")
	}
}
