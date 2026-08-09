package engine

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

func stringPointer(value string) *string { return &value }

func TestMasking(t *testing.T) {
	tests := []struct {
		name  string
		value *string
		kind  string
		want  *string
	}{
		{"last_n reveals only final four", stringPointer("987-65-4320"), "LAST_N", stringPointer("*******4320")},
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
			got := applyMaskKind(test.value, test.kind)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

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
			masks:       []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(1)}},
			columnCount: 2,
			wantByIndex: map[int]string{1: "FIXED"},
		},
		{
			name:        "name is ignored",
			masks:       []*pb.ColumnMask{{Column: "EXPR$0", Kind: "LAST_N", Ordinal: proto.Int32(0)}},
			columnCount: 1,
			wantByIndex: map[int]string{0: "LAST_N"},
		},
		{
			name:        "out of range ordinal is unbound",
			masks:       []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(5)}},
			columnCount: 2,
			wantByIndex: map[int]string{},
			wantUnbound: []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(5)}},
		},
		{
			// Ordinal nil = proto explicit-presence absent. Must be reported unbound, NOT silently bound
			// to result column 0 (which would mask the wrong column and leak the intended-masked one).
			name:        "absent ordinal is unbound (never binds to result column 0)",
			masks:       []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED"}},
			columnCount: 2,
			wantByIndex: map[int]string{},
			wantUnbound: []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED"}},
		},
		{
			name: "multiple ordinals bind",
			masks: []*pb.ColumnMask{
				{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(0)},
				{Column: "email", Kind: "LAST_N", Ordinal: proto.Int32(2)},
			},
			columnCount: 3,
			wantByIndex: map[int]string{0: "FIXED", 2: "LAST_N"},
		},
		{
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
			if !reflect.DeepEqual(binding.Unbound, test.wantUnbound) {
				t.Fatalf("Unbound got %#v, want %#v", binding.Unbound, test.wantUnbound)
			}
			if got, want := binding.AllBound(), len(test.wantUnbound) == 0; got != want {
				t.Fatalf("AllBound got %v, want %v", got, want)
			}
		})
	}
}

func TestRowMasker(t *testing.T) {
	if masker := NewRowMasker([]*pb.ColumnMask{{Column: "ssn", Kind: "redact", Ordinal: proto.Int32(2)}}, 2); masker != nil {
		t.Fatalf("out-of-range ordinal must fail closed: %#v", masker)
	}

	masker := NewRowMasker([]*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(1)}}, 2)
	if masker == nil {
		t.Fatal("valid ordinal unexpectedly failed to bind")
	}
	original := []*string{stringPointer("clear"), stringPointer("secret")}
	masked := masker.Apply(original)
	want := []*string{stringPointer("clear"), stringPointer("####")}
	if !reflect.DeepEqual(masked, want) {
		t.Fatalf("masked row got %#v, want %#v", masked, want)
	}
	if *original[1] != "secret" {
		t.Fatalf("Apply mutated input row: %#v", original)
	}
}
