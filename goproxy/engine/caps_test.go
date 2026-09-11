package engine

import (
	"reflect"
	"testing"
)

func TestParseResultCaps(t *testing.T) {
	got, err := ParseResultCaps("5000/50MB, pii:500/5MB ,pci:300")
	if err != nil {
		t.Fatal(err)
	}
	want := ResultCaps{Default: RowsBytes{5000, 50_000_000}, ByTag: map[string]RowsBytes{"pii": {500, 5_000_000}, "pci": {300, 0}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("caps = %+v, want %+v", got, want)
	}
	if _, err := ParseResultCaps(DefaultResultCaps); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"", "pii:500", "5000", "5000/50MB,6000/1MB", "0/1MB", "5000/50MB,pii:-1", "5000/50MB,pii:500,pii:400", "5000/50MB,:500", "5000/x", "5000/50MB,pii:500/0"} {
		if _, err := ParseResultCaps(spec); err == nil {
			t.Errorf("%q parsed, want an error", spec)
		}
	}
	for text, want := range map[string]int64{"7": 7, "7k": 7_000, "7KB": 7_000, "5MB": 5_000_000, "2G": 2_000_000_000} {
		if got, err := parseByteSize(text); err != nil || got != want {
			t.Errorf("parseByteSize(%q) = %d, %v; want %d", text, got, err, want)
		}
	}
}

func TestResultCapsResolve(t *testing.T) {
	caps, _ := ParseResultCaps("5000/50MB,pii:500/5MB,pci:300,wide:9000/1MB")
	for _, tc := range []struct {
		unbounded bool
		tags      []string
		want      RowsBytes
	}{
		{false, nil, RowsBytes{5000, 50_000_000}},
		{false, []string{"unknown"}, RowsBytes{5000, 50_000_000}},
		{false, []string{"pii"}, RowsBytes{500, 5_000_000}},
		{false, []string{"pci"}, RowsBytes{300, 50_000_000}},
		{false, []string{"pii", "pci"}, RowsBytes{300, 5_000_000}},
		{false, []string{"wide"}, RowsBytes{5000, 1_000_000}},
		{true, []string{"pii"}, RowsBytes{}},
	} {
		if got := caps.Resolve(tc.unbounded, tc.tags); got != tc.want {
			t.Errorf("Resolve(%v, %v) = %+v, want %+v", tc.unbounded, tc.tags, got, tc.want)
		}
	}
}
