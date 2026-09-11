package engine

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

type refetchDb struct{}

func (refetchDb) Dialect() Dialect            { return MySQL }
func (refetchDb) NamespaceProbeSQL() string   { return "namespace" }
func (refetchDb) SupportsTempOverlay() bool   { return false }
func (refetchDb) TempColumnsProbeSQL() string { return "" }
func (refetchDb) HashSetupProbeSQL() string   { return "setup" }
func (refetchDb) HashSetupColumns() int       { return 1 }
func (refetchDb) SchemaHashSQL(schema string, _ [][]*string) (string, int, error) {
	return "hash:" + schema, 1, nil
}
func (refetchDb) SchemaHashFromRows(rows [][]*string) ([]byte, bool, error) {
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil {
		return nil, false, errors.New("bad hash rows")
	}
	if *rows[0][0] == "untrusted" {
		return []byte("untrusted"), false, nil
	}
	return []byte(*rows[0][0]), true, nil
}
func (refetchDb) SchemaColumnsSQL(schema string) string { return "columns:" + schema }
func (refetchDb) LowerCaseTableNamesProbeSQL() string   { return "" }
func (refetchDb) FoldFunctionName(name string) string   { return name }

func (refetchDb) NormalizeColumns(_ int, columns []*analyzerpb.Column) []*analyzerpb.Column {
	return columns
}

func ptr(s string) *string { return &s }

func fragmentRows(schema string) [][]*string {
	return [][]*string{{ptr(schema), ptr("t"), ptr("c"), ptr("text"), ptr("1"), ptr("NO")}}
}

func TestRefetcherUnchangedOnHashMatch(t *testing.T) {
	var probes []string
	var pushed *pb.SchemaFragmentPush
	r := Refetcher{
		Db:                refetchDb{},
		ConnectionID:      []byte("0123456789abcdef"),
		BackendGeneration: 7,
		Probe: func(sql string, columns int) ([][]*string, error) {
			probes = append(probes, sql)
			if sql == "setup" {
				return [][]*string{{ptr("crypto")}}, nil
			}
			return [][]*string{{ptr("same")}}, nil
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 9, nil },
	}
	if err := r.Run(&pb.Refetch{Schema: "app", IfHashDiffers: []byte("same")}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(probes, []string{"setup", "hash:app"}) {
		t.Fatalf("probes = %v", probes)
	}
	if !pushed.Unchanged || !bytes.Equal(pushed.ContentHash, []byte("same")) || len(pushed.Columns) != 0 {
		t.Fatalf("push = %+v, want unchanged hash-only push", pushed)
	}
	if !bytes.Equal(pushed.ConnectionId, r.ConnectionID) || pushed.BackendGeneration != 7 {
		t.Fatalf("push identity/generation = %+v", pushed)
	}
}

func TestRefetcherUnconditionalFetch(t *testing.T) {
	var hashCalls int
	var pushed *pb.SchemaFragmentPush
	r := Refetcher{
		Db: refetchDb{},
		Probe: func(sql string, columns int) ([][]*string, error) {
			switch {
			case sql == "setup":
				return nil, errors.New("optional setup failed")
			case strings.HasPrefix(sql, "hash:"):
				hashCalls++
				return [][]*string{{ptr("stable")}}, nil
			default:
				return fragmentRows("app"), nil
			}
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
	}
	if err := r.Run(&pb.Refetch{Schema: "app"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hashCalls != 2 {
		t.Fatalf("hash probes = %d, want 2", hashCalls)
	}
	if pushed.Unchanged || !bytes.Equal(pushed.ContentHash, []byte("stable")) || len(pushed.Columns) != 1 {
		t.Fatalf("push = %+v, want coherent full fragment", pushed)
	}
}

// normalizingRefetchDb proves Run wires the mode probe into NormalizeColumns (not that folding itself
// is correct — that's covered by analyzer/probe's and goproxy/db's own tests). It records the mode it
// was called with and uppercases every field, an arbitrary but easy-to-assert-on transform.
type normalizingRefetchDb struct {
	refetchDb
	gotMode *int
}

func (d *normalizingRefetchDb) LowerCaseTableNamesProbeSQL() string { return "lctn" }
func (d *normalizingRefetchDb) FoldFunctionName(name string) string { return name }

func (d *normalizingRefetchDb) NormalizeColumns(mode int, columns []*analyzerpb.Column) []*analyzerpb.Column {
	d.gotMode = &mode
	out := make([]*analyzerpb.Column, len(columns))
	for i, c := range columns {
		out[i] = &analyzerpb.Column{Schema: strings.ToUpper(c.GetSchema()), Table: strings.ToUpper(c.GetTable()), Column: strings.ToUpper(c.GetColumn())}
	}
	return out
}

func TestRefetcherProbesModeAndNormalizesBeforePush(t *testing.T) {
	fakeDb := &normalizingRefetchDb{}
	var pushed *pb.SchemaFragmentPush
	r := Refetcher{
		Db: fakeDb,
		Probe: func(sql string, columns int) ([][]*string, error) {
			switch {
			case sql == "lctn":
				return [][]*string{{ptr("2")}}, nil
			case sql == "setup":
				return nil, errors.New("no setup")
			case strings.HasPrefix(sql, "hash:"):
				return nil, errors.New("untrusted")
			default:
				return fragmentRows("app"), nil
			}
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
	}
	if err := r.Run(&pb.Refetch{Schema: "app"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fakeDb.gotMode == nil || *fakeDb.gotMode != 2 {
		t.Fatalf("NormalizeColumns called with mode %v, want 2 (from the lctn probe)", fakeDb.gotMode)
	}
	if len(pushed.Columns) != 1 || pushed.Columns[0].GetSchema() != "APP" || pushed.Columns[0].GetTable() != "T" || pushed.Columns[0].GetColumn() != "C" {
		t.Fatalf("pushed columns = %+v, want the NormalizeColumns-transformed (uppercased) fragment", pushed.Columns)
	}
}

func TestRefetcherUntrustedAndIncoherentHashesUseNonce(t *testing.T) {
	cases := []struct {
		name   string
		hashes []string
		errAt  int
	}{
		{name: "untrusted", hashes: []string{"untrusted", "untrusted"}},
		{name: "first probe error", hashes: []string{"ignored", "stable"}, errAt: 1},
		{name: "coherence mismatch", hashes: []string{"first", "second"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hashCalls int
			var pushed *pb.SchemaFragmentPush
			r := Refetcher{
				Db: refetchDb{},
				Probe: func(sql string, columns int) ([][]*string, error) {
					if sql == "setup" {
						return nil, nil
					}
					if strings.HasPrefix(sql, "hash:") {
						hashCalls++
						if tc.errAt == hashCalls {
							return nil, errors.New("hash failed")
						}
						return [][]*string{{ptr(tc.hashes[hashCalls-1])}}, nil
					}
					return fragmentRows("app"), nil
				},
				Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
			}
			if err := r.Run(&pb.Refetch{Schema: "app", IfHashDiffers: []byte("never")}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(pushed.ContentHash) != 32 {
				t.Fatalf("nonce length = %d, want 32", len(pushed.ContentHash))
			}
			for _, measured := range tc.hashes {
				if bytes.Equal(pushed.ContentHash, []byte(measured)) {
					t.Fatalf("nonce aliases measured hash %q", measured)
				}
			}
		})
	}
}

func TestRefetcherTerminalErrors(t *testing.T) {
	t.Run("blank schema", func(t *testing.T) {
		r := Refetcher{Db: refetchDb{}, Probe: func(string, int) ([][]*string, error) { return nil, nil }, Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 0, nil }}
		if err := r.Run(&pb.Refetch{}); err == nil {
			t.Fatal("Run succeeded, want blank-schema error")
		}
	})
	t.Run("introspection", func(t *testing.T) {
		r := Refetcher{Db: refetchDb{}, Probe: func(sql string, _ int) ([][]*string, error) {
			if strings.HasPrefix(sql, "columns:") {
				return nil, errors.New("introspection failed")
			}
			return [][]*string{{ptr("hash")}}, nil
		}, Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 0, nil }}
		if err := r.Run(&pb.Refetch{Schema: "app"}); err == nil {
			t.Fatal("Run succeeded, want introspection error")
		}
	})
	t.Run("push", func(t *testing.T) {
		r := Refetcher{Db: refetchDb{}, Probe: func(sql string, _ int) ([][]*string, error) {
			if strings.HasPrefix(sql, "columns:") {
				return fragmentRows("app"), nil
			}
			return [][]*string{{ptr("hash")}}, nil
		}, Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 0, errors.New("push failed") }}
		if err := r.Run(&pb.Refetch{Schema: "app"}); err == nil || !strings.Contains(err.Error(), "push failed") {
			t.Fatalf("Run error = %v, want push failure", err)
		}
	})
}

func TestRefetcherRunAllOrdersAndStops(t *testing.T) {
	var pushed []string
	r := Refetcher{
		Db: refetchDb{},
		Probe: func(sql string, _ int) ([][]*string, error) {
			if strings.HasPrefix(sql, "columns:") {
				return fragmentRows(strings.TrimPrefix(sql, "columns:")), nil
			}
			return [][]*string{{ptr("hash")}}, nil
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) {
			pushed = append(pushed, push.Schema)
			if push.Schema == "two" {
				return 0, errors.New("stop")
			}
			return 1, nil
		},
	}
	err := r.RunAll([]*pb.Refetch{{Schema: "one"}, {Schema: "two"}, {Schema: "three"}})
	if err == nil {
		t.Fatal("RunAll succeeded, want second-command error")
	}
	if !reflect.DeepEqual(pushed, []string{"one", "two"}) {
		t.Fatalf("push order = %v, want [one two]", pushed)
	}
}
