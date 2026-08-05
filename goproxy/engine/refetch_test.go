package engine

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

type refetchDb struct{}

func (refetchDb) Dialect() Dialect             { return MySQL }
func (refetchDb) NamespaceProbeSQL() string    { return "namespace" }
func (refetchDb) SupportsTempOverlay() bool    { return false }
func (refetchDb) TempColumnsProbeSQL() string  { return "" }
func (refetchDb) HashSetupProbeSQL() string    { return "setup" }
func (refetchDb) HashSetupColumns() int        { return 1 }
func (refetchDb) CatalogVisibilitySQL() string { return "" }
func (refetchDb) SchemaHashSQL(schema string, _ [][]*string) (string, int, error) {
	return "hash:" + schema, 3, nil
}
func (refetchDb) SchemaHashFromRows(rows [][]*string) (HashObservation, error) {
	if len(rows) != 1 || len(rows[0]) != 3 || rows[0][0] == nil || rows[0][1] == nil || rows[0][2] == nil {
		return HashObservation{}, errors.New("bad hash rows")
	}
	clock, err := strconv.ParseInt(*rows[0][1], 10, 64)
	if err != nil {
		return HashObservation{}, err
	}
	return HashObservation{
		Hash:          []byte(*rows[0][0]),
		Trusted:       *rows[0][0] != "untrusted",
		DbClockMicros: clock,
		BackendID:     *rows[0][2],
	}, nil
}
func (refetchDb) ServerHashSQL(_ [][]*string) (string, int, error) { return "server-hash", 3, nil }
func (refetchDb) ServerHashFromRows(_ [][]*string) ([]SchemaHashObservation, error) {
	return nil, nil
}
func (refetchDb) SchemaColumnsSQL(schema string) string                     { return "columns:" + schema }
func (refetchDb) LowerCaseTableNamesProbeSQL() string                       { return "" }
func (refetchDb) NormalizeColumns(_ int, columns []*pb.Column) []*pb.Column { return columns }

func ptr(s string) *string { return &s }

func fragmentRows(schema string) [][]*string {
	return [][]*string{{ptr(schema), ptr("t"), ptr("c"), ptr("text"), ptr("1"), ptr("NO")}}
}

func hashRows(hash, backendID string) [][]*string {
	return hashRowsAt(hash, "123", backendID)
}

func hashRowsAt(hash, clock, backendID string) [][]*string {
	return [][]*string{{ptr(hash), ptr(clock), ptr(backendID)}}
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
			return hashRows("same", "backend-1"), nil
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
	// Run alone is the before_decide position: no latch and no positional argument, so the measurement
	// cannot prove it is settled and stamps itself in-transaction.
	if !pushed.HashTrusted || pushed.DbClockMicros != 123 || pushed.BackendId != "backend-1" || !pushed.MeasuredInTransaction {
		t.Fatalf("push observation = %+v, want a trusted first measurement stamped unproven", pushed)
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
				return hashRowsAt("stable", strconv.Itoa(100+hashCalls), "backend-1"), nil
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
	if !pushed.HashTrusted || pushed.DbClockMicros != 101 || pushed.BackendId != "backend-1" || !pushed.MeasuredInTransaction {
		t.Fatalf("push observation = %+v, want a trusted first measurement stamped unproven", pushed)
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
func (d *normalizingRefetchDb) NormalizeColumns(mode int, columns []*pb.Column) []*pb.Column {
	d.gotMode = &mode
	out := make([]*pb.Column, len(columns))
	for i, c := range columns {
		out[i] = &pb.Column{Schema: strings.ToUpper(c.GetSchema()), Table: strings.ToUpper(c.GetTable()), Column: strings.ToUpper(c.GetColumn())}
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

func TestRefetcherUntrustedPushCarriesGenuineMeasurement(t *testing.T) {
	cases := []struct {
		name       string
		hashes     []string
		backendIDs []string
		errAt      int
		wantHash   string
		wantID     string
	}{
		{name: "coherence mismatch", hashes: []string{"first", "second"}, backendIDs: []string{"backend-1", "backend-1"}, wantHash: "second", wantID: "backend-1"},
		{name: "backend id mismatch", hashes: []string{"same", "same"}, backendIDs: []string{"backend-1", "backend-2"}, wantHash: "same", wantID: "backend-1"},
		{name: "first probe error", hashes: []string{"ignored", "second"}, backendIDs: []string{"", "backend-2"}, errAt: 1, wantHash: "second", wantID: "backend-2"},
		{name: "second probe error", hashes: []string{"first", "ignored"}, backendIDs: []string{"backend-1", ""}, errAt: 2, wantHash: "first", wantID: "backend-1"},
		{name: "both probes error", hashes: []string{"ignored", "ignored"}, backendIDs: []string{"", ""}, errAt: -1},
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
						if tc.errAt == hashCalls || tc.errAt == -1 {
							return nil, errors.New("hash failed")
						}
						return hashRows(tc.hashes[hashCalls-1], tc.backendIDs[hashCalls-1]), nil
					}
					return fragmentRows("app"), nil
				},
				Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
			}
			if err := r.Run(&pb.Refetch{Schema: "app", IfHashDiffers: []byte("never")}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if pushed.Unchanged || pushed.HashTrusted || !bytes.Equal(pushed.ContentHash, []byte(tc.wantHash)) {
				t.Fatalf("push = %+v, want untrusted full fragment with genuine hash %q", pushed, tc.wantHash)
			}
			if pushed.BackendId != tc.wantID || len(pushed.Columns) != 1 {
				t.Fatalf("push identity/columns = %+v, want backend %q and full columns", pushed, tc.wantID)
			}
		})
	}
}

func TestRefetcherTransactionStatus(t *testing.T) {
	var statusCalls int
	dirtyOnSecondMeasurement := func() bool {
		statusCalls++
		return statusCalls == 2
	}
	for _, tc := range []struct {
		name          string
		ifHashDiffers []byte
		supplier      func() bool
		wantDirty     bool
	}{
		{name: "unchanged supplied true", ifHashDiffers: []byte("same"), supplier: func() bool { return true }, wantDirty: true},
		{name: "full supplied true", supplier: func() bool { return true }, wantDirty: true},
		{name: "dirty second measurement wins", supplier: dirtyOnSecondMeasurement, wantDirty: true},
		// No latch at an unproven position: the fail-closed reading is that a transaction may be open.
		{name: "nil supplier", ifHashDiffers: []byte("same"), wantDirty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pushed *pb.SchemaFragmentPush
			r := Refetcher{
				Db: refetchDb{},
				Probe: func(sql string, _ int) ([][]*string, error) {
					if sql == "setup" {
						return nil, nil
					}
					if strings.HasPrefix(sql, "hash:") {
						return hashRows("same", "backend-1"), nil
					}
					return fragmentRows("app"), nil
				},
				Push:          func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
				InTransaction: tc.supplier,
			}
			if err := r.Run(&pb.Refetch{Schema: "app", IfHashDiffers: tc.ifHashDiffers}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if pushed.MeasuredInTransaction != tc.wantDirty {
				t.Fatalf("MeasuredInTransaction = %v, want %v", pushed.MeasuredInTransaction, tc.wantDirty)
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
			return hashRows("hash", "backend-1"), nil
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
			return hashRows("hash", "backend-1"), nil
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
			return hashRows("hash", "backend-1"), nil
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

// The MySQL rule from the design: a measurement's transaction status is decided by its POSITION when the
// dialect exposes no latch, and only two positions may claim it is settled. Getting this backwards is a
// leak, not a slowdown — a before_decide probe measured inside a client's own transaction, stamped clean,
// would let another connection adopt a view that never existed outside it.
func TestRefetcherPositionDecidesSettledWithoutALatch(t *testing.T) {
	newRefetcher := func(pushed **pb.SchemaFragmentPush) *Refetcher {
		return &Refetcher{
			Db: refetchDb{},
			Probe: func(sql string, _ int) ([][]*string, error) {
				if strings.HasPrefix(sql, "hash:") {
					return hashRows("h", "backend-1"), nil
				}
				return fragmentRows("app"), nil
			},
			Push: func(push *pb.SchemaFragmentPush) (uint64, error) { *pushed = push; return 1, nil },
		}
	}

	t.Run("before_decide cannot prove it is settled", func(t *testing.T) {
		var pushed *pb.SchemaFragmentPush
		if err := newRefetcher(&pushed).RunAll([]*pb.Refetch{{Schema: "app"}}); err != nil {
			t.Fatalf("RunAll: %v", err)
		}
		if !pushed.MeasuredInTransaction {
			t.Fatal("MeasuredInTransaction = false at before_decide; an unprovable measurement must not read as settled")
		}
	})

	t.Run("on_open and after_statement are settled by construction", func(t *testing.T) {
		var pushed *pb.SchemaFragmentPush
		if err := newRefetcher(&pushed).RunAllSettled([]*pb.Refetch{{Schema: "app"}}); err != nil {
			t.Fatalf("RunAllSettled: %v", err)
		}
		if pushed.MeasuredInTransaction {
			t.Fatal("MeasuredInTransaction = true at a by-construction position; the observation could never be shared")
		}
	})

	t.Run("the settled claim does not leak into the next command batch", func(t *testing.T) {
		// The position is a property of one call. A claim that outlived it would vouch for every later
		// measurement on the connection, including the before_decide probes this rule exists to catch.
		var pushed *pb.SchemaFragmentPush
		r := newRefetcher(&pushed)
		if err := r.RunAllSettled([]*pb.Refetch{{Schema: "app"}}); err != nil {
			t.Fatalf("RunAllSettled: %v", err)
		}
		if err := r.RunAll([]*pb.Refetch{{Schema: "app"}}); err != nil {
			t.Fatalf("RunAll: %v", err)
		}
		if !pushed.MeasuredInTransaction {
			t.Fatal("a later before_decide measurement inherited the settled claim")
		}
	})

	t.Run("a real latch overrides the positional claim", func(t *testing.T) {
		// A measured fact beats an argument from position, and the two disagree exactly where the argument
		// is wrong: a PostgreSQL COMMIT refetch issued while a failed transaction is still open.
		var pushed *pb.SchemaFragmentPush
		r := newRefetcher(&pushed)
		r.InTransaction = func() bool { return true }
		if err := r.RunAllSettled([]*pb.Refetch{{Schema: "app"}}); err != nil {
			t.Fatalf("RunAllSettled: %v", err)
		}
		if !pushed.MeasuredInTransaction {
			t.Fatal("the positional claim overrode a latch that reported an open transaction")
		}
	})
}
