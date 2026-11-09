package sqldb

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"google.golang.org/protobuf/proto"
)

// refetchQueries answers every query with a recognizable string.
var refetchQueries = Queries{
	HashSetupProbe:   "setup",
	HashSetupColumns: 1,
	SchemaHash: func(schema string, _ [][]*string) (string, int, error) {
		return "hash:" + schema, 1, nil
	},
	SchemaHashFromRows: func(rows [][]*string) ([]byte, bool, error) {
		if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == nil {
			return nil, false, errors.New("bad hash rows")
		}
		if *rows[0][0] == "untrusted" {
			return []byte("untrusted"), false, nil
		}
		return []byte(*rows[0][0]), true, nil
	},
	SchemaColumns:         func(schema string) string { return "columns:" + schema },
	Routines:              "routines",
	SchemaRoutines:        func(schema string) string { return "routines:" + schema },
	Engine:                engines.Postgres,
	TargetSettingsProbe:   "settings",
	TargetSettingsColumns: 1,
	TargetSettings: func(row []*string) (*analyzerpb.TargetSettings, error) {
		return &analyzerpb.TargetSettings{}, nil
	},
}

var testSession, _ = engines.Postgres.NewSession(nil)

func ptr(s string) *string { return &s }

func fragmentRows(schema string) [][]*string {
	return [][]*string{{ptr(schema), ptr("t"), ptr("c"), ptr("text"), ptr("1"), ptr("NO"), ptr("def")}}
}

func TestRefetchUnchangedOnHashMatch(t *testing.T) {
	var probes []string
	var pushed *pb.SchemaFragmentPush
	r := ProxyCommandRunner{
		Catalog: "def",
		Queries: refetchQueries, Session: testSession,
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
	if err := r.Refetch(&pb.Refetch{Schema: "app", Catalog: "def", IfHashDiffers: []byte("same")}); err != nil {
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

func TestRefetchUnconditionalFetch(t *testing.T) {
	var hashCalls int
	var pushed *pb.SchemaFragmentPush
	r := ProxyCommandRunner{
		Catalog: "def",
		Queries: refetchQueries, Session: testSession,
		Probe: func(sql string, columns int) ([][]*string, error) {
			switch {
			case sql == "setup":
				return nil, errors.New("optional setup failed")
			case strings.HasPrefix(sql, "hash:"):
				hashCalls++
				return [][]*string{{ptr("stable")}}, nil
			case strings.HasPrefix(sql, "routines:"):
				return [][]*string{{ptr("add_tax")}, {ptr("lookup")}}, nil
			default:
				return fragmentRows("app"), nil
			}
		},
		Push: func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil },
	}
	if err := r.Refetch(&pb.Refetch{Schema: "app", Catalog: "def"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hashCalls != 2 {
		t.Fatalf("hash probes = %d, want 2", hashCalls)
	}
	if pushed.Unchanged || !bytes.Equal(pushed.ContentHash, []byte("stable")) || len(pushed.Columns) != 1 {
		t.Fatalf("push = %+v, want coherent full fragment", pushed)
	}
	if !reflect.DeepEqual(pushed.Routines, []string{"add_tax", "lookup"}) {
		t.Fatalf("push routines = %v, want the schema's routines", pushed.Routines)
	}
}

func TestRefetchFoldsByTheHeldSessionWithoutProbingIt(t *testing.T) {
	// Athena folds every name, so a fold shows the held session was used.
	session, err := engines.Athena.NewSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	var pushed *pb.SchemaFragmentPush
	r := NewProxyCommandRunner(refetchQueries, session, nil, 0, func(sql string, columns int) ([][]*string, error) {
		switch {
		case sql == "settings":
			t.Fatal("a refetch probed the target settings its connection already holds")
		case sql == "setup":
			return nil, errors.New("no setup")
		case strings.HasPrefix(sql, "hash:"):
			return nil, errors.New("untrusted")
		case strings.HasPrefix(sql, "routines:"):
			return [][]*string{{ptr("AddTax")}}, nil
		}
		return [][]*string{{ptr("App"), ptr("T"), ptr("C"), ptr("text"), ptr("1"), ptr("NO"), ptr("def")}}, nil
	}, func(push *pb.SchemaFragmentPush) (uint64, error) { pushed = push; return 1, nil })
	r.Catalog = "def"
	for range 2 {
		if err := r.Refetch(&pb.Refetch{Schema: "App", Catalog: "def"}); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}
	if len(pushed.Columns) != 1 || pushed.Columns[0].GetSchema() != "app" || pushed.Columns[0].GetTable() != "t" || pushed.Columns[0].GetColumn() != "c" {
		t.Fatalf("pushed columns = %+v, want the fragment folded by the held session", pushed.Columns)
	}
}

func TestProbeSessionFailsWithoutTheSettingsRow(t *testing.T) {
	for name, probe := range map[string]func(string, int) ([][]*string, error){
		"probe error": func(string, int) ([][]*string, error) { return nil, errors.New("lost connection") },
		"no row":      func(string, int) ([][]*string, error) { return nil, nil },
	} {
		if _, err := NewSession(refetchQueries, probe); err == nil {
			t.Errorf("%s: NewSession succeeded, want the connection refused", name)
		}
	}
}

func TestRefetchIncoherentHashesAreTerminal(t *testing.T) {
	var hashCalls int
	r := ProxyCommandRunner{
		Catalog: "def",
		Queries: refetchQueries, Session: testSession,
		Probe: func(sql string, columns int) ([][]*string, error) {
			if strings.HasPrefix(sql, "hash:") {
				hashCalls++
				return [][]*string{{ptr([]string{"first", "second"}[hashCalls-1])}}, nil
			}
			return fragmentRows("app"), nil
		},
		Push: func(*pb.SchemaFragmentPush) (uint64, error) {
			t.Fatal("a schema that changed under the read must not be pushed")
			return 0, nil
		},
	}
	if err := r.Refetch(&pb.Refetch{Schema: "app", Catalog: "def", IfHashDiffers: []byte("never")}); err == nil || !strings.Contains(err.Error(), "changed during introspection") {
		t.Fatalf("Run error = %v, want changed-during-introspection", err)
	}
}

func TestRefetchUntrustedHashesUseNonce(t *testing.T) {
	cases := []struct {
		name   string
		hashes []string
		errAt  int
	}{
		{name: "untrusted", hashes: []string{"untrusted", "untrusted"}},
		{name: "first probe error", hashes: []string{"ignored", "stable"}, errAt: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hashCalls int
			var pushed *pb.SchemaFragmentPush
			r := ProxyCommandRunner{
				Catalog: "def",
				Queries: refetchQueries, Session: testSession,
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
			if err := r.Refetch(&pb.Refetch{Schema: "app", Catalog: "def", IfHashDiffers: []byte("never")}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(pushed.ContentHash) != 32 {
				t.Fatalf("nonce length = %d, want 32", len(pushed.ContentHash))
			}
			for _, h := range tc.hashes {
				if bytes.Equal(pushed.ContentHash, []byte(h)) {
					t.Fatalf("nonce aliases inspected hash %q", h)
				}
			}
		})
	}
}

func TestRefetchTerminalErrors(t *testing.T) {
	t.Run("blank schema", func(t *testing.T) {
		r := ProxyCommandRunner{Catalog: "def", Queries: refetchQueries, Session: testSession, Probe: func(string, int) ([][]*string, error) { return nil, nil }, Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 0, nil }}
		if err := r.Refetch(&pb.Refetch{Catalog: "def"}); err == nil {
			t.Fatal("Run succeeded, want blank-schema error")
		}
	})
	t.Run("introspection", func(t *testing.T) {
		r := ProxyCommandRunner{Catalog: "def", Queries: refetchQueries, Session: testSession, Probe: func(sql string, _ int) ([][]*string, error) {
			if strings.HasPrefix(sql, "columns:") {
				return nil, errors.New("introspection failed")
			}
			return [][]*string{{ptr("hash")}}, nil
		}, Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 0, nil }}
		if err := r.Refetch(&pb.Refetch{Schema: "app", Catalog: "def"}); err == nil {
			t.Fatal("Run succeeded, want introspection error")
		}
	})
	t.Run("push", func(t *testing.T) {
		r := ProxyCommandRunner{Catalog: "def", Queries: refetchQueries, Session: testSession, Probe: func(sql string, _ int) ([][]*string, error) {
			if strings.HasPrefix(sql, "columns:") {
				return fragmentRows("app"), nil
			}
			return [][]*string{{ptr("hash")}}, nil
		}, Push: func(*pb.SchemaFragmentPush) (uint64, error) { return 0, errors.New("push failed") }}
		if err := r.Refetch(&pb.Refetch{Schema: "app", Catalog: "def"}); err == nil || !strings.Contains(err.Error(), "push failed") {
			t.Fatalf("Run error = %v, want push failure", err)
		}
	})
}

func TestRefetchRunAllOrdersAndStops(t *testing.T) {
	var pushed []string
	r := ProxyCommandRunner{
		Catalog: "def",
		Queries: refetchQueries, Session: testSession,
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
	refetch := func(schema string) *pb.ProxyCommand {
		return &pb.ProxyCommand{Command: &pb.ProxyCommand_Refetch{Refetch: &pb.Refetch{Catalog: "def", Schema: schema}}}
	}
	err := r.RunAll([]*pb.ProxyCommand{refetch("one"), refetch("two"), refetch("three")}, nil)
	if err == nil {
		t.Fatal("RunAll succeeded, want second-command error")
	}
	if !reflect.DeepEqual(pushed, []string{"one", "two"}) {
		t.Fatalf("push order = %v, want [one two]", pushed)
	}
}

func TestFragmentColumnsFromRowsStrict(t *testing.T) {
	str := func(s string) *string { return &s }
	valid := [][]*string{{str("app"), str("users"), str("id"), str("integer"), str("1"), str("NO"), str("db")}, {str("app"), str("users"), str("email"), str("text"), str("2"), str("YES"), str("db")}}
	got, err := FragmentColumnsFromRows(testSession, "app", valid)
	if err != nil {
		t.Fatalf("FragmentColumnsFromRows: %v", err)
	}
	want := []*analyzerpb.Column{{Catalog: "db", Schema: "app", Table: "users", Column: "id", DataType: "integer", Ordinal: 1}, {Catalog: "db", Schema: "app", Table: "users", Column: "email", DataType: "text", Ordinal: 2, Nullable: true}}
	if !slices.EqualFunc(got, want, func(a, b *analyzerpb.Column) bool { return proto.Equal(a, b) }) {
		t.Fatalf("columns = %+v, want %+v", got, want)
	}

	cases := []struct {
		name string
		rows [][]*string
	}{
		{"wrong width", [][]*string{{str("app")}}},
		{"nil field", [][]*string{{str("app"), nil, str("id"), str("int"), str("1"), str("NO"), str("db")}}},
		{"schema mismatch", [][]*string{{str("other"), str("t"), str("c"), str("int"), str("1"), str("NO"), str("db")}}},
		{"bad ordinal", [][]*string{{str("app"), str("t"), str("c"), str("int"), str("2147483648"), str("NO"), str("db")}}},
		{"bad nullable", [][]*string{{str("app"), str("t"), str("c"), str("int"), str("1"), str("TRUE"), str("db")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FragmentColumnsFromRows(testSession, "app", tc.rows); err == nil {
				t.Fatal("FragmentColumnsFromRows succeeded, want strict error")
			}
		})
	}
}
