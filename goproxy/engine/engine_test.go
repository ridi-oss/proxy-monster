package engine

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

type fakeDb struct {
	dialect      Dialect
	nsProbeSQL   string
	tempOverlay  bool
	tempProbeSQL string
}

func (f fakeDb) Dialect() Dialect            { return f.dialect }
func (f fakeDb) NamespaceProbeSQL() string   { return f.nsProbeSQL }
func (f fakeDb) SupportsTempOverlay() bool   { return f.tempOverlay }
func (f fakeDb) TempColumnsProbeSQL() string { return f.tempProbeSQL }
func (f fakeDb) HashSetupProbeSQL() string   { return "" }
func (f fakeDb) HashSetupColumns() int       { return 0 }
func (f fakeDb) SchemaHashSQL(string, [][]*string) (string, int, error) {
	return "hash", 1, nil
}
func (f fakeDb) SchemaHashFromRows([][]*string) ([]byte, bool, error)      { return nil, false, nil }
func (f fakeDb) SchemaColumnsSQL(string) string                            { return "columns" }
func (f fakeDb) LowerCaseTableNamesProbeSQL() string                       { return "" }
func (f fakeDb) NormalizeColumns(_ int, columns []*pb.Column) []*pb.Column { return columns }

var mysqlDb = fakeDb{dialect: MySQL, nsProbeSQL: "SELECT DATABASE()"}
var pgDb = fakeDb{dialect: Postgres, nsProbeSQL: "probe", tempOverlay: true, tempProbeSQL: "temps"}

type fakeDecider struct {
	outcome DecisionOutcome
	calls   int
	lastReq DecideRequest
}

func (f *fakeDecider) Decide(req DecideRequest) DecisionOutcome {
	f.calls++
	f.lastReq = req
	return f.outcome
}

func okOutcome(action string, masks []*pb.ColumnMask) DecisionOutcome {
	return DecisionOutcome{Decision: &Decision{Action: action, Masks: masks}}
}

// staticNamespace returns a probe callback that yields ns (no ANSI_QUOTES) and counts its calls.
func staticNamespace(ns []string, calls *int) func() (NamespaceProbe, error) {
	return func() (NamespaceProbe, error) {
		*calls++
		return NamespaceProbe{Namespace: ns}, nil
	}
}

func TestAuthorizeReducesControlPlaneVerdict(t *testing.T) {
	masks := []*pb.ColumnMask{{Column: "ssn", Kind: "FIXED", Ordinal: proto.Int32(1)}}
	cases := []struct {
		name    string
		outcome DecisionOutcome
		want    Verdict
	}{
		{"allow", okOutcome("ALLOW", nil), Proceed{Decision: &Decision{Action: "ALLOW"}}},
		{"mask", okOutcome("MASK", masks), Proceed{Decision: &Decision{Action: "MASK", Masks: masks}, Masks: masks}},
		{"deny", okOutcome("DENY", nil), Deny{Decision: &Decision{Action: "DENY"}}},
		{"cp-error fails closed", DecisionOutcome{Err: "unreachable"}, Fail{Message: "unreachable"}},
		{"unexpected action fails closed to deny", okOutcome("SURPRISE", nil), Deny{Decision: &Decision{Action: "SURPRISE"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dec := &fakeDecider{outcome: c.outcome}
			e := NewQueryEngine(mysqlDb, dec)
			got := e.Authorize(AuthzInput{SQL: "SELECT 1", ProbeNamespace: staticNamespace([]string{"app"}, new(int))})
			if reflect.TypeOf(got) != reflect.TypeOf(c.want) {
				t.Fatalf("verdict type: got %T, want %T", got, c.want)
			}
			if p, ok := got.(Proceed); ok && !reflect.DeepEqual(p.Masks, c.want.(Proceed).Masks) {
				t.Fatalf("masks: got %+v, want %+v", p.Masks, c.want.(Proceed).Masks)
			}
		})
	}
}

func TestAuthorizeSanitizeDiagnosticsIsPerDecision(t *testing.T) {
	dec := &fakeDecider{outcome: DecisionOutcome{Decision: &Decision{Action: "ALLOW", SanitizeDiagnostics: true}}}
	e := NewQueryEngine(mysqlDb, dec)
	if e.SanitizeDiagnostics() {
		t.Fatal("must start clear")
	}
	e.Authorize(AuthzInput{SQL: "SELECT 1", ProbeNamespace: staticNamespace([]string{"app"}, new(int))})
	if !e.SanitizeDiagnostics() {
		t.Fatal("a decision with SanitizeDiagnostics=true must set it")
	}
	// Per-decision, NOT monotonic: a later decision that does not request redaction clears it. This is what
	// lets a MySQL ALLOW after a MASK relay its diagnostics verbatim (the control plane decides fresh each
	// Decide; an ALLOW MySQL query cannot leak a protected value through a diagnostic).
	dec.outcome = DecisionOutcome{Decision: &Decision{Action: "ALLOW", SanitizeDiagnostics: false}}
	e.Authorize(AuthzInput{SQL: "SELECT 2", ProbeNamespace: staticNamespace([]string{"app"}, new(int))})
	if e.SanitizeDiagnostics() {
		t.Fatal("a later decision with SanitizeDiagnostics=false must clear it (per-decision, not latched)")
	}
}

func TestAuthorizeSanitizeDiagnosticsStaysClearWhenNeverRequested(t *testing.T) {
	// A decision that never requests redaction (e.g. a system:development datasource, or a MySQL ALLOW)
	// leaves diagnostics relaying verbatim for debugging.
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	e := NewQueryEngine(mysqlDb, dec)
	e.Authorize(AuthzInput{SQL: "SELECT 1", ProbeNamespace: staticNamespace([]string{"app"}, new(int))})
	if e.SanitizeDiagnostics() {
		t.Fatal("must stay clear when no decision requests redaction")
	}
}

func TestAuthorizePassesConnectionCatalogCallbacks(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	connectionID := []byte("0123456789abcdef")
	runCommands := func([]*pb.Refetch) error { return nil }
	got := NewQueryEngine(mysqlDb, dec).Authorize(AuthzInput{
		SQL:              "SELECT 1",
		Token:            "token",
		ClientAddr:       "127.0.0.1:1234",
		ConnectionID:     connectionID,
		ProbeNamespace:   staticNamespace([]string{"app"}, new(int)),
		ProbeTempColumns: nil,
		RunCommands:      runCommands,
	})
	if _, ok := got.(Proceed); !ok {
		t.Fatalf("Authorize verdict = %T, want Proceed", got)
	}
	if !reflect.DeepEqual(dec.lastReq.ConnectionID, connectionID) {
		t.Fatalf("ConnectionID = %x, want %x", dec.lastReq.ConnectionID, connectionID)
	}
	if dec.lastReq.RunCommands == nil {
		t.Fatal("RunCommands was not passed through")
	}
	if reflect.ValueOf(dec.lastReq.RunCommands).Pointer() != reflect.ValueOf(runCommands).Pointer() {
		t.Fatal("Authorize replaced the RunCommands callback")
	}
}

func TestAuthorizeNamespaceProbeFailureFailsClosed(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	e := NewQueryEngine(mysqlDb, dec)
	got := e.Authorize(AuthzInput{SQL: "SELECT 1", ProbeNamespace: func() (NamespaceProbe, error) { return NamespaceProbe{}, errors.New("boom") }})
	if _, ok := got.(Fail); !ok {
		t.Fatalf("want Fail on namespace probe error, got %T", got)
	}
	if dec.calls != 0 {
		t.Fatalf("must not call Decide when namespace is unknown; calls=%d", dec.calls)
	}
}

func TestNamespaceCachedUntilDirty(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	e := NewQueryEngine(mysqlDb, dec)
	probes := 0
	in := AuthzInput{SQL: "SELECT 1", ProbeNamespace: staticNamespace([]string{"app"}, &probes)}

	e.Authorize(in)
	e.Authorize(in)
	if probes != 1 {
		t.Fatalf("namespace should be probed once and cached; probes=%d", probes)
	}
	e.MarkNamespaceDirty()
	e.Authorize(in)
	if probes != 2 {
		t.Fatalf("dirty namespace should re-probe; probes=%d", probes)
	}
	if !reflect.DeepEqual(dec.lastReq.Namespace, []string{"app"}) {
		t.Fatalf("Decide got namespace %v", dec.lastReq.Namespace)
	}

	observed := []string{"other"}
	e.SetNamespace(observed)
	observed[0] = "mutated"
	e.Authorize(in)
	if probes != 2 {
		t.Fatalf("observed namespace should avoid a probe; probes=%d", probes)
	}
	if !reflect.DeepEqual(dec.lastReq.Namespace, []string{"other"}) {
		t.Fatalf("Decide got observed namespace %v", dec.lastReq.Namespace)
	}

	e.SetNamespace([]string{})
	e.Authorize(in)
	if probes != 2 {
		t.Fatalf("observed empty namespace should avoid a probe; probes=%d", probes)
	}
	if dec.lastReq.Namespace == nil || len(dec.lastReq.Namespace) != 0 {
		t.Fatalf("Decide got empty namespace %#v, want a non-nil empty slice", dec.lastReq.Namespace)
	}
}

func TestMysqlAnsiQuotesForwardedAndCached(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	e := NewQueryEngine(mysqlDb, dec)
	probes := 0
	in := AuthzInput{SQL: `SELECT "card_number" FROM cards`, ProbeNamespace: func() (NamespaceProbe, error) {
		probes++
		return NamespaceProbe{Namespace: []string{"app"}, MySQLAnsiQuotes: true}, nil
	}}

	e.Authorize(in)
	if !dec.lastReq.MysqlAnsiQuotes {
		t.Fatal("an observed ANSI_QUOTES session must be forwarded to Decide")
	}
	// The observation rides the namespace cache: a second authorize without a re-probe reuses it.
	e.Authorize(in)
	if probes != 1 {
		t.Fatalf("ANSI_QUOTES observation should ride the namespace cache; probes=%d", probes)
	}
	if !dec.lastReq.MysqlAnsiQuotes {
		t.Fatal("the cached ANSI_QUOTES observation must still be forwarded")
	}

	// Per-probe, not latched: a later probe that no longer observes ANSI_QUOTES clears the forwarded flag,
	// so a mid-session flip back to the default mode is decided under the default lexer.
	e.MarkNamespaceDirty()
	in.ProbeNamespace = func() (NamespaceProbe, error) { return NamespaceProbe{Namespace: []string{"app"}}, nil }
	e.Authorize(in)
	if dec.lastReq.MysqlAnsiQuotes {
		t.Fatal("a probe that no longer observes ANSI_QUOTES must clear the forwarded flag")
	}
}

func TestTempOverlayOnlyWhenSupported(t *testing.T) {
	temps := []TempColumn{{Schema: "pg_temp_3", Table: "t", Column: "c", Ordinal: 0}}
	probeTemps := func() ([]TempColumn, error) { return temps, nil }

	// MySQL: no overlay -> temp probe never consulted.
	decMy := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	NewQueryEngine(mysqlDb, decMy).Authorize(AuthzInput{
		SQL: "SELECT 1", ProbeNamespace: staticNamespace([]string{"app"}, new(int)), ProbeTempColumns: probeTemps,
	})
	if len(decMy.lastReq.TempColumns) != 0 {
		t.Fatalf("MySQL (no overlay) must send no temp columns; got %+v", decMy.lastReq.TempColumns)
	}

	// PG: overlay supported -> temp columns forwarded.
	decPg := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	NewQueryEngine(pgDb, decPg).Authorize(AuthzInput{
		SQL: "SELECT 1", ProbeNamespace: staticNamespace([]string{"public"}, new(int)), ProbeTempColumns: probeTemps,
	})
	if !reflect.DeepEqual(decPg.lastReq.TempColumns, temps) {
		t.Fatalf("PG overlay temp columns: got %+v, want %+v", decPg.lastReq.TempColumns, temps)
	}
}

func TestFragmentColumnsFromRowsStrict(t *testing.T) {
	str := func(s string) *string { return &s }
	valid := [][]*string{{str("app"), str("users"), str("id"), str("integer"), str("1"), str("NO")}, {str("app"), str("users"), str("email"), str("text"), str("2"), str("YES")}}
	got, err := FragmentColumnsFromRows(fakeDb{}, 0, "app", valid)
	if err != nil {
		t.Fatalf("FragmentColumnsFromRows: %v", err)
	}
	want := []*pb.Column{{Schema: "app", Table: "users", Column: "id", DataType: "integer", Ordinal: 1}, {Schema: "app", Table: "users", Column: "email", DataType: "text", Ordinal: 2, Nullable: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("columns = %+v, want %+v", got, want)
	}

	cases := []struct {
		name string
		rows [][]*string
	}{
		{"wrong width", [][]*string{{str("app")}}},
		{"nil field", [][]*string{{str("app"), nil, str("id"), str("int"), str("1"), str("NO")}}},
		{"schema mismatch", [][]*string{{str("other"), str("t"), str("c"), str("int"), str("1"), str("NO")}}},
		{"bad ordinal", [][]*string{{str("app"), str("t"), str("c"), str("int"), str("2147483648"), str("NO")}}},
		{"bad nullable", [][]*string{{str("app"), str("t"), str("c"), str("int"), str("1"), str("TRUE")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FragmentColumnsFromRows(fakeDb{}, 0, "app", tc.rows); err == nil {
				t.Fatal("FragmentColumnsFromRows succeeded, want strict error")
			}
		})
	}
}

func TestTempProbeIsBestEffort(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	e := NewQueryEngine(pgDb, dec)
	got := e.Authorize(AuthzInput{
		SQL:              "SELECT 1",
		ProbeNamespace:   staticNamespace([]string{"public"}, new(int)),
		ProbeTempColumns: func() ([]TempColumn, error) { return nil, errors.New("temp probe failed") },
	})
	// A failed temp probe is swallowed (fail-closed at the CP against the base catalog), not a Fail.
	if _, ok := got.(Proceed); !ok {
		t.Fatalf("temp probe failure must be best-effort, got %T", got)
	}
	if dec.calls != 1 || len(dec.lastReq.TempColumns) != 0 {
		t.Fatalf("Decide should run once with no temps; calls=%d temps=%+v", dec.calls, dec.lastReq.TempColumns)
	}
}
