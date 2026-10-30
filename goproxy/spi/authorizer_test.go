package spi

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

type fakeDecider struct {
	ControlPlane
	outcome  DecisionOutcome
	calls    int
	lastReq  DecideRequest
	identity Identity
}

func (f *fakeDecider) OpenConnection(string, string) (Identity, error) { return f.identity, nil }

func (f *fakeDecider) Decide(req DecideRequest) DecisionOutcome {
	f.calls++
	f.lastReq = req
	return f.outcome
}

func okOutcome(action string, masks []*pb.ColumnMask) DecisionOutcome {
	return DecisionOutcome{Decision: &Decision{Action: action, Masks: masks}}
}

// staticNamespace returns a probe callback that yields ns (no ANSI_QUOTES) and counts its calls.
func staticNamespace(ns []string, calls *int) func() (SessionSnapshot, error) {
	return func() (SessionSnapshot, error) {
		*calls++
		return SessionSnapshot{Namespace: ns}, nil
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
			authz := NewAuthorizer(dec, "", nil)
			got := authz.Authorize(AuthzInput{SQL: "SELECT 1", ProbeSession: staticNamespace([]string{"app"}, new(int))})
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
	authz := NewAuthorizer(dec, "", nil)
	if authz.SanitizeDiagnostics() {
		t.Fatal("must start clear")
	}
	authz.Authorize(AuthzInput{SQL: "SELECT 1", ProbeSession: staticNamespace([]string{"app"}, new(int))})
	if !authz.SanitizeDiagnostics() {
		t.Fatal("a decision with SanitizeDiagnostics=true must set it")
	}
	// Per-decision, NOT monotonic: a later decision that does not request redaction clears it. This is what
	// lets a MySQL ALLOW after a MASK relay its diagnostics verbatim (the control plane decides fresh each
	// Decide; an ALLOW MySQL query cannot leak a protected value through a diagnostic).
	dec.outcome = DecisionOutcome{Decision: &Decision{Action: "ALLOW", SanitizeDiagnostics: false}}
	authz.Authorize(AuthzInput{SQL: "SELECT 2", ProbeSession: staticNamespace([]string{"app"}, new(int))})
	if authz.SanitizeDiagnostics() {
		t.Fatal("a later decision with SanitizeDiagnostics=false must clear it (per-decision, not latched)")
	}
}

func TestAuthorizeSanitizeDiagnosticsStaysClearWhenNeverRequested(t *testing.T) {
	// A decision that never requests redaction (e.g. a system:development datasource, or a MySQL ALLOW)
	// leaves diagnostics relaying verbatim for debugging.
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(dec, "", nil)
	authz.Authorize(AuthzInput{SQL: "SELECT 1", ProbeSession: staticNamespace([]string{"app"}, new(int))})
	if authz.SanitizeDiagnostics() {
		t.Fatal("must stay clear when no decision requests redaction")
	}
}

func TestAuthorizePassesConnectionCatalogCallbacks(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	connectionID := []byte("0123456789abcdef")
	commandRunner := &fakeCommandRunner{}
	dec.identity = Identity{ConnectionID: connectionID}
	authz, _, err := Authenticate(dec, "token", "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	got := authz.Authorize(AuthzInput{
		SQL:              "SELECT 1",
		ProbeSession:     staticNamespace([]string{"app"}, new(int)),
		ProbeTempColumns: nil,
		Commands:         commandRunner,
	})
	if _, ok := got.(Proceed); !ok {
		t.Fatalf("Authorize verdict = %T, want Proceed", got)
	}
	if dec.lastReq.Token != "token" || dec.lastReq.ClientAddr != "127.0.0.1:1234" {
		t.Fatalf("Token, ClientAddr = %q, %q", dec.lastReq.Token, dec.lastReq.ClientAddr)
	}
	if !reflect.DeepEqual(dec.lastReq.ConnectionID, connectionID) {
		t.Fatalf("ConnectionID = %x, want %x", dec.lastReq.ConnectionID, connectionID)
	}
	if dec.lastReq.Commands != commandRunner {
		t.Fatal("Authorize did not pass the command runner through")
	}
}

func TestAuthorizeNamespaceProbeFailureFailsClosed(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(dec, "", nil)
	got := authz.Authorize(AuthzInput{SQL: "SELECT 1", ProbeSession: func() (SessionSnapshot, error) { return SessionSnapshot{}, errors.New("boom") }})
	if _, ok := got.(Fail); !ok {
		t.Fatalf("want Fail on namespace probe error, got %T", got)
	}
	if dec.calls != 0 {
		t.Fatalf("must not call Decide when namespace is unknown; calls=%d", dec.calls)
	}
}

func TestNamespaceCachedUntilDirty(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(dec, "", nil)
	probes := 0
	in := AuthzInput{SQL: "SELECT 1", ProbeSession: staticNamespace([]string{"app"}, &probes)}

	authz.Authorize(in)
	authz.Authorize(in)
	if probes != 1 {
		t.Fatalf("namespace should be probed once and cached; probes=%d", probes)
	}
	authz.MarkNamespaceDirty()
	authz.Authorize(in)
	if probes != 2 {
		t.Fatalf("dirty namespace should re-probe; probes=%d", probes)
	}
	if !reflect.DeepEqual(dec.lastReq.Snapshot.Namespace, []string{"app"}) {
		t.Fatalf("Decide got namespace %v", dec.lastReq.Snapshot.Namespace)
	}

	observed := []string{"other"}
	authz.SetSnapshot(SessionSnapshot{Namespace: observed})
	observed[0] = "mutated"
	authz.Authorize(in)
	if probes != 2 {
		t.Fatalf("observed namespace should avoid a probe; probes=%d", probes)
	}
	if !reflect.DeepEqual(dec.lastReq.Snapshot.Namespace, []string{"other"}) {
		t.Fatalf("Decide got observed namespace %v", dec.lastReq.Snapshot.Namespace)
	}

	authz.SetSnapshot(SessionSnapshot{Namespace: []string{}})
	authz.Authorize(in)
	if probes != 2 {
		t.Fatalf("observed empty namespace should avoid a probe; probes=%d", probes)
	}
	if dec.lastReq.Snapshot.Namespace == nil || len(dec.lastReq.Snapshot.Namespace) != 0 {
		t.Fatalf("Decide got empty namespace %#v, want a non-nil empty slice", dec.lastReq.Snapshot.Namespace)
	}
}

func TestMysqlAnsiQuotesForwardedAndCached(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(dec, "", nil)
	probes := 0
	in := AuthzInput{SQL: `SELECT "card_number" FROM cards`, ProbeSession: func() (SessionSnapshot, error) {
		probes++
		return SessionSnapshot{Namespace: []string{"app"}, SessionObservation: &analyzerpb.SessionObservation{Engine: &analyzerpb.SessionObservation_Mysql{Mysql: &analyzerpb.MySqlSession{AnsiQuotes: true}}}}, nil
	}}

	authz.Authorize(in)
	if !dec.lastReq.Snapshot.GetMysql().GetAnsiQuotes() {
		t.Fatal("an observed ANSI_QUOTES session must be forwarded to Decide")
	}
	// The observation rides the namespace cache: a second authorize without a re-probe reuses it.
	authz.Authorize(in)
	if probes != 1 {
		t.Fatalf("ANSI_QUOTES observation should ride the namespace cache; probes=%d", probes)
	}
	if !dec.lastReq.Snapshot.GetMysql().GetAnsiQuotes() {
		t.Fatal("the cached ANSI_QUOTES observation must still be forwarded")
	}

	// Per-probe, not latched: a later probe that no longer observes ANSI_QUOTES clears the forwarded flag,
	// so a mid-session flip back to the default mode is decided under the default lexer.
	authz.MarkNamespaceDirty()
	in.ProbeSession = func() (SessionSnapshot, error) {
		return SessionSnapshot{Namespace: []string{"app"}, SessionObservation: &analyzerpb.SessionObservation{Engine: &analyzerpb.SessionObservation_Mysql{Mysql: &analyzerpb.MySqlSession{AnsiQuotes: false}}}}, nil
	}
	authz.Authorize(in)
	if dec.lastReq.Snapshot.GetMysql().GetAnsiQuotes() {
		t.Fatal("a probe that no longer observes ANSI_QUOTES must clear the forwarded flag")
	}
}

func TestPostgresLookupStateForwardedAndCached(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(dec, "", nil)
	probes := 0
	observations := []SessionSnapshot{
		{
			Namespace: []string{"pg_catalog", "app"},
			SessionObservation: &analyzerpb.SessionObservation{Engine: &analyzerpb.SessionObservation_Postgres{Postgres: &analyzerpb.PostgresSession{
				ShadowedFunctions: []string{"unnest"}, FunctionShadowingObserved: true, SystemXidVisible: proto.Bool(true),
			}}},
		},
		{
			Namespace: []string{"pg_catalog", "app"},
			SessionObservation: &analyzerpb.SessionObservation{Engine: &analyzerpb.SessionObservation_Postgres{Postgres: &analyzerpb.PostgresSession{
				ShadowedFunctions: []string{}, FunctionShadowingObserved: true, SystemXidVisible: proto.Bool(false),
			}}},
		},
	}
	in := AuthzInput{
		SQL: "SELECT 1",
		ProbeSession: func() (SessionSnapshot, error) {
			probe := observations[probes]
			probes++
			return probe, nil
		},
	}

	authz.Authorize(in)
	if !proto.Equal(dec.lastReq.Snapshot.SessionObservation, observations[0].SessionObservation) {
		t.Fatalf("first Decide session = %+v, want observed [unnest] and visible xid", dec.lastReq.Snapshot)
	}
	authz.Authorize(in)
	if probes != 1 || !proto.Equal(dec.lastReq.Snapshot.SessionObservation, observations[0].SessionObservation) {
		t.Fatalf("cached session probes/request = %d/%+v", probes, dec.lastReq.Snapshot)
	}

	authz.MarkNamespaceDirty()
	authz.Authorize(in)
	if probes != 2 || !proto.Equal(dec.lastReq.Snapshot.SessionObservation, observations[1].SessionObservation) {
		t.Fatalf("re-probed session probes/request = %d/%+v", probes, dec.lastReq.Snapshot)
	}
}

func TestTempOverlayOnlyWhenProvided(t *testing.T) {
	temps := []TempColumn{{Schema: "pg_temp_3", Table: "t", Column: "c", Ordinal: 0}}
	probeTemps := func() ([]TempColumn, error) { return temps, nil }

	// MySQL: no overlay -> temp probe never consulted.
	decMy := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	NewAuthorizer(decMy, "", nil).Authorize(AuthzInput{
		SQL: "SELECT 1", ProbeSession: staticNamespace([]string{"app"}, new(int)),
	})
	if len(decMy.lastReq.TempColumns) != 0 {
		t.Fatalf("MySQL (no overlay) must send no temp columns; got %+v", decMy.lastReq.TempColumns)
	}

	// PG: overlay supported -> temp columns forwarded.
	decPg := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	NewAuthorizer(decPg, "", nil).Authorize(AuthzInput{
		SQL: "SELECT 1", ProbeSession: staticNamespace([]string{"public"}, new(int)), ProbeTempColumns: probeTemps,
	})
	if !reflect.DeepEqual(decPg.lastReq.TempColumns, temps) {
		t.Fatalf("PG overlay temp columns: got %+v, want %+v", decPg.lastReq.TempColumns, temps)
	}
}

func TestTempProbeIsBestEffort(t *testing.T) {
	dec := &fakeDecider{outcome: okOutcome("ALLOW", nil)}
	authz := NewAuthorizer(dec, "", nil)
	got := authz.Authorize(AuthzInput{
		SQL:              "SELECT 1",
		ProbeSession:     staticNamespace([]string{"public"}, new(int)),
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

type fakeCommandRunner struct{}

func (*fakeCommandRunner) RunAll([]*pb.ProxyCommand, *SessionSnapshot) error { return nil }
