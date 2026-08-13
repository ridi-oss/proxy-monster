package probe

import (
	"sort"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestDerivedProjectionFacts locks the derived-projection masking facts (docs/derived-masking.md):
// a pure per-row scalar transform of a column emits an OriginInfo with derived=true carrying the base
// columns on the ordinal, so the control-plane can redact a masked base column in full. An aggregate/
// window/subquery output, or any DISTINCT query, is NOT derived — it stays a DERIVED reference so a
// masked base column DENYs (row-collapsing/reshaping cannot be neutralized by cell redaction). A base
// column that also reaches a row-shaping position (ORDER BY / GROUP BY / predicate) is recorded in
// that reference bucket independently, so the reference check denies before any ordinal redaction.
func TestDerivedProjectionFacts(t *testing.T) {
	// MySQL leads (def catalog, ansi schema = mysql "database"); Postgres re-runs the same shapes.
	engines := []struct {
		name  string
		ec    *pb.EngineConfig
		ns    *pb.Namespace
		cols  []*pb.ColumnSpec
		ssn   string // fully-qualified base key of the protected column
		email string
		id    string
	}{
		{
			name: "mysql",
			ec:   &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)},
			ns:   &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}},
			cols: []*pb.ColumnSpec{
				columnSpec("def", "app", "users", "id", "BIGINT"),
				columnSpec("def", "app", "users", "ssn", "VARCHAR"),
				columnSpec("def", "app", "users", "email", "VARCHAR"),
			},
			ssn: "def.app.users.ssn", email: "def.app.users.email", id: "def.app.users.id",
		},
		{
			name: "postgres",
			ec:   &pb.EngineConfig{Engine: pb.Engine_POSTGRES},
			ns:   &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}},
			cols: []*pb.ColumnSpec{
				columnSpec("acme", "public", "users", "id", "BIGINT"),
				columnSpec("acme", "public", "users", "ssn", "VARCHAR"),
				columnSpec("acme", "public", "users", "email", "VARCHAR"),
			},
			ssn: "acme.public.users.ssn", email: "acme.public.users.email", id: "acme.public.users.id",
		},
	}

	for _, e := range engines {
		t.Run(e.name, func(t *testing.T) {
			// wantOrigin is one expected output ordinal: its derived flag and base columns.
			type wantOrigin struct {
				derived bool
				origins []string
			}
			cases := []struct {
				name string
				sql  string
				// origins expected per output ordinal, in order.
				origins []wantOrigin
				// reference-context buckets that MUST contain the protected column (the DENY path).
				refHas map[string][]string
				// reference-context buckets that must be ABSENT (proves the redact path is unblocked).
				refAbsent []string
			}{
				{
					name:      "scalar transform → derived, redactable, no reference",
					sql:       "SELECT upper(ssn) FROM users",
					origins:   []wantOrigin{{derived: true, origins: []string{e.ssn}}},
					refAbsent: []string{"DERIVED", "ORDER_BY", "GROUP_BY", "PREDICATE"},
				},
				{
					name:    "direct projection stays non-derived (masked via its own kind)",
					sql:     "SELECT ssn FROM users",
					origins: []wantOrigin{{derived: false, origins: []string{e.ssn}}},
				},
				{
					name: "mixed: direct id + derived transform of ssn",
					sql:  "SELECT id, upper(ssn) AS x FROM users",
					origins: []wantOrigin{
						{derived: false, origins: []string{e.id}},
						{derived: true, origins: []string{e.ssn}},
					},
					refAbsent: []string{"DERIVED"},
				},
				{
					name:      "multi-base scalar transform carries every base column",
					sql:       "SELECT concat(ssn, email) FROM users",
					origins:   []wantOrigin{{derived: true, origins: []string{e.email, e.ssn}}},
					refAbsent: []string{"DERIVED"},
				},
				{
					name:    "aggregate is NOT derived → DERIVED reference (deny)",
					sql:     "SELECT max(ssn) FROM users",
					origins: []wantOrigin{{derived: false, origins: []string{}}},
					refHas:  map[string][]string{"DERIVED": {e.ssn}},
				},
				{
					name:    "window is NOT derived → row-shaping reference (deny)",
					sql:     "SELECT row_number() OVER (ORDER BY ssn) FROM users",
					origins: []wantOrigin{{derived: false, origins: []string{}}},
					refHas:  map[string][]string{"ORDER_BY": {e.ssn}},
				},
				{
					name:    "DISTINCT scalar transform is NOT derived (dedup cardinality leak)",
					sql:     "SELECT DISTINCT upper(ssn) FROM users",
					origins: []wantOrigin{{derived: false, origins: []string{}}},
					refHas:  map[string][]string{"DERIVED": {e.ssn}},
				},
				{
					name:    "derived transform ALSO in ORDER BY → recorded as a reference (deny before redact)",
					sql:     "SELECT upper(ssn) FROM users ORDER BY upper(ssn)",
					origins: []wantOrigin{{derived: true, origins: []string{e.ssn}}},
					refHas:  map[string][]string{"ORDER_BY": {e.ssn}},
				},
				{
					name:    "positional ORDER BY over a derived transform → ORDER_BY reference (deny)",
					sql:     "SELECT upper(ssn) FROM users ORDER BY 1",
					origins: []wantOrigin{{derived: true, origins: []string{e.ssn}}},
					refHas:  map[string][]string{"ORDER_BY": {e.ssn}},
				},
				{
					name:    "aliased ORDER BY over a derived transform → ORDER_BY reference (deny)",
					sql:     "SELECT upper(ssn) AS u FROM users ORDER BY u",
					origins: []wantOrigin{{derived: true, origins: []string{e.ssn}}},
					refHas:  map[string][]string{"ORDER_BY": {e.ssn}},
				},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					r := analyzeProbe(t, &pb.AnalyzeRequest{Sql: tc.sql, EngineConfig: e.ec, Namespace: e.ns, Catalog: e.cols})
					if !r.Resolved {
						t.Fatalf("expected resolved=true; sql=%q detail=%q", tc.sql, r.Detail)
					}
					if len(r.Origins) != len(tc.origins) {
						t.Fatalf("origin count = %d, want %d; origins=%+v", len(r.Origins), len(tc.origins), r.Origins)
					}
					for i, want := range tc.origins {
						got := r.Origins[i]
						if got.Derived != want.derived {
							t.Errorf("origin[%d] derived = %v, want %v (col=%q)", i, got.Derived, want.derived, got.Column)
						}
						if !sameSet(got.Origins, want.origins) {
							t.Errorf("origin[%d] origins = %v, want %v", i, got.Origins, want.origins)
						}
					}
					refs := r.References
					for ctx, cols := range tc.refHas {
						got := refs[ctx]
						if got == nil || !containsAll(got, cols) {
							t.Errorf("references[%s] = %v, want ⊇ %v", ctx, colsOf(got), cols)
						}
					}
					for _, ctx := range tc.refAbsent {
						if got := refs[ctx]; got != nil && len(got) > 0 {
							t.Errorf("references[%s] = %v, want absent (redact path must be unblocked)", ctx, got)
						}
					}
				})
			}
		})
	}
}

// TestRedactableWhitelistGate locks the security boundary of the redaction whitelist
// (docs/derived-masking.md): ONLY a provably-total, side-effect-free string transform of the masked
// column is redactable. Anything that can fault or warn on the value — cast/coercion, arithmetic,
// comparison, conditional, a column in a numeric arg, or a transform hidden through a subquery — must NOT
// be marked derived (it stays a DERIVED reference → DENY), because executing it leaks the value through
// the error-presence / SQLSTATE / warning-count channel that blanking the output cell cannot close.
func TestRedactableWhitelistGate(t *testing.T) {
	for _, e := range []struct {
		name, cat, sch string
		ec             *pb.EngineConfig
		ns             *pb.Namespace
	}{
		{"mysql", "def", "app", &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(1)}, &pb.Namespace{Catalog: "def", SearchPath: []string{"app"}}},
		{"postgres", "acme", "public", &pb.EngineConfig{Engine: pb.Engine_POSTGRES}, &pb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}},
	} {
		t.Run(e.name, func(t *testing.T) {
			cols := []*pb.ColumnSpec{
				columnSpec(e.cat, e.sch, "users", "id", "BIGINT"),
				columnSpec(e.cat, e.sch, "users", "ssn", "VARCHAR"),
				columnSpec(e.cat, e.sch, "users", "email", "VARCHAR"),
			}
			ssn := e.cat + "." + e.sch + ".users.ssn"
			// redactable returns true iff output ordinal 0 is a redactable derived transform (derived=true
			// and the masked column is NOT in any reference bucket).
			redactable := func(sql string) bool {
				r := analyzeProbe(t, &pb.AnalyzeRequest{Sql: sql, EngineConfig: e.ec, Namespace: e.ns, Catalog: cols})
				if !r.Resolved || len(r.Origins) == 0 || !r.Origins[0].Derived {
					return false
				}
				for _, cr := range r.References {
					for _, c := range cr {
						if c == ssn {
							return false
						}
					}
				}
				return true
			}
			// Provably-total string transforms → redactable.
			for _, sql := range []string{
				"SELECT upper(ssn) FROM users",
				"SELECT lower(ssn) FROM users",
				"SELECT substr(ssn, 1, 3) FROM users",
				"SELECT left(ssn, 3) FROM users",
				"SELECT concat(ssn, '-x') FROM users",
				"SELECT md5(ssn) FROM users",
				"SELECT length(ssn) FROM users",
				"SELECT upper(substr(ssn, 1, 6)) FROM users",
				"SELECT coalesce(ssn, 'unknown') FROM users", // string-literal fallback is total
			} {
				if !redactable(sql) {
					t.Errorf("want REDACTABLE, got denied: %q", sql)
				}
			}
			// Fault/warn-capable or subquery-hidden → must NOT be redactable (→ DENY).
			for _, sql := range []string{
				"SELECT cast(ssn as char) FROM users",                               // cast/coercion
				"SELECT 1/(ascii(substr(ssn,1,1)) - 115) FROM users",                // division equality oracle
				"SELECT pow(1e300, ascii(substr(ssn,1,1)) - 100) FROM users",        // overflow threshold oracle
				"SELECT case when ssn like '90%' then 1 else 0 end FROM users",      // conditional
				"SELECT (ssn = 'x') FROM users",                                     // comparison
				"SELECT substr(ssn, ascii(ssn), 1) FROM users",                      // column in a numeric arg
				"SELECT c FROM (SELECT cast(ssn as char) AS c FROM users) t",        // oracle hidden in a subquery
				"SELECT upper(c) FROM (SELECT cast(ssn as char) AS c FROM users) t", // hidden under a whitelisted wrapper
				"SELECT c FROM (SELECT md5(ssn) AS c FROM users) t",                 // even a safe transform hidden below → deny
				"SELECT coalesce(ssn, 0) FROM users",                                // numeric fallback → type-unification, can fault
			} {
				if redactable(sql) {
					t.Errorf("want DENY (not redactable), got redactable: %q", sql)
				}
			}
		})
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func containsAll(hay, needles []string) bool {
	set := map[string]bool{}
	for _, h := range hay {
		set[h] = true
	}
	for _, n := range needles {
		if !set[n] {
			return false
		}
	}
	return true
}

func colsOf(r []string) []string { return r }
