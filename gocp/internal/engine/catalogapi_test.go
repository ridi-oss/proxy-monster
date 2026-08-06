package engine

import (
	"errors"
	"strings"
	"testing"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// Port of probe/AnalyzerTest.kt — 72 LOC, 3 cases. In Kotlin these needed the native probe loaded through
// FFM (--enable-native-access, the c-shared library bundled by :analyzer:jvm's processResources). Here
// analyzer/probe is an ordinary Go package, so they are plain package tests with nothing to load.
//
// The tests appended after case 3 close the coverage gaps 13-engine.md §6 names for this sub-area; each
// says which.

func testColumn(catalog, schema, table, name string, pii bool) *probepb.ColumnSpec {
	return &probepb.ColumnSpec{
		Catalog: catalog,
		Identity: &probepb.RelationIdentity{
			Schema: schema,
			Table:  table,
			Column: name,
		},
		DataType: "VARCHAR",
		Pii:      pii,
	}
}

func testNamespace() *probepb.Namespace {
	return &probepb.Namespace{Catalog: "acme", SearchPath: []string{"public"}}
}

func testEngineConfig() *probepb.EngineConfig {
	// AnalyzerTest builds `engineConfig { engine = Engine.POSTGRES }` — no version, no case mode, no
	// ansi_quotes. 13-engine.md §6 flags that as a gap in its own right: the MySQL-specific
	// fail-closed-without-a-parseable-version path is not exercised from this module at all.
	return &probepb.EngineConfig{Engine: probepb.Engine_POSTGRES}
}

func testColumns() []*probepb.ColumnSpec {
	return []*probepb.ColumnSpec{
		testColumn("acme", "public", "users", "id", false),
		testColumn("acme", "public", "users", "rrn", true),
	}
}

// Case 1 — INV-A13-17, INV-A13-16, and the only assertion on PiiColumns anywhere (F23).
// KT: AnalyzerTest.kt#analyzer retains validated request snapshot and returns StatementFacts
func TestAnalyzerRetainsValidatedRequestSnapshotAndReturnsStatementFacts(t *testing.T) {
	ns := testNamespace()
	columns := testColumns()
	config := testEngineConfig()

	analyzer, err := AnalyzerFor(ns, columns, config)
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}
	facts := analyzer.Analyze("select rrn from users")
	if !facts.GetResolved() {
		t.Fatalf("expected a resolved analysis, got failureClass=%v stage=%q detail=%q",
			facts.GetFailureClass(), facts.GetFailedStage(), facts.GetDetail())
	}
	// The request snapshot is held, not copied or rebuilt: these are the exact inputs the caller supplied.
	if analyzer.Namespace() != ns {
		t.Error("the namespace snapshot must be the exact input")
	}
	// The Kotlin is `assertEquals(columns, analyzer.catalogProto)` — the WHOLE list, element for element.
	// Checking only [0] would stay green on a port that kept the length but substituted a later element.
	if got := analyzer.Catalog(); len(got) != len(columns) {
		t.Errorf("the catalog snapshot has %d columns, want the %d supplied", len(got), len(columns))
	} else {
		for i := range columns {
			if got[i] != columns[i] {
				t.Errorf("catalog snapshot[%d] is not the exact input column", i)
			}
		}
	}
	if analyzer.EngineConfig() != config {
		t.Error("the engine config must be forwarded as-is — no re-derivation, no re-parsing")
	}
	// F23: PiiColumns is the rendered key of every ColumnSpec.pii column, insertion-ordered.
	if got, want := analyzer.PiiColumns, []string{"acme.public.users.rrn"}; !equalStrings(got, want) {
		t.Errorf("PiiColumns got %v, want %v", got, want)
	}
	// INV-A13-16: ColumnKeys[i] corresponds to the i-th input column. A6 zips the two lists positionally.
	if got, want := analyzer.ColumnKeys, []string{"acme.public.users.id", "acme.public.users.rrn"}; !equalStrings(got, want) {
		t.Errorf("ColumnKeys got %v, want %v", got, want)
	}
	var sawRRN bool
	for _, grant := range facts.GetRequiredGrants() {
		if grant.GetColumn().GetIdentity().GetColumn() == "rrn" {
			sawRRN = true
		}
	}
	if !sawRRN {
		t.Error("the analysis must require a grant on the projected rrn column")
	}
}

// Case 2 — 🔒 INV-A13-13. A duplicate (schema, table, column) triple is rejected at construction.
//
// ⚠️ The Kotlin test is named "invalid catalog identity fails BEFORE native analysis", but the "before"
// part lives in the NAME ONLY: its body is a bare assertFailsWith with no spy and no call counter, so a
// port that validated lazily inside analyze would still pass it. The ordering is real here — validation
// runs in AnalyzerFor, the probe only in Analyze — and the second half of this test asserts it, which the
// Kotlin never did.
// KT: AnalyzerTest.kt#invalid catalog identity fails before native analysis
// KT: SchemaKeyWiringTest.kt#duplicate catalog keys are rejected as ambiguous — the same seenColumns exact-duplicate branch, asserted here with the message too; the Kotlin's mysqlEngineConfig is immaterial (validateUniqueness never reads engineConfig, catalogapi.go:310)
func TestInvalidCatalogIdentityFailsBeforeNativeAnalysis(t *testing.T) {
	_, err := AnalyzerFor(
		testNamespace(),
		[]*probepb.ColumnSpec{
			testColumn("acme", "public", "users", "id", false),
			testColumn("acme", "public", "users", "id", false),
		},
		testEngineConfig(),
	)
	if err == nil {
		t.Fatal("a duplicate column identity must be rejected")
	}
	if !errors.Is(err, ErrAnalyzerCatalog) {
		t.Errorf("expected an ErrAnalyzerCatalog, got %v", err)
	}
	if want := "catalog contains duplicate column identity: acme.public.users.id"; !strings.Contains(err.Error(), want) {
		t.Errorf("message %q must contain %q — it is wire-visible deny prose through A6's catch", err.Error(), want)
	}
	// The "before native analysis" half, asserted rather than merely named: no Analyzer is returned at
	// all, so there is nothing that could have run the probe.
	analyzer, err := AnalyzerFor(testNamespace(), nil, testEngineConfig())
	if err != nil || analyzer == nil {
		t.Fatalf("an empty catalog is valid; got analyzer=%v err=%v", analyzer, err)
	}
}

// Case 3 — 🔒 the UNANALYZABLE/INADMISSIBLE split, which is exactly what A6 step 16 branches on, and
// INV-A13-14's multi-statement fail-close.
// KT: AnalyzerTest.kt#malformed and batched statements fail closed with explicit failure classes
func TestMalformedAndBatchedStatementsFailClosedWithExplicitFailureClasses(t *testing.T) {
	analyzer, err := AnalyzerFor(testNamespace(), testColumns(), testEngineConfig())
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}

	malformed := analyzer.Analyze("select 'unterminated")
	if malformed.GetResolved() {
		t.Error("a malformed statement must not resolve")
	}
	if got := malformed.GetFailureClass(); got != probepb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
		t.Errorf("failureClass got %v, want UNANALYZABLE", got)
	}

	batch := analyzer.Analyze("select 1; select 2")
	if batch.GetResolved() {
		t.Error("a batched statement must not resolve")
	}
	if got := batch.GetFailureClass(); got != probepb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
		t.Errorf("failureClass got %v, want INADMISSIBLE — the >1-statement fail-close is the admission guard", got)
	}
}

// ---- coverage gaps 13-engine.md §6 names, closed here -------------------------------------------

// 🔒 "The dot-collision case (two DIFFERENT identities rendering to one key) is untested. AnalyzerTest
// case 2 covers only the EXACT DUPLICATE branch. The collision branch is the security-relevant one — it is
// A2 INV-A2-6's analogue and A2 DOES test its half. Add catalog "a.b" + schema "c" vs catalog "a" +
// schema "b.c" in Step 3." — 13-engine.md §6.
//
// '.' is legal inside a quoted SQL identifier, so without this guard two distinct columns share one
// analyzer key and one column's grants apply to the other.
func TestTwoDifferentIdentitiesRenderingToOneAnalyzerKeyAreRejected(t *testing.T) {
	// KT: SchemaKeyWiringTest.kt#dot-containing identifiers that render to one key are rejected rather than parsed — the Kotlin's public+"users.archive" vs "public.users"+archive is this same table-key collision branch
	t.Run("table key collision", func(t *testing.T) {
		_, err := AnalyzerFor(
			&probepb.Namespace{Catalog: "a.b", SearchPath: []string{"c"}},
			[]*probepb.ColumnSpec{
				testColumn("a.b", "c", "t", "x", false), // renders a.b.c.t
				testColumn("a", "b.c", "t", "y", false), // renders a.b.c.t as well, from a DIFFERENT identity
			},
			testEngineConfig(),
		)
		if err == nil {
			t.Fatal("a table-key collision must be a HARD failure, not a warning")
		}
		want := "catalog table identities render to the same analyzer key 'a.b.c.t': " +
			"TableIdentity(schema=SchemaIdentity(catalog=a.b, schema=c), table=t) and " +
			"TableIdentity(schema=SchemaIdentity(catalog=a, schema=b.c), table=t)"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message:\n got %q\nwant it to contain %q", err.Error(), want)
		}
	})

	t.Run("column key collision", func(t *testing.T) {
		// The table renders identically AND consistently here (same catalog+schema+table), so the table
		// check passes and the COLUMN check is what fires: "t.x" vs "t" + "x" as separate parts.
		_, err := AnalyzerFor(
			&probepb.Namespace{Catalog: "a", SearchPath: []string{"b"}},
			[]*probepb.ColumnSpec{
				testColumn("a", "b", "c", "d.e", false), // renders a.b.c.d.e
				testColumn("a", "b", "c.d", "e", false), // renders a.b.c.d.e too — different identity
			},
			testEngineConfig(),
		)
		if err == nil {
			t.Fatal("a column-key collision must be a HARD failure")
		}
		// The table check fires first for this pair (c vs c.d render differently, so no table collision;
		// the column keys collide). Assert the failure names the shared rendered key either way.
		if !strings.Contains(err.Error(), "render to the same analyzer key") {
			t.Errorf("expected a collision message, got %q", err.Error())
		}
	})

	t.Run("a repeated identity that renders identically is FINE", func(t *testing.T) {
		// Two columns of the SAME table: the table key repeats, but with an EQUAL identity, so putIfAbsent's
		// previous value compares equal and validation passes. This is the common case and must not regress.
		analyzer, err := AnalyzerFor(testNamespace(), testColumns(), testEngineConfig())
		if err != nil {
			t.Fatalf("two columns of one table must validate: %v", err)
		}
		if len(analyzer.ColumnKeys) != 2 {
			t.Errorf("ColumnKeys got %v, want one key per input column", analyzer.ColumnKeys)
		}
	})
}

// "validateNamespace (blank catalog, empty search path, blank entry) is untested" and "validateColumn's
// blank-dataType rejection is untested" — 13-engine.md §6. Every message is wire-visible deny prose
// through A6's catch, so the exact text is pinned.
func TestNamespaceAndColumnValidationMessages(t *testing.T) {
	ns := testNamespace()
	ok := testColumns()

	for _, tc := range []struct {
		name    string
		ns      *probepb.Namespace
		columns []*probepb.ColumnSpec
		want    string
	}{
		{
			name: "blank namespace catalog",
			ns:   &probepb.Namespace{Catalog: "  ", SearchPath: []string{"public"}},
			want: "analyzer namespace catalog is required",
		},
		{
			name: "empty search path",
			ns:   &probepb.Namespace{Catalog: "acme"},
			want: "analyzer namespace searchPath is required",
		},
		{
			name: "blank search path entry",
			ns:   &probepb.Namespace{Catalog: "acme", SearchPath: []string{"public", " "}},
			want: "analyzer namespace searchPath entries are required",
		},
		{
			name:    "blank column catalog",
			ns:      ns,
			columns: []*probepb.ColumnSpec{testColumn("", "public", "users", "id", false)},
			want:    "column catalog is required",
		},
		{
			name:    "blank column schema",
			ns:      ns,
			columns: []*probepb.ColumnSpec{testColumn("acme", "", "users", "id", false)},
			want:    "column schema is required",
		},
		{
			name:    "blank column table",
			ns:      ns,
			columns: []*probepb.ColumnSpec{testColumn("acme", "public", "", "id", false)},
			want:    "column table is required",
		},
		{
			name:    "blank column name",
			ns:      ns,
			columns: []*probepb.ColumnSpec{testColumn("acme", "public", "users", "", false)},
			want:    "column name is required",
		},
		{
			// Note the message says "sqlType" (the control-plane's field name) while the proto field is
			// data_type. Reproduced verbatim.
			name: "blank dataType",
			ns:   ns,
			columns: []*probepb.ColumnSpec{{
				Catalog:  "acme",
				Identity: &probepb.RelationIdentity{Schema: "public", Table: "users", Column: "id"},
				DataType: "",
			}},
			want: "column sqlType is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			columns := tc.columns
			if columns == nil {
				columns = ok
			}
			_, err := AnalyzerFor(tc.ns, columns, testEngineConfig())
			if err == nil {
				t.Fatalf("expected rejection with %q", tc.want)
			}
			if !errors.Is(err, ErrAnalyzerCatalog) {
				t.Errorf("expected an ErrAnalyzerCatalog, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message:\n got %q\nwant it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

// 🔒 INV-A13-15 + F28 / 13-engine.md Q2 — "SqlglotProbe's catch-all is untested; there is no way to make
// the FFM call throw from a test. It disappears in Go, but F28's question (what failedStage/failure class
// an analyzer ERROR gets) should be pinned by a new test on whatever mapping the port chooses."
//
// In Go the error path IS reachable: probe.AnalyzeStatement returns an error when the flat catalog cannot
// be built into a schema.Mapping. This pins the chosen mapping — UNANALYZABLE + "LINEAGE", NOT "VALIDATE",
// because "VALIDATE" is already the live probe signal for a missing/unparseable MySQL engine_version and
// reusing it would merge two distinct faults into one audited failed_stage value (F33).
func TestAnAnalyzerErrorFailsClosedAsUnanalyzableAtStageLineage(t *testing.T) {
	facts := unanalyzableFacts(errors.New("boom"))
	if facts.GetResolved() {
		t.Error("a failed analysis must never report resolved")
	}
	if got := facts.GetFailureClass(); got != probepb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
		t.Errorf("failureClass got %v, want UNANALYZABLE", got)
	}
	if got := facts.GetFailedStage(); got != "LINEAGE" {
		t.Errorf("failedStage got %q, want \"LINEAGE\" — \"VALIDATE\" is taken by the live MySQL "+
			"engine_version signal (F33), so reusing it would merge two distinct faults", got)
	}
	if got := facts.GetStatementClass(); got != probepb.StatementClass_STATEMENT_CLASS_UNSPECIFIED {
		t.Errorf("statementClass got %v, want UNSPECIFIED", got)
	}
	if got := facts.GetDetail(); got != "boom" {
		t.Errorf("detail got %q, want %q", got, "boom")
	}

	// Kotlin truncates detail with .take(150) — 150 UTF-16 CODE UNITS.
	long := strings.Repeat("x", 200)
	if got := unanalyzableFacts(errors.New(long)).GetDetail(); len(got) != 150 {
		t.Errorf("detail length got %d, want 150", len(got))
	}

	// And Analyze never returns an error, whatever the probe does: 🔒 INV-A13-15. An exception escaping
	// into A6's decision path would skip the audit write for a statement that was in fact examined.
	analyzer, err := AnalyzerFor(testNamespace(), testColumns(), testEngineConfig())
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}
	for _, sql := range []string{"", "   ", ";", "select 'unterminated", "select 1; select 2", "\x00"} {
		if got := analyzer.Analyze(sql); got == nil {
			t.Errorf("Analyze(%q) returned nil — it must ALWAYS return StatementFacts", sql)
		}
	}
}

// 🔒 INV-A13-15, the half the direct-call simplification puts at risk: Analyze must survive a PANIC from
// the probe, not just an error return.
//
// Kotlin could not hit this — it reached the probe through probe.AnalyzeStatementSafe (total, panic-safe,
// analyzer/probe/wire.go:32-40) and caught Throwable on top. The Go control plane calls the UNGUARDED
// probe.AnalyzeStatement, where only four stages run under runStage's recover and EmitFacts's emitters
// run outside any guard. An escaped panic would bypass A6's decision/audit contract for a statement that
// WAS examined, which is precisely the failure INV-A13-15's quoted reason names.
func TestAnalyzeSurvivesAProbePanicAndStillReturnsFailClosedFacts(t *testing.T) {
	analyzer, err := AnalyzerFor(testNamespace(), testColumns(), testEngineConfig())
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}

	original := probeAnalyzeStatement
	t.Cleanup(func() { probeAnalyzeStatement = original })
	probeAnalyzeStatement = func(*probepb.AnalyzeRequest) (*probepb.StatementFacts, error) {
		panic("probe exploded")
	}

	facts := analyzer.Analyze("select rrn from users")
	if facts == nil {
		t.Fatal("a panicking probe must still yield StatementFacts — a nil return nil-panics every caller")
	}
	if facts.GetResolved() {
		t.Error("a panicked analysis must never report resolved")
	}
	if got := facts.GetFailureClass(); got != probepb.FailureClass_FAILURE_CLASS_UNANALYZABLE {
		t.Errorf("failureClass got %v, want UNANALYZABLE", got)
	}
	// Stage and detail match AnalyzeStatementSafe's own recovered-panic rendering (wire.go:36-40), so one
	// audited failed_stage value covers the case however the probe is reached.
	if got := facts.GetFailedStage(); got != "LINEAGE" {
		t.Errorf("failedStage got %q, want \"LINEAGE\"", got)
	}
	if got := facts.GetDetail(); got != "panic: probe exploded" {
		t.Errorf("detail got %q, want %q", got, "panic: probe exploded")
	}

	// A nil-nil probe return is likewise fail-closed rather than a nil deref one layer up.
	probeAnalyzeStatement = func(*probepb.AnalyzeRequest) (*probepb.StatementFacts, error) { return nil, nil }
	if facts := analyzer.Analyze("select 1"); facts == nil || facts.GetResolved() {
		t.Errorf("a nil-nil probe return must fail closed, got %v", facts)
	}
}

// INV-A13-14 — do NOT pre-clean the SQL. A trailing terminator, surrounding whitespace and a ';' inside a
// string literal are all sqlglot's job; a port that stripped them "to help" would, for the multi-statement
// case, help an attacker.
func TestNoSQLPreCleaningBeforeAnalyze(t *testing.T) {
	analyzer, err := AnalyzerFor(testNamespace(), testColumns(), testEngineConfig())
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}
	for _, sql := range []string{
		"select rrn from users;",
		"  select rrn from users  ",
		"select rrn from users where rrn = 'a;b'",
	} {
		if facts := analyzer.Analyze(sql); !facts.GetResolved() {
			t.Errorf("sqlglot handles %q itself; got failureClass=%v detail=%q",
				sql, facts.GetFailureClass(), facts.GetDetail())
		}
	}
	// …and the genuine multi-statement still fail-closes, which is the reason not to pre-clean.
	if got := analyzer.Analyze("select 1; select 2").GetFailureClass(); got != probepb.FailureClass_FAILURE_CLASS_INADMISSIBLE {
		t.Errorf("multi-statement got %v, want INADMISSIBLE", got)
	}
}

// INV-A13-33 — no normalization or case folding happens here. Two normalization sites disagreeing is how a
// masked column stops matching its catalog row, so the rendered key must be pure concatenation of the
// already-canonical parts.
func TestColumnKeyRenderingDoesNoFolding(t *testing.T) {
	analyzer, err := AnalyzerFor(
		&probepb.Namespace{Catalog: "Acme", SearchPath: []string{"Public"}},
		[]*probepb.ColumnSpec{testColumn("Acme", "Public", "Users", "RRN", false)},
		testEngineConfig(),
	)
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}
	if got, want := analyzer.ColumnKeys[0], "Acme.Public.Users.RRN"; got != want {
		t.Errorf("ColumnKeys[0] got %q, want %q — this is pure concatenation, not a fold", got, want)
	}
}

// F23 — PiiColumns is insertion-ordered (Kotlin builds it with mapTo(linkedSetOf())), so a Go port owes an
// ordered, test-visible equivalent rather than a map. Pinned because ordering is the only property of the
// Kotlin type a map would silently drop.
func TestPiiColumnsIsInsertionOrdered(t *testing.T) {
	analyzer, err := AnalyzerFor(
		testNamespace(),
		[]*probepb.ColumnSpec{
			testColumn("acme", "public", "users", "zeta", true),
			testColumn("acme", "public", "users", "id", false),
			testColumn("acme", "public", "users", "alpha", true),
		},
		testEngineConfig(),
	)
	if err != nil {
		t.Fatalf("AnalyzerFor: %v", err)
	}
	want := []string{"acme.public.users.zeta", "acme.public.users.alpha"}
	if !equalStrings(analyzer.PiiColumns, want) {
		t.Errorf("PiiColumns got %v, want %v (INPUT order, not sorted)", analyzer.PiiColumns, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
