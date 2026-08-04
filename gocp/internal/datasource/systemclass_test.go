package datasource

import (
	"errors"
	"sort"
	"testing"
)

// Port of SystemClassificationServiceTest.kt (147 LOC, 6 cases) — 05-datasources-catalog.md §9.
//
// Case 1 (parseServerVersion) is PURE and is ported verbatim below.
//
// 🔴 TODO(A13): cases 2-6 construct `SystemClassificationService()` over THE REAL CLASSPATH
// MANIFESTS, so they prove parse→resolve→classify end to end. internal/engine is not ported, so the
// manifests do not exist in Go yet. What is ported here instead is the half A5 actually owns — the
// floor combinator, the no-manifest union, the opposite polarity of the command and function
// absences, and the boot abort — over a fake manifest store. When A13 lands, re-point cases 2-6 at
// the real store; a fake-only suite proves the service agrees with itself and nothing else.

// case 1 — 🔒 INV-A5-61
// KT: SystemClassificationServiceTest.kt#parseServerVersion handles vanilla and Aurora formats
func TestParseServerVersionHandlesVanillaAndAuroraFormats(t *testing.T) {
	parse := func(e Engine, v string) (string, bool) {
		version, aurora := ParseServerVersion(e, &v)
		if version == nil {
			return "", aurora
		}
		return *version, aurora
	}
	for _, tc := range []struct {
		engine      Engine
		raw         string
		wantVersion string
		wantAurora  bool
	}{
		// PostgreSQL
		{EnginePostgres, "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc", "17.4", false},
		{EnginePostgres, "PostgreSQL 16.13 on aarch64 (aurora 16.13...)", "16.13", true},
		// MySQL vanilla
		{EngineMySQL, "8.0.44", "8.0.44", false},
		{EngineMySQL, "8.0.44-log", "8.0.44", false},
		// MySQL Aurora — the mysql_aurora infix must NOT let the Aurora engine version leak in
		{EngineMySQL, "8.0.mysql_aurora.3.04.0 (aurora 3.04.0)", "8.0", true},
		{EngineMySQL, "8.4.mysql_aurora.4.0.0", "8.4", true},
		{EngineMySQL, "5.7.mysql_aurora.2.11.4", "5.7", true},
	} {
		version, aurora := parse(tc.engine, tc.raw)
		if version != tc.wantVersion || aurora != tc.wantAurora {
			t.Errorf("parseServerVersion(%v, %q) = (%q, %v), want (%q, %v)",
				tc.engine, tc.raw, version, aurora, tc.wantVersion, tc.wantAurora)
		}
	}
	// Garbage / empty → nil (deny-by-default, fail-closed)
	for _, tc := range []struct {
		engine Engine
		raw    string
	}{{EngineMySQL, ""}, {EnginePostgres, "   "}} {
		if v, _ := ParseServerVersion(tc.engine, &tc.raw); v != nil {
			t.Errorf("parseServerVersion(%v, %q) = %q, want nil", tc.engine, tc.raw, *v)
		}
	}
	if v, aurora := ParseServerVersion(EngineMySQL, nil); v != nil || aurora {
		t.Errorf("a nil engine_version must parse to (nil, false), got (%v, %v)", v, aurora)
	}
}

// ---- Fakes standing in for A13's manifest bundle ---------------------------------------------

type fakeTag struct {
	id       string
	strength int
}

func (t fakeTag) ID() string    { return t.id }
func (t fakeTag) Strength() int { return t.strength }

// The four shipped tags, in DECLARATION (= strength) order. 🔒 INV-A13-18.
var (
	tagCritical = fakeTag{"system:critical", 0}
	tagDataLeak = fakeTag{"system:data-leak", 1}
	tagActivity = fakeTag{"system:activity", 2}
	tagCatalog  = fakeTag{"system:catalog", 3}
)

type fakeClassifier struct {
	relations map[string]SystemTag // "schema.table"
	functions map[string]SystemTag
	commands  map[string]SystemTag
}

func (c fakeClassifier) ClassifyRelation(_, schema, name string) (SystemTag, bool) {
	tag, ok := c.relations[schema+"."+name]
	return tag, ok
}
func (c fakeClassifier) ClassifyBareFunction(name string) (SystemTag, bool) {
	tag, ok := c.functions[name]
	return tag, ok
}
func (c fakeClassifier) ClassifyCommand(id string) (SystemTag, bool) {
	tag, ok := c.commands[id]
	return tag, ok
}

type fakeStore struct {
	bySeries map[string]fakeClassifier // "engine/series"
}

func (s fakeStore) Resolve(engine, serverVersion string, allowFallback bool) (ResolvedClassification, bool) {
	series := seriesOf(engine, serverVersion)
	if c, ok := s.bySeries[engine+"/"+series]; ok {
		return ResolvedClassification{Classifier: c, RequestedSeries: series, ResolvedSeries: series}, true
	}
	if !allowFallback {
		return ResolvedClassification{}, false
	}
	// ⚠️ FLAKE FIX (found while porting A6; the assertion and the production code are UNCHANGED).
	// This loop used to range over bySeries directly, and Go randomises map iteration order — so with
	// two shipped postgres manifests it picked "postgres/16" or "postgres/17" at random. Only 17
	// carries relation rules in this fixture, so `TestTagForTableIsAbsentWithoutAGoverningManifest`'s
	// last assertion ("with fallback on, the nearest major governs") failed roughly 1 run in 10.
	// Measured before the fix: 3 failures in 30 `-count=1` runs of that one test.
	//
	// Descending order picks the HIGHEST available series, which is what "the nearest major governs"
	// means for a requested major above every supported one — and is deterministic either way.
	keys := make([]string, 0, len(s.bySeries))
	for key := range s.bySeries {
		if len(key) > len(engine) && key[:len(engine)] == engine {
			keys = append(keys, key)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys {
		return ResolvedClassification{
			Classifier: s.bySeries[key], RequestedSeries: series,
			ResolvedSeries: key[len(engine)+1:], IsFallback: true,
		}, true
	}
	return ResolvedClassification{}, false
}

func (s fakeStore) ClassifiersForEngine(engine string) []ManifestClassifier {
	out := []ManifestClassifier{}
	for key, c := range s.bySeries {
		if len(key) > len(engine) && key[:len(engine)] == engine {
			out = append(out, c)
		}
	}
	return out
}

func (s fakeStore) Supported() []EngineSeries {
	out := []EngineSeries{}
	for key := range s.bySeries {
		for i := 0; i < len(key); i++ {
			if key[i] == '/' {
				out = append(out, EngineSeries{key[:i], key[i+1:]})
				break
			}
		}
	}
	return out
}

func (s fakeStore) Checksum() string { return "deadbeefcafebabe0123" }

// seriesOf is 13-engine.md's SystemClassificationStore.seriesOf: MySQL takes the first two dotted
// components, EVERYTHING ELSE takes the first.
func seriesOf(engine, version string) string {
	if engine == "mysql" {
		dots := 0
		for i := 0; i < len(version); i++ {
			if version[i] == '.' {
				dots++
				if dots == 2 {
					return version[:i]
				}
			}
		}
		return version
	}
	for i := 0; i < len(version); i++ {
		if version[i] == '.' {
			return version[:i]
		}
	}
	return version
}

type fakeBaseline struct{ byName map[string]SystemTag }

func (b fakeBaseline) Classify(name string) (SystemTag, bool) {
	tag, ok := b.byName[name]
	return tag, ok
}

func newTestService(t *testing.T, allowFallback bool) *SystemClassificationService {
	t.Helper()
	store := fakeStore{bySeries: map[string]fakeClassifier{
		"postgres/17": {
			relations: map[string]SystemTag{
				"pg_catalog.pg_authid": tagCritical,
				"pg_catalog.pg_class":  tagCatalog,
			},
			functions: map[string]SystemTag{
				"pg_read_file":         tagDataLeak,
				"set_config":           tagCritical,
				"pg_terminate_backend": tagCritical,
			},
			commands: map[string]SystemTag{"PG_SHOW_GUC": tagActivity},
		},
		"postgres/16": {
			// The 16 manifest classifies a family 17's does not, so the no-manifest UNION must find it.
			functions: map[string]SystemTag{"table_to_xml": tagDataLeak, "set_config": tagActivity},
		},
	}}
	baseline := fakeBaseline{byName: map[string]SystemTag{"lo_export": tagCritical, "pg_read_file": tagDataLeak}}
	svc, err := NewSystemClassificationService(
		func() (ManifestStore, error) { return store, nil }, baseline, allowFallback,
	)
	if err != nil {
		t.Fatalf("NewSystemClassificationService: %v", err)
	}
	return svc
}

func strptr(s string) *string { return &s }

// 🔒 INV-A5-55 — a malformed manifest ABORTS STARTUP. The loader's error must reach the caller, never
// be degraded to a warning: booting unclassified silently loses the dangerous-function floor.
func TestAMalformedManifestAbortsConstruction(t *testing.T) {
	_, err := NewSystemClassificationService(
		func() (ManifestStore, error) {
			return nil, errors.New("postgres/17: relation rule has non-system tag 'oops'")
		},
		fakeBaseline{}, false,
	)
	if err == nil {
		t.Fatal("a manifest that fails validation must abort construction")
	}
	if _, err := NewSystemClassificationService(nil, fakeBaseline{}, false); err == nil {
		t.Error("a missing loader must abort construction")
	}
	if _, err := NewSystemClassificationService(
		func() (ManifestStore, error) { return fakeStore{}, nil }, nil, false,
	); err == nil {
		t.Error("a missing baseline floor must abort construction")
	}
}

// Shape of case 3: a governed datasource classifies; NO VERSION → no manifest → absent
// (deny-by-default). TODO(A13): re-point at the real pg_authid / pg_class manifest rows.
func TestTagForTableIsAbsentWithoutAGoverningManifest(t *testing.T) {
	svc := newTestService(t, false)
	pg := "PostgreSQL 17.4 on x86_64 (aurora 17.4...)"
	if tag, ok := svc.TagForTable(EnginePostgres, &pg, "acme", "pg_catalog", "pg_authid"); !ok || tag != "system:critical" {
		t.Errorf("tagForTable = %q, %v", tag, ok)
	}
	if tag, ok := svc.TagForTable(EnginePostgres, &pg, "acme", "pg_catalog", "pg_class"); !ok || tag != "system:catalog" {
		t.Errorf("tagForTable = %q, %v", tag, ok)
	}
	// no version → no manifest → absent (deny-by-default)
	if _, ok := svc.TagForTable(EnginePostgres, nil, "acme", "pg_catalog", "pg_authid"); ok {
		t.Error("no version must resolve to no manifest, so the object stays deny-by-default")
	}
	// An uncertified series with fallback OFF is the same answer (🔒 INV-A13-27).
	if _, ok := svc.TagForTable(EnginePostgres, strptr("PostgreSQL 42.0 on x86_64"), "acme", "pg_catalog", "pg_authid"); ok {
		t.Error("an uncertified major must stay deny-by-default with fallback off")
	}
	// The operator opt-in is a WIDENING, and it is off by default.
	widened := newTestService(t, true)
	if _, ok := widened.TagForTable(EnginePostgres, strptr("PostgreSQL 42.0 on x86_64"), "acme", "pg_catalog", "pg_authid"); !ok {
		t.Error("with fallback on, the nearest major governs")
	}
}

// Shape of cases 4-6 — 🔒 INV-A5-56 (absent means SAFE) · INV-A5-58 (the no-manifest union) ·
// INV-A5-59 (the baseline is a floor that never lowers and classifies no safe function).
func TestTagForFunctionFloorsTheManifestAndTheBaseline(t *testing.T) {
	svc := newTestService(t, false)
	pg := strptr("PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc")

	// Governed: the manifest classifies.
	if tag, ok := svc.TagForFunction(EnginePostgres, pg, "set_config"); !ok || tag != "system:critical" {
		t.Errorf("governed set_config = %q, %v", tag, ok)
	}
	// Governed: a name only the BASELINE classifies is still gated — the floor unions in.
	if tag, ok := svc.TagForFunction(EnginePostgres, pg, "lo_export"); !ok || tag != "system:critical" {
		t.Errorf("governed lo_export = %q, %v; the baseline unions into a governed datasource", tag, ok)
	}
	// 🔒 INV-A5-56 — a safe builtin / unclassified UDF stays ABSENT in every state. The negative half
	// is as load-bearing as the positive one: marshalling a safe function would deny-by-default and
	// break every now()/user-UDF query.
	for _, safe := range []string{"now", "count", "lower", "concat", "my_udf"} {
		if _, ok := svc.TagForFunction(EnginePostgres, pg, safe); ok {
			t.Errorf("%s governed must stay safe", safe)
		}
		if _, ok := svc.TagForFunction(EnginePostgres, nil, safe); ok {
			t.Errorf("%s no-manifest must stay safe", safe)
		}
	}
	// 🔒 INV-A5-58 — no manifest: the union over EVERY shipped manifest of the engine, strongest tag
	// per name. table_to_xml is in the 16 manifest only, and set_config is critical in 17 but only
	// activity in 16 — the union must take the STRONGER.
	if tag, ok := svc.TagForFunction(EnginePostgres, nil, "table_to_xml"); !ok || tag != "system:data-leak" {
		t.Errorf("no-manifest table_to_xml = %q, %v; the union must reach a family the governing series lacks", tag, ok)
	}
	if tag, ok := svc.TagForFunction(EnginePostgres, nil, "set_config"); !ok || tag != "system:critical" {
		t.Errorf("no-manifest set_config = %q, %v; the union takes the STRONGEST tag per name", tag, ok)
	}
	// 🔒 INV-A5-59 — the baseline can RAISE but never LOWER. In the 16 manifest pg_read_file is absent
	// and the baseline says data-leak, so no-manifest still gates it.
	if tag, ok := svc.TagForFunction(EnginePostgres, nil, "pg_read_file"); !ok || tag != "system:data-leak" {
		t.Errorf("no-manifest pg_read_file = %q, %v", tag, ok)
	}
}

// 🔒 INV-A5-60 — for a UTILITY, absent does NOT mean safe, and there is NO baseline/union path: the
// two absences have OPPOSITE meanings and A6/A2 depend on that.
func TestTagForCommandHasNoNoManifestFloor(t *testing.T) {
	svc := newTestService(t, false)
	pg := strptr("PostgreSQL 17.4 on x86_64")
	if tag, ok := svc.TagForCommand(EnginePostgres, pg, "PG_SHOW_GUC"); !ok || tag != "system:activity" {
		t.Errorf("governed PG_SHOW_GUC = %q, %v", tag, ok)
	}
	// No manifest: absent — and the CALLER marshals the utility anyway, so it denies by default.
	if _, ok := svc.TagForCommand(EnginePostgres, nil, "PG_SHOW_GUC"); ok {
		t.Error("no manifest must yield no command tag (the caller then denies by default)")
	}
	// An unrecognized command under a governing manifest is absent too — same deny-by-default.
	if _, ok := svc.TagForCommand(EnginePostgres, pg, "SHOW_NOTHING"); ok {
		t.Error("an unclassified recognized utility must not be tagged")
	}
}

// §9 "Coverage gaps in A5": "describeManifestFor's three output shapes are untested (log-only, but
// the FALLBACK wording is how an operator learns a datasource is uncertified)."
func TestDescribeManifestForHasThreeShapes(t *testing.T) {
	svc := newTestService(t, false)
	if got := svc.DescribeManifestFor(EnginePostgres, nil); got != "postgres (version unreported) → no manifest (system schemas deny-by-default)" {
		t.Errorf("unreported = %q", got)
	}
	if got := svc.DescribeManifestFor(EnginePostgres, strptr("PostgreSQL 42.0 on x86_64")); got != "postgres 42.0 → no manifest (uncertified series → system schemas deny-by-default)" {
		t.Errorf("uncertified = %q", got)
	}
	if got := svc.DescribeManifestFor(EnginePostgres, strptr("PostgreSQL 17.4 on x86_64")); got != "postgres 17.4 → manifest postgres/17" {
		t.Errorf("governed = %q", got)
	}
	// §9: "allowFallback = true is never exercised — every test constructs the service with the
	// default." The FALLBACK wording is the operator's only signal.
	widened := newTestService(t, true)
	got := widened.DescribeManifestFor(EnginePostgres, strptr("PostgreSQL 42.0 on x86_64"))
	if got != "postgres 42.0 → manifest postgres/17 (FALLBACK — series 42 uncertified)" &&
		got != "postgres 42.0 → manifest postgres/16 (FALLBACK — series 42 uncertified)" {
		t.Errorf("fallback = %q", got)
	}
}

// StrongerTag is the comparison INV-A13-18 is about — ordinal, not string.
func TestStrongerTagUsesTheOrdinalNotTheString(t *testing.T) {
	if got := StrongerTag(tagCatalog, tagCritical); got.ID() != "system:critical" {
		t.Errorf("stronger(catalog, critical) = %s", got.ID())
	}
	if got := StrongerTag(tagDataLeak, tagActivity); got.ID() != "system:data-leak" {
		t.Errorf("stronger(data-leak, activity) = %s", got.ID())
	}
	// A ties-keep-a check: `if (a.ordinal <= b.ordinal) a else b`.
	if got := StrongerTag(tagActivity, tagActivity); got.ID() != "system:activity" {
		t.Errorf("stronger(activity, activity) = %s", got.ID())
	}
	// Lexicographically "system:activity" < "system:critical", so a string comparison would answer
	// activity here. That is the inversion INV-A13-18 forbids.
	if got := StrongerTag(tagActivity, tagCritical); got.ID() != "system:critical" {
		t.Errorf("stronger(activity, critical) = %s; a string comparison would get this backwards", got.ID())
	}
}
