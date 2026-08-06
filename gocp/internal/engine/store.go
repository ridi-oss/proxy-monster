package engine

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// manifestFS embeds the four bundled manifests. D10: embed.FS replaces the JVM classpath, which makes a
// missing bundle a BUILD error rather than a runtime one — a strengthening, so LoadSystemClassificationStore
// keeps the runtime "missing" check anyway (13-engine.md §4.4 Go shape).
//
// The files are byte-for-byte copies of engine/src/main/resources/system-classification/**; the bundle
// checksum is over the RAW FILE TEXT, so a reformat here changes every operator's logged checksum.
//
//go:embed manifests
var manifestFS embed.FS

// manifestResourceDir ports `private const val RESOURCE_DIR = "/system-classification"`.
const manifestResourceDir = "manifests"

// bundledManifestStems ports `private val BUNDLED`. Adding an engine version is a deliberate,
// release-reviewed change here PLUS the resource file (the safety-property curation loop).
//
// Note it is NOT written in sorted order — postgres/* precedes mysql/* — and load() iterates
// BUNDLED.sorted(). INV-A13-30 depends on that: sorting makes the digest independent of the declaration
// order here.
var bundledManifestStems = []string{
	"postgres/16",
	"postgres/17",
	"mysql/8.0",
	"mysql/8.4",
}

// engineSeries is the (engine, series) map key. Go's map key rules make Kotlin's Pair unnecessary.
type engineSeries struct {
	engine string
	series string
}

// ResolvedClassification is a resolved manifest for a datasource's detected engine version.
//
// IsFallback is true when no manifest matched the version's major and the nearest supported major is
// being used instead — the caller raises the high-severity classification_stale/fallback health signal and
// audits ResolvedSeries != RequestedSeries.
//
// ⚠️ That caller obligation is NOT discharged in A5's SystemClassificationService, which defers
// per-datasource fallback observability. The port inherits the gap, not a feature (13-engine.md Q7).
type ResolvedClassification struct {
	Classifier      *SystemClassifier
	RequestedSeries string
	ResolvedSeries  string
	IsFallback      bool
}

// SystemClassificationStore loads and holds all bundled system-classification manifests. Every manifest is
// validated at construction — a malformed or conflicting manifest is a *SystemManifestError and MUST abort
// startup, like a failed Flyway migration (INV-A13-19). Manifests are keyed by engine + MAJOR series;
// Resolve selects a datasource's manifest by its parsed engine version, with an opt-in fallback for a
// version no bundled manifest covers.
//
// The bundled set covers PostgreSQL 16 & 17 and MySQL 8.0 & 8.4, vanilla or Aurora: a manifest is keyed by
// engine major series, and each also classifies the Aurora-proprietary system surface vanilla lacks.
type SystemClassificationStore struct {
	byEngineSeries map[engineSeries]*SystemClassifier
	checksum       string
}

// Checksum is the SHA-256 hex over the concatenated raw manifest texts, in sorted-stem order. A5 logs
// checksum[:12] at boot so an operator can spot a drifted bundle.
func (s *SystemClassificationStore) Checksum() string { return s.checksum }

// Resolve returns the manifest for a datasource. serverVersion is the parsed backend release (e.g. "17.9",
// "8.0.44", "8.4.7"). allowFallback is the operator opt-in.
//
// 🔒 INV-A13-27 — with fallback OFF (the safe default), an uncertified major returns nil and the
// datasource's system schemas stay UNAVAILABLE: the caller then does NOT expose them (fail-closed; user
// schemas keep ordinary deny-by-default). A5 turns this into A6's step-13 utility hard-deny and the
// tagForTable null. The operator opt-in is a WIDENING, so the default must stay false in the port (A5 owns
// the flag).
func (s *SystemClassificationStore) Resolve(engine, serverVersion string, allowFallback bool) *ResolvedClassification {
	eng := strings.ToLower(engine)
	requested := SeriesOf(eng, serverVersion)
	if c, ok := s.byEngineSeries[engineSeries{eng, requested}]; ok {
		return &ResolvedClassification{Classifier: c, RequestedSeries: requested, ResolvedSeries: requested, IsFallback: false}
	}
	if !allowFallback {
		return nil
	}
	nearest, ok := s.nearestSeries(eng, requested)
	if !ok {
		return nil
	}
	return &ResolvedClassification{
		Classifier:      s.byEngineSeries[engineSeries{eng, nearest}],
		RequestedSeries: requested,
		ResolvedSeries:  nearest,
		IsFallback:      true,
	}
}

// Supported returns all (engine, series) pairs with a bundled manifest — for health/diagnostics. Kotlin
// returns the HashMap's key Set; the slice returned here is sorted so a diagnostic caller has a stable
// rendering (Kotlin's set is unordered, so no ordering was observable to lose).
func (s *SystemClassificationStore) Supported() []EngineSeries {
	out := make([]EngineSeries, 0, len(s.byEngineSeries))
	for k := range s.byEngineSeries {
		out = append(out, EngineSeries{Engine: k.engine, Series: k.series})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}
		return out[i].Series < out[j].Series
	})
	return out
}

// EngineSeries is one supported (engine, series) pair, the exported shape of Supported's Kotlin
// Pair<String, String>.
type EngineSeries struct {
	Engine string
	Series string
}

// ClassifierFor returns the classifier for an EXACT (engine, series), or nil — for tests/diagnostics.
//
// It lowercases engine but NOT series, reproducing the Kotlin asymmetry verbatim.
func (s *SystemClassificationStore) ClassifierFor(engine, series string) *SystemClassifier {
	return s.byEngineSeries[engineSeries{strings.ToLower(engine), series}]
}

// ClassifiersForEngine returns every shipped classifier for one engine (all its certified series).
//
// 🔒 INV-A13-29 — this exists so the no-manifest dangerous-function floor is DERIVED from the shipped
// manifests, never hand-listed. It builds the version-INDEPENDENT floor for a datasource whose version
// resolves to NO manifest (uncertified/absent major): the union of these classifiers, strongest tag per
// name, closes the no-manifest function leak (the manifest's table_to_xml*/pageinspect/lo_*/replication
// families a thin hand-curated baseline MISSED) without a hand-maintained duplicate that would drift from
// the manifests. A port that re-hand-lists the floor reintroduces exactly that drift. Empty for an engine
// with no bundled manifest.
//
// Kotlin returns them in HashMap entry order (unordered); order is not observable because the only
// consumer takes the strongest tag across the list. This returns them in sorted-series order for
// determinism, which is a strict subset of "any order is fine".
func (s *SystemClassificationStore) ClassifiersForEngine(engine string) []*SystemClassifier {
	eng := strings.ToLower(engine)
	keys := make([]engineSeries, 0, len(s.byEngineSeries))
	for k := range s.byEngineSeries {
		if k.engine == eng {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].series < keys[j].series })
	out := make([]*SystemClassifier, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.byEngineSeries[k])
	}
	return out
}

// nearestSeries ports the private helper.
//
// INV-A13-28 — fallback picks the HIGHEST supported major ≤ requested; if the datasource is older than
// every supported major, the LOWEST supported. It NEVER crosses engines (candidates are filtered by engine
// first). Series compare component-wise as ints.
func (s *SystemClassificationStore) nearestSeries(engine, requested string) (string, bool) {
	var candidates []string
	for k := range s.byEngineSeries {
		if k.engine == engine {
			candidates = append(candidates, k.series)
		}
	}
	if len(candidates) == 0 {
		return "", false
	}
	req := seriesKey(requested)
	var notNewer []string
	for _, c := range candidates {
		if seriesKey(c) <= req {
			notNewer = append(notNewer, c)
		}
	}
	if len(notNewer) > 0 {
		// maxByOrNull: Kotlin keeps the FIRST maximum on a tie. Ties are only reachable through
		// seriesKey collisions ("8" and "8.0" both key to 8000), and iteration order over the underlying
		// HashMap is unspecified on both sides, so no tie-break is contract here.
		best := notNewer[0]
		for _, c := range notNewer[1:] {
			if seriesKey(c) > seriesKey(best) {
				best = c
			}
		}
		return best, true
	}
	best := candidates[0]
	for _, c := range candidates[1:] {
		if seriesKey(c) < seriesKey(best) {
			best = c
		}
	}
	return best, true
}

// LoadSystemClassificationStore loads, validates and indexes every bundled manifest. It returns a
// *SystemManifestError on any problem — 🔒 INV-A13-19, this MUST abort startup.
func LoadSystemClassificationStore() (*SystemClassificationStore, error) {
	byES := make(map[engineSeries]*SystemClassifier)
	digest := sha256.New()

	// INV-A13-30 — the checksum is over BUNDLED.sorted() order and over the raw file TEXT. Both matter for
	// reproducibility: the sort makes the digest independent of the declaration order in
	// bundledManifestStems (which is NOT sorted as written), and hashing the text rather than the parsed
	// model means a reformat changes the checksum. A port that sorts differently changes every
	// deployment's logged checksum.
	stems := append([]string(nil), bundledManifestStems...)
	sort.Strings(stems)

	for _, stem := range stems {
		path := manifestResourceDir + "/" + stem + ".json"
		text, err := manifestFS.ReadFile(path)
		if err != nil {
			// Unreachable through the embedded FS (//go:embed already makes an unmatched pattern a build
			// error), but kept because Kotlin's classpath read could fail at runtime and the message is
			// part of the contract.
			return nil, manifestErrf("bundled manifest missing from the classpath: %s", "/system-classification/"+stem+".json")
		}
		digest.Write(text)

		var manifest SystemManifest
		if err := json.Unmarshal(text, &manifest); err != nil {
			return nil, manifestErrf("malformed manifest %s: %s", "/system-classification/"+stem+".json", err.Error())
		}

		// Path ↔ (engine, series) consistency. Compared CASE-SENSITIVELY against the path, so a manifest
		// declaring "Postgres" is rejected outright — which makes the lowercase() on the map key below
		// inert for this path (the engine string is already pinned to the lower-case directory name). Only
		// SystemClassificationStoreOf relies on that fold.
		dirEngine, fileSeries, _ := strings.Cut(stem, "/")
		if manifest.Engine != dirEngine || manifest.Series != fileSeries {
			return nil, manifestErrf(
				"manifest %s declares engine/series %s/%s but its path says %s/%s",
				"/system-classification/"+stem+".json", manifest.Engine, manifest.Series, dirEngine, fileSeries,
			)
		}

		classifier, err := NewSystemClassifier(manifest) // validates; fails on any manifest violation
		if err != nil {
			return nil, err
		}
		key := engineSeries{strings.ToLower(manifest.Engine), manifest.Series}
		if _, exists := byES[key]; exists {
			// UNREACHABLE through the resource files: the path check above forces (engine, series) to equal
			// the stem, and the four stems are distinct. This is a guard on the CONSTANT, not on the data —
			// it can only fire if bundledManifestStems gains a repeated entry, which is what
			// TestBundledStemListIsASet asserts instead.
			return nil, manifestErrf("duplicate manifest for %s/%s", manifest.Engine, manifest.Series)
		}
		byES[key] = classifier
	}

	return &SystemClassificationStore{byEngineSeries: byES, checksum: hex.EncodeToString(digest.Sum(nil))}, nil
}

// SystemClassificationStoreOf is the test/diagnostic factory from in-memory manifests (bypasses the
// embedded bundle). Ports `fun of(manifests: List<SystemManifest>)`.
//
// F26 — REPRODUCE. `of` omits BOTH of load's structural guards: no duplicate (engine, series) check (a
// later manifest silently OVERWRITES an earlier one) and no path/declaration consistency check (there is
// no path). A manifest list with a duplicate passes silently here where the same content on disk would
// abort boot. The asymmetry is observable, so it is kept, with this comment naming the finding; adding
// the guards is a separate decision.
func SystemClassificationStoreOf(manifests []SystemManifest) (*SystemClassificationStore, error) {
	byES := make(map[engineSeries]*SystemClassifier, len(manifests))
	for _, m := range manifests {
		classifier, err := NewSystemClassifier(m)
		if err != nil {
			return nil, err
		}
		byES[engineSeries{strings.ToLower(m.Engine), m.Series}] = classifier // last-wins, unchecked — F26
	}
	return &SystemClassificationStore{byEngineSeries: byES, checksum: "test"}, nil
}

// SeriesOf maps an engine version to its major series. PostgreSQL takes the leading integer (17.9 → 17);
// MySQL takes the LTS family (8.0.44 → 8.0, 8.4.7 → 8.4).
//
// The else branch is the PostgreSQL rule AND the rule for any unknown engine name.
func SeriesOf(engine, version string) string {
	if strings.ToLower(engine) == "mysql" {
		parts := strings.Split(version, ".")
		if len(parts) > 2 {
			parts = parts[:2]
		}
		return strings.Join(parts, ".")
	}
	before, _, _ := strings.Cut(version, ".")
	return before
}

// seriesKey is a single comparable key for ordering series WITHIN one engine (never compared
// cross-engine): major*1000 + minor. PostgreSQL 17 → 17000, MySQL 8.0 → 8000, 8.4 → 8004.
//
// Two observable edges neither Kotlin test covers, REPRODUCEd: a NON-NUMERIC series keys to 0, so with
// fallback on it resolves to the LOWEST supported major (no notNewer candidate); and MySQL "8" and "8.0"
// both key to 8000, so a single-component MySQL version misses the exact lookup and falls back to 8.0. In
// production A5 guards the input (classifierFor returns null when parseServerVersion yields null), so
// neither is reachable today — but that guard is a DIFFERENT area's.
func seriesKey(series string) int {
	parts := strings.Split(series, ".")
	major := 0
	minor := 0
	if len(parts) > 0 {
		major = atoiOrZero(parts[0])
	}
	if len(parts) > 1 {
		minor = atoiOrZero(parts[1])
	}
	return major*1000 + minor
}

// atoiOrZero is Kotlin's `toIntOrNull() ?: 0`.
func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
