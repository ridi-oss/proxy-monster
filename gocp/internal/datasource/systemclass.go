package datasource

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

// ---- SystemClassificationService (05-datasources-catalog.md §7) ------------------------------
//
// Control-plane wrapper over the bundled system-classification manifests (docs/system-classification
// .md). At decision time it maps a system Table / function / utility to its shipped `system:` tag by
// resolving the datasource's engine version to the right manifest.
//
// Keyed off the STORED datasource.engine_version (raw `SELECT version()` + `(aurora <v>)`), so it is
// PATH-AGNOSTIC — it works identically for a proxy-PushCatalog datasource and a legacy CP-introspected
// one, without touching either catalog path. A datasource whose version is absent or an uncertified
// major resolves to no manifest → no system tag → the object stays deny-by-default (system schemas
// closed) unless the operator enables the nearest-major fallback.

// ---- The narrow seam onto A13 ----------------------------------------------------------------
//
// TODO(A13): SystemTag, SystemClassifier, SystemClassificationStore and BaselineDangerousFunctions
// all live in the ENGINE module (13-engine.md §4.4), which is not ported. The interfaces below are
// the exact slice A5 consumes (13-engine.md's cross-area table row "**A5**
// SystemClassificationService"), declared here so this layer can land and be tested. When A13 lands,
// its concrete types satisfy these — do NOT grow a second manifest model here.

// SystemTag is one shipped `system:` classification.
//
// 🔒 INV-A13-18 — the DECLARATION ORDER is the strength order and the enum ordinal is the comparison:
// CRITICAL(0) · DATA_LEAK(1) · ACTIVITY(2) · CATALOG(3), strongest first. [Strength] is that ordinal.
// A string comparison of ids would silently invert every precedence decision.
type SystemTag interface {
	// ID is the wire/Cedar tag id, e.g. "system:critical".
	ID() string
	// Strength is the enum ordinal: LOWER IS STRONGER.
	Strength() int
}

// StrongerTag is `SystemTag.stronger(a, b)` — `if (a.ordinal <= b.ordinal) a else b`, so ties keep a.
func StrongerTag(a, b SystemTag) SystemTag {
	if a.Strength() <= b.Strength() {
		return a
	}
	return b
}

// ManifestClassifier classifies an already schema-resolved identity into exactly one [SystemTag].
type ManifestClassifier interface {
	ClassifyRelation(catalog, schema, name string) (SystemTag, bool)
	ClassifyBareFunction(name string) (SystemTag, bool)
	ClassifyCommand(id string) (SystemTag, bool)
}

// EngineSeries is one supported (engine, series) pair, for the boot log.
type EngineSeries struct {
	Engine string
	Series string
}

// ResolvedClassification is the manifest that governs one (engine, version).
//
// IsFallback is true when no manifest matched the version's major and the nearest supported major is
// being used instead. ⚠️ The Kotlin's stated caller obligation (raise the classification_stale signal
// and audit resolvedSeries != requestedSeries) is NOT discharged by this service — its own
// known-limitations note defers per-datasource fallback observability. The Go port INHERITS THE GAP,
// it does not get a feature.
type ResolvedClassification struct {
	Classifier      ManifestClassifier
	RequestedSeries string
	ResolvedSeries  string
	IsFallback      bool
}

// ManifestStore is the loaded, validated manifest bundle.
type ManifestStore interface {
	Resolve(engine, serverVersion string, allowFallback bool) (ResolvedClassification, bool)
	ClassifiersForEngine(engine string) []ManifestClassifier
	Supported() []EngineSeries
	Checksum() string
}

// BaselineClassifier is BaselineDangerousFunctions — the version-INDEPENDENT floor.
type BaselineClassifier interface {
	Classify(name string) (SystemTag, bool)
}

// SystemClassificationService is the A5 wrapper.
type SystemClassificationService struct {
	store         ManifestStore
	baseline      BaselineClassifier
	allowFallback bool
}

// NewSystemClassificationService loads + validates every manifest once at construction.
//
// 🔒 INV-A5-55 — A MALFORMED MANIFEST ABORTS STARTUP, like a failed migration. `load` is the Go form
// of Kotlin's `store: SystemClassificationStore = SystemClassificationStore.load()` default
// argument, whose throw is the abort; TODO(A13) supplies it. The returned error MUST propagate out of
// A1's ControlPlaneCore construction. Degrading it to a warning would boot with system schemas
// UNCLASSIFIED, and A6's utility path hard-denies unclassified utilities while its function path
// treats an unclassified function as SAFE — i.e. a silent loss of the dangerous-function floor.
//
// 🔒 INV-A13-27 — allowFallback must default to FALSE. The operator opt-in is a WIDENING: with
// fallback off, an uncertified major resolves to no manifest and the datasource's system schemas stay
// unavailable (fail-closed; user schemas keep ordinary deny-by-default).
func NewSystemClassificationService(
	load func() (ManifestStore, error), baseline BaselineClassifier, allowFallback bool,
) (*SystemClassificationService, error) {
	if load == nil {
		return nil, errors.New("system classification: no manifest loader")
	}
	store, err := load()
	if err != nil {
		return nil, fmt.Errorf("system classification manifests failed to load: %w", err)
	}
	if store == nil {
		return nil, errors.New("system classification: manifest loader returned no store")
	}
	if baseline == nil {
		return nil, errors.New("system classification: no baseline dangerous-function classifier")
	}
	s := &SystemClassificationService{store: store, baseline: baseline, allowFallback: allowFallback}
	s.logGoverningSet()
	return s, nil
}

// logGoverningSet is the Kotlin `init` block: the manifest count, the sorted "<engine>/<series>"
// list, the checksum truncated to 12 chars ("to spot a drifted bundle") and the fallback posture.
func (s *SystemClassificationService) logGoverningSet() {
	supported := s.store.Supported()
	manifests := make([]string, 0, len(supported))
	for _, e := range supported {
		manifests = append(manifests, e.Engine+"/"+e.Series)
	}
	sort.Strings(manifests)
	fallback := "off — uncertified versions keep system schemas deny-by-default"
	if s.allowFallback {
		fallback = "on"
	}
	checksum := s.store.Checksum()
	if len(checksum) > 12 {
		checksum = checksum[:12]
	}
	slog.Info("system-classification: manifest(s) loaded",
		"count", len(manifests),
		"manifests", strings.Join(manifests, ", "),
		"checksum", checksum,
		"uncertified-version-fallback", fallback,
	)
}

// TagForTable is the shipped `system:` tag id for a Table, or ok=false when no manifest governs the
// datasource. Consumed by A6 as the systemTags map feeding A2's Table entity parents.
func (s *SystemClassificationService) TagForTable(
	engine Engine, engineVersion *string, catalog, schema, table string,
) (string, bool) {
	classifier, ok := s.classifierFor(engine, engineVersion)
	if !ok {
		return "", false
	}
	tag, ok := classifier.ClassifyRelation(catalog, schema, table)
	if !ok {
		return "", false
	}
	return tag.ID(), true
}

// TagForFunction is the shipped `system:` tag id for a called function, or ok=false when it is an
// ordinary safe function.
//
// 🔒 INV-A5-56 — the function model is enumerate-dangerous / allow-safe, and ABSENT MEANS SAFE: "a
// standard builtin or an unclassified user/UDF … Only a non-null (dangerous) result is marshalled as
// a Cedar Function and hits the shipped system:data-leak/system:critical forbid." A safe function has
// no tag and no permit, so marshalling it would deny-by-default and break every now()/user-UDF query.
//
// 🔒 INV-A5-57 — the analyzer emits only BARE function names (sqlglot drops the schema qualifier at
// parse time), so this resolves against every system/logical schema plus the cross-schema rules.
//
// 🔒 INV-A5-58 — the no-manifest path unions EVERY shipped manifest of the engine, strongest tag per
// name. The bug this fixed is named in the source: a thin hand-curated baseline missed whole
// dangerous families → "a cleartext-PII relay on any pg≠16/17, mysql≠8.0/8.4 datasource".
// Over-classifying a function absent in the datasource's real version is a harmless over-deny.
//
// 🔒 INV-A5-59 — the baseline is a FLOOR: it can raise or match, never lower, and classifies no safe
// function. A GOVERNED datasource still gets the baseline unioned in.
func (s *SystemClassificationService) TagForFunction(engine Engine, engineVersion *string, name string) (string, bool) {
	var manifestTag SystemTag
	var hasManifestTag bool
	if governing, ok := s.classifierFor(engine, engineVersion); ok {
		manifestTag, hasManifestTag = governing.ClassifyBareFunction(name)
	} else {
		manifestTag, hasManifestTag = s.noManifestFunctionFloor(engine, name)
	}
	baselineTag, hasBaselineTag := s.baseline.Classify(name)
	tag, ok := floorTag(manifestTag, hasManifestTag, baselineTag, hasBaselineTag)
	if !ok {
		return "", false
	}
	return tag.ID(), true
}

// noManifestFunctionFloor is the strongest dangerous-function tag any shipped manifest of engine
// assigns name — the version-independent floor for a datasource with no governing manifest.
//
// 🔒 INV-A13-29 — the floor is DERIVED from the shipped manifests, never hand-listed.
func (s *SystemClassificationService) noManifestFunctionFloor(engine Engine, name string) (SystemTag, bool) {
	var tag SystemTag
	found := false
	wire, err := WireName(engine)
	if err != nil {
		// The Kotlin calls `engine.wireName`, whose `else -> error(...)` throws here. The store is
		// keyed by wire name, so there is nothing to iterate for an unspecified engine.
		return nil, false
	}
	for _, classifier := range s.store.ClassifiersForEngine(wire) {
		candidate, ok := classifier.ClassifyBareFunction(name)
		if !ok {
			continue
		}
		if !found {
			tag, found = candidate, true
			continue
		}
		tag = StrongerTag(tag, candidate)
	}
	return tag, found
}

// floorTag is the FLOOR combinator: the baseline never weakens a manifest classification, and a name
// neither classifies stays absent (safe).
func floorTag(manifestTag SystemTag, hasManifest bool, baselineTag SystemTag, hasBaseline bool) (SystemTag, bool) {
	switch {
	case !hasManifest && !hasBaseline:
		return nil, false
	case !hasManifest:
		return baselineTag, true
	case !hasBaseline:
		return manifestTag, true
	default:
		return StrongerTag(manifestTag, baselineTag), true
	}
}

// TagForCommand is the `system:` tag id for a utility command id — SHOW_PROCESSLIST →
// system:activity, SHOW_BINLOG_EVENTS → system:data-leak, … — or ok=false when no manifest governs
// the datasource.
//
// 🔒 INV-A5-60 — for a UTILITY, absent does NOT mean safe. The caller marshals the utility anyway, so
// an unclassified RECOGNIZED utility denies-by-default (Authz.authorizeUtilities). The two absences
// have OPPOSITE meanings and A6/A2 depend on that: treating an absent command as safe relays
// `SHOW CREATE USER`; treating an absent function as dangerous denies now().
func (s *SystemClassificationService) TagForCommand(engine Engine, engineVersion *string, command string) (string, bool) {
	classifier, ok := s.classifierFor(engine, engineVersion)
	if !ok {
		return "", false
	}
	tag, ok := classifier.ClassifyCommand(command)
	if !ok {
		return "", false
	}
	return tag.ID(), true
}

func (s *SystemClassificationService) classifierFor(engine Engine, engineVersion *string) (ManifestClassifier, bool) {
	version, _ := ParseServerVersion(engine, engineVersion)
	if version == nil {
		return nil, false
	}
	wire, err := WireName(engine)
	if err != nil {
		return nil, false
	}
	resolved, ok := s.store.Resolve(wire, *version, s.allowFallback)
	if !ok {
		return nil, false
	}
	return resolved.Classifier, true
}

// DescribeManifestFor is a one-line description of which shipped manifest governs a datasource's
// (engine, engineVersion) — for the proxy-registration log, so an operator can see at connect time
// whether that datasource's system schemas are classified by an exact manifest, a fallback major, or
// left uncertified (deny-by-default). TODO(A10): A10's pushCatalog calls it.
func (s *SystemClassificationService) DescribeManifestFor(engine Engine, engineVersion *string) string {
	engineName, err := WireName(engine)
	if err != nil {
		engineName = engine.String()
	}
	version, _ := ParseServerVersion(engine, engineVersion)
	if version == nil {
		return engineName + " (version unreported) → no manifest (system schemas deny-by-default)"
	}
	resolved, ok := s.store.Resolve(engineName, *version, s.allowFallback)
	if !ok {
		return engineName + " " + *version + " → no manifest (uncertified series → system schemas deny-by-default)"
	}
	if resolved.IsFallback {
		return fmt.Sprintf("%s %s → manifest %s/%s (FALLBACK — series %s uncertified)",
			engineName, *version, engineName, resolved.ResolvedSeries, resolved.RequestedSeries)
	}
	return fmt.Sprintf("%s %s → manifest %s/%s", engineName, *version, engineName, resolved.ResolvedSeries)
}

var (
	mysqlThreeComponent = regexp.MustCompile(`\d+\.\d+\.\d+`)
	mysqlTwoComponent   = regexp.MustCompile(`\d+\.\d+`)
	postgresLabelled    = regexp.MustCompile(`PostgreSQL\s+(\d+(?:\.\d+)?)`)
	postgresBare        = regexp.MustCompile(`\d+(?:\.\d+)?`)
)

// ParseServerVersion extracts the comparable server version plus the Aurora marker from a
// `datasource.engine_version` string (the raw `SELECT version()` output, with `(aurora <v>)` appended
// when aurora_version() resolves). Returns (versionForResolution, isAurora); a nil version when
// nothing is parseable.
//
// 🔒 INV-A5-61 — NEVER grab the Aurora engine version as the server version. Aurora MySQL version()
// embeds the MySQL major.minor BEFORE a `mysql_aurora` infix — `8.0.mysql_aurora.3.04.0` → 8.0,
// `5.7.mysql_aurora.2.11.4` → 5.7 — so the base is taken BEFORE either marker. Before the fix the
// regex grabbed 3.04.0 → no manifest → classification INERT, i.e. system schemas silently
// unclassified on every Aurora MySQL datasource.
//
// Note the asymmetry the tests pin: Aurora MySQL resolves to "8.0" (two components, because the
// three-component regex fails on the truncated base) while vanilla MySQL resolves to "8.0.44" (three).
// Both resolve to the same manifest series.
//
// ⚠️ The `else` arm means ENGINE_UNSPECIFIED silently takes the PostgreSQL regex rather than failing
// closed like every other mapping in engine.go (contrast INV-A5-4). §10 Q4 — REPRODUCED, not fixed.
func ParseServerVersion(e Engine, raw *string) (*string, bool) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, false
	}
	text := *raw
	isAurora := strings.Contains(strings.ToLower(text), "aurora")

	var version string
	if e == EngineMySQL {
		base := substringBefore(substringBefore(text, "mysql_aurora"), "(aurora")
		version = mysqlThreeComponent.FindString(base)
		if version == "" {
			version = mysqlTwoComponent.FindString(base)
		}
	} else {
		if m := postgresLabelled.FindStringSubmatch(text); m != nil {
			version = m[1]
		} else {
			version = postgresBare.FindString(text)
		}
	}
	if version == "" {
		return nil, isAurora
	}
	return &version, isAurora
}

// substringBefore is Kotlin's String.substringBefore: the whole string when the delimiter is absent.
func substringBefore(s, delimiter string) string {
	if i := strings.Index(s, delimiter); i >= 0 {
		return s[:i]
	}
	return s
}
