package datasource

import "github.com/ridi-oss/proxy-monster/controlplane/internal/engine"

// The BUNDLED wiring of [SystemClassificationService] — the Go form of Kotlin's two default
// arguments, `store: SystemClassificationStore = SystemClassificationStore.load()` and
// `baseline: BaselineDangerousFunctions = BaselineDangerousFunctions` (SystemClassifier.kt).
//
// Every Kotlin production caller and every Kotlin gate suite constructs the service as bare
// `SystemClassificationService()`, i.e. over the four SHIPPED manifests and the static baseline. This
// file is the only thing that made that spelling unavailable in Go, and systemclass.go's seam
// comment named it: "TODO(A13): … When A13 lands, its concrete types satisfy these — do NOT grow a
// second manifest model here." internal/engine (A13) has landed, so this is that wiring and nothing
// more: three method-forwarding shims and one constructor. No classification logic lives here.
//
// ⚠️ LANGUAGE-FORCED DEVIATION, and the reason this is not a plain assignment. Go interface
// satisfaction is INVARIANT in return types: *engine.SystemClassifier.ClassifyRelation returns
// engine.SystemTag (a defined int), while [ManifestClassifier] declares the [SystemTag] INTERFACE.
// engine.SystemTag does implement SystemTag — ID() and Strength() are both defined on it — but a
// method returning the concrete type does not satisfy a method returning the interface, so the
// forwarding shims below are mandatory rather than stylistic. They also carry the `ok=false ⇒ nil
// interface` conversion, which matters: returning a typed engine.SystemTag alongside ok=false would
// hand callers a NON-NIL SystemTag interface holding TagCritical (the zero value), i.e. it would
// silently read as "critical" at exactly the sites that treat absence as safe.

// bundledClassifier adapts one compiled manifest onto [ManifestClassifier].
type bundledClassifier struct{ inner *engine.SystemClassifier }

func (c bundledClassifier) ClassifyRelation(catalog, schema, name string) (SystemTag, bool) {
	tag, ok := c.inner.ClassifyRelation(catalog, schema, name)
	if !ok {
		return nil, false
	}
	return tag, true
}

func (c bundledClassifier) ClassifyBareFunction(name string) (SystemTag, bool) {
	tag, ok := c.inner.ClassifyBareFunction(name)
	if !ok {
		return nil, false
	}
	return tag, true
}

func (c bundledClassifier) ClassifyCommand(id string) (SystemTag, bool) {
	tag, ok := c.inner.ClassifyCommand(id)
	if !ok {
		return nil, false
	}
	return tag, true
}

// bundledManifestStore adapts *engine.SystemClassificationStore onto [ManifestStore].
type bundledManifestStore struct {
	inner *engine.SystemClassificationStore
}

// Resolve forwards the engine store's nil-pointer "no governing manifest" answer as ok=false, which
// is the shape [SystemClassificationService.classifierFor] tests.
func (s bundledManifestStore) Resolve(eng, serverVersion string, allowFallback bool) (ResolvedClassification, bool) {
	resolved := s.inner.Resolve(eng, serverVersion, allowFallback)
	if resolved == nil {
		return ResolvedClassification{}, false
	}
	return ResolvedClassification{
		Classifier:      bundledClassifier{inner: resolved.Classifier},
		RequestedSeries: resolved.RequestedSeries,
		ResolvedSeries:  resolved.ResolvedSeries,
		IsFallback:      resolved.IsFallback,
	}, true
}

// ClassifiersForEngine is INV-A13-29's no-manifest function floor: the union across every shipped
// manifest of the engine, derived from the bundle rather than hand-listed.
func (s bundledManifestStore) ClassifiersForEngine(eng string) []ManifestClassifier {
	inner := s.inner.ClassifiersForEngine(eng)
	out := make([]ManifestClassifier, 0, len(inner))
	for _, c := range inner {
		out = append(out, bundledClassifier{inner: c})
	}
	return out
}

func (s bundledManifestStore) Supported() []EngineSeries {
	inner := s.inner.Supported()
	out := make([]EngineSeries, 0, len(inner))
	for _, e := range inner {
		out = append(out, EngineSeries{Engine: e.Engine, Series: e.Series})
	}
	return out
}

func (s bundledManifestStore) Checksum() string { return s.inner.Checksum() }

// bundledBaseline adapts BaselineDangerousFunctions onto [BaselineClassifier].
type bundledBaseline struct{}

func (bundledBaseline) Classify(name string) (SystemTag, bool) {
	tag, ok := engine.ClassifyBaselineDangerousFunction(name)
	if !ok {
		return nil, false
	}
	return tag, true
}

// NewBundledSystemClassificationService is Kotlin's bare `SystemClassificationService()`: the service
// over the four EMBEDDED manifests (postgres 16/17, mysql 8.0/8.4) and the static
// BaselineDangerousFunctions floor.
//
// 🔒 INV-A5-55 — a malformed manifest ABORTS STARTUP. The load error is returned, never logged and
// swallowed: booting with system schemas UNCLASSIFIED silently loses the dangerous-function floor
// while A6's utility path hard-denies every utility, so the two failure modes are not symmetric and
// neither is acceptable.
//
// 🔒 INV-A13-27 — allowFallback is the OPERATOR OPT-IN and is a WIDENING; there is no default here
// precisely so a caller cannot acquire it by omission. A5 owns the flag.
func NewBundledSystemClassificationService(allowFallback bool) (*SystemClassificationService, error) {
	return NewSystemClassificationService(
		func() (ManifestStore, error) {
			store, err := engine.LoadSystemClassificationStore()
			if err != nil {
				return nil, err
			}
			return bundledManifestStore{inner: store}, nil
		},
		bundledBaseline{},
		allowFallback,
	)
}
