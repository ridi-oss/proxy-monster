// Package engine is the Go port of the Kotlin `engine/` module — the enforcement code the control
// plane shares with the wire proxy (area doc: plans/proxy-monster-go-port/13-engine.md).
//
// Kotlin sources: classification/SystemClassifier.kt (183) · classification/SystemClassificationStore.kt
// (157) · probe/CatalogApi.kt (118) · probe/TableDetail.kt (82) · classification/SystemManifest.kt (68) ·
// classification/BaselineDangerousFunctions.kt (59) · probe/Sqlglot.kt (52) · probe/SqlNormalize.kt (34) ·
// probe/Masks.kt (26) · probe/Masking.kt (22) · probe/Dialect.kt (3). 804 LOC.
//
// Four separable concerns plus one production-dead one:
//
//  1. Masking (masking.go)          — deterministic value masking + mask-to-result-column binding.
//  2. System classification         — the four shipped per-engine-major manifests, the classifier, the
//     (systemtag/manifest/          version resolver, and the version-independent dangerous-function
//     classifier/store/baseline)    floor.
//  3. The analyzer facade           — the per-STATEMENT analyzer snapshot, the collision-free catalog
//     (catalogapi.go)               validation, and the fail-closed probe wrapper.
//  4. Shared DTOs (tabledetail.go)  — the table-browser shape the proxy produces and A5/A11 serve through.
//  5. SQL normalization             — production-dead (F21); REPRODUCEd, test surface included, because
//     (sqlnormalize.go)             the disposition is DEFER, not OMIT (13-engine.md §4.2, Q4).
//
// # DB tables: none
//
// This package holds no SQL and opens no connection. It reads only its embedded manifests. Its outputs
// land in tables other areas own: mask_fn.kind (V2), column_classification (V2), datasource.engine_version.
//
// # It is a leaf
//
// Nothing here depends on any other control-plane area, so it is ported BEFORE A5, A6 and A7. Its
// consumers are A5 (SystemClassificationService, TableDetailService, DatasourceStore), A6 (decideQuery),
// A7 (decideResultView), A9 (the mask_fn kind vocabulary) and A11 (management + MCP).
//
// # The three big simplifications, applied
//
// The analyzer is called DIRECTLY as a Go package (analyzer/probe): no FFM, no c-shared library, no
// analyzer/jvm. probe/Sqlglot.kt and probe/SqlNormalize.kt's binding halves are deleted, not ported —
// what survives is their fail-closed mapping (INV-A13-15) and F28's failedStage choice, both in
// catalogapi.go.
//
// goproxy/engine/masking.go is the hand-maintained Go twin of probe/Masking.kt. 13-engine.md §1.1
// recommends importing it rather than creating a third copy. That import is NOT POSSIBLE: goproxy's
// masking speaks github.com/ridi-oss/proxy-monster/goproxy/internal/pb.ColumnMask, and Go's internal/
// rule bars every package outside goproxy/ from importing it — a module boundary, not a style choice.
// masking.go here is therefore a deliberate line-by-line transcription of that file over the control
// plane's own internal/pb.ColumnMask, and masking_test.go carries goproxy's 11-row table verbatim so
// the two cannot drift silently (INV-A13-5). See 13-engine.md Q5, which asks this exact question.
//
// # Port policy notes carried in the code
//
// F32/INV-A13-35 (commandTags + functionAnySchema are last-wins with no duplicate check), F29 (the
// family-overlap Map.plus shadowing hole), F26 (Of() is missing load()'s two guards), F30
// (logicalFunctionSchemas ignores catalog), F31 (CommandRule.resource is never read), F23
// (Analyzer.PiiColumns has no production consumer) and F21/F79 (the unrecognised-mask-kind "****"
// arm is a reachable security default, not dead code) are all REPRODUCEd, each with a comment naming
// the finding and, where the finding sits on a security path, a test asserting the buggy behaviour.
//
// F22 (columnKey) is the area's only OMIT: no caller anywhere, main or test, so there is no observable
// behaviour to preserve. Its rendering rule is REPRODUCEd — it lives inside validateUniqueness.
package engine
