package engine

import (
	"errors"
	"fmt"
	"unicode"

	"github.com/ridi-oss/proxy-monster/analyzer/probe"
	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// The analyzer facade — probe/CatalogApi.kt plus the surviving half of probe/Sqlglot.kt.
//
// Sqlglot.kt existed only to marshal an AnalyzeRequest, hand the bytes across the FFM boundary and parse
// the StatementFacts back. The Go control plane calls probe.AnalyzeStatement DIRECTLY, in-process, with no
// serialization, so Sqlglot.kt and the whole of analyzer/jvm are DELETED, not ported. What is carried over
// is not code but its fail-closed mapping (INV-A13-15) and its two division-of-labour rules (F33).

// ErrAnalyzerCatalog is the class of every AnalyzerFor validation failure — the Go stand-in for the
// IllegalArgumentException Kotlin's `require` throws.
//
// ⚠️ These messages are WIRE-VISIBLE deny prose. A6 wraps the whole construction in a catch and converts
// it to structuralDeny("$CATALOG_CONFIGURATION_DENY: ${e.message}", …).copy(catalogMiss = true), so the
// text below reaches DecisionContext.denyReason carrying catalog identities. That is F13 territory
// (unlocalized deny prose) and, separately, mild structure disclosure; sanitizeDiagnostics (A6 step 31)
// redacts BACKEND diagnostics, not denyReason. The messages are therefore reproduced verbatim, including
// the Kotlin data-class toString rendering of the identity types (see schemaIdentity.String below).
var ErrAnalyzerCatalog = errors.New("analyzer catalog validation")

func catalogErrf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAnalyzerCatalog, fmt.Sprintf(format, args...))
}

// Analyzer is a validated, immutable per-request snapshot bound to one datasource state. It is
// constructible only through AnalyzerFor (Kotlin's constructor is `internal`).
//
// INV-A13-17 — the request snapshot is FIXED for the lifetime of an Analyzer; only sql varies per call.
// The native probe is pure, so an Analyzer is cheap to build per request — there is nothing to pool or
// warm.
//
// 🔒 INV-A13-34 — the scope of "fixed" is ONE STATEMENT, not one datasource: an Analyzer MUST NEVER be
// cached across statements. EngineConfig.mysql_ansi_quotes is a LIVE per-session observation of the
// backend's sql_mode (analyzer.proto:70-71: "sql_mode is mutable per session, so this is observed and
// forwarded per statement"), and A6 rebuilds the whole config from the live value on every decision. A
// port that memoizes an Analyzer per datasource — the obvious "optimization", and cheap-looking because
// construction is pure — would freeze a stale ansi_quotes and, when the client turns ANSI_QUOTES on
// mid-session, parse "masked_col" as a STRING LITERAL instead of a column read: the masked column then
// leaks cleartext. The catalog snapshot has the same problem in the other direction (a stale catalog
// misses a newly classified column). Rebuild per statement; the invariant that makes that affordable is
// the probe's PURITY, not a cache.
type Analyzer struct {
	namespaceProto    *probepb.Namespace
	catalogProto      []*probepb.ColumnSpec
	engineConfigProto *probepb.EngineConfig

	// PiiColumns is the catalog's fully-qualified rendered keys for every column whose ColumnSpec.pii is
	// set, in input order.
	//
	// F23 — REPRODUCE. It has NO production consumer (only AnalyzerTest reads it), so it is a live TEST
	// fixture, not dead code, and it stays outside the OMIT boundary. Kotlin builds it with
	// `mapTo(linkedSetOf())`, i.e. an INSERTION-ORDERED set — hence a slice here, not a map: the ordering
	// is what the Kotlin type promises. Worse, the word means something different here than in A6:
	// ColumnSpec.pii is set from `col.classification != null` ("has ANY classification") while A6 step 28
	// computes the real PII set from `classification.tags.contains("pii")`. Two meanings of "pii" one
	// function apart; reconciling them is a separate decision, not a port task.
	PiiColumns []string

	// ColumnKeys is every input column's rendered key, in input order — exposed so callers needing a key
	// per catalog row reuse construction's work rather than walking the catalog twice.
	//
	// INV-A13-16 — ColumnKeys[i] corresponds to the i-th element of the slice passed to AnalyzerFor, and
	// equals what the four-part rendering would produce for it. A6's index build (buildCatalogColumnIndex)
	// ZIPS the two lists positionally under a require(len(catalog) == len(ColumnKeys)), so any reordering
	// or filtering breaks the catalog index silently.
	ColumnKeys []string
}

// Namespace returns the exact namespace AnalyzerFor validated (Kotlin's `internal val namespaceProto`).
func (a *Analyzer) Namespace() *probepb.Namespace { return a.namespaceProto }

// Catalog returns the exact flat column list AnalyzerFor validated.
func (a *Analyzer) Catalog() []*probepb.ColumnSpec { return a.catalogProto }

// EngineConfig returns the exact engine config AnalyzerFor was given. The control plane forwards this
// as-is from what the proxy already reported at introspection time; it does NOT re-derive or re-parse any
// of these values itself (analyzer.proto:52-55). No version parsing, no case-mode inference here.
func (a *Analyzer) EngineConfig() *probepb.EngineConfig { return a.engineConfigProto }

// Analyze runs the probe over sql against this snapshot.
//
// INV-A13-14 — do NOT pre-clean the SQL. sqlglot parses a trailing terminator ';', surrounding
// whitespace, and a ';' inside a string literal on its own, and fail-closes a genuine multi-statement (>1
// parsed statement) — so no pre-cleaning is needed here. A port that stripped trailing semicolons or
// trimmed whitespace "to help" would, for the multi-statement case, help an attacker: the fail-close on
// >1 statement is the admission guard.
//
// 🔒 INV-A13-15 — Analyze NEVER returns an error and NEVER panics; it always returns StatementFacts.
// Sqlglot.kt:22-24 states the reason: "any binding/parse error here also surfaces as an unresolved
// StatementFacts (→ DENY), never an escaped exception (which would bypass the decision/audit contract)".
// An error escaping into A6's decision path would skip the audit write for a statement that was in fact
// examined.
//
// ⚠️ The recover below is REQUIRED BY THE DIRECT-CALL SIMPLIFICATION, not an addition to the Kotlin's
// behaviour. Kotlin reached the probe through TWO total layers: the c-shared export called
// probe.AnalyzeStatementSafe, which is "total, panic-safe … never a panic escaping to the caller"
// (analyzer/probe/wire.go:32-34) and turns a recovered panic into fail-closed facts at stage "LINEAGE"
// (wire.go:36-40), and Sqlglot.kt then caught Throwable on top of it. The Go control plane calls
// probe.AnalyzeStatement — the UNGUARDED entry point: only four stages inside it run under runStage's
// recover (probe.go:145,213,256,269), while EmitFacts's emitters and grant builders run outside any guard
// (facts.go:113-142). Without this recover a probe panic escapes into A6's decision path and skips the
// audit write — exactly the failure INV-A13-15's quoted reason names. Detail and stage match
// AnalyzeStatementSafe's own recovered-panic rendering so one audited failed_stage value covers the case
// however the probe is reached.
func (a *Analyzer) Analyze(sql string) (facts *probepb.StatementFacts) {
	defer func() {
		if r := recover(); r != nil {
			facts = unanalyzableFacts(fmt.Errorf("panic: %v", r))
		}
	}()
	req := &probepb.AnalyzeRequest{
		Sql:          sql,
		Namespace:    a.namespaceProto,
		Catalog:      a.catalogProto,
		EngineConfig: a.engineConfigProto,
	}
	out, err := probeAnalyzeStatement(req)
	if err != nil {
		return unanalyzableFacts(err)
	}
	if out == nil {
		// probe.AnalyzeStatement returns (facts, nil) or (nil, err); a nil-nil return would otherwise
		// nil-panic every caller. Fail closed on it rather than trust the contract.
		return unanalyzableFacts(errors.New("analyzer returned no facts"))
	}
	return out
}

// probeAnalyzeStatement is the in-process analyzer call. It is a package variable ONLY so the
// panic-safety test (INV-A13-15) can substitute a panicking probe — there is no other way to reach that
// arm, since making the real probe panic on demand is not possible from a test. Production always calls
// analyzer/probe.AnalyzeStatement, and nothing outside this package can rebind it.
var probeAnalyzeStatement = probe.AnalyzeStatement

// unanalyzableFacts is Sqlglot.kt's catch-all branch, ported.
//
// F28 / 13-engine.md Q2 — the failedStage choice is DELIBERATE, not inherited by accident. The Kotlin
// wrapper labelled its catch-all "LINEAGE" while the Go probe's own AnalyzeStatementSafe labels a
// decode/build failure "VALIDATE". F33 settles it: "VALIDATE" is ALREADY the live probe signal for a
// missing or unparseable MySQL engine_version (analyzer.proto:58-61) — Go owns all engine-specific
// validation from engineConfig alone — so reusing "VALIDATE" for a CALL error would merge two distinct
// faults into one audited failed_stage value. This keeps "LINEAGE", matching the Kotlin wrapper.
//
// ⚠️ F28's other half survives the port unchanged and is NOT fixed here: FAILURE_CLASS_UNANALYZABLE is the
// class A6 step 16 routes to Cedar sql.unanalyzable, so on a datasource that permits the unanalyzable
// relay (a dev datasource with the shipped system:development posture, A2 INV-A2-1) an analyzer failure
// becomes a PASSTHROUGH, not a deny. Nothing in the failure class distinguishes "the analyzer says it
// cannot reason about this statement" from "the analyzer did not run". Deliberate per AGENTS.md:136-139
// ("fail-closed through Cedar, not a hardcoded deny").
func unanalyzableFacts(err error) *probepb.StatementFacts {
	stage := "LINEAGE"
	// Kotlin: `(e.message ?: e.javaClass.simpleName).take(150)` — 150 UTF-16 CODE UNITS, where the Go
	// probe's own truncateDetail counts 150 RUNES. takeUTF16 reproduces the Kotlin count. A Go error
	// always renders a non-empty string, so the class-name fallback has no Go analogue.
	return &probepb.StatementFacts{
		Resolved:     false,
		FailureClass: probepb.FailureClass_FAILURE_CLASS_UNANALYZABLE,
		FailedStage:  &stage,
		Detail:       takeUTF16(err.Error(), 150),
		// StatementClass is left at STATEMENT_CLASS_UNSPECIFIED (the proto zero), matching the Kotlin
		// builder's explicit assignment.
	}
}

// AnalyzerFor builds an Analyzer from an insertion-ordered flat catalog and engine-config snapshot. It
// returns an error (wrapping ErrAnalyzerCatalog) rather than a partial analyzer.
//
// Order matches Kotlin exactly: validateNamespace, then validateUniqueness (which itself calls
// validateColumn per column, in order), then the pii projection, then construction. Validation runs HERE,
// never lazily inside Analyze — AnalyzerTest case 2 only asserts that construction fails, not that it
// fails before the probe runs, so the ordering is real but was unasserted on the Kotlin side; keeping it
// here is what makes the test name true.
func AnalyzerFor(namespace *probepb.Namespace, columns []*probepb.ColumnSpec, engineConfig *probepb.EngineConfig) (*Analyzer, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	// Validation already renders every column's key while checking for collisions; reuse those for both
	// PiiColumns and the exposed ColumnKeys instead of re-deriving them.
	renderedKeys, err := validateUniqueness(columns)
	if err != nil {
		return nil, err
	}
	var pii []string
	for i, c := range columns {
		if c.GetPii() {
			pii = append(pii, renderedKeys[i])
		}
	}
	return &Analyzer{
		namespaceProto:    namespace,
		catalogProto:      columns,
		engineConfigProto: engineConfig,
		PiiColumns:        pii,
		ColumnKeys:        renderedKeys,
	}, nil
}

// The three structural identity types. They carry the identity the collision checks compare, as distinct
// from the dot-joined rendered key — a NESTED triple, not a flat one, exactly as Kotlin declares them.
//
// 🔒 Their comparability is what makes INV-A13-13 detectable at all: ("a.b","c","t","x") and
// ("a","b.c","t","x") render to the identical key a.b.c.t.x but are DIFFERENT columnIdentity values, so
// the putIfAbsent returns a non-equal previous value and validation fails. A Go port that keyed the
// collision maps on the joined string alone CANNOT implement INV-A13-13 — it needs both the rendered key
// and the structured identity. These are comparable Go structs, so == is component-wise, matching Kotlin
// data-class equals.
type schemaIdentity struct {
	catalog string
	schema  string
}

type tableIdentity struct {
	schema schemaIdentity
	table  string
}

type columnIdentity struct {
	table  tableIdentity
	column string
}

// String reproduces Kotlin's data-class toString on purpose. The two collision messages interpolate the
// DATA CLASSES, not the key, so the emitted prose is e.g.
//
//	TableIdentity(schema=SchemaIdentity(catalog=a, schema=b), table=c)
//
// and it reaches denyReason through A6's catch. Replicating the format keeps deny prose byte-comparable
// across the port, which 13-engine.md §4.3 says is otherwise unachievable here.
func (s schemaIdentity) String() string {
	return fmt.Sprintf("SchemaIdentity(catalog=%s, schema=%s)", s.catalog, s.schema)
}

func (t tableIdentity) String() string {
	return fmt.Sprintf("TableIdentity(schema=%s, table=%s)", t.schema, t.table)
}

func (c columnIdentity) String() string {
	return fmt.Sprintf("ColumnIdentity(table=%s, column=%s)", c.table, c.column)
}

// validateNamespace ports the three requires verbatim, including their messages.
func validateNamespace(namespace *probepb.Namespace) error {
	if isBlank(namespace.GetCatalog()) {
		return catalogErrf("analyzer namespace catalog is required")
	}
	if len(namespace.GetSearchPath()) == 0 {
		return catalogErrf("analyzer namespace searchPath is required")
	}
	for _, entry := range namespace.GetSearchPath() {
		if isBlank(entry) {
			return catalogErrf("analyzer namespace searchPath entries are required")
		}
	}
	return nil
}

// validateColumn ports the five requires, each with its own message.
//
// Note the last message says "sqlType" (the control-plane's field name) while the proto field is
// data_type. Reproduced verbatim — it is wire-visible deny prose.
func validateColumn(column *probepb.ColumnSpec) error {
	if isBlank(column.GetCatalog()) {
		return catalogErrf("column catalog is required")
	}
	if isBlank(column.GetIdentity().GetSchema()) {
		return catalogErrf("column schema is required")
	}
	if isBlank(column.GetIdentity().GetTable()) {
		return catalogErrf("column table is required")
	}
	if isBlank(column.GetIdentity().GetColumn()) {
		return catalogErrf("column name is required")
	}
	if isBlank(column.GetDataType()) {
		return catalogErrf("column sqlType is required")
	}
	return nil
}

// validateUniqueness checks the catalog's identities are collision-free and returns each column's rendered
// key, in the same order as columns.
//
// 🔒 INV-A13-13 — the analyzer key must be INJECTIVE, and a collision is a HARD FAILURE, not a warning.
// CatalogApi.kt:81-87: every column's identity already arrives canonical (goproxy normalizes at
// introspection), so there is nothing here to fold — only two genuine risks remain: an exact duplicate
// (schema, table, column) triple, and two DIFFERENT identities whose dot-joined key happens to render
// identically (a dot embedded in a raw identifier, e.g. catalog "a.b" + schema "c" vs. catalog "a" +
// schema "b.c", both → "a.b.c"). This is the SAME delimiter-collision class as A2's INV-A2-6 — '.' is
// legal inside a quoted SQL identifier, so without the guard two distinct columns share one analyzer key
// and one column's grants apply to the other. A2 guards it at the Cedar EUID; this guards it at the
// analyzer key. BOTH are required; neither substitutes for the other.
//
// INV-A13-33 — NO normalization or case folding happens here. goproxy normalizes every catalog column
// (its bulk introspection push AND the per-connection schema-fragment refetch path both call
// analyzer/probe.NormalizeRelation directly, in-process) before it ever reaches the control plane. This is
// pure concatenation of already-canonical parts. A port must not add folding: two normalization sites
// disagreeing is how a masked column stops matching its catalog row.
//
// F22 note: the rendering rule that dead `columnKey(namespace, column)` implemented lives HERE — the
// four-part "catalog.schema.table.column" join. Only the unreachable entry point is OMITted.
func validateUniqueness(columns []*probepb.ColumnSpec) ([]string, error) {
	seenColumns := make(map[columnIdentity]struct{}, len(columns))
	renderedTables := make(map[string]tableIdentity, len(columns))
	renderedColumns := make(map[string]columnIdentity, len(columns))
	renderedKeys := make([]string, 0, len(columns))

	for _, column := range columns {
		if err := validateColumn(column); err != nil {
			return nil, err
		}
		schema := schemaIdentity{catalog: column.GetCatalog(), schema: column.GetIdentity().GetSchema()}
		table := tableIdentity{schema: schema, table: column.GetIdentity().GetTable()}
		renderedTable := schema.catalog + "." + schema.schema + "." + table.table
		if previous, exists := renderedTables[renderedTable]; exists {
			if previous != table {
				return nil, catalogErrf(
					"catalog table identities render to the same analyzer key '%s': %v and %v",
					renderedTable, previous, table,
				)
			}
		} else {
			renderedTables[renderedTable] = table // putIfAbsent
		}

		colID := columnIdentity{table: table, column: column.GetIdentity().GetColumn()}
		rendered := renderedTable + "." + colID.column
		if _, dup := seenColumns[colID]; dup {
			return nil, catalogErrf("catalog contains duplicate column identity: %s", rendered)
		}
		seenColumns[colID] = struct{}{}

		if previous, exists := renderedColumns[rendered]; exists {
			if previous != colID {
				return nil, catalogErrf(
					"catalog column identities render to the same analyzer key '%s': %v and %v",
					rendered, previous, colID,
				)
			}
		} else {
			renderedColumns[rendered] = colID // putIfAbsent
		}
		renderedKeys = append(renderedKeys, rendered)
	}
	return renderedKeys, nil
}

// isBlank is Kotlin's CharSequence.isBlank(): empty, or every character is whitespace. It is spelled out
// rather than delegated to strings.TrimSpace because Go's unicode.IsSpace is the Unicode White_Space
// property, which EXCLUDES U+001C..U+001F (the four ISO separators) while JDK Character.isWhitespace —
// and therefore Kotlin's Char.isWhitespace — includes them. None can appear in a canonical catalog
// identity, and the direction on a blank-looking identity is a REJECT either way, so the difference is
// not reachable through this validator; it is reproduced so the predicate does not have to be re-derived
// if it ever is.
func isBlank(s string) bool {
	for _, r := range s {
		if !isKotlinWhitespace(r) {
			return false
		}
	}
	return true
}

// IsBlank exports [isBlank] unchanged, so a consumer needing Kotlin's `CharSequence.isBlank()` /
// `ifBlank {}` semantics reuses THIS predicate instead of re-deriving it.
//
// A6's decideQuery needs it three times — `ds.dbName.ifBlank { "public" }`,
// `facts.detail.ifBlank { … }` and `ds.engineVersion.isNullOrBlank()` (Query.kt:312, 358, 418) — and
// a `strings.TrimSpace(s) == ""` stand-in there would silently disagree with this one on
// U+001C..U+001F. One definition, per the doc-comment above.
func IsBlank(s string) bool { return isBlank(s) }

// isKotlinWhitespace mirrors Kotlin's Char.isWhitespace, which is JDK
// Character.isWhitespace || Character.isSpaceChar.
func isKotlinWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}
