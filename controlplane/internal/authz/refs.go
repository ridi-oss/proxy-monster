package authz

// The batch-decision input refs and their verdict enums — Authz.kt:96-151.
//
// 🔒 INV-A2-4 — Key is OPAQUE and identity is never recovered by parsing it. Catalog/Schema/Table/
// Column come from the exact matching catalog row (or the analyzer's resolved identity for tables);
// Key is ONLY the map key the verdict returns under. Reconstructing identity by splitting Key would
// reintroduce exactly the delimiter-collision class INV-A2-6 exists to prevent.
//
// 🔒 INV-A2-5 — every input gets an explicit verdict; there is no "absent = allow". All four batch
// functions return a verdict for every entry in their input list.

// ColumnRef is a column touched by a query, marshalled to Cedar entities by AuthorizeColumns. Tags
// drive tag-scoped grants/exclusions (e.g. "read table X except pii"); the CALLER resolves them from
// the catalog — Authz never queries it.
type ColumnRef struct {
	Key     string
	Catalog string
	Schema  string
	Table   string
	Column  string
	Tags    []string
}

// ColumnVerdict is the per-column authz verdict — deny-by-default: DENIED unless a Cedar grant says
// otherwise.
//
// Masking is not authorization: MASKED says *a* mask applies; WHICH mask fn is column config,
// resolved elsewhere (A9 Policies.kt).
type ColumnVerdict int

const (
	ColumnDenied ColumnVerdict = iota // zero value is the deny-by-default verdict, deliberately
	ColumnUnmasked
	ColumnMasked
)

func (v ColumnVerdict) String() string {
	switch v {
	case ColumnUnmasked:
		return "UNMASKED"
	case ColumnMasked:
		return "MASKED"
	default:
		return "DENIED"
	}
}

// TableRef is a physical table SCANNED by a query with zero traced columns (docs/facts-emission.md),
// marshalled to a Cedar Table entity by AuthorizeTables.
type TableRef struct {
	Key     string
	Catalog string
	Schema  string
	Table   string
}

// TableVerdict is the per-table scan verdict — deny-by-default.
//
// READ is granted by EITHER result.read.unmasked OR result.read.masked, because a masked reader
// already observes the table's rows through masked projections, so existence and cardinality are not
// additionally protected.
type TableVerdict int

const (
	TableDenied TableVerdict = iota
	TableRead
)

func (v TableVerdict) String() string {
	if v == TableRead {
		return "READ"
	}
	return "DENIED"
}

// FunctionRef is a function CALLED by a query (facts-emission.md). Name is the BARE, unqualified
// function name — the analyzer drops the schema qualifier at parse time.
//
// 🔒 INV-A2-11 (half 1) — the caller passes ONLY DANGEROUS-classified functions. A safe function has
// no tag and no permit, so marshalling it would deny-by-default and break every now()/user-UDF query.
type FunctionRef struct {
	Name string
}

// FunctionVerdict is DENIED when a system: forbid covers the function, else ALLOWED.
type FunctionVerdict int

const (
	FunctionDenied FunctionVerdict = iota
	FunctionAllowed
)

func (v FunctionVerdict) String() string {
	if v == FunctionAllowed {
		return "ALLOWED"
	}
	return "DENIED"
}

// UtilityRef is a resource-bearing UTILITY command a statement performs (facts-emission.md). Command
// is the canonical per-engine command id (SHOW_PROCESSLIST, …).
//
// 🔒 INV-A2-11 (half 2), the subtlest rule in the area — the caller passes ONLY CLASSIFIED utilities.
// An unclassifiable one is HARD-denied UPSTREAM, because an untagged Utility (Datasource parent only,
// no forbid) would be PERMITTED by a datasource-scoped read grant. Marshalling an unclassified utility
// INVERTS the decision from deny to allow. The deny-by-default on an untagged EUID remains a defensive
// backstop but is NOT the load-bearing path, so the Go port must keep the upstream hard-deny.
type UtilityRef struct {
	Command string
}

// UtilityVerdict is deny-by-default; USE iff a result.read permit covers the Utility and no system:
// forbid overrides.
type UtilityVerdict int

const (
	UtilityDenied UtilityVerdict = iota
	UtilityUse
)

func (v UtilityVerdict) String() string {
	if v == UtilityUse {
		return "USE"
	}
	return "DENIED"
}

// TableIdentity is the (catalog, schema, table) key of the systemTags maps AuthorizeColumns and
// AuthorizeTables take — the port of Kotlin's Triple<String, String, String>.
type TableIdentity struct {
	Catalog string
	Schema  string
	Table   string
}
