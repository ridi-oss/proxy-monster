package datasource

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// The datasource engine is the proto enum [Engine] (proxymonster.v1.Engine) used directly as the
// domain type — there is no parallel twin. The functions below are the single home for every
// "is this MySQL or Postgres?" decision, so nothing else compares an engine string literal. MySQL is
// the priority engine and is listed first in each mapping. (Engines.kt:12-15.)
//
// ⚠️ LANGUAGE-FORCED DEVIATION. Kotlin states these as extension properties/functions on the proto
// enum; Go cannot declare methods on a type from another package. Engine is therefore a type ALIAS
// (identical to enginepb.Engine, not a defined twin — the spec's "used directly as the domain type"
// is preserved) and the nine mappings are package-level functions. Kotlin extensions compile to
// static functions taking the receiver as the first argument, so this is the same shape, not a
// redesign.
//
// ⚠️ LANGUAGE-FORCED DEVIATION #2. Kotlin's `else -> error(...)` arms throw IllegalStateException.
// Each is reproduced as an `(T, error)` return: an unchecked JVM exception and a Go panic are not
// the same observable thing at an RPC boundary, and INV-A5-5 explicitly asks for `(int, error)`
// rather than a zero value on the one arm the spec dictates a shape for. Where the Kotlin call site
// does NOT handle the throw (poolKey, defaultSchema, decideConnection), a Must* wrapper panics with
// the identical message — see mustIsFixedSystemSchema and friends. That keeps "this cannot happen,
// and if it does it propagates" faithful without inventing a new error path in the middle of the
// enforcement flow.
type Engine = enginepb.Engine

// The three enum values, re-exported so callers of this package do not import the proto package for
// a constant. These are the SAME constants, not copies.
const (
	EngineUnspecified = enginepb.Engine_ENGINE_UNSPECIFIED
	EngineMySQL       = enginepb.Engine_MYSQL
	EnginePostgres    = enginepb.Engine_POSTGRES
)

// Dialect is the analyzer SQL dialect.
//
// TODO(A13): the canonical home is engine/probe/Dialect.kt (13-engine.md §4.2), which is
// production-dead but REPRODUCE-as-test-visible under F21/Q4, so internal/engine owns it when A13
// lands. It is declared here because `Engine.dialect` (EnginesTest case 4) is A5's and A13 is not
// ported; move it and alias, do not fork it.
type Dialect int

const (
	DialectMySQL Dialect = iota
	DialectPostgres
)

func (d Dialect) String() string {
	switch d {
	case DialectMySQL:
		return "MYSQL"
	case DialectPostgres:
		return "POSTGRES"
	default:
		return fmt.Sprintf("Dialect(%d)", int(d))
	}
}

// ErrUnknownEngine is returned by [EngineFromWire] for anything but the two canonical spellings.
var ErrUnknownEngine = errors.New("unknown datasource engine")

// engineError reproduces Kotlin's `error("<msg>: $this")` payload. The message text is part of what
// a log line shows an operator, so it is carried verbatim.
func engineError(msg string, e Engine) error {
	return fmt.Errorf("%s: %s", msg, e)
}

// WireName is the canonical persistence / registration / wire string for an engine: "mysql" or
// "postgres". (Engines.kt:18-23.)
func WireName(e Engine) (string, error) {
	switch e {
	case EngineMySQL:
		return "mysql", nil
	case EnginePostgres:
		return "postgres", nil
	default:
		return "", engineError("engine has no canonical wire name", e)
	}
}

// MustWireName is [WireName] at a call site the Kotlin does not guard, where the throw propagates.
func MustWireName(e Engine) string {
	name, err := WireName(e)
	if err != nil {
		panic(err)
	}
	return name
}

// IsMySQL reports whether this is MySQL.
//
// Calling this at a call site to branch behavior is almost always wrong: per-engine behavior belongs
// in a function on [Engine] (see [CatalogName], [DefaultSchema], [RequireCaseMode],
// [ParseServerVersion], …), so adding a future engine means implementing the type's functions, not
// hunting down scattered call-site branches. Kept only for a genuinely local one-off.
//
// ⚠️ Zero main-source call sites in the Kotlin (§3, candidate finding: dead in production code) —
// only test fixtures use it. REPRODUCE-as-test-helper, not OMIT.
func IsMySQL(e Engine) bool { return e == EngineMySQL }

// IsPostgres reports whether this is Postgres. See [IsMySQL].
func IsPostgres(e Engine) bool { return e == EnginePostgres }

// EngineDialect is the analyzer SQL dialect for this engine. (Engines.kt:42-47.)
func EngineDialect(e Engine) (Dialect, error) {
	switch e {
	case EngineMySQL:
		return DialectMySQL, nil
	case EnginePostgres:
		return DialectPostgres, nil
	default:
		return 0, engineError("engine has no dialect", e)
	}
}

// CatalogName is the analyzer catalog segment: MySQL pins "def"; Postgres uses the database name.
//
// 🔒 This is the same value DatasourceStore.catalog's SQL CASE computes
// (`CASE WHEN lower(d.engine)='mysql' THEN 'def' ELSE d.db_name END`). Two implementations of one
// rule — §3 flags it as a candidate duplication finding; keep them in agreement.
func CatalogName(e Engine, dbName string) (string, error) {
	switch e {
	case EngineMySQL:
		return "def", nil
	case EnginePostgres:
		return dbName, nil
	default:
		return "", engineError("engine has no catalog mapping", e)
	}
}

// MustCatalogName is [CatalogName] at a call site the Kotlin does not guard (decideConnection).
func MustCatalogName(e Engine, dbName string) string {
	name, err := CatalogName(e, dbName)
	if err != nil {
		panic(err)
	}
	return name
}

// DefaultSchema is the schema an unqualified table lives under by default for this engine. In ANSI
// terms a MySQL "database" IS the schema (catalog is always "def"), so the default schema is the
// database name; Postgres defaults to "public". (Engines.kt:61-65.)
func DefaultSchema(e Engine, dbName string) (string, error) {
	switch e {
	case EngineMySQL:
		return dbName, nil
	case EnginePostgres:
		return "public", nil
	default:
		return "", engineError("engine has no default schema", e)
	}
}

// ResolveSchema resolves a per-request schema to the concrete schema a table lives under. The
// cross-engine "public" default selector maps to this engine's [DefaultSchema] (MySQL's database,
// Postgres's "public"); any other value is an explicit schema — for MySQL an explicit database,
// since a MySQL "database" is the ANSI schema — and is used as-is, so MySQL addresses every
// database, not only the connection's default.
//
// 🔒 Mirrors goproxy/engine.Dialect.ResolveSchema (goproxy/engine/engine.go:115, read this session).
// The two must stay byte-identical: TableDetailService sends the RAW schema down the wire and
// compares against its OWN resolution, so a drift turns every `?schema=public` MySQL request into a
// spurious "proxy returned table detail for an unexpected table" (INV-A5-63).
func ResolveSchema(e Engine, requestedSchema, dbName string) (string, error) {
	if requestedSchema != "public" {
		return requestedSchema, nil
	}
	return DefaultSchema(e, dbName)
}

// RequireCaseMode is the MySQL `lower_case_table_names` case-folding mode the analyzer needs, or a
// nil result for an engine that has no such mode. MySQL requires the value to have been captured by
// introspection; Postgres has none.
//
// 🔒 INV-A5-5 — MySQL refuses to analyze without a captured case mode. Guessing the fold would make
// identifier resolution wrong in the direction of resolving a name to a DIFFERENT table. The return
// is (*int, error), never an int zero value: 0 is a VALID lower_case_table_names, so a port using
// the zero value as "absent" silently picks case-sensitive mode.
func RequireCaseMode(e Engine, lowerCaseTableNames *int) (*int, error) {
	switch e {
	case EngineMySQL:
		if lowerCaseTableNames == nil {
			return nil, errors.New("MySQL lower_case_table_names has not been captured by introspection")
		}
		return lowerCaseTableNames, nil
	case EnginePostgres:
		return nil, nil
	default:
		return nil, engineError("engine has no case mode", e)
	}
}

// mysqlSystemSchemas / postgresSystemSchemas are package-level so [SystemSchemas] hands out a copy
// rather than a shared mutable map — Kotlin's setOf is immutable and Go's map is not.
var (
	mysqlSystemSchemas    = []string{"information_schema", "mysql", "performance_schema", "sys"}
	postgresSystemSchemas = []string{"pg_catalog", "information_schema"}
)

// SystemSchemas is the engine's concrete, enumerable system namespaces — the fixed catalog schemas
// whose content is identical across every datasource of the same engine version. This is the single
// source of truth for those names: the enforcement catalog pools them by engine version, and
// search-path building enumerates them, so it holds only CONCRETE names — Postgres's per-session
// `pg_temp_` / `pg_toast` schemas are ephemeral and never appear. (Engines.kt:95-100.)
//
// ⚠️ DEVIATION: Kotlin's `Set<String>` becomes a `map[string]struct{}` so membership stays O(1) and
// the value is not order-bearing. A fresh map is returned per call, matching the immutability of
// Kotlin's setOf.
func SystemSchemas(e Engine) (map[string]struct{}, error) {
	names, err := SystemSchemaNames(e)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out, nil
}

// SystemSchemaNames is [SystemSchemas] in DECLARATION ORDER.
//
// It exists because Kotlin's `setOf(...)` is a LinkedHashSet, so `ds.defaultSchemas +
// ds.engine.systemSchemas` — the seed A10's ValidateToken/Decide hand to
// [ConnectionCatalogRegistry.Open] / [ConnectionCatalogRegistry.Recover] — produces a DETERMINISTIC
// on-open Refetch list. Ranging a Go map would randomise that list per call, so the handshake's
// commands would arrive in a different order on every connection. Same names, same source slices,
// order-bearing.
func SystemSchemaNames(e Engine) ([]string, error) {
	var names []string
	switch e {
	case EngineMySQL:
		names = mysqlSystemSchemas
	case EnginePostgres:
		names = postgresSystemSchemas
	default:
		return nil, engineError("engine has no system schemas", e)
	}
	return append([]string(nil), names...), nil
}

// IsFixedSystemSchema reports whether schema is one of the engine's fixed catalog schemas —
// [SystemSchemas] membership with engine-correct casing (MySQL folds; Postgres matches exactly, its
// unquoted identifiers being canonically lowercase). Excludes Postgres's ephemeral `pg_temp_` /
// `pg_toast` schemas, so this is the predicate for an enumerable / poolable system schema (the
// catalog pool key); use [IsSystemSchema] for the full test.
//
// The asymmetry is deliberate and documented: the MySQL fold is an interim compensation for schema
// names that reach the control plane un-canonicalized (safe only because MySQL system schemas are
// always case-insensitive) — see KNOWN_LIMITATIONS.md "Identifier handling".
func IsFixedSystemSchema(e Engine, schema string) (bool, error) {
	switch e {
	case EngineMySQL:
		_, ok := setOfSystemSchemas(mysqlSystemSchemas)[strings.ToLower(schema)]
		return ok, nil
	case EnginePostgres:
		_, ok := setOfSystemSchemas(postgresSystemSchemas)[schema]
		return ok, nil
	default:
		return false, engineError("engine has no system schemas", e)
	}
}

// MustIsFixedSystemSchema is [IsFixedSystemSchema] at a call site the Kotlin does not guard —
// ConnectionCatalogRegistry.poolKey, which takes a stored Datasource whose engine came through
// EngineFromWire and therefore cannot be unspecified.
func MustIsFixedSystemSchema(e Engine, schema string) bool {
	ok, err := IsFixedSystemSchema(e, schema)
	if err != nil {
		panic(err)
	}
	return ok
}

func setOfSystemSchemas(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// IsSystemSchema reports whether schema names any engine-owned system namespace —
// [IsFixedSystemSchema] plus Postgres's ephemeral per-session `pg_temp_` / `pg_toast` schemas (which
// answer the membership test but are not enumerable, so they stay out of [SystemSchemas] /
// [IsFixedSystemSchema]).
//
// ⚠️ Note the prefixes: `pg_temp_` requires the trailing underscore, `pg_toast` does not. So
// "pg_temp" alone is NOT a system schema while "pg_toast" alone is. EnginesTest case 11 pins it.
// Reproduce exactly.
func IsSystemSchema(e Engine, schema string) (bool, error) {
	switch e {
	case EngineMySQL:
		return IsFixedSystemSchema(e, schema)
	case EnginePostgres:
		fixed, err := IsFixedSystemSchema(e, schema)
		if err != nil {
			return false, err
		}
		return fixed || strings.HasPrefix(schema, "pg_temp_") || strings.HasPrefix(schema, "pg_toast"), nil
	default:
		return false, engineError("engine has no system schemas", e)
	}
}

// MustIsSystemSchema is [IsSystemSchema] at a call site the Kotlin does not guard
// (DatasourceStore.defaultSchema, whose Datasource came from the store).
func MustIsSystemSchema(e Engine, schema string) bool {
	ok, err := IsSystemSchema(e, schema)
	if err != nil {
		panic(err)
	}
	return ok
}

// CatalogIsConnectionIndependent reports whether a schema's catalog content is the same for every
// connection to a datasource, so one connection's measurement answers for all of them.
//
// MySQL's temporary tables are absent from `information_schema.COLUMNS` entirely — a session's temp
// tables cannot appear in a catalog scan, so nothing a scan returns varies by connection. They reach
// a decision as the per-request temp overlay instead, never through the catalog. PostgreSQL's
// `pg_temp_*` schemas are real, per-session, and visible in the catalog, so there a fragment is only
// true for the connection that measured it.
//
// 🔒 INV-A5-6 — adoption is legal only where a scan cannot vary by connection. Flipping this to true
// for Postgres lets connection B decide against connection A's temp tables — a wrong-grant read.
//
// Its ONLY job is to supply adoptHeldContent at every registry entry point, and ALL FOUR are wired: the
// gRPC ValidateToken open and the Decide recover (internal/grpcsvc), plus RunExecService's one-shot and
// persistent-session opens (internal/runexec's openCatalogConnection, which both Run and OpenSession go
// through). Wiring it into only the gRPC path silently forces a full catalog fetch on every editor
// session — no failure, just a slow cold open, which is why the count is stated.
func CatalogIsConnectionIndependent(e Engine) (bool, error) {
	switch e {
	case EngineMySQL:
		return true, nil
	case EnginePostgres:
		return false, nil
	default:
		return false, engineError("engine has no catalog scope", e)
	}
}

// EngineFromWire parses a wire / registration engine string, fail-closed and case-insensitive:
// "mysql" → MYSQL, "postgres" → POSTGRES, anything else is an error. This is the one gate raw engine
// input passes through; it accepts exactly the two canonical spellings the store persists and the
// proxy registers.
//
// 🔒 INV-A5-7 — exactly two spellings, case-insensitive, no aliases. "postgresql" is REJECTED. The
// admin-create route canonicalizes through it BEFORE storing, because a non-canonical value
// ("Postgres", "psql") would be stored verbatim and then LOCKED by the engine-immutability guard, so
// the datasource could never be adopted by its proxy.
func EngineFromWire(raw string) (Engine, error) {
	e, ok := EngineFromWireOrNull(raw)
	if !ok {
		return EngineUnspecified, fmt.Errorf("%w '%s' (expected 'mysql' or 'postgres')", ErrUnknownEngine, raw)
	}
	return e, nil
}

// EngineFromWireOrNull is [EngineFromWire] but reports ok=false instead of erroring, for validation
// paths that render their own error.
func EngineFromWireOrNull(raw string) (Engine, bool) {
	switch strings.ToLower(raw) {
	case "mysql":
		return EngineMySQL, true
	case "postgres":
		return EnginePostgres, true
	default:
		return EngineUnspecified, false
	}
}

// MarshalEngineJSON encodes an [Engine] as its [WireName] string, so the JSON API shape stays
// exactly "mysql" / "postgres" rather than the proto enum name. It is the port of
// `object EngineWireSerializer : KSerializer<Engine>` (Engines.kt:169-173).
//
// ⚠️ LANGUAGE-FORCED DEVIATION: kotlinx.serialization applies a serializer per FIELD
// (`@Serializable(with = …)`); encoding/json can only dispatch on the field's TYPE, and Engine is an
// alias of a proto enum this package may not add methods to. The codec is therefore a pair of
// functions, and [Datasource] calls them from its own MarshalJSON/UnmarshalJSON. Same wire bytes.
func MarshalEngineJSON(e Engine) ([]byte, error) {
	name, err := WireName(e)
	if err != nil {
		return nil, err
	}
	return json.Marshal(name)
}

// UnmarshalEngineJSON decodes the wire string through [EngineFromWire].
//
// No route ever deserializes a Datasource in the Kotlin (verified in §1), so this half is exercised
// only by EnginesTest case 3.
func UnmarshalEngineJSON(b []byte) (Engine, error) {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return EngineUnspecified, err
	}
	return EngineFromWire(raw)
}
