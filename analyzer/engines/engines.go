// Package engines is the one list of target engines and the static facts every Go module shares.
package engines

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// Engine is one target engine.
type Engine struct {
	// WireName is the persistence, registration, and JSON name.
	WireName string
	Proto    pb.Engine
	// DefaultSchemaSettable reports whether the engine has a statement that sets a session's default schema.
	DefaultSchemaSettable bool
	DefaultProxyPort      int
	DefaultTargetPort     int
	// BuiltinSchema holds the engine's builtin functions and types; "" when it has none.
	BuiltinSchema string

	numberedPlaceholders bool
	foldCase             bool
	systemSchemas        []string
	tempSchema           string
	sessionPrefixes      []string
	catalogName          func(dbName string) string
}

var (
	MySQL = &Engine{
		WireName: "mysql", Proto: pb.Engine_MYSQL, DefaultSchemaSettable: true,
		DefaultProxyPort: 6033, DefaultTargetPort: 3307, foldCase: true,
		systemSchemas: []string{"information_schema", "mysql", "performance_schema", "sys"},
		catalogName:   func(string) string { return "def" },
	}
	Postgres = &Engine{
		WireName: "postgres", Proto: pb.Engine_POSTGRES, DefaultSchemaSettable: true,
		DefaultProxyPort: 6432, DefaultTargetPort: 5433, BuiltinSchema: "pg_catalog", numberedPlaceholders: true,
		systemSchemas: []string{"pg_catalog", "information_schema"},
		tempSchema:    "pg_temp", sessionPrefixes: []string{"pg_temp_", "pg_toast"},
		catalogName: func(db string) string { return db },
	}
	Athena = &Engine{
		WireName: "athena", Proto: pb.Engine_ATHENA,
		DefaultProxyPort: 6443, DefaultTargetPort: 443, foldCase: true,
		systemSchemas: []string{"information_schema"},
		catalogName:   strings.ToLower,
	}
	// All is every engine, MySQL first.
	All = []*Engine{MySQL, Postgres, Athena}
)

// Parse maps an exact wire name to its engine; anything else, a different case included, is an error.
func Parse(wireName string) (*Engine, error) {
	if i := slices.IndexFunc(All, func(e *Engine) bool { return e.WireName == wireName }); i >= 0 {
		return All[i], nil
	}
	return nil, fmt.Errorf("unsupported engine %q (expected mysql, postgres, or athena)", wireName)
}

// ByProto is the engine a proto Engine denotes; ENGINE_UNSPECIFIED and unknown values are not one.
func ByProto(p pb.Engine) (*Engine, bool) {
	i := slices.IndexFunc(All, func(e *Engine) bool { return e.Proto == p })
	if i < 0 {
		return nil, false
	}
	return All[i], true
}

// Placeholder is the nth (1-based) bind-parameter placeholder: "?" or "$n".
func (e *Engine) Placeholder(n int) string {
	if e.numberedPlaceholders {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// IsSystemSchema is the engine's fixed system schemas plus its per-session ones (Postgres pg_temp_*, pg_toast).
func (e *Engine) IsSystemSchema(schema string) bool {
	if e.foldCase {
		schema = strings.ToLower(schema)
	}
	if slices.Contains(e.systemSchemas, schema) {
		return true
	}
	return slices.ContainsFunc(e.sessionPrefixes, func(p string) bool { return strings.HasPrefix(schema, p) })
}

// IsTempSchema reports whether an already-folded schema name is the session temp schema (pg_temp, pg_temp_3).
func (e *Engine) IsTempSchema(schema string) bool {
	return e.tempSchema != "" && (schema == e.tempSchema || strings.HasPrefix(schema, e.tempSchema+"_"))
}

// CatalogName is the analyzer catalog segment for a datasource registered on database dbName.
func (e *Engine) CatalogName(dbName string) string { return e.catalogName(dbName) }
