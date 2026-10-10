// Package engine holds what the control plane knows about each target engine, so no call site branches
// on the engine name. It mirrors the Kotlin EngineDefinition objects.
package engine

import (
	"slices"
	"strings"
)

// Requests is which authorizer decides an engine's operations that carry no SQL (AuthorizeRequest).
type Requests int

const (
	// MetadataRequests admits catalog and table-metadata reads under datasource.connect.
	MetadataRequests Requests = iota
	// AthenaRequests admits Athena API calls described by an AthenaNativeDescriptor.
	AthenaRequests
)

// Definition is one engine.
type Definition struct {
	// WireName is the persistence, registration, and JSON name: "mysql", "postgres", "athena".
	WireName string
	// DefaultSchemaSettable reports whether the engine has a statement that sets a session's default schema.
	DefaultSchemaSettable bool
	Requests              Requests

	systemSchemas   []string
	foldCase        bool
	sessionPrefixes []string
	catalogName     func(dbName string) string
}

var definitions = []*Definition{
	{
		WireName: "mysql", DefaultSchemaSettable: true, foldCase: true,
		systemSchemas: []string{"information_schema", "mysql", "performance_schema", "sys"},
		catalogName:   func(string) string { return "def" },
	},
	{
		WireName: "postgres", DefaultSchemaSettable: true,
		systemSchemas:   []string{"pg_catalog", "information_schema"},
		sessionPrefixes: []string{"pg_temp_", "pg_toast"},
		catalogName:     func(db string) string { return db },
	},
	{
		WireName: "athena", foldCase: true, Requests: AthenaRequests,
		systemSchemas: []string{"information_schema"},
		catalogName:   strings.ToLower,
	},
}

// ByWireName is the engine a stored or requested name denotes, matched case-insensitively.
func ByWireName(name string) (*Definition, bool) {
	name = strings.ToLower(name)
	i := slices.IndexFunc(definitions, func(d *Definition) bool { return d.WireName == name })
	if i < 0 {
		return nil, false
	}
	return definitions[i], true
}

// IsSystemSchema is the engine's fixed system schemas plus its per-session ones (Postgres pg_temp_*, pg_toast).
func (d *Definition) IsSystemSchema(schema string) bool {
	if d.foldCase {
		schema = strings.ToLower(schema)
	}
	if slices.Contains(d.systemSchemas, schema) {
		return true
	}
	return slices.ContainsFunc(d.sessionPrefixes, func(p string) bool { return strings.HasPrefix(schema, p) })
}

// CatalogName is the analyzer catalog segment for a datasource registered on database dbName.
func (d *Definition) CatalogName(dbName string) string { return d.catalogName(dbName) }
