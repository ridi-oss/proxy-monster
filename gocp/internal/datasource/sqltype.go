package datasource

import "strings"

// SQLTypeFor maps a raw DB type name (Postgres or MySQL `data_type`) to a SQL type name the sqlglot
// schema understands. Port of Datasources.kt:138-147.
//
// 🔒 INV-A5-8 — SQLTypeFor is idempotent on its own outputs. All eight outputs map to themselves.
// This matters because it is applied TWICE on the enforcement path: storePushedCatalog derives
// sql_type from the raw data_type, and decideConnection re-derives sqlType = SQLTypeFor(row.dataType)
// from a fragment column whose dataType may already be normalized. A default arm that mangled an
// already-normalized name would silently widen every column to VARCHAR.
func SQLTypeFor(dataType string) string {
	switch strings.TrimSpace(strings.ToLower(dataType)) {
	case "integer", "int", "int4", "smallint", "int2", "serial", "tinyint", "mediumint":
		return "INTEGER"
	case "bigint", "int8", "bigserial":
		return "BIGINT"
	case "numeric", "decimal", "real", "double precision", "double", "float", "float4", "float8", "money":
		return "DECIMAL"
	case "boolean", "bool":
		return "BOOLEAN"
	case "date", "year":
		return "DATE"
	case "timestamp", "timestamp without time zone", "timestamp with time zone", "timestamptz", "datetime":
		return "TIMESTAMP"
	case "time", "time without time zone", "time with time zone":
		return "TIME"
	default:
		return "VARCHAR" // varchar, text, char, uuid, json, jsonb, bytea, blob, enum, set, ...
	}
}
