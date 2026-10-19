package sqldb

import (
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// Queries is the SQL one engine runs through sqldb; a field is a func only where the SQL takes arguments.
type Queries struct {
	// HashSetupProbe locates optional hash support (Postgres pgcrypto) in HashSetupColumns columns; "" means none.
	HashSetupProbe   string
	HashSetupColumns int
	// SchemaHash is the DB-side hash query for one schema and its result width.
	SchemaHash func(schema string, setupRows [][]*string) (sql string, columns int, err error)
	// SchemaHashFromRows validates and decodes the hash query result.
	SchemaHashFromRows func(rows [][]*string) (hash []byte, trusted bool, err error)
	// SchemaColumns returns the seven fragment columns, catalog last, ordered by binary (table, ordinal, column).
	SchemaColumns func(schema string) string
	// SchemaRoutines returns one schema's routine names, one column; they share the fragment's content hash.
	SchemaRoutines func(schema string) string
	// Routines lists every routine as (schema, name).
	Routines string
	// LowerCaseTableNamesProbe yields MySQL's live lower_case_table_names; "" where the engine has none.
	LowerCaseTableNamesProbe string
	// NormalizeColumns folds columns to the analyzer's canonical spelling, by lower_case_table_names for MySQL.
	NormalizeColumns func(lowerCaseTableNames int, columns []*enginepb.Column) []*enginepb.Column
	// FoldFunctionName folds an introspected function name the way the analyzer resolves an unquoted call.
	FoldFunctionName func(name string) string
}
