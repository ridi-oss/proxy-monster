package sqldb

import (
	"github.com/ridi-oss/proxy-monster/analyzer/engines"
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
	// Engine is the engine these queries are for.
	Engine *engines.Engine
	// TargetSettingsProbe reads, in one row of TargetSettingsColumns values, what TargetSettings is built from.
	TargetSettingsProbe   string
	TargetSettingsColumns int
	// TargetSettings is what the target reported, from its TargetSettingsProbe row.
	TargetSettings func(row []*string) (*enginepb.TargetSettings, error)
}
