// Package db is the DUMB per-database adapter set: the few facts engine.QueryEngine needs to gather
// context (namespace probe SQL, temp-overlay support), plus each dialect's NormalizeColumns
// specialization (analyzer/probe.NormalizeRelation — Go-to-Go, no SQL driver, no cgo). No enforcement
// logic, no state machine.
package db

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/ridi-oss/proxy-monster/analyzer/probe"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// MySqlDb is the engine.Db adapter for MySQL.
type MySqlDb struct{}

// NamespaceProbeSQL yields the connection's current database.
func (MySqlDb) NamespaceProbeSQL() string { return "SELECT DATABASE()" }

func (MySqlDb) SupportsTempOverlay() bool   { return false }
func (MySqlDb) TempColumnsProbeSQL() string { return "" }
func (MySqlDb) HashSetupProbeSQL() string   { return "" }
func (MySqlDb) HashSetupColumns() int       { return 0 }

// LowerCaseTableNamesProbeSQL yields the connection's live lower_case_table_names mode.
func (MySqlDb) LowerCaseTableNamesProbeSQL() string { return "SELECT @@lower_case_table_names" }

// NormalizeColumns folds each column to analyzer/probe's canonical MySQL spelling — the SAME
// normalization introspect's bulk catalog push uses, so the schema-fragment pool this feeds
// (goproxy/engine.Refetcher) and the persisted catalog never disagree on spelling.
//
// Folds through probe.NormalizeMySQLColumns, which memoizes the per-(schema, table) identifier parse.
// A schema fragment repeats one schema and each table name once per column, so the per-row path
// re-parsed the same two identifiers thousands of times: ~13s of CPU on a 4,390-column schema, enough
// to push a catalog refetch past the control plane's run-open deadline and fail every query on the
// datasource. The batched fold is O(distinct tables) parses instead of O(columns).
func (MySqlDb) NormalizeColumns(lowerCaseTableNames int, columns []*pb.Column) []*pb.Column {
	schemas := make([]string, len(columns))
	tables := make([]string, len(columns))
	names := make([]string, len(columns))
	for i, c := range columns {
		schemas[i], tables[i], names[i] = c.GetSchema(), c.GetTable(), c.GetColumn()
	}
	outSchemas, outTables, outColumns := probe.NormalizeMySQLColumns(lowerCaseTableNames, schemas, tables, names)
	out := make([]*pb.Column, len(columns))
	for i, c := range columns {
		out[i] = &pb.Column{
			Schema: outSchemas[i], Table: outTables[i], Column: outColumns[i],
			DataType: c.GetDataType(), Ordinal: c.GetOrdinal(), Nullable: c.GetNullable(),
		}
	}
	return out
}

// mysqlSchemaFilter renders the WHERE-clause comparison for schema (a possibly-canonical spelling —
// see analyzer/probe.NormalizeRelation) against the live TABLE_SCHEMA. Mode 0 never folds schema names
// (canonical == raw) and mode 1 folds AT THE STORAGE LAYER itself (information_schema already reports
// lowercase), so both compare byte-exact. Mode 2 is the one case canonical (folded) can diverge from
// the live stored spelling (case preserved in storage, looked up case-insensitively) — MySQL guarantees
// no two mode-2 schemas differ only by case, so folding the comparison introduces no ambiguity there.
// The hex literal avoids every sql_mode and escaping ambiguity; binary comparisons/order preserve byte
// identity everywhere this ISN'T the mode-2 fold.
func mysqlSchemaFilter(column, schema string) string {
	literal := hex.EncodeToString([]byte(schema))
	return fmt.Sprintf(
		`(CASE WHEN @@lower_case_table_names = 2 THEN LOWER(CAST(%s AS BINARY)) ELSE CAST(%s AS BINARY) END) = X'%s'`,
		column, column, literal,
	)
}

// SchemaColumnsSQL returns one schema fragment without excluding system schemas.
func (MySqlDb) SchemaColumnsSQL(schema string) string {
	return fmt.Sprintf(`SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION, IS_NULLABLE
FROM information_schema.COLUMNS
WHERE %s
ORDER BY CAST(TABLE_NAME AS BINARY), ORDINAL_POSITION, CAST(COLUMN_NAME AS BINARY)`, mysqlSchemaFilter("TABLE_SCHEMA", schema))
}

// SchemaHashSQL hashes the exact six-field fragment serialization and returns hash, aggregate length,
// and row count. SET_VAR scopes the large GROUP_CONCAT bound to this one statement.
func (MySqlDb) SchemaHashSQL(schema string, _ [][]*string) (string, int, error) {
	return fmt.Sprintf(`SELECT /*+ SET_VAR(group_concat_max_len=33554432) */
  SHA2(COALESCE(GROUP_CONCAT(row_digest ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY) SEPARATOR ''), ''), 256),
  COALESCE(LENGTH(GROUP_CONCAT(row_digest ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY) SEPARATOR '')), 0),
  COUNT(*)
FROM (
  SELECT tn, op, cn, SHA2(CONCAT(
    LENGTH(CAST(sn AS BINARY)), ':', CAST(sn AS BINARY),
    LENGTH(CAST(tn AS BINARY)), ':', CAST(tn AS BINARY),
    LENGTH(CAST(cn AS BINARY)), ':', CAST(cn AS BINARY),
    LENGTH(CAST(dt AS BINARY)), ':', CAST(dt AS BINARY),
    LENGTH(CAST(op AS CHAR CHARACTER SET ascii)), ':', CAST(op AS CHAR CHARACTER SET ascii),
    LENGTH(CAST(nl AS BINARY)), ':', CAST(nl AS BINARY)
  ), 256) AS row_digest
  FROM (
    SELECT TABLE_SCHEMA AS sn, TABLE_NAME AS tn, COLUMN_NAME AS cn, DATA_TYPE AS dt,
      ORDINAL_POSITION AS op, IS_NULLABLE AS nl
    FROM information_schema.COLUMNS
    WHERE %s
  ) AS fragment_rows
) AS row_hashes`, mysqlSchemaFilter("TABLE_SCHEMA", schema)), 3, nil
}

func (MySqlDb) SchemaHashFromRows(rows [][]*string) ([]byte, bool, error) {
	if len(rows) != 1 || len(rows[0]) != 3 || rows[0][0] == nil || rows[0][1] == nil || rows[0][2] == nil {
		return nil, false, nil
	}
	hash, err := decodeHash(*rows[0][0], 64)
	if err != nil {
		return nil, false, nil
	}
	produced, err := strconv.ParseUint(*rows[0][1], 10, 64)
	if err != nil {
		return nil, false, nil
	}
	count, err := strconv.ParseUint(*rows[0][2], 10, 64)
	if err != nil || count > ^uint64(0)/64 || produced != 64*count {
		return nil, false, nil
	}
	return hash, true, nil
}

// PgDb is the engine.Db adapter for Postgres.
type PgDb struct{}

// NamespaceProbeSQL yields one JSON observation containing the connection's effective search_path,
// visible non-pg_catalog overloads of polymorphic builtins, and pg_catalog.xid type visibility.
func (PgDb) NamespaceProbeSQL() string {
	return `SELECT pg_catalog.json_build_object(
  'search_path', pg_catalog.current_schemas(true),
  'shadowed_functions', COALESCE((
    SELECT pg_catalog.json_agg(visible.proname ORDER BY visible.proname)
    FROM (
      SELECT DISTINCT p.proname
      FROM pg_catalog.pg_proc AS p
      WHERE p.proname OPERATOR(pg_catalog.=) 'unnest'::pg_catalog.name
        AND p.pronamespace OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.regnamespace
        AND pg_catalog.pg_function_is_visible(p.oid)
    ) AS visible
  ), '[]'::pg_catalog.json),
  'pg_catalog_xid_visible', pg_catalog.pg_type_is_visible(
    'pg_catalog.xid'::pg_catalog.regtype::pg_catalog.oid
  )
)::pg_catalog.text`
}

func (PgDb) SupportsTempOverlay() bool { return true }

// TempColumnsProbeSQL is the session-temp overlay probe.
func (PgDb) TempColumnsProbeSQL() string {
	return `SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnum
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname LIKE 'pg_temp%' AND pg_catalog.pg_table_is_visible(c.oid)
  AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum`
}

func (PgDb) HashSetupProbeSQL() string {
	return `SELECT n.nspname
FROM pg_catalog.pg_extension e
JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
WHERE e.extname = 'pgcrypto'`
}
func (PgDb) HashSetupColumns() int { return 1 }

// LowerCaseTableNamesProbeSQL: Postgres has no such concept — NormalizeColumns is an identity function
// regardless of the mode argument.
func (PgDb) LowerCaseTableNamesProbeSQL() string { return "" }

// NormalizeColumns is an identity function: Postgres never folds — a quoted-vs-unquoted identifier
// pair is genuinely two distinct columns, and introspection already reports each one's real, resolved
// spelling (analyzer/probe.NormalizeRelation's contract for any non-MySQL dialect).
func (PgDb) NormalizeColumns(_ int, columns []*pb.Column) []*pb.Column { return columns }

func (PgDb) SchemaColumnsSQL(schema string) string {
	return fmt.Sprintf(`SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
FROM information_schema.columns
WHERE table_schema = pg_catalog.convert_from('%s'::pg_catalog.bytea, 'UTF8')
ORDER BY table_name::pg_catalog.text COLLATE "C", ordinal_position, column_name::pg_catalog.text COLLATE "C"`, pgByteaLiteral(schema))
}

func (PgDb) SchemaHashSQL(schema string, setupRows [][]*string) (string, int, error) {
	aggregate := `COALESCE(pg_catalog.string_agg(row_blob, '' ORDER BY tn::pg_catalog.text COLLATE "C", op, cn::pg_catalog.text COLLATE "C"), '')`
	hashExpr := "pg_catalog.md5(" + aggregate + ")"
	if len(setupRows) == 1 && len(setupRows[0]) == 1 && setupRows[0][0] != nil && *setupRows[0][0] != "" {
		hashExpr = fmt.Sprintf(`pg_catalog.encode(%s.digest(pg_catalog.convert_to(%s, 'UTF8'), 'sha256'), 'hex')`, quotePgIdentifier(*setupRows[0][0]), aggregate)
	}
	return fmt.Sprintf(`SELECT %s, pg_catalog.count(*), pg_catalog.count(*) FILTER (WHERE row_blob IS NULL)
FROM (
  SELECT tn, op, cn, CASE WHEN sn IS NULL OR tn IS NULL OR cn IS NULL OR dt IS NULL OR op IS NULL OR nl IS NULL
  THEN NULL ELSE pg_catalog.concat(
    pg_catalog.octet_length(sn::pg_catalog.text), ':', sn,
    pg_catalog.octet_length(tn::pg_catalog.text), ':', tn,
    pg_catalog.octet_length(cn::pg_catalog.text), ':', cn,
    pg_catalog.octet_length(dt::pg_catalog.text), ':', dt,
    pg_catalog.octet_length(op::pg_catalog.text), ':', op,
    pg_catalog.octet_length(nl::pg_catalog.text), ':', nl
  ) END AS row_blob
  FROM (
    SELECT table_schema AS sn, table_name AS tn, column_name AS cn, data_type AS dt,
      ordinal_position AS op, is_nullable AS nl
    FROM information_schema.columns
    WHERE table_schema = pg_catalog.convert_from('%s'::pg_catalog.bytea, 'UTF8')
  ) AS fragment_rows
) AS serialized_rows`, hashExpr, pgByteaLiteral(schema)), 3, nil
}

func (PgDb) SchemaHashFromRows(rows [][]*string) ([]byte, bool, error) {
	if len(rows) != 1 || len(rows[0]) != 3 || rows[0][0] == nil || rows[0][1] == nil || rows[0][2] == nil {
		return nil, false, nil
	}
	if _, err := strconv.ParseUint(*rows[0][1], 10, 64); err != nil {
		return nil, false, nil
	}
	nulls, err := strconv.ParseUint(*rows[0][2], 10, 64)
	if err != nil || nulls != 0 {
		return nil, false, nil
	}
	hashText := *rows[0][0]
	if len(hashText) != 64 && len(hashText) != 32 {
		return nil, false, nil
	}
	hash, err := decodeHash(hashText, len(hashText))
	if err != nil {
		return nil, false, nil
	}
	return hash, true, nil
}

func decodeHash(value string, wantHexLen int) ([]byte, error) {
	if len(value) != wantHexLen {
		return nil, fmt.Errorf("hash has %d hex characters, want %d", len(value), wantHexLen)
	}
	return hex.DecodeString(value)
}

func pgByteaLiteral(value string) string {
	return `\x` + hex.EncodeToString([]byte(value))
}

func quotePgIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
