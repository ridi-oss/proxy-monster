package mysql

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
	"github.com/ridi-oss/sqlglot-go/dialects"
	"google.golang.org/protobuf/proto"
)

// Queries is the SQL the shared database/sql code runs on a MySQL target.
var Queries = sqldb.Queries{
	Routines:                 routinesSQL,
	SchemaRoutines:           schemaRoutinesSQL,
	SchemaColumns:            schemaColumnsSQL,
	SchemaHash:               schemaHashSQL,
	SchemaHashFromRows:       schemaHashFromRows,
	LowerCaseTableNamesProbe: "SELECT @@lower_case_table_names",
	NormalizeColumns:         normalizeColumns,
	// MySQL routine and native names are case-insensitive regardless of lower_case_table_names.
	FoldFunctionName: dialects.MySQLLower,
}

// normalizeColumns folds each column to analyzer/engines's canonical MySQL spelling — the SAME
// normalization introspect's bulk catalog push uses, so the schema-fragment pool this feeds
// (goproxy/sqldb.Refetcher) and the persisted catalog never disagree on spelling.
//
// Folds through engines.NormalizeMySQLColumns, which memoizes the per-(schema, table) identifier parse.
// A schema fragment repeats one schema and each table name once per column, so the per-row path
// re-parsed the same two identifiers thousands of times: ~13s of CPU on a 4,390-column schema, enough
// to push a catalog refetch past the control plane's run-open deadline and fail every query on the
// datasource. The batched fold is O(distinct tables) parses instead of O(columns).
func normalizeColumns(lowerCaseTableNames int, columns []*analyzerpb.Column) []*analyzerpb.Column {
	schemas := make([]string, len(columns))
	tables := make([]string, len(columns))
	names := make([]string, len(columns))
	for i, c := range columns {
		schemas[i], tables[i], names[i] = c.GetSchema(), c.GetTable(), c.GetColumn()
	}
	outSchemas, outTables, outColumns := engines.NormalizeMySQLColumns(lowerCaseTableNames, schemas, tables, names)
	out := make([]*analyzerpb.Column, len(columns))
	for i, c := range columns {
		out[i] = proto.Clone(c).(*analyzerpb.Column)
		out[i].Schema, out[i].Table, out[i].Column = outSchemas[i], outTables[i], outColumns[i]
	}
	return out
}

// mysqlSchemaFilter renders the WHERE-clause comparison for schema (a possibly-canonical spelling —
// see analyzer/engines.NormalizeRelation) against the live TABLE_SCHEMA. Mode 0 never folds schema names
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

// schemaColumnsSQL returns one schema fragment without excluding system schemas.
// routinesSQL lists (schema, name) for every stored function; mysql.func loadables have no schema and
// are listed under "mysql".
const routinesSQL = `SELECT ROUTINE_SCHEMA, ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION'
UNION ALL SELECT 'mysql', name FROM mysql.func`

// Ordered by binary name: the control plane compares pushed lists positionally.
func schemaRoutinesSQL(schema string) string {
	routines := fmt.Sprintf(`SELECT ROUTINE_NAME AS name FROM information_schema.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION' AND %s`, mysqlSchemaFilter("ROUTINE_SCHEMA", schema))
	if schema == "mysql" {
		routines += `
UNION ALL SELECT name FROM mysql.func`
	}
	return routines + `
ORDER BY CAST(name AS BINARY)`
}

func schemaColumnsSQL(schema string) string {
	return fmt.Sprintf(`SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION, IS_NULLABLE, TABLE_CATALOG
FROM information_schema.COLUMNS
WHERE %s
ORDER BY CAST(TABLE_NAME AS BINARY), ORDINAL_POSITION, CAST(COLUMN_NAME AS BINARY)`, mysqlSchemaFilter("TABLE_SCHEMA", schema))
}

// schemaHashSQL hashes columns and routines as one row set; a routine is the row
// (app, <empty table>, add_tax, function, 0, NO), which no real column row can equal. Returns hash,
// aggregate length, row count. SET_VAR raises the GROUP_CONCAT limit for this statement only.
func schemaHashSQL(schema string, _ [][]*string) (string, int, error) {
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
    UNION ALL
    SELECT ROUTINE_SCHEMA, '', ROUTINE_NAME, 'function', 0, 'NO'
    FROM information_schema.ROUTINES
    WHERE ROUTINE_TYPE = 'FUNCTION' AND %s%s
  ) AS fragment_rows
) AS row_hashes`, mysqlSchemaFilter("TABLE_SCHEMA", schema), mysqlSchemaFilter("ROUTINE_SCHEMA", schema), mysqlLoadableHashRows(schema)), 3, nil
}

func mysqlLoadableHashRows(schema string) string {
	if schema != "mysql" {
		return ""
	}
	return `
    UNION ALL
    SELECT 'mysql', '', name, 'function', 0, 'NO' FROM mysql.func`
}

func schemaHashFromRows(rows [][]*string) ([]byte, bool, error) {
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

func decodeHash(value string, wantHexLen int) ([]byte, error) {
	if len(value) != wantHexLen {
		return nil, fmt.Errorf("hash has %d hex characters, want %d", len(value), wantHexLen)
	}
	return hex.DecodeString(value)
}
