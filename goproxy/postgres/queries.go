// Package db is the DUMB per-database adapter set: the few facts spi.Authorizer needs to gather
// context (namespace probe SQL, temp-overlay support), plus each dialect's NormalizeColumns
// specialization (analyzer/engines.NormalizeRelation — Go-to-Go, no SQL driver, no cgo). No enforcement
// logic, no state machine.
package postgres

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/sqlglot-go/dialects"
)

// TargetSQL is PostgreSQL's relay.Db.
type TargetSQL struct{}

// NamespaceProbeSQL yields one JSON observation containing the connection's effective search_path,
// visible non-pg_catalog overloads of polymorphic builtins, and pg_catalog.xid type visibility.
func (TargetSQL) NamespaceProbeSQL() string {
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

func (TargetSQL) FoldFunctionName(name string) string {
	return dialects.Postgres().FoldIdentifierName(name, false)
}

func (TargetSQL) SupportsTempOverlay() bool { return true }

// TempColumnsProbeSQL is the session-temp overlay probe.
func (TargetSQL) TempColumnsProbeSQL() string {
	return `SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnum, pg_catalog.current_database()
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname LIKE 'pg_temp%' AND pg_catalog.pg_table_is_visible(c.oid)
  AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum`
}

func (TargetSQL) HashSetupProbeSQL() string {
	return `SELECT n.nspname
FROM pg_catalog.pg_extension e
JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
WHERE e.extname = 'pgcrypto'`
}
func (TargetSQL) HashSetupColumns() int { return 1 }

// LowerCaseTableNamesProbeSQL: Postgres has no such concept — NormalizeColumns is an identity function
// regardless of the mode argument.
func (TargetSQL) LowerCaseTableNamesProbeSQL() string { return "" }

// NormalizeColumns is an identity function: Postgres never folds — a quoted-vs-unquoted identifier
// pair is genuinely two distinct columns, and introspection already reports each one's real, resolved
// spelling (analyzer/engines.NormalizeRelation's contract for any non-MySQL dialect).
func (TargetSQL) NormalizeColumns(_ int, columns []*analyzerpb.Column) []*analyzerpb.Column {
	return columns
}

func (TargetSQL) RoutinesSQL() string {
	return `SELECT n.nspname, p.proname FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace`
}

func (TargetSQL) SchemaRoutinesSQL(schema string) string {
	return fmt.Sprintf(`SELECT p.proname FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = pg_catalog.convert_from('%s'::pg_catalog.bytea, 'UTF8')
ORDER BY p.proname::pg_catalog.text COLLATE "C"`, pgByteaLiteral(schema))
}

func (TargetSQL) SchemaColumnsSQL(schema string) string {
	return fmt.Sprintf(`SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable, table_catalog
FROM information_schema.columns
WHERE table_schema = pg_catalog.convert_from('%s'::pg_catalog.bytea, 'UTF8')
ORDER BY table_name::pg_catalog.text COLLATE "C", ordinal_position, column_name::pg_catalog.text COLLATE "C"`, pgByteaLiteral(schema))
}

func (TargetSQL) SchemaHashSQL(schema string, setupRows [][]*string) (string, int, error) {
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
    UNION ALL
    SELECT n.nspname, '', p.proname, 'function', 0, 'NO'
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = pg_catalog.convert_from('%s'::pg_catalog.bytea, 'UTF8')
  ) AS fragment_rows
) AS serialized_rows`, hashExpr, pgByteaLiteral(schema), pgByteaLiteral(schema)), 3, nil
}

func (TargetSQL) SchemaHashFromRows(rows [][]*string) ([]byte, bool, error) {
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
