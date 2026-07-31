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
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
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

// CatalogVisibilitySQL reports whether this connection sees every schema on the server.
// information_schema.COLUMNS is privilege-filtered per row, so an account with only per-schema grants
// silently reads a subset — and a subset presented as a whole-server scan tells the manager every
// unseen schema was dropped. A global (*.*) SELECT grant is what removes that filter.
//
// Two things make "does this account hold global SELECT" more than a lookup of its own grants, and
// both were measured on live MySQL 8.0 and 8.4 rather than reasoned about:
//
//   - Partial revokes. With @@partial_revokes = ON, `GRANT SELECT ON *.*` can coexist with
//     `REVOKE SELECT ON hidden.*`: the global grant row is still there while information_schema hides
//     `hidden` entirely. The per-account restriction list lives in mysql.user.User_attributes, which a
//     least-privilege service account cannot read — so the only fail-closed reading available to every
//     account is the server-wide switch. ON without any restriction for this account merely costs
//     completeness, and the switch cannot be turned off while any restriction exists (error 3896), so
//     it is exactly the condition under which global SELECT stops implying a complete view.
//   - Roles. A service account typically holds nothing directly and inherits global SELECT from an
//     active role, whose USER_PRIVILEGES rows are keyed by the ROLE's name, not the account's. Matching
//     only CURRENT_USER() reports "incomplete" for an account that does see every schema, permanently
//     suppressing dropped-schema reconciliation. ENABLED_ROLES lists the roles active in this session
//     (a role granted but not activated confers nothing and must not count), and the recursive step
//     walks APPLICABLE_ROLES for roles those roles hold — MySQL does not flatten that chain, and it
//     cannot cycle (error 4027 refuses a looping GRANT).
//
// GRANTEE is stored pre-quoted ('user'@'host'), so both comparisons rebuild that spelling rather than
// matching raw.
func (MySqlDb) CatalogVisibilitySQL() string {
	return `WITH RECURSIVE active_role (name, host) AS (
  SELECT ROLE_NAME, ROLE_HOST FROM information_schema.ENABLED_ROLES
  UNION
  SELECT a.ROLE_NAME, a.ROLE_HOST
  FROM information_schema.APPLICABLE_ROLES a
  JOIN active_role r ON a.GRANTEE = r.name AND a.GRANTEE_HOST = r.host
)
SELECT @@partial_revokes = 0 AND EXISTS(
  SELECT 1 FROM information_schema.USER_PRIVILEGES
  WHERE PRIVILEGE_TYPE = 'SELECT'
    AND (GRANTEE = CONCAT(QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)), '@', QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', -1)))
      OR GRANTEE IN (SELECT CONCAT(QUOTE(name), '@', QUOTE(host)) FROM active_role))
)`
}

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

// mysqlHashClockAndIdentity is the clock and server identity every MySQL hash statement reads beside
// its digest, so the reading timestamps the measurement itself.
//
// SYSDATE(6), never NOW(6): NOW(6) returns the session's `SET timestamp` value, and hash probes run on
// the client's own backend connection — so a session could stamp its refetches with an arbitrary future
// clock, and the manager's strictly-newer ordering rule would then reject every later genuine
// observation, freezing shared state on the poisoned version. SYSDATE(6) reads the real clock at
// evaluation time and ignores `SET timestamp`. UNIX_TIMESTAMP yields an epoch, so `SET time_zone`
// does not move it either.
//
// `SYSDATE(6) <> NOW(6)` is the guard, not decoration: a server started with --sysdate-is-now aliases
// SYSDATE back to NOW, which silently restores the very poisoning SYSDATE was chosen to prevent (the
// option exposes no variable to probe — it is only observable by the two clocks agreeing). The two
// differ by the statement's own elapsed time on an unaliased server, and the hash statement scans
// information_schema, so the difference is microseconds of real work rather than a race. Reporting 0
// (unavailable) on the aliased server costs only recency: the manager treats a clockless observation as
// unordered rather than trusting a client-movable one.
const mysqlHashClockAndIdentity = `CASE WHEN SYSDATE(6) <> NOW(6)
    THEN CAST(ROUND(UNIX_TIMESTAMP(SYSDATE(6)) * 1000000) AS UNSIGNED) ELSE 0 END,
  @@server_uuid`

// SchemaHashSQL hashes the exact six-field fragment serialization and returns hash, aggregate length,
// row count, database clock, and backend identity. SET_VAR scopes the large GROUP_CONCAT bound to this
// one statement.
func (MySqlDb) SchemaHashSQL(schema string, _ [][]*string) (string, int, error) {
	return fmt.Sprintf(`SELECT /*+ SET_VAR(group_concat_max_len=33554432) */
  SHA2(COALESCE(GROUP_CONCAT(row_digest ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY) SEPARATOR ''), ''), 256),
  COALESCE(LENGTH(GROUP_CONCAT(row_digest ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY) SEPARATOR '')), 0),
  COUNT(*),
  %s
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
) AS row_hashes`, mysqlHashClockAndIdentity, mysqlSchemaFilter("TABLE_SCHEMA", schema)), 5, nil
}

func (MySqlDb) SchemaHashFromRows(rows [][]*string) (engine.HashObservation, error) {
	if len(rows) != 1 || len(rows[0]) != 5 {
		return engine.HashObservation{}, nil
	}
	return mysqlHashObservation(rows[0][0], rows[0][1], rows[0][2], rows[0][3], rows[0][4]), nil
}

// ServerHashSQL measures every schema on the server in one grouped statement. Grouping is on the
// BINARY cast of the schema name, not the bare column: under a case-insensitive collation two
// byte-distinct schemas would merge into one group and report a hash for neither.
func (MySqlDb) ServerHashSQL(_ [][]*string) (string, int, error) {
	return fmt.Sprintf(`SELECT /*+ SET_VAR(group_concat_max_len=33554432) */
  sng,
  SHA2(COALESCE(GROUP_CONCAT(row_digest ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY) SEPARATOR ''), ''), 256),
  COALESCE(LENGTH(GROUP_CONCAT(row_digest ORDER BY CAST(tn AS BINARY), op, CAST(cn AS BINARY) SEPARATOR '')), 0),
  COUNT(*),
  %s
FROM (
  SELECT CAST(sn AS BINARY) AS sng, tn, op, cn, SHA2(CONCAT(
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
  ) AS fragment_rows
) AS row_hashes
GROUP BY sng`, mysqlHashClockAndIdentity), 6, nil
}

func (MySqlDb) ServerHashFromRows(rows [][]*string) ([]engine.SchemaHashObservation, error) {
	observations := make([]engine.SchemaHashObservation, 0, len(rows))
	for i, row := range rows {
		if len(row) != 6 {
			return nil, fmt.Errorf("server hash row %d has %d columns, want 6", i, len(row))
		}
		if row[0] == nil {
			return nil, fmt.Errorf("server hash row %d schema is NULL", i)
		}
		observations = append(observations, engine.SchemaHashObservation{
			Schema:          *row[0],
			HashObservation: mysqlHashObservation(row[1], row[2], row[3], row[4], row[5]),
		})
	}
	return observations, nil
}

func mysqlHashObservation(hashText, producedText, countText, clockText, backendID *string) engine.HashObservation {
	observation := engine.HashObservation{}
	if hashText != nil {
		observation.Hash = decodeHash(*hashText, 64)
	}
	if clockText != nil {
		observation.DbClockMicros, _ = strconv.ParseInt(*clockText, 10, 64)
	}
	if backendID != nil && validMySQLBackendID(*backendID) {
		observation.BackendID = *backendID
	}
	if observation.Hash == nil || producedText == nil || countText == nil {
		return observation
	}
	produced, producedErr := strconv.ParseUint(*producedText, 10, 64)
	count, countErr := strconv.ParseUint(*countText, 10, 64)
	observation.Trusted = producedErr == nil && countErr == nil && count <= ^uint64(0)/64 && produced == 64*count
	return observation
}

// validMySQLBackendID accepts only a well-formed @@server_uuid. The id defines the clock-comparability
// domain, so a malformed reading must degrade to "unavailable" (no comparison) rather than become a
// domain of its own that two measurements could spuriously agree on.
func validMySQLBackendID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// PgDb is the engine.Db adapter for Postgres.
type PgDb struct{}

// NamespaceProbeSQL yields the connection's effective search_path schemas, QUALIFIED — distinct from
// introspect.Run's unqualified namespace probe used at a different call site.
func (PgDb) NamespaceProbeSQL() string {
	return "SELECT pg_catalog.unnest(pg_catalog.current_schemas(true))"
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

// HashSetupProbeSQL gathers both facts the hash statement cannot ask for itself: the schema pgcrypto
// lives in, and whether this role may read the backend identity.
//
// The identity privilege MUST be resolved here rather than by an inline guard. PostgreSQL checks
// function EXECUTE at plan time, so a CASE whose true branch selects from pg_control_system() still
// aborts the whole statement with "permission denied for function pg_control_system" on a cluster that
// revoked it from PUBLIC — the false branch is never reached, turning an unavailable identity into a
// total loss of every schema hash. Answering the privilege question in this separate best-effort
// statement keeps the degradation where it belongs: an empty backend_id and a still-valid hash.
func (PgDb) HashSetupProbeSQL() string {
	return `SELECT
  (SELECT n.nspname
   FROM pg_catalog.pg_extension e
   JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
   WHERE e.extname = 'pgcrypto'),
  pg_catalog.has_function_privilege('pg_catalog.pg_control_system()', 'EXECUTE')::pg_catalog.int4`
}
func (PgDb) HashSetupColumns() int { return 2 }

// CatalogVisibilitySQL reports whether this connection sees every schema on the server.
// information_schema.columns shows only objects the caller has some privilege on, so a least-privilege
// service account reads a strict subset — which, pushed as a whole-server scan, tells the manager the
// schemas it cannot see were dropped. Superuser and pg_read_all_data are the memberships that lift the
// filter entirely.
func (PgDb) CatalogVisibilitySQL() string {
	return `SELECT (pg_catalog.current_setting('is_superuser') = 'on'
  OR pg_catalog.pg_has_role(CURRENT_USER, 'pg_read_all_data', 'USAGE'))::pg_catalog.int4`
}

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

// pgSetupCell reads one column of the single HashSetupProbeSQL row, or nil when the probe returned
// nothing usable — the probe is best-effort, so every reader must tolerate its absence.
func pgSetupCell(setupRows [][]*string, column int) *string {
	if len(setupRows) != 1 || len(setupRows[0]) <= column {
		return nil
	}
	return setupRows[0][column]
}

func pgHashExpression(setupRows [][]*string, aggregate string) string {
	if schema := pgSetupCell(setupRows, 0); schema != nil && *schema != "" {
		return fmt.Sprintf(`pg_catalog.encode(%s.digest(pg_catalog.convert_to(%s, 'UTF8'), 'sha256'), 'hex')`, quotePgIdentifier(*schema), aggregate)
	}
	return "pg_catalog.md5(" + aggregate + ")"
}

// pgHashClockAndIdentity emits the clock plus either the real identity read or a literal empty string.
// The privilege was resolved by HashSetupProbeSQL, so an unprivileged role never names
// pg_control_system() here — see HashSetupProbeSQL for why an inline guard cannot work.
//
// clock_timestamp(), never statement_timestamp(): the latter is frozen at the transaction's start, so
// two measurements inside one transaction would report the same instant and could not be ordered.
func pgHashClockAndIdentity(setupRows [][]*string) string {
	identity := `''`
	if privilege := pgSetupCell(setupRows, 1); privilege != nil && *privilege == "1" {
		identity = `(SELECT system_identifier::pg_catalog.text FROM pg_catalog.pg_control_system())`
	}
	return `(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000)::pg_catalog.int8,
  ` + identity
}

func (PgDb) SchemaHashSQL(schema string, setupRows [][]*string) (string, int, error) {
	aggregate := `COALESCE(pg_catalog.string_agg(row_blob, '' ORDER BY tn::pg_catalog.text COLLATE "C", op, cn::pg_catalog.text COLLATE "C"), '')`
	hashExpr := pgHashExpression(setupRows, aggregate)
	return fmt.Sprintf(`SELECT %s, pg_catalog.count(*), pg_catalog.count(*) FILTER (WHERE row_blob IS NULL),
  %s
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
) AS serialized_rows`, hashExpr, pgHashClockAndIdentity(setupRows), pgByteaLiteral(schema)), 5, nil
}

func (PgDb) SchemaHashFromRows(rows [][]*string) (engine.HashObservation, error) {
	if len(rows) != 1 || len(rows[0]) != 5 {
		return engine.HashObservation{}, nil
	}
	return pgHashObservation(rows[0][0], rows[0][1], rows[0][2], rows[0][3], rows[0][4]), nil
}

func (PgDb) ServerHashSQL(setupRows [][]*string) (string, int, error) {
	aggregate := `COALESCE(pg_catalog.string_agg(row_blob, '' ORDER BY tn::pg_catalog.text COLLATE "C", op, cn::pg_catalog.text COLLATE "C"), '')`
	hashExpr := pgHashExpression(setupRows, aggregate)
	return fmt.Sprintf(`SELECT sn, %s, pg_catalog.count(*), pg_catalog.count(*) FILTER (WHERE row_blob IS NULL),
  %s
FROM (
  SELECT sn, tn, op, cn, CASE WHEN sn IS NULL OR tn IS NULL OR cn IS NULL OR dt IS NULL OR op IS NULL OR nl IS NULL
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
  ) AS fragment_rows
) AS serialized_rows
GROUP BY sn`, hashExpr, pgHashClockAndIdentity(setupRows)), 6, nil
}

func (PgDb) ServerHashFromRows(rows [][]*string) ([]engine.SchemaHashObservation, error) {
	observations := make([]engine.SchemaHashObservation, 0, len(rows))
	for i, row := range rows {
		if len(row) != 6 {
			return nil, fmt.Errorf("server hash row %d has %d columns, want 6", i, len(row))
		}
		if row[0] == nil {
			return nil, fmt.Errorf("server hash row %d schema is NULL", i)
		}
		observations = append(observations, engine.SchemaHashObservation{
			Schema:          *row[0],
			HashObservation: pgHashObservation(row[1], row[2], row[3], row[4], row[5]),
		})
	}
	return observations, nil
}

func pgHashObservation(hashText, countText, nullsText, clockText, backendID *string) engine.HashObservation {
	observation := engine.HashObservation{}
	if hashText != nil && (len(*hashText) == 64 || len(*hashText) == 32) {
		observation.Hash = decodeHash(*hashText, len(*hashText))
	}
	if clockText != nil {
		observation.DbClockMicros, _ = strconv.ParseInt(*clockText, 10, 64)
	}
	if backendID != nil {
		if _, err := strconv.ParseUint(*backendID, 10, 64); err == nil {
			observation.BackendID = *backendID
		}
	}
	if observation.Hash == nil || countText == nil || nullsText == nil {
		return observation
	}
	_, countErr := strconv.ParseUint(*countText, 10, 64)
	nulls, nullsErr := strconv.ParseUint(*nullsText, 10, 64)
	observation.Trusted = countErr == nil && nullsErr == nil && nulls == 0
	return observation
}

// decodeHash returns the decoded digest, or nil for anything that is not exactly wantHexLen hex
// characters. nil is the caller's "no genuine measurement" signal, so a partial decode must never
// escape: hex.DecodeString returns the bytes it managed to read ALONGSIDE its error, which for a
// corrupt digest is a non-nil short (or empty) slice that reads as a real hash — and two such empty
// hashes compare equal, making unrelated schemas look coherent.
func decodeHash(value string, wantHexLen int) []byte {
	if len(value) != wantHexLen {
		return nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil
	}
	return decoded
}

func pgByteaLiteral(value string) string {
	return `\x` + hex.EncodeToString([]byte(value))
}

func quotePgIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
