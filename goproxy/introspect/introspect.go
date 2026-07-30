// Package introspect is the proxy's own live-connection introspection of its target — the catalog it
// pushes to the control plane (docs/datasource-registration.md). The control plane never dials the
// target; the proxy is the one side with a live connection and the credential that matters, so
// introspection lives here.
package introspect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	// pgx registers the "pgx" database/sql driver via its init(); we never reference it by name.
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/protobuf/proto"

	// The named mysql import both registers the "mysql" driver (via init()) AND gives us mysql.Config
	// for safe DSN construction, so no separate blank import is needed.
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// queryTimeout bounds every introspection query. A full catalog scan of a large schema on a remote
// backend has been measured at ~53s, so a bound near that turns an ordinary slow scan into a failed
// refresh; this leaves room for one well clear of the observed cost.
const queryTimeout = 120 * time.Second

// connectTimeout bounds establishing the introspection connection to the target.
const connectTimeout = 5 * time.Second

// columnsSQL introspects column metadata for every table.
//
// Introspect ALL schemas, including the system catalogs (pg_catalog / information_schema / mysql /
// performance_schema / sys). We do NOT exclude them: a system schema on the search path that is absent
// from the mapping makes bare-name resolution diverge from the backend (the backend binds pg_catalog
// first; we would fall through to a user schema shadowing a system-table name) — a fail-open leak.
// System objects are first-class access-controlled resources: deny-by-default until the access-model
// `system:` tags open the safe ones. Never re-add a NOT IN (...) exclusion here.
const columnsSQL = `SELECT table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
FROM information_schema.columns
ORDER BY table_schema, table_name, ordinal_position`

// OpenMySQLTarget opens a database/sql handle to a MySQL target (plaintext link, 5s connect / 30s socket).
func OpenMySQLTarget(target spi.BackendTarget) (*sql.DB, error) {
	cfg := mysqldriver.NewConfig()
	cfg.User = target.User
	cfg.Passwd = target.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", target.Host, target.Port)
	cfg.DBName = target.Db
	cfg.Timeout = connectTimeout
	cfg.ReadTimeout = queryTimeout
	cfg.WriteTimeout = queryTimeout
	// go-sql-driver handles caching_sha2_password public-key retrieval natively; no
	// allowPublicKeyRetrieval equivalent is needed. zeroDateTimeBehavior/connectionTimeZone are moot
	// since every read here is a string or int (no parseTime).
	cfg.TLSConfig = "false"
	// Hand the *Config straight to a connector rather than FormatDSN()->sql.Open(): FormatDSN does not
	// escape the username, so a service account like "svc:reader" would round-trip back through the DSN
	// grammar as user "svc" / password "reader:<pw>" and fail auth on every catalog refresh. The
	// connector path keeps credentials as structured fields, never serialized through DSN syntax.
	connector, err := mysqldriver.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("introspect: building mysql connector: %w", err)
	}
	return sql.OpenDB(connector), nil
}

// OpenPostgresTarget opens a database/sql handle to a Postgres target.
func OpenPostgresTarget(target spi.BackendTarget) (*sql.DB, error) {
	// pgx has no socket-timeout DSN param; the per-query 30s context below carries that intent.
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(target.User, target.Password),
		Host:     fmt.Sprintf("%s:%d", target.Host, target.Port),
		Path:     "/" + target.Db,
		RawQuery: "connect_timeout=5",
	}
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		return nil, fmt.Errorf("introspect: opening postgres target: %w", err)
	}
	return db, nil
}

// TargetOpener supplies the dialect-specific open + namespace-probe capabilities Run needs, plus the
// dialect's engine.Db — whose NormalizeColumns is the one place that decides how a dialect folds
// identifiers, so Run never branches on a dialect name to normalize.
type TargetOpener interface {
	OpenTarget(target spi.BackendTarget) (*sql.DB, error)
	ProbeNamespace(conn *sql.Conn, targetDb string) (defaultSchemas []string, mysqlLowerCaseTableNames *int32, err error)
	NewDb() engine.Db
}

// Run introspects the target's information_schema over a live connection and returns the catalog to
// push to the control plane. DatasourceName is left blank — the caller (cp.PushCatalog) stamps it.
func Run(opener TargetOpener, target spi.BackendTarget) (*pb.CatalogRequest, error) {
	db, err := opener.OpenTarget(target)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Pin ONE physical connection for the whole introspection and verify it up front. The *sql.DB handle
	// is a lazy pool: without pinning, each of probeVersion's two queries and the namespace/columns probes
	// would independently dial the target, so a dead or misauthenticated target would incur several failed
	// logins per refresh (and, across the boot retries, several times that) — risking service-account
	// lockout and tripling dead-target boot latency. db.Conn(ctx) establishes exactly one connection here
	// (a dial failure returns immediately, no reconnect), and every probe runs on it.
	connectCtx, connectCancel := context.WithTimeout(context.Background(), connectTimeout+queryTimeout)
	defer connectCancel()
	started := time.Now()
	conn, err := db.Conn(connectCtx)
	if err != nil {
		return nil, fmt.Errorf("introspect: connecting to target: %w", err)
	}
	defer conn.Close()
	connectMs := time.Since(started).Milliseconds()

	phase := time.Now()
	engineVersion := probeVersion(conn)
	versionMs := time.Since(phase).Milliseconds()

	phase = time.Now()
	defaultSchemas, mysqlLowerCaseTableNames, err := opener.ProbeNamespace(conn, target.Db)
	if err != nil {
		return nil, err
	}
	namespaceMs := time.Since(phase).Milliseconds()

	phase = time.Now()
	columns, err := introspectColumns(conn)
	if err != nil {
		return nil, err
	}
	columnsMs := time.Since(phase).Milliseconds()

	// Normalize to the SAME canonical spelling the analyzer treats as authoritative (analyzer/probe,
	// Go-to-Go — no FFM/marshaling) — an identity function for Postgres, MySQL's role-aware fold
	// (gated by lctnMode) for MySQL — before this ever reaches the control plane. Nothing downstream
	// (catalog storage, browse_catalog, Cedar Table::/Column:: EUIDs, column_classification, the
	// per-connection schema-fragment pool normalized the same way in goproxy/db) ever sees raw
	// introspected spelling; no caller decides whether/how to fold.
	// The dialect's own engine.Db owns the fold, so this call site names no dialect. Only the MySQL
	// namespace probe sets mysqlLowerCaseTableNames (the Postgres probe returns nil), and it carries the
	// fold mode MySQL's NormalizeColumns is gated by; Postgres ignores the argument.
	lctnMode := 0
	if mysqlLowerCaseTableNames != nil {
		lctnMode = int(*mysqlLowerCaseTableNames)
	}
	phase = time.Now()
	dbImpl := opener.NewDb()
	columns = dbImpl.NormalizeColumns(lctnMode, columns)
	defaultSchemas = normalizeSchemas(dbImpl, lctnMode, defaultSchemas)
	normalizeMs := time.Since(phase).Milliseconds()

	distinctTables := map[string]struct{}{}
	for _, c := range columns {
		distinctTables[c.GetSchema()+"."+c.GetTable()] = struct{}{}
	}
	// Per-phase timings, not just the total: introspection against a remote backend has been observed
	// taking tens of seconds, and the total alone cannot say whether that is the dial, the catalog scan,
	// or the fold over every column.
	slog.Info("introspected catalog",
		"columns", len(columns),
		"tables", len(distinctTables),
		"default_schemas", defaultSchemas,
		"engine_version", engineVersion,
		"total_ms", time.Since(started).Milliseconds(),
		"connect_ms", connectMs,
		"version_ms", versionMs,
		"namespace_ms", namespaceMs,
		"columns_ms", columnsMs,
		"normalize_ms", normalizeMs,
	)

	return &pb.CatalogRequest{
		DefaultSchemas:           defaultSchemas,
		MysqlLowerCaseTableNames: mysqlLowerCaseTableNames,
		Columns:                  columns,
		EngineVersion:            engineVersion,
	}, nil
}

// normalizeSchemas folds each bare schema name (default_schemas / search_path entries have no
// associated table) through the dialect's own NormalizeColumns with placeholder table/column values,
// discarding those parts — the fold decision is schema-name-only (verified empirically: stable
// regardless of the table argument). One call folds the whole list, so a dialect that memoizes
// per-(schema, table) work does it once here too.
func normalizeSchemas(dbImpl engine.Db, lctnMode int, schemas []string) []string {
	placeholders := make([]*pb.Column, len(schemas))
	for i, s := range schemas {
		placeholders[i] = &pb.Column{Schema: s, Table: "_", Column: "_"}
	}
	out := make([]string, len(schemas))
	for i, c := range dbImpl.NormalizeColumns(lctnMode, placeholders) {
		out[i] = c.GetSchema()
	}
	return out
}

// ProbeMySQLNamespace captures the current database plus the load-bearing
// @@lower_case_table_names and verifies the connection's database matches the bound one.
func ProbeMySQLNamespace(conn *sql.Conn, targetDb string) (defaultSchemas []string, mysqlLowerCaseTableNames *int32, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	row := conn.QueryRowContext(ctx, "SELECT DATABASE(), @@lower_case_table_names, DATABASE() = ?", targetDb)
	var currentDb sql.NullString
	var lctn int
	var matches sql.NullBool
	if err := row.Scan(&currentDb, &lctn, &matches); err != nil {
		return nil, nil, fmt.Errorf("introspect: MySQL namespace probe: %w", err)
	}
	if !currentDb.Valid {
		return nil, nil, errors.New("introspect: MySQL connection has no current database")
	}
	if lctn < 0 || lctn > 2 {
		return nil, nil, fmt.Errorf("introspect: MySQL returned invalid lower_case_table_names: %d", lctn)
	}
	if !matches.Valid || !matches.Bool {
		return nil, nil, fmt.Errorf("introspect: MySQL current database %q does not match bound database %q", currentDb.String, targetDb)
	}
	return []string{currentDb.String}, proto.Int32(int32(lctn)), nil
}

// ProbePostgresNamespace captures the effective search_path.
func ProbePostgresNamespace(conn *sql.Conn, _ string) (defaultSchemas []string, mysqlLowerCaseTableNames *int32, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	// This literal is UNQUALIFIED — deliberately distinct from the qualified namespace-probe form used
	// elsewhere; do not swap it in here.
	rows, err := conn.QueryContext(ctx, "SELECT unnest(current_schemas(true))")
	if err != nil {
		return nil, nil, fmt.Errorf("introspect: Postgres namespace probe: %w", err)
	}
	defer rows.Close()
	var schemas []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, nil, fmt.Errorf("introspect: scanning Postgres namespace row: %w", err)
		}
		schemas = append(schemas, schema)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("introspect: Postgres namespace probe: %w", err)
	}
	return schemas, nil, nil
}

// introspectColumns runs columnsSQL on the pinned connection and scans every row into a *pb.Column.
func introspectColumns(conn *sql.Conn) ([]*pb.Column, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	rows, err := conn.QueryContext(ctx, columnsSQL)
	if err != nil {
		return nil, fmt.Errorf("introspect: columns query: %w", err)
	}
	defer rows.Close()

	var columns []*pb.Column
	for rows.Next() {
		var schema, table, column, dataType, isNullable string
		var ordinal int32
		if err := rows.Scan(&schema, &table, &column, &dataType, &ordinal, &isNullable); err != nil {
			return nil, fmt.Errorf("introspect: scanning column row: %w", err)
		}
		columns = append(columns, &pb.Column{
			Schema:   schema,
			Table:    table,
			Column:   column,
			DataType: dataType,
			Ordinal:  ordinal,
			Nullable: isNullable == "YES",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("introspect: columns query: %w", err)
	}
	return columns, nil
}

// probeVersion returns the target's live server version, for system-classification's manifest
// resolution. `version()` works on both PostgreSQL and MySQL and always carries the major. Aurora
// additionally exposes `aurora_version()` (vanilla PG/MySQL don't — a failure there simply means "not
// Aurora"); when it resolves the suffix "(aurora <v>)" is appended. Best-effort: an empty string on probe
// failure. Runs on the pinned connection so it adds no extra dials.
func probeVersion(conn *sql.Conn) string {
	base := ""
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()
		row := conn.QueryRowContext(ctx, "SELECT version()")
		var v sql.NullString
		if err := row.Scan(&v); err != nil {
			slog.Warn("engine version probe failed", "error", err)
			return
		}
		base = v.String
	}()

	var aurora string
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()
		row := conn.QueryRowContext(ctx, "SELECT aurora_version()")
		var v sql.NullString
		// Best-effort: any error (missing function on a non-Aurora target) simply means "not Aurora";
		// ignore it.
		if err := row.Scan(&v); err != nil {
			return
		}
		aurora = v.String
	}()

	if strings.TrimSpace(aurora) != "" {
		return base + " (aurora " + aurora + ")"
	}
	return base
}
