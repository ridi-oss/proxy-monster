// Package introspect is the proxy's own live-connection introspection of its target — the catalog it
// pushes to the control plane (docs/datasource-registration.md). The control plane never dials the
// target; the proxy is the one side with a live connection and the credential that matters, so
// introspection lives here.
package sqldb

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	// The named mysql import both registers the "mysql" driver (via init()) AND gives us mysql.Config
	// for safe DSN construction, so no separate blank import is needed.

	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// QueryTimeout bounds every introspection query. A full catalog scan of a large schema on a remote
// target DB has been measured at ~53s, so a bound near that turns an ordinary slow scan into a failed
// refresh; this leaves room for one well clear of the observed cost.
const QueryTimeout = 120 * time.Second

// ConnectTimeout bounds establishing the introspection connection to the target.
const ConnectTimeout = 5 * time.Second

// columnsSQL introspects column metadata for every table.
//
// Introspect ALL schemas, including the system catalogs (pg_catalog / information_schema / mysql /
// performance_schema / sys). We do NOT exclude them: a system schema on the search path that is absent
// from the mapping makes bare-name resolution diverge from the target DB (the target DB binds pg_catalog
// first; we would fall through to a user schema shadowing a system-table name) — a fail-open leak.
// System objects are first-class access-controlled resources: deny-by-default until the access-model
// `system:` tags open the safe ones. Never re-add a NOT IN (...) exclusion here.
const columnsSQL = `SELECT table_catalog, table_schema, table_name, column_name, data_type, ordinal_position, is_nullable
FROM information_schema.columns
ORDER BY table_schema, table_name, ordinal_position`

// OpenPostgresTarget opens a database/sql handle to a Postgres target.
func OpenPostgresTarget(config spi.TargetConfig) (*sql.DB, error) {
	// pgx has no socket-timeout DSN param; the per-query 30s context below carries that intent.
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(config.User, config.Password),
		Host:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Path:     "/" + config.Db,
		RawQuery: "connect_timeout=5&sslmode=disable",
	}
	return sql.OpenDB(pgConnector{dsn: u.String(), tls: config.TLS}), nil
}

// pgConnector parses at connect time, as sql.Open does, so an unusable target fails its first connect, not the open.
type pgConnector struct {
	dsn string
	tls *tls.Config
}

func (c pgConnector) Connect(ctx context.Context) (driver.Conn, error) {
	config, err := pgx.ParseConfig(c.dsn)
	if err != nil {
		return nil, fmt.Errorf("introspect: parsing postgres target config: %w", err)
	}
	if c.tls != nil {
		config.TLSConfig = c.tls.Clone()
	}
	return stdlib.GetConnector(*config).Connect(ctx)
}

func (pgConnector) Driver() driver.Driver { return stdlib.GetDefaultDriver() }

// NamespaceProbe reads the connection's effective namespace into a CatalogRequest: default_schemas, plus
// MySQL's lower_case_table_names.
type NamespaceProbe func(ctx context.Context, conn *sql.Conn, targetDb string) (*pb.CatalogRequest, error)

// Introspect introspects the target's information_schema over a live connection and returns the catalog to
// push to the control plane. DatasourceName is left blank — the caller (cp.PushCatalog) stamps it.
func Introspect(ctx context.Context, db *sql.DB, queries relay.Db, probe NamespaceProbe, targetDb string) (*pb.CatalogRequest, error) {
	// Pin ONE physical connection for the whole introspection and verify it up front. The *sql.DB handle
	// is a lazy pool: without pinning, each of probeVersion's two queries and the namespace/columns probes
	// would independently dial the target, so a dead or misauthenticated target would incur several failed
	// logins per refresh (and, across the boot retries, several times that) — risking service-account
	// lockout and tripling dead-target boot latency. db.Conn(ctx) establishes exactly one connection here
	// (a dial failure returns immediately, no reconnect), and every probe runs on it.
	connectCtx, connectCancel := context.WithTimeout(ctx, ConnectTimeout+QueryTimeout)
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
	catalog, err := probe(ctx, conn, targetDb)
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

	// Normalize to the SAME canonical spelling the analyzer treats as authoritative (analyzer/engines,
	// Go-to-Go — no FFM/marshaling) — an identity function for Postgres, MySQL's role-aware fold
	// (gated by lctnMode) for MySQL — before this ever reaches the control plane. Nothing downstream
	// (catalog storage, browse_catalog, Cedar Table::/Column:: EUIDs, column_classification, the
	// per-connection schema-fragment pool normalized the same way in goproxy/db) ever sees raw
	// introspected spelling; no caller decides whether/how to fold.
	// The dialect's own relay.Db owns the fold, so this call site names no dialect. Only the MySQL
	// namespace probe sets mysqlLowerCaseTableNames (the Postgres probe returns nil), and it carries the
	// fold mode MySQL's NormalizeColumns is gated by; Postgres ignores the argument.
	lctnMode := 0
	if catalog.MysqlLowerCaseTableNames != nil {
		lctnMode = int(catalog.GetMysqlLowerCaseTableNames())
	}
	phase = time.Now()
	columns = queries.NormalizeColumns(lctnMode, columns)
	catalog.DefaultSchemas = normalizeSchemas(queries, lctnMode, catalog.DefaultSchemas)
	normalizeMs := time.Since(phase).Milliseconds()

	phase = time.Now()
	routines, err := introspectRoutines(conn, queries, lctnMode)
	if err != nil {
		return nil, err
	}
	routinesMs := time.Since(phase).Milliseconds()

	distinctTables := map[string]struct{}{}
	for _, c := range columns {
		distinctTables[c.GetSchema()+"."+c.GetTable()] = struct{}{}
	}
	// Per-phase timings, not just the total: introspection against a remote target DB has been observed
	// taking tens of seconds, and the total alone cannot say whether that is the dial, the catalog scan,
	// or the fold over every column.
	slog.Info("introspected catalog",
		"columns", len(columns),
		"tables", len(distinctTables),
		"default_schemas", catalog.DefaultSchemas,
		"engine_version", engineVersion,
		"total_ms", time.Since(started).Milliseconds(),
		"connect_ms", connectMs,
		"version_ms", versionMs,
		"namespace_ms", namespaceMs,
		"columns_ms", columnsMs,
		"normalize_ms", normalizeMs,
		"routines_ms", routinesMs,
	)

	catalog.EngineVersion = engineVersion
	catalog.Catalog = &analyzerpb.CatalogSnapshot{Columns: columns, Routines: routines}
	return catalog, nil
}

type schemaNamePair struct{ schema, name string }

func introspectRoutines(conn *sql.Conn, queries relay.Db, lctnMode int) ([]*analyzerpb.SchemaFunctions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()
	rows, err := conn.QueryContext(ctx, queries.RoutinesSQL())
	if err != nil {
		return nil, fmt.Errorf("introspect: routines query: %w", err)
	}
	defer rows.Close()
	var pairs []schemaNamePair
	for rows.Next() {
		var schema, name sql.NullString
		if err := rows.Scan(&schema, &name); err != nil {
			return nil, fmt.Errorf("introspect: scanning routine row: %w", err)
		}
		if schema.Valid && name.Valid {
			pairs = append(pairs, schemaNamePair{schema: schema.String, name: name.String})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("introspect: routines query: %w", err)
	}
	return foldFunctionSchemas(queries, lctnMode, pairs), nil
}

// foldFunctionSchemas groups (schema, function) pairs by their canonical schema, folding the schema
// through the dialect's NormalizeColumns and the function name through its FoldFunctionName.
func foldFunctionSchemas(queries relay.Db, lctnMode int, pairs []schemaNamePair) []*analyzerpb.SchemaFunctions {
	if len(pairs) == 0 {
		return nil
	}
	placeholders := make([]*analyzerpb.Column, len(pairs))
	for i, p := range pairs {
		placeholders[i] = &analyzerpb.Column{Schema: p.schema, Table: "_", Column: "_"}
	}
	folded := queries.NormalizeColumns(lctnMode, placeholders)
	grouped := make([]schemaNamePair, len(pairs))
	for i, p := range pairs {
		grouped[i] = schemaNamePair{schema: folded[i].GetSchema(), name: queries.FoldFunctionName(p.name)}
	}
	return groupBySchema(grouped)
}

// groupBySchema deduplicates names while preserving first-seen order.
func groupBySchema(pairs []schemaNamePair) []*analyzerpb.SchemaFunctions {
	order := make([]string, 0)
	names := make(map[string][]string)
	seen := make(map[string]map[string]struct{})
	for _, p := range pairs {
		if _, ok := seen[p.schema]; !ok {
			seen[p.schema] = make(map[string]struct{})
			order = append(order, p.schema)
		}
		if _, dup := seen[p.schema][p.name]; dup {
			continue
		}
		seen[p.schema][p.name] = struct{}{}
		names[p.schema] = append(names[p.schema], p.name)
	}
	out := make([]*analyzerpb.SchemaFunctions, 0, len(order))
	for _, schema := range order {
		out = append(out, &analyzerpb.SchemaFunctions{Schema: schema, Names: names[schema]})
	}
	return out
}

// normalizeSchemas folds each bare schema name (default_schemas / search_path entries have no
// associated table) through the dialect's own NormalizeColumns with placeholder table/column values,
// discarding those parts — the fold decision is schema-name-only (verified empirically: stable
// regardless of the table argument). One call folds the whole list, so a dialect that memoizes
// per-(schema, table) work does it once here too.
func normalizeSchemas(queries relay.Db, lctnMode int, schemas []string) []string {
	placeholders := make([]*analyzerpb.Column, len(schemas))
	for i, s := range schemas {
		placeholders[i] = &analyzerpb.Column{Schema: s, Table: "_", Column: "_"}
	}
	out := make([]string, len(schemas))
	for i, c := range queries.NormalizeColumns(lctnMode, placeholders) {
		out[i] = c.GetSchema()
	}
	return out
}

// ReadPostgresCatalog returns current_database(); the catalog every fragment and temp column from this
// connection is stamped with.
func ReadPostgresCatalog(ctx context.Context, conn *sql.Conn) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	var catalog string
	if err := conn.QueryRowContext(ctx, "SELECT pg_catalog.current_database()").Scan(&catalog); err != nil {
		return "", fmt.Errorf("introspect: Postgres catalog probe: %w", err)
	}
	if catalog == "" {
		return "", errors.New("introspect: Postgres connection has no current database")
	}

	return catalog, nil
}

// ProbePostgresNamespace captures the effective search_path.
func ProbePostgresNamespace(ctx context.Context, conn *sql.Conn, _ string) (*pb.CatalogRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	catalog, err := ReadPostgresCatalog(ctx, conn)
	if err != nil {
		return nil, err
	}

	// This literal is UNQUALIFIED — deliberately distinct from the qualified namespace-probe form used
	// elsewhere; do not swap it in here.
	rows, err := conn.QueryContext(ctx, "SELECT unnest(current_schemas(true))")
	if err != nil {
		return nil, fmt.Errorf("introspect: Postgres namespace probe: %w", err)
	}
	defer rows.Close()
	var schemas []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, fmt.Errorf("introspect: scanning Postgres namespace row: %w", err)
		}
		schemas = append(schemas, schema)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("introspect: Postgres namespace probe: %w", err)
	}
	return &pb.CatalogRequest{DefaultSchemas: schemas, CurrentCatalog: catalog}, nil
}

// introspectColumns runs columnsSQL on the pinned connection and scans every row into a *analyzerpb.Column.
func introspectColumns(conn *sql.Conn) ([]*analyzerpb.Column, error) {
	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()

	rows, err := conn.QueryContext(ctx, columnsSQL)
	if err != nil {
		return nil, fmt.Errorf("introspect: columns query: %w", err)
	}
	defer rows.Close()

	var columns []*analyzerpb.Column
	for rows.Next() {
		var catalog, schema, table, column, dataType, isNullable string
		var ordinal int32
		if err := rows.Scan(&catalog, &schema, &table, &column, &dataType, &ordinal, &isNullable); err != nil {
			return nil, fmt.Errorf("introspect: scanning column row: %w", err)
		}
		columns = append(columns, &analyzerpb.Column{
			Catalog:  catalog,
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
		ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
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
		ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
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
