// Introspection is the proxy's own live-connection introspection of its target — the catalog it
// pushes to the control plane (docs/datasource-registration.md). The control plane never dials the
// target; the proxy is the one side with a live connection and the credential that matters, so
// introspection lives here.

package sqldb

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	analyzerpb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
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

// NamespaceProbe reads the connection's namespace into a CatalogRequest, with the session settings it carries.
type NamespaceProbe func(ctx context.Context, conn *sql.Conn, targetDb string, session *engines.Session) (*pb.CatalogRequest, error)

// Introspect introspects the target's information_schema over a live connection and returns the catalog to
// push to the control plane. DatasourceName is left blank — the caller (cp.PushCatalog) stamps it.
func Introspect(ctx context.Context, db *sql.DB, queries Queries, probe NamespaceProbe, targetDb string) (*pb.CatalogRequest, error) {
	// Pin ONE physical connection for the whole introspection and verify it up front. The *sql.DB handle
	// is a lazy pool: without pinning, each of the version and namespace/columns probes
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
	session, err := NewConnSession(ctx, conn, queries)
	if err != nil {
		return nil, err
	}
	engineVersion := withAuroraVersion(conn, session.EngineVersion())
	versionMs := time.Since(phase).Milliseconds()

	phase = time.Now()
	catalog, err := probe(ctx, conn, targetDb, session)
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
	// (by the connection's session) for MySQL — before this ever reaches the control plane. Nothing downstream
	// (catalog storage, browse_catalog, Cedar Table::/Column:: EUIDs, column_classification, the
	// per-connection schema-fragment pool normalized the same way by the relay) ever sees raw
	// introspected spelling; no caller decides whether/how to fold.
	phase = time.Now()
	columns = session.CanonicalColumns(columns)
	for i, schema := range session.CanonicalSchemas(catalog.DefaultSchemas) {
		catalog.DefaultSchemas[i] = schema.String()
	}
	normalizeMs := time.Since(phase).Milliseconds()

	phase = time.Now()
	routines, err := introspectRoutines(conn, queries, session)
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

func introspectRoutines(conn *sql.Conn, queries Queries, session *engines.Session) ([]*analyzerpb.SchemaFunctions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()
	rows, err := conn.QueryContext(ctx, queries.Routines)
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
	return foldFunctionSchemas(session, pairs), nil
}

// foldFunctionSchemas groups (schema, function) pairs by their canonical schema and function name.
func foldFunctionSchemas(session *engines.Session, pairs []schemaNamePair) []*analyzerpb.SchemaFunctions {
	if len(pairs) == 0 {
		return nil
	}
	schemas := make([]string, len(pairs))
	for i, p := range pairs {
		schemas[i] = p.schema
	}
	grouped := make([]schemaNamePair, len(pairs))
	for i, schema := range session.CanonicalSchemas(schemas) {
		grouped[i] = schemaNamePair{schema: schema.String(), name: session.FunctionName(pairs[i].name).String()}
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

// NewConnSession builds conn's engine session from its target settings probe, once; conn keeps it for its lifetime.
func NewConnSession(ctx context.Context, conn *sql.Conn, queries Queries) (*engines.Session, error) {
	return NewSession(queries, func(statement string, columns int) ([][]*string, error) {
		ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
		defer cancel()
		values := make([]sql.NullString, columns)
		dest := make([]any, columns)
		for i := range values {
			dest[i] = &values[i]
		}
		if err := conn.QueryRowContext(ctx, statement).Scan(dest...); err != nil {
			return nil, err
		}
		row := make([]*string, columns)
		for i, v := range values {
			if v.Valid {
				row[i] = &v.String
			}
		}
		return [][]*string{row}, nil
	})
}

// withAuroraVersion appends "(aurora <v>)" on Aurora; elsewhere aurora_version() fails and base is returned.
func withAuroraVersion(conn *sql.Conn, base string) string {
	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()
	var aurora sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT aurora_version()").Scan(&aurora); err != nil || strings.TrimSpace(aurora.String) == "" {
		return base
	}
	return base + " (aurora " + aurora.String + ")"
}
