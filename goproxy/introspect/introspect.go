// Package introspect is the proxy's own live-connection introspection of its target — the catalog it
// pushes to the control plane (docs/datasource-registration.md). The control plane never dials the
// target; the proxy is the one side with a live connection and the credential that matters, so
// introspection lives here.
package introspect

import (
	"bytes"
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

	dbImpl := opener.NewDb()
	var setupRows [][]*string
	if setupSQL := dbImpl.HashSetupProbeSQL(); setupSQL != "" {
		if rows, setupErr := queryStrings(conn, setupSQL, dbImpl.HashSetupColumns()); setupErr == nil {
			setupRows = rows
		}
	}

	// Visibility is bracketed like the hashes, and for the same reason. Claiming to enumerate every
	// schema is what licenses a reader to conclude a schema it does not see has been dropped, so the
	// claim has to hold across the whole reading: a privilege revoked partway through would otherwise
	// narrow the scan while the opening probe still vouched for it, and the schemas that fell out of
	// view would look deleted rather than hidden.
	sawEverySchemaBefore := probeCatalogVisibility(conn, dbImpl)

	// Measure, fetch, measure — the same bracket goproxy/engine.Refetcher applies per schema, here over
	// the whole server: a schema whose two hashes agree is one the column scan read while the backend
	// held still, and only that pairing may be trusted. Every step runs on the one pinned connection.
	obs1, hashErr1 := measureServerHash(conn, dbImpl, setupRows)
	phase = time.Now()
	columns, err := introspectColumns(conn)
	if err != nil {
		return nil, err
	}
	columnsMs := time.Since(phase).Milliseconds()
	obs2, hashErr2 := measureServerHash(conn, dbImpl, setupRows)
	seesEverySchema := sawEverySchemaBefore && probeCatalogVisibility(conn, dbImpl)

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
	columns = dbImpl.NormalizeColumns(lctnMode, columns)
	defaultSchemas = normalizeSchemas(dbImpl, lctnMode, defaultSchemas)
	measurement := measureServer(dbImpl, lctnMode, seesEverySchema, obs1, hashErr1, obs2, hashErr2)
	// Publish content only for schemas the hash bracket covered. The column scan is its own statement, so
	// a schema created after the opening hashes were taken shows up in the columns with no hash behind it
	// — content the manager could not version, and a version is what decides whether an observation may
	// install. Dropping those columns keeps every published schema one coherent measurement; the schema
	// arrives with the next scan, which brackets it properly.
	contentSchemas, columns := coherentContent(columns, measurement.schemaHashes)
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
		SchemaHashes:             measurement.schemaHashes,
		DbClockMicros:            measurement.dbClockMicros,
		BackendId:                measurement.backendID,
		HashesOnly:               false,
		ContentSchemas:           contentSchemas,
		NamespaceComplete:        measurement.namespaceComplete,
	}, nil
}

// serverMeasurement is what the two grouped scans establish about the backend, including whether the
// result may claim to enumerate every schema.
type serverMeasurement struct {
	schemaHashes      []*pb.SchemaHash
	dbClockMicros     int64
	backendID         string
	namespaceComplete bool
}

// measureServer brackets the column scan with the two grouped measurements. Any failure — either
// statement, or an undecodable result — degrades to today's wire shape (nil hashes, no clock, no
// identity), which a control plane already reads as "content only". A hash failure must never fail the
// run: registration succeeds without hashes today.
//
// The completeness claim is decided here rather than by the caller, because it is exactly the two facts
// this function holds: hashes were produced at all, and seesEverySchema says the connection's
// privilege-filtered catalog views hid nothing. Both are required — the manager deletes every schema
// missing from a push that claims completeness.
func measureServer(dbImpl engine.Db, lctnMode int, seesEverySchema bool, first []engine.SchemaHashObservation, firstErr error, second []engine.SchemaHashObservation, secondErr error) serverMeasurement {
	hashes, clock, backendID, err := coherentSchemaHashes(dbImpl, lctnMode, first, second)
	if firstErr != nil || secondErr != nil || err != nil {
		slog.Warn("whole-server catalog hash measurement failed; pushing columns without hashes",
			"first_error", firstErr,
			"second_error", secondErr,
			"coherence_error", err,
		)
		return serverMeasurement{}
	}
	if !seesEverySchema {
		slog.Warn("introspection connection cannot see every schema; sending hashes without claiming a complete namespace",
			"schemas", len(hashes),
		)
	}
	return serverMeasurement{
		schemaHashes:      hashes,
		dbClockMicros:     clock,
		backendID:         backendID,
		namespaceComplete: len(hashes) > 0 && seesEverySchema,
	}
}

// probeCatalogVisibility answers whether this connection is guaranteed to see every schema on the
// server. Anything short of a definite yes — no probe for the dialect, a probe failure, a value other
// than 1 — fails closed to false, because the only thing a false costs is the manager's license to
// delete, while a wrong true deletes schemas that exist.
func probeCatalogVisibility(conn *sql.Conn, dbImpl engine.Db) bool {
	statement := dbImpl.CatalogVisibilitySQL()
	if statement == "" {
		return false
	}
	rows, err := queryStrings(conn, statement, 1)
	if err != nil {
		slog.Warn("catalog visibility probe failed; not claiming a complete namespace", "error", err)
		return false
	}
	return len(rows) == 1 && len(rows[0]) == 1 && rows[0][0] != nil && (*rows[0][0] == "1" || *rows[0][0] == "true")
}

func measureServerHash(conn *sql.Conn, dbImpl engine.Db, setupRows [][]*string) ([]engine.SchemaHashObservation, error) {
	statement, width, err := dbImpl.ServerHashSQL(setupRows)
	if err != nil {
		return nil, err
	}
	rows, err := queryStrings(conn, statement, width)
	if err != nil {
		return nil, err
	}
	return dbImpl.ServerHashFromRows(rows)
}

func queryStrings(conn *sql.Conn, statement string, expectedColumns int) ([][]*string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	rows, err := conn.QueryContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columnNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columnNames) != expectedColumns {
		return nil, fmt.Errorf("query returned %d columns, want %d", len(columnNames), expectedColumns)
	}
	var result [][]*string
	for rows.Next() {
		values := make([]sql.NullString, expectedColumns)
		destinations := make([]any, expectedColumns)
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		row := make([]*string, expectedColumns)
		for i := range values {
			if values[i].Valid {
				value := values[i].String
				row[i] = &value
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func coherentSchemaHashes(dbImpl engine.Db, lctnMode int, first, second []engine.SchemaHashObservation) ([]*pb.SchemaHash, int64, string, error) {
	firstBySchema, err := observationsBySchema(first)
	if err != nil {
		return nil, 0, "", err
	}
	secondBySchema, err := observationsBySchema(second)
	if err != nil {
		return nil, 0, "", err
	}

	rawSchemas := make([]string, 0, len(firstBySchema)+len(secondBySchema))
	seenRaw := make(map[string]struct{}, len(firstBySchema)+len(secondBySchema))
	for _, observations := range [][]engine.SchemaHashObservation{first, second} {
		for _, observation := range observations {
			if _, seen := seenRaw[observation.Schema]; seen {
				continue
			}
			seenRaw[observation.Schema] = struct{}{}
			rawSchemas = append(rawSchemas, observation.Schema)
		}
	}
	canonicalSchemas := normalizeSchemas(dbImpl, lctnMode, rawSchemas)
	canonicalRaw := make(map[string]string, len(canonicalSchemas))
	for i, canonical := range canonicalSchemas {
		if previous, exists := canonicalRaw[canonical]; exists && previous != rawSchemas[i] {
			return nil, 0, "", fmt.Errorf("schema hash names %q and %q normalize to %q", previous, rawSchemas[i], canonical)
		}
		canonicalRaw[canonical] = rawSchemas[i]
	}

	hashes := make([]*pb.SchemaHash, 0, len(rawSchemas))
	for i, rawSchema := range rawSchemas {
		firstObservation, inFirst := firstBySchema[rawSchema]
		secondObservation, inSecond := secondBySchema[rawSchema]
		// The first measurement's hash, matching the clock and identity below, which also come from
		// measurement 1: an entry that paired scan 2's hash with scan 1's clock would describe a state
		// that never existed at that instant. The second scan only supplies a hash for a schema the first
		// never saw, where there is no first-measurement reading to contradict.
		hash := firstObservation.Hash
		if !inFirst {
			hash = secondObservation.Hash
		}
		trusted := inFirst && inSecond && firstObservation.Trusted && secondObservation.Trusted &&
			bytes.Equal(firstObservation.Hash, secondObservation.Hash) && firstObservation.BackendID == secondObservation.BackendID
		hashes = append(hashes, &pb.SchemaHash{
			Schema:  canonicalSchemas[i],
			Hash:    append([]byte(nil), hash...),
			Trusted: trusted,
		})
	}

	var clock int64
	backendID := ""
	for _, observation := range first {
		if observation.DbClockMicros > 0 && (clock == 0 || observation.DbClockMicros < clock) {
			clock = observation.DbClockMicros
		}
		if backendID == "" && observation.BackendID != "" {
			backendID = observation.BackendID
		}
	}
	return hashes, clock, backendID, nil
}

func observationsBySchema(observations []engine.SchemaHashObservation) (map[string]engine.SchemaHashObservation, error) {
	bySchema := make(map[string]engine.SchemaHashObservation, len(observations))
	for _, observation := range observations {
		if _, exists := bySchema[observation.Schema]; exists {
			return nil, fmt.Errorf("duplicate schema hash measurement for %q", observation.Schema)
		}
		bySchema[observation.Schema] = observation
	}
	return bySchema, nil
}

func distinctColumnSchemas(columns []*pb.Column) []string {
	seen := make(map[string]struct{})
	var schemas []string
	for _, column := range columns {
		schema := column.GetSchema()
		if _, exists := seen[schema]; exists {
			continue
		}
		seen[schema] = struct{}{}
		schemas = append(schemas, schema)
	}
	return schemas
}

// coherentContent keeps only the columns whose schema carries a hash from the same scan, and returns the
// schemas that survive. A schema the column scan saw but the hash bracket did not — one created between
// the two statements — has content with nothing to version it, and an observation the manager cannot
// order is one it cannot safely install.
func coherentContent(columns []*pb.Column, hashes []*pb.SchemaHash) ([]string, []*pb.Column) {
	measured := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		measured[hash.GetSchema()] = struct{}{}
	}
	kept := make([]*pb.Column, 0, len(columns))
	for _, column := range columns {
		if _, ok := measured[column.GetSchema()]; ok {
			kept = append(kept, column)
		}
	}
	return distinctColumnSchemas(kept), kept
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
