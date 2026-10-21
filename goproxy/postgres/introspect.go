package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

// OpenPool opens a database/sql handle to a Postgres target.
func OpenPool(config spi.TargetConfig) (*sql.DB, error) {
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

// ReadCatalog returns current_database(); the catalog every fragment and temp column from this
// connection is stamped with.
func ReadCatalog(ctx context.Context, conn *sql.Conn) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sqldb.QueryTimeout)
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

// ProbeNamespace captures the effective search_path.
func ProbeNamespace(ctx context.Context, conn *sql.Conn, _ string) (*pb.CatalogRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, sqldb.QueryTimeout)
	defer cancel()

	catalog, err := ReadCatalog(ctx, conn)
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
