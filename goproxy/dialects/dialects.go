// Package dialects wires concrete per-dialect implementations behind the proxy SPI.
package dialects

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/athena"
	"github.com/ridi-oss/proxy-monster/goproxy/db"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/postgres"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

const tableDetailConnectTimeout = 5 * time.Second

// sqlProvider is a database/sql-backed dialect: MySQL and PostgreSQL differ only in the functions below.
type sqlProvider struct {
	engine  *engines.Engine
	queries relay.Db
	open    func(spi.TargetConfig) (*sql.DB, error)
	probe   sqldb.NamespaceProbe
	// catalog reads the connection's current catalog; MySQL pins "def", Postgres asks the server.
	catalog    func(context.Context, *sql.Conn) (string, error)
	readDetail func(*sql.Conn, string, string) (*spi.TableDetail, error)
	newServer  func(spi.Listen, spi.TargetConfig, spi.ControlPlane, relay.Db, func() (*tls.Config, error)) spi.WireServer
	newSession func(context.Context, spi.TargetConfig, relay.Db, *spi.Authorizer, spi.ExecGuard, time.Duration, string) (spi.Session, error)
}

func (p sqlProvider) Engine() *engines.Engine { return p.engine }

func (p sqlProvider) OpenTarget(config spi.TargetConfig) (spi.Target, error) {
	pool, err := p.open(config)
	if err != nil {
		return nil, err
	}
	// Metadata reads must observe the defaults a new target session would inherit.
	pool.SetMaxIdleConns(0)
	advertise, _ := os.LookupEnv("PM_ADVERTISE_ADDR")
	return &sqlDb{provider: p, config: config, pool: pool, endpoint: strings.TrimSpace(advertise)}, nil
}

// sqlDb is one open MySQL or PostgreSQL target: the pool serves introspection and table detail; the wire
// server and run sessions dial the target themselves with the same TargetDb.
type sqlDb struct {
	provider sqlProvider
	config   spi.TargetConfig
	pool     *sql.DB
	endpoint string
}

func (d *sqlDb) Config() spi.TargetConfig { return d.config }

func (d *sqlDb) ConnectionInfo() *pb.ConnectionInfo { return &pb.ConnectionInfo{Endpoint: d.endpoint} }

func (d *sqlDb) Introspect(ctx context.Context) (*pb.CatalogRequest, error) {
	return sqldb.Introspect(ctx, d.pool, d.provider.queries, d.provider.probe, d.config.Db)
}

func (d *sqlDb) ReadTableDetail(ctx context.Context, table *enginepb.ObjectRef) (*spi.TableDetail, error) {
	if table == nil || table.Schema == "" || table.Table == "" {
		return nil, fmt.Errorf("table selector is incomplete")
	}
	connectCtx, cancel := context.WithTimeout(ctx, tableDetailConnectTimeout+sqldb.DetailQueryTimeout)
	defer cancel()
	conn, err := d.pool.Conn(connectCtx)
	if err != nil {
		return nil, fmt.Errorf("connecting to target: %w", err)
	}
	defer conn.Close()
	catalog, err := d.provider.catalog(ctx, conn)
	if err != nil {
		return nil, err
	}
	if table.Catalog != catalog {
		return nil, fmt.Errorf("table catalog %q does not match target catalog %q", table.Catalog, catalog)
	}
	schema := table.Schema
	exists, err := tableDetailTableExists(conn, d.provider.engine, schema, table.Table)
	if err != nil || !exists {
		return nil, err
	}
	detail, err := d.provider.readDetail(conn, schema, table.Table)
	if detail != nil {
		detail.Catalog = catalog
		for i := range detail.ForeignKeys {
			detail.ForeignKeys[i].SourceCatalog, detail.ForeignKeys[i].TargetCatalog = catalog, catalog
		}
		for i := range detail.ReferencedBy {
			detail.ReferencedBy[i].SourceCatalog, detail.ReferencedBy[i].TargetCatalog = catalog, catalog
		}
	}
	return detail, err
}

func (d *sqlDb) NewWireServer(listen spi.Listen, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return d.provider.newServer(listen, d.config, client, d.provider.queries, tlsProvider)
}

func (d *sqlDb) NewRunSession(ctx context.Context, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Session, error) {
	return d.provider.newSession(ctx, d.config, d.provider.queries, authz, guard, readTimeout, defaultSchema)
}

func (d *sqlDb) Close() error { return d.pool.Close() }

var registry = spi.MustRegistry(
	athena.Provider{},
	sqlProvider{
		engine:     engines.MySQL,
		queries:    mysql.TargetSQL{},
		open:       mysql.OpenPool,
		probe:      mysql.ProbeNamespace,
		catalog:    func(context.Context, *sql.Conn) (string, error) { return "def", nil },
		readDetail: mysql.ReadTableDetail,
		newServer: func(listen spi.Listen, config spi.TargetConfig, client spi.ControlPlane, queries relay.Db, tlsProvider func() (*tls.Config, error)) spi.WireServer {
			return mysql.New(listen, config, client, queries, tlsProvider)
		},
		newSession: func(ctx context.Context, config spi.TargetConfig, queries relay.Db, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Session, error) {
			return mysql.NewRunSession(ctx, config, queries, authz, guard, readTimeout, defaultSchema)
		},
	},
	sqlProvider{
		engine:     engines.Postgres,
		queries:    db.PgDb{},
		open:       sqldb.OpenPostgresTarget,
		probe:      sqldb.ProbePostgresNamespace,
		catalog:    sqldb.ReadPostgresCatalog,
		readDetail: readPostgresTableDetail,
		newServer: func(listen spi.Listen, config spi.TargetConfig, client spi.ControlPlane, queries relay.Db, tlsProvider func() (*tls.Config, error)) spi.WireServer {
			return postgres.New(listen, config, client, queries, tlsProvider)
		},
		newSession: func(ctx context.Context, config spi.TargetConfig, queries relay.Db, authz *spi.Authorizer, guard spi.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.Session, error) {
			return postgres.NewRunSession(ctx, config, queries, authz, guard, readTimeout, defaultSchema)
		},
	},
)

// Registry returns the executable composition root's immutable provider registry.
func Registry() spi.Registry { return registry }

// For returns the registered provider for an engine.
func For(e *engines.Engine) (spi.Provider, error) { return registry.For(e) }

var (
	_ spi.Provider   = sqlProvider{}
	_ spi.Target     = (*sqlDb)(nil)
	_ spi.Session    = (*mysql.RunSession)(nil)
	_ spi.Session    = (*postgres.RunSession)(nil)
	_ spi.WireServer = (*mysql.Server)(nil)
	_ spi.WireServer = (*postgres.Server)(nil)
)
