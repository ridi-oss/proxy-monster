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
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/postgres"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const tableDetailConnectTimeout = 5 * time.Second

// sqlProvider is a database/sql-backed dialect: MySQL and PostgreSQL differ only in the functions below.
type sqlProvider struct {
	engine *engines.Engine
	db     relay.Db
	open   func(spi.TargetDb) (*sql.DB, error)
	probe  introspect.NamespaceProbe
	// catalog reads the connection's current catalog; MySQL pins "def", Postgres asks the server.
	catalog    func(context.Context, *sql.Conn) (string, error)
	readDetail func(*sql.Conn, string, string) (*spi.TableDetail, error)
	newServer  func(spi.Listen, spi.TargetDb, spi.ControlPlane, relay.Db, func() (*tls.Config, error)) spi.WireServer
	newSession func(context.Context, spi.TargetDb, relay.Db, spi.ControlPlane, string, []byte, relay.ExecGuard, time.Duration, string) (spi.TargetDbSession, error)
}

func (p sqlProvider) Engine() *engines.Engine { return p.engine }

func (p sqlProvider) NewDb(target spi.TargetDb) (spi.Db, error) {
	pool, err := p.open(target)
	if err != nil {
		return nil, err
	}
	// Metadata reads must observe the defaults a new target session would inherit.
	pool.SetMaxIdleConns(0)
	advertise, _ := os.LookupEnv("PM_ADVERTISE_ADDR")
	return &sqlDb{provider: p, target: target, pool: pool, endpoint: strings.TrimSpace(advertise)}, nil
}

// sqlDb is one open MySQL or PostgreSQL target: the pool serves introspection and table detail; the wire
// server and run sessions dial the target themselves with the same TargetDb.
type sqlDb struct {
	provider sqlProvider
	target   spi.TargetDb
	pool     *sql.DB
	endpoint string
}

func (d *sqlDb) TargetDb() spi.TargetDb { return d.target }

func (d *sqlDb) ConnectionInfo() *pb.ConnectionInfo { return &pb.ConnectionInfo{Endpoint: d.endpoint} }

func (d *sqlDb) Introspect(ctx context.Context) (*pb.CatalogRequest, error) {
	return introspect.Run(ctx, d.pool, d.provider.db, d.provider.probe, d.target.Db)
}

func (d *sqlDb) ReadTableDetail(ctx context.Context, table *enginepb.ObjectRef) (*spi.TableDetail, error) {
	if table == nil || table.Schema == "" || table.Table == "" {
		return nil, fmt.Errorf("table selector is incomplete")
	}
	connectCtx, cancel := context.WithTimeout(ctx, tableDetailConnectTimeout+tableDetailQueryTimeout)
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
	return d.provider.newServer(listen, d.target, client, d.provider.db, tlsProvider)
}

func (d *sqlDb) NewRunSession(ctx context.Context, client spi.ControlPlane, token string, connectionID []byte, guard relay.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.TargetDbSession, error) {
	return d.provider.newSession(ctx, d.target, d.provider.db, client, token, connectionID, guard, readTimeout, defaultSchema)
}

func (d *sqlDb) Close() error { return d.pool.Close() }

var registry = spi.MustRegistry(
	athena.Provider{},
	sqlProvider{
		engine:     engines.MySQL,
		db:         db.MySqlDb{},
		open:       introspect.OpenMySQLTarget,
		probe:      introspect.ProbeMySQLNamespace,
		catalog:    func(context.Context, *sql.Conn) (string, error) { return "def", nil },
		readDetail: readMySQLTableDetail,
		newServer: func(listen spi.Listen, target spi.TargetDb, client spi.ControlPlane, db relay.Db, tlsProvider func() (*tls.Config, error)) spi.WireServer {
			return mysql.New(listen, target, client, db, tlsProvider)
		},
		newSession: func(ctx context.Context, target spi.TargetDb, db relay.Db, client spi.ControlPlane, token string, connectionID []byte, guard relay.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.TargetDbSession, error) {
			return mysql.NewRunSession(ctx, target, db, client, token, connectionID, guard, readTimeout, defaultSchema)
		},
	},
	sqlProvider{
		engine:     engines.Postgres,
		db:         db.PgDb{},
		open:       introspect.OpenPostgresTarget,
		probe:      introspect.ProbePostgresNamespace,
		catalog:    introspect.ReadPostgresCatalog,
		readDetail: readPostgresTableDetail,
		newServer: func(listen spi.Listen, target spi.TargetDb, client spi.ControlPlane, db relay.Db, tlsProvider func() (*tls.Config, error)) spi.WireServer {
			return postgres.New(listen, target, client, db, tlsProvider)
		},
		newSession: func(ctx context.Context, target spi.TargetDb, db relay.Db, client spi.ControlPlane, token string, connectionID []byte, guard relay.ExecGuard, readTimeout time.Duration, defaultSchema string) (spi.TargetDbSession, error) {
			return postgres.NewRunSession(ctx, target, db, client, token, connectionID, guard, readTimeout, defaultSchema)
		},
	},
)

// Registry returns the executable composition root's immutable provider registry.
func Registry() spi.Registry { return registry }

// For returns the registered provider for an engine.
func For(e *engines.Engine) (spi.Provider, error) { return registry.For(e) }

var (
	_ spi.Provider        = sqlProvider{}
	_ spi.Db              = (*sqlDb)(nil)
	_ spi.TargetDbSession = (*mysql.RunSession)(nil)
	_ spi.TargetDbSession = (*postgres.RunSession)(nil)
	_ spi.WireServer      = (*mysql.Server)(nil)
	_ spi.WireServer      = (*postgres.Server)(nil)
)
