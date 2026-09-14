// Package dialects wires concrete per-dialect implementations behind the proxy SPI.
package dialects

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/dialects/athena"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/mysqlproxy"
	"github.com/ridi-oss/proxy-monster/goproxy/pgproxy"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqltarget"
)

type sqlProvider struct {
	catalog           func(context.Context, *sql.Conn) (string, error)
	defaultTargetPort int
	definition        spi.Definition
	dialect           engine.Dialect
	db                engine.Db
	open              func(sqltarget.Config) (*sql.DB, error)
	probe             introspect.NamespaceProbe
	readDetail        func(context.Context, *sql.Conn, string, string) (*spi.TableDetail, error)
	newServer         func(sqltarget.Config, engine.Db, spi.NativeServerOptions) spi.WireServer
	newSession        func(context.Context, sqltarget.Config, engine.Db, spi.RunSessionOptions) (spi.TargetDbSession, error)
}

func (p sqlProvider) Definition() spi.Definition { return p.definition }

func (p sqlProvider) Configure(lookup spi.LookupEnv) (spi.Target, error) {
	config := sqltarget.Configure(lookup, p.defaultTargetPort)
	endpoint, _ := lookup("PM_ADVERTISE_ADDR")
	pool, err := p.open(config)
	if err != nil {
		return nil, err
	}
	// Metadata reads must observe the defaults a new target session would inherit.
	pool.SetMaxIdleConns(0)
	return &sqlTarget{provider: p, config: config, pool: pool, endpoint: strings.TrimSpace(endpoint)}, nil
}

type sqlTarget struct {
	endpoint string
	provider sqlProvider
	config   sqltarget.Config
	pool     *sql.DB
}

func (t *sqlTarget) ReadCatalog(ctx context.Context) (*pb.CatalogRequest, error) {
	return introspect.ReadCatalog(ctx, t.pool, t.provider.db, t.provider.probe, t.config.Db)
}

func (t *sqlTarget) ReadTableDetail(ctx context.Context, selector *enginepb.TableRef) (*spi.TableDetail, error) {
	if selector == nil || selector.GetSchema() == "" || selector.GetTable() == "" {
		return nil, fmt.Errorf("table selector is incomplete")
	}
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second+tableDetailQueryTimeout)
	defer cancel()
	conn, err := t.pool.Conn(connectCtx)
	if err != nil {
		return nil, fmt.Errorf("connecting to target: %w", err)
	}
	defer conn.Close()
	catalog, err := t.provider.catalog(ctx, conn)
	if err != nil {
		return nil, err
	}
	if selector.Catalog != "" && selector.Catalog != catalog {
		return nil, fmt.Errorf("table catalog %q does not match target catalog %q", selector.Catalog, catalog)
	}
	schema := selector.Schema
	if selector.Catalog == "" {
		schema = t.provider.dialect.ResolveSchema(schema, t.config.Db)
	}
	exists, err := tableDetailTableExists(ctx, conn, t.provider.dialect, schema, selector.Table)
	if err != nil || !exists {
		return nil, err
	}
	detail, err := t.provider.readDetail(ctx, conn, schema, selector.Table)
	if detail != nil {
		detail.Catalog = &catalog
		for i := range detail.ForeignKeys {
			detail.ForeignKeys[i].SourceCatalog, detail.ForeignKeys[i].TargetCatalog = &catalog, &catalog
		}
		for i := range detail.ReferencedBy {
			detail.ReferencedBy[i].SourceCatalog, detail.ReferencedBy[i].TargetCatalog = &catalog, &catalog
		}
	}
	return detail, err
}

func (t *sqlTarget) TargetInfo() spi.TargetInfo {
	return spi.TargetInfo{Host: t.config.Host, Port: t.config.Port, Database: t.config.Db}
}

func (t *sqlTarget) ConnectionInfo() *pb.ConnectionInfo {
	return &pb.ConnectionInfo{Endpoint: t.endpoint}
}

func (t *sqlTarget) NewNativeServer(options spi.NativeServerOptions) spi.WireServer {
	return t.provider.newServer(t.config, t.provider.db, options)
}

func (t *sqlTarget) NewRunSession(ctx context.Context, options spi.RunSessionOptions) (spi.TargetDbSession, error) {
	return t.provider.newSession(ctx, t.config, t.provider.db, options)
}

func (t *sqlTarget) Close() error { return t.pool.Close() }

var registry = spi.MustRegistry(
	athena.Provider{},
	sqlProvider{
		definition:        spi.Definition{Name: "mysql", Engine: engine.MySQL.Proto(), DefaultProxyPort: 6033},
		dialect:           engine.MySQL,
		defaultTargetPort: 3307,
		catalog:           func(context.Context, *sql.Conn) (string, error) { return "def", nil },
		db:                db.MySqlDb{},
		open:              introspect.OpenMySQLTarget,
		probe:             introspect.ProbeMySQLNamespace,
		readDetail:        readMySQLTableDetail,
		newServer: func(target sqltarget.Config, db engine.Db, options spi.NativeServerOptions) spi.WireServer {
			return mysqlproxy.New(options.Port, target, options.Client, db, options.TLSProvider)
		},
		newSession: func(ctx context.Context, target sqltarget.Config, db engine.Db, options spi.RunSessionOptions) (spi.TargetDbSession, error) {
			return mysqlproxy.NewRunSession(ctx, target, db, options.Client, options.Token, options.ConnectionID, options.Guard, options.ReadTimeout)
		},
	},
	sqlProvider{
		definition:        spi.Definition{Name: "postgres", Engine: engine.Postgres.Proto(), DefaultProxyPort: 6432},
		dialect:           engine.Postgres,
		defaultTargetPort: 5433,
		catalog:           introspect.ReadPostgresCatalog,
		db:                db.PgDb{},
		open:              introspect.OpenPostgresTarget,
		probe:             introspect.ProbePostgresNamespace,
		readDetail:        readPostgresTableDetail,
		newServer: func(target sqltarget.Config, db engine.Db, options spi.NativeServerOptions) spi.WireServer {
			return pgproxy.New(options.Port, target, options.Client, db, options.TLSProvider)
		},
		newSession: func(ctx context.Context, target sqltarget.Config, db engine.Db, options spi.RunSessionOptions) (spi.TargetDbSession, error) {
			return pgproxy.NewRunSession(ctx, target, db, options.Client, options.Token, options.ConnectionID, options.Guard, options.ReadTimeout)
		},
	},
)

func Registry() spi.Registry { return registry }

func For(dialect engine.Dialect) (spi.Provider, error) { return registry.For(dialect.WireName()) }

var (
	_ spi.Provider        = sqlProvider{}
	_ spi.Target          = (*sqlTarget)(nil)
	_ spi.TargetDbSession = (*mysqlproxy.RunSession)(nil)
	_ spi.TargetDbSession = (*pgproxy.RunSession)(nil)
	_ spi.WireServer      = (*mysqlproxy.Server)(nil)
	_ spi.WireServer      = (*pgproxy.Server)(nil)
)
