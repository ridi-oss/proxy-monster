package mysql

import (
	"context"
	"crypto/tls"
	"database/sql"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

// Provider is MySQL's spi.Provider.
type Provider struct{}

func (Provider) Engine() *engines.Engine { return engines.MySQL }

func (Provider) OpenTarget(config spi.TargetConfig) (spi.Target, error) {
	pool, info, err := sqldb.OpenPool(OpenPool, config)
	if err != nil {
		return nil, err
	}
	return &target{config: config, pool: pool, info: info}, nil
}

// target is one open MySQL target; its pool serves introspection and table detail.
type target struct {
	config spi.TargetConfig
	pool   *sql.DB
	info   *pb.ConnectionInfo
}

func (t *target) Config() spi.TargetConfig { return t.config }

func (t *target) ConnectionInfo() *pb.ConnectionInfo { return t.info }

func (t *target) Introspect(ctx context.Context) (*pb.CatalogRequest, error) {
	return sqldb.Introspect(ctx, t.pool, Queries, ProbeNamespace, t.config.Db)
}

func (t *target) ReadTableDetail(ctx context.Context, table *enginepb.ObjectRef) (*spi.TableDetail, error) {
	return sqldb.ReadTableDetail(ctx, t.pool, Queries, readCatalog, readMySQLTableDetail, table)
}

// readCatalog is MySQL's one catalog, whatever the database.
func readCatalog(context.Context, *sql.Conn) (string, error) {
	return engines.MySQL.CatalogName("").String(), nil
}

func (t *target) NewWireServer(listen spi.Listen, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return newServer(listen, t, client, tlsProvider)
}

func (t *target) Close() error { return t.pool.Close() }

var (
	_ spi.Provider   = Provider{}
	_ spi.Target     = (*target)(nil)
	_ spi.Connection = (*connection)(nil)
	_ spi.WireServer = (*Server)(nil)
)
