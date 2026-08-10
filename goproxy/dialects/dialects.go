// Package dialects wires concrete per-dialect implementations behind the proxy SPI.
package dialects

import (
	"context"
	"crypto/tls"
	"database/sql"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/db"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/mysqlproxy"
	"github.com/ridi-oss/proxy-monster/goproxy/pgproxy"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

type mysqlProvider struct{}
type pgProvider struct{}

func (mysqlProvider) Dialect() engine.Dialect { return engine.MySQL }
func (mysqlProvider) NewDb() engine.Db        { return db.MySqlDb{} }
func (mysqlProvider) OpenTarget(target spi.BackendTarget) (*sql.DB, error) {
	return introspect.OpenMySQLTarget(target)
}
func (mysqlProvider) ProbeNamespace(conn *sql.Conn, targetDb string) ([]string, *int32, error) {
	return introspect.ProbeMySQLNamespace(conn, targetDb)
}
func (p mysqlProvider) ReadTableDetail(conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	exists, err := tableDetailTableExists(conn, p, schema, table)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return readMySQLTableDetail(conn, schema, table)
}
func (mysqlProvider) NewWireServer(port int, backend spi.BackendTarget, client spi.EnforcementClient, dbImpl engine.Db, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return mysqlproxy.New(port, backend, client, dbImpl, tlsProvider)
}
func (mysqlProvider) NewRunSession(ctx context.Context, target spi.BackendTarget, dbImpl engine.Db, client spi.SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (spi.BackendSession, error) {
	return mysqlproxy.NewRunSession(ctx, target, dbImpl, client, token, connectionID, guard, readTimeout)
}

func (pgProvider) Dialect() engine.Dialect { return engine.Postgres }
func (pgProvider) NewDb() engine.Db        { return db.PgDb{} }
func (pgProvider) OpenTarget(target spi.BackendTarget) (*sql.DB, error) {
	return introspect.OpenPostgresTarget(target)
}
func (pgProvider) ProbeNamespace(conn *sql.Conn, targetDb string) ([]string, *int32, error) {
	return introspect.ProbePostgresNamespace(conn, targetDb)
}
func (p pgProvider) ReadTableDetail(conn *sql.Conn, schema, table string) (*spi.TableDetail, error) {
	exists, err := tableDetailTableExists(conn, p, schema, table)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return readPostgresTableDetail(conn, schema, table)
}
func (pgProvider) NewWireServer(port int, backend spi.BackendTarget, client spi.EnforcementClient, dbImpl engine.Db, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return pgproxy.New(port, backend, client, dbImpl, tlsProvider)
}
func (pgProvider) NewRunSession(ctx context.Context, target spi.BackendTarget, dbImpl engine.Db, client spi.SessionClient, token string, connectionID []byte, guard engine.ExecGuard, readTimeout time.Duration) (spi.BackendSession, error) {
	return pgproxy.NewRunSession(ctx, target, dbImpl, client, token, connectionID, guard, readTimeout)
}

var registry = spi.MustRegistry(mysqlProvider{}, pgProvider{})

// Registry returns the executable composition root's immutable provider registry.
func Registry() spi.Registry { return registry }

// For returns the registered provider for a canonical dialect key.
func For(dialect engine.Dialect) (spi.Provider, error) { return registry.For(dialect) }

var (
	_ spi.Provider       = mysqlProvider{}
	_ spi.Provider       = pgProvider{}
	_ spi.BackendSession = (*mysqlproxy.RunSession)(nil)
	_ spi.BackendSession = (*pgproxy.RunSession)(nil)
	_ spi.WireServer     = (*mysqlproxy.Server)(nil)
	_ spi.WireServer     = (*pgproxy.Server)(nil)
)
