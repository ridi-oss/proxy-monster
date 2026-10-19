// Package postgres is the blocking PostgreSQL wire broker for the simple and extended query protocols.
// It owns only wire I/O and mechanically applies engine verdicts; authorization remains exclusively in
// spi.Authorizer. COPY is deferred to a later phase.
package postgres

import (
	"crypto/tls"

	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

// Server is the PostgreSQL wire broker: the shared wire.Server lifecycle (accept loop, connection tracking,
// graceful drain) plus this protocol's per-connection handler and its target DB/enforcement dependencies.
type Server struct {
	*wire.Server
	config      spi.TargetConfig
	client      spi.ControlPlane
	db          relay.Db
	tlsProvider func() (*tls.Config, error)
}

// New constructs a PostgreSQL wire broker for one target DB datasource.
func New(listen spi.Listen, config spi.TargetConfig, client spi.ControlPlane, dbImpl relay.Db, tlsProvider func() (*tls.Config, error)) *Server {
	s := &Server{config: config, client: client, db: dbImpl, tlsProvider: tlsProvider}
	s.Server = wire.New(listen, "pgproxy", s.handleConn)
	return s
}
