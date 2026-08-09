// Package pgproxy is the blocking PostgreSQL wire broker for the simple and extended query protocols.
// It owns only wire I/O and mechanically applies engine verdicts; authorization remains exclusively in
// engine.QueryEngine. COPY is deferred to a later phase.
package pgproxy

import (
	"crypto/tls"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

// Server is the PostgreSQL wire broker: the shared wire.Server lifecycle (accept loop, connection tracking,
// graceful drain) plus this protocol's per-connection handler and its backend/enforcement dependencies.
type Server struct {
	*wire.Server
	backend     spi.BackendTarget
	client      spi.EnforcementClient
	db          engine.Db
	tlsProvider func() (*tls.Config, error)
}

// New constructs a PostgreSQL wire broker for one backend datasource.
func New(port int, backend spi.BackendTarget, client spi.EnforcementClient, dbImpl engine.Db, tlsProvider func() (*tls.Config, error)) *Server {
	s := &Server{backend: backend, client: client, db: dbImpl, tlsProvider: tlsProvider}
	s.Server = wire.New(port, "pgproxy", s.handleConn)
	return s
}
