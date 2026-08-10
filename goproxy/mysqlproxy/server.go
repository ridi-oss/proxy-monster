// Package mysqlproxy is the blocking MySQL wire broker. It runs the protocol path in one goroutine
// per connection. It owns only wire I/O and mechanically applies engine verdicts; authorization remains
// exclusively in engine.QueryEngine. Prepared statements are authorized at PREPARE and re-authorized on every
// EXECUTE against their frozen prepare-time namespace, so mid-session token, grant, or permit revocation fails
// closed on the next EXECUTE. Binary results relay only under that fresh verdict and its unmaskable permit.
package mysqlproxy

import (
	"crypto/tls"
	"sync/atomic"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
)

// Server is the MySQL wire broker: the shared wire.Server lifecycle (accept loop, connection tracking,
// graceful drain) plus this protocol's per-connection handler and its target DB/enforcement dependencies.
type Server struct {
	*wire.Server
	targetDb    spi.TargetDb
	client      spi.EnforcementClient
	db          engine.Db
	tlsProvider func() (*tls.Config, error)
	connID      atomic.Uint32
}

// New constructs a MySQL wire broker for one target DB datasource.
func New(port int, targetDb spi.TargetDb, client spi.EnforcementClient, dbImpl engine.Db, tlsProvider func() (*tls.Config, error)) *Server {
	s := &Server{targetDb: targetDb, client: client, db: dbImpl, tlsProvider: tlsProvider}
	s.Server = wire.New(port, "mysqlproxy", s.handleConn)
	return s
}
