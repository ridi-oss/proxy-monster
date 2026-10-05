// Command pmon is the proxy-monster client connector. A background daemon holds a short-lived wire token and
// runs one loopback listener per datasource, injecting the token upstream — so a saved SQL connection uses a
// stable local port and a password that never changes.
//
// The daemon owns all state and logic and exposes a local control socket. This CLI and the menu-bar app are
// SYMMETRIC peers over that socket: neither is privileged, both can start and stop the daemon, and both work
// when it is down. Brokers come up as soon as credentials exist — logging in is the only step.
//
//	pmon server set [name] --url U  # add a server ("default" unless named)
//	pmon login [name]               # device-auth in your browser; starts the daemon and opens the brokers
//	pmon show [name] <ds>           # print a datasource's local connection string (--url default)
//	pmon status                     # every server's login and brokered datasources
//	pmon mcp [name]                 # a stdio MCP server for an agent, over the pmon login
//	pmon start | stop | restart
package main

import (
	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/cli"
)

func init() {
	// This binary understands `pmon daemon`, so it may start the daemon by re-exec'ing itself. Declared rather
	// than inferred from the filename: a release artifact or a symlinked install has a different basename, and a
	// peer that is a DIFFERENT program must never re-exec itself.
	control.SelfRunsDaemon = true
}

func main() {
	cli.Main(FullVersion())
}
