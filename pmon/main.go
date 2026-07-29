// Command pmon is the proxy-monster client connector. A background daemon holds a short-lived wire token and
// runs one loopback listener per datasource, injecting the token upstream — so a saved SQL connection uses a
// stable local port and a password that never changes.
//
// The daemon owns all state and logic and exposes a local control socket. This CLI and the menu-bar app are
// SYMMETRIC peers over that socket: neither is privileged, both can start and stop the daemon, and both work
// when it is down. Brokers come up as soon as credentials exist — logging in is the only step.
//
//	pmon login                 # device-auth in your browser; starts the daemon and opens the brokers
//	pmon show <ds>             # print a datasource's local connection string (--url default)
//	pmon status                # principal, token expiry, and every brokered datasource
//	pmon start | stop | restart
package main

import (
	"github.com/alecthomas/kong"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

func init() {
	// This binary understands `pmon daemon`, so it may start the daemon by re-exec'ing itself. Declared rather
	// than inferred from the filename: a release artifact or a symlinked install has a different basename, and a
	// peer that is a DIFFERENT program must never re-exec itself.
	control.SelfRunsDaemon = true
}

// cli is the kong grammar for pmon's subcommands (matching goproxy's kong usage, kept consistent across the
// repo rather than hand-rolled flag sets).
type cli struct {
	Login   loginCmd   `cmd:"" help:"Authenticate in your browser; starts the daemon and opens the brokers."`
	Logout  logoutCmd  `cmd:"" help:"Clear the stored credentials and close the brokers (the daemon stays up)."`
	Show    showCmd    `cmd:"" help:"Print one datasource's local connection string."`
	Status  statusCmd  `cmd:"" help:"Show the daemon's state: login, token expiry, brokered datasources."`
	Start   startCmd   `cmd:"" help:"Start the daemon (no-op if one is already running)."`
	Stop    stopCmd    `cmd:"" help:"Stop the daemon."`
	Restart restartCmd `cmd:"" help:"Stop the daemon and start a fresh one."`
	Daemon  daemonCmd  `cmd:"" hidden:"" help:"Run the daemon in the foreground (the exec target of 'pmon start')."`

	Version kong.VersionFlag `help:"Print the version and exit." short:"V"`
}

func main() {
	var c cli
	ctx := kong.Parse(&c,
		kong.Name("pmon"),
		kong.Description("proxy-monster connector — reach a datasource on a stable local port with a password that never changes."),
		kong.UsageOnError(),
		kong.Vars{"version": Version},
	)
	ctx.FatalIfErrorf(ctx.Run())
}
