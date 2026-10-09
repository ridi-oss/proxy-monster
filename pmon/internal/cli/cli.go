package cli

import "github.com/alecthomas/kong"

// version is what this binary reports: `pmon --version`, the daemon's /status, and the skew warning.
var version string

// root is the kong grammar for pmon's subcommands (matching goproxy's kong usage, kept consistent across the
// repo rather than hand-rolled flag sets).
type root struct {
	Server  serverCmd  `cmd:"" help:"Manage the servers pmon logs in to."`
	Login   loginCmd   `cmd:"" help:"Authenticate in your browser; starts the daemon and opens the brokers."`
	Logout  logoutCmd  `cmd:"" help:"Clear a server's credentials and close its brokers (the daemon stays up)."`
	Show    showCmd    `cmd:"" help:"Print one datasource's local connection string."`
	Status  statusCmd  `cmd:"" help:"Show the daemon's state: every server's login and brokered datasources."`
	MCP     mcpCmd     `cmd:"" name:"mcp" help:"Run a local stdio MCP server that relays to the server's MCP endpoint over the pmon login; with --install, register it with the AI apps on this machine."`
	Start   startCmd   `cmd:"" help:"Start the daemon (no-op if one is already running)."`
	Stop    stopCmd    `cmd:"" help:"Stop the daemon."`
	Restart restartCmd `cmd:"" help:"Stop the daemon and start a fresh one."`
	Daemon  daemonCmd  `cmd:"" hidden:"" help:"Run the daemon in the foreground (the exec target of 'pmon start')."`
	Ver     versionCmd `cmd:"" name:"version" help:"Print the version of pmon, of its daemon, and of each server."`

	Version kong.VersionFlag `help:"Print the version and exit." short:"V"`
}

// Main parses the command line and runs the chosen command, reporting v as this binary's version.
func Main(v string) {
	version = v
	var r root
	ctx := kong.Parse(&r,
		kong.Name("pmon"),
		kong.Description("proxy-monster connector — reach a datasource on a stable local port with a password that never changes."),
		kong.UsageOnError(),
		kong.Vars{"version": version},
	)
	ctx.FatalIfErrorf(ctx.Run())
}
