package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// startCmd starts the daemon if none is running. Symmetric with the menu-bar app's Start: both call the same
// [control.EnsureDaemon], so start-if-needed has one implementation.
type startCmd struct{}

func (startCmd) Run() error {
	ctx := context.Background()
	if _, err := control.Connect(ctx); err == nil {
		fmt.Println("the daemon is already running")
		return nil
	}
	c, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := c.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Println("daemon started — " + loginLine(s))
	return nil
}

// stopCmd stops the daemon. It warns before dropping live connections: the daemon is a shared resource and
// either peer can stop it, so the honest guard is telling the user what they are about to break rather than
// tracking who started it.
type stopCmd struct {
	Force bool `short:"f" help:"Stop without asking, even with connections open."`
}

func (c *stopCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		fmt.Println("the daemon is not running")
		return nil
	}
	if !c.Force {
		if s, err := client.Status(ctx); err == nil && !confirmDrop(s.TotalLiveConns(), "Stop anyway?") {
			fmt.Println("left the daemon running")
			return nil
		}
	}
	if err := control.StopDaemon(ctx); err != nil {
		if errors.Is(err, control.ErrDaemonNotRunning) {
			fmt.Println("the daemon is not running")
			return nil
		}
		return err
	}
	fmt.Println("daemon stopped")
	return nil
}

// restartCmd stops a running daemon and starts a fresh one.
type restartCmd struct {
	Force bool `short:"f" help:"Restart without asking, even with connections open."`
}

func (c *restartCmd) Run() error {
	ctx := context.Background()
	if client, err := control.Connect(ctx); err == nil {
		if !c.Force {
			if s, err := client.Status(ctx); err == nil && !confirmDrop(s.TotalLiveConns(), "Restart anyway?") {
				fmt.Println("left the daemon running")
				return nil
			}
		}
		if err := control.StopDaemon(ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
			return err
		}
	}
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Println("daemon restarted — " + loginLine(s))
	return nil
}

// logoutCmd clears a server's credentials and closes its brokers, leaving the daemon up.
type logoutCmd struct {
	Server string `arg:"" optional:"" default:"default" help:"Server to log out of."`
	All    bool   `help:"Log out of every server."`
	Force  bool   `short:"f" help:"Log out without asking, even with connections open."`
}

func (c *logoutCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		fmt.Println("the daemon is not running — nothing to log out of")
		return nil
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	conns := s.TotalLiveConns()
	if !c.All {
		if s.Server(c.Server) == nil {
			return fmt.Errorf("unknown server %q", c.Server)
		}
		conns = s.ServerLiveConns(c.Server)
	}
	if !c.Force && !confirmDrop(conns, "Log out anyway?") {
		fmt.Println("still logged in")
		return nil
	}
	if err := client.Logout(ctx, control.LogoutRequest{Server: c.Server, All: c.All}); err != nil {
		return err
	}
	if c.All {
		fmt.Println("logged out of every server — the brokers are closed and the daemon is idle")
	} else {
		fmt.Printf("logged out of %q — its brokers are closed\n", c.Server)
	}
	return nil
}

// loginLine summarizes which servers are logged in, for start/restart.
func loginLine(s *control.Status) string {
	servers := s.LoggedInServers()
	if len(servers) == 0 {
		return "not logged in; run `pmon login`"
	}
	parts := make([]string, 0, len(servers))
	for _, srv := range servers {
		parts = append(parts, fmt.Sprintf("%s as %s", srv.Name, srv.Principal))
	}
	return fmt.Sprintf("logged in to %s, %d datasource(s) brokered", strings.Join(parts, ", "), brokeredCount(s, ""))
}

// stdinIsTerminal reports whether stdin is a character device, i.e. someone is there to answer. Done with a
// mode check rather than an isatty dependency: pmon stays a pure-Go binary with no library it does not need.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// brokeredCount counts brokered datasources on server, or on every server when server is empty.
func brokeredCount(s *control.Status, server string) int {
	n := 0
	for _, ds := range s.Datasources {
		if ds.Brokered && (server == "" || ds.Server == server) {
			n++
		}
	}
	return n
}

// confirmDrop asks before dropping n live connections; with none open there is nothing to ask.
func confirmDrop(n int, question string) bool {
	return n == 0 || confirm(fmt.Sprintf("%d active connection(s) will be dropped. %s", n, question))
}

// confirm asks a yes/no question. With no terminal (a script, a hook) it answers NO, so an unattended run
// never silently drops someone's connections — `--force` is the explicit way through.
func confirm(question string) bool {
	if !stdinIsTerminal() {
		fmt.Fprintf(os.Stderr, "%s (no terminal to ask; refusing — pass --force)\n", question)
		return false
	}
	fmt.Printf("%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
