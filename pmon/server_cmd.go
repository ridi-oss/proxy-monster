package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// serverCmd manages the control planes pmon logs in to. A command that names no server addresses "default".
type serverCmd struct {
	Set   serverSetCmd   `cmd:"" help:"Create a server or change its URL (logs it out if the URL changes)."`
	Unset serverUnsetCmd `cmd:"" help:"Log a server out and delete it."`
	List  serverListCmd  `cmd:"" default:"withargs" help:"List the servers."`
}

type serverSetCmd struct {
	Name string `arg:"" optional:"" default:"default" help:"Server name."`
	URL  string `required:"" help:"Control-plane base URL."`
}

func (c *serverSetCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	res, err := client.SetServer(ctx, control.SetServerRequest{Name: c.Name, ControlPlane: c.URL})
	if err != nil {
		return err
	}
	switch {
	case res.Created:
		fmt.Printf("server %q set to %s — run `%s` to log in\n", c.Name, c.URL, loginHint(c.Name))
	case res.LoggedOut:
		fmt.Printf("server %q moved to %s and logged out — run `%s` to log in\n", c.Name, c.URL, loginHint(c.Name))
	case res.Changed:
		fmt.Printf("server %q set to %s\n", c.Name, c.URL)
	default:
		fmt.Printf("server %q is already %s\n", c.Name, c.URL)
	}
	return nil
}

type serverUnsetCmd struct {
	Name  string `arg:"" optional:"" default:"default" help:"Server name."`
	Force bool   `short:"f" help:"Delete without asking, even with connections open."`
}

func (c *serverUnsetCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if err := requireCurrentDaemon(s); err != nil {
		return err
	}
	if s.Server(c.Name) == nil {
		return fmt.Errorf("unknown server %q", c.Name)
	}
	if !c.Force && !confirmDrop(s.ServerLiveConns(c.Name), "Delete the server anyway?") {
		fmt.Printf("left server %q in place\n", c.Name)
		return nil
	}
	if err := client.UnsetServer(ctx, control.UnsetServerRequest{Name: c.Name}); err != nil {
		return err
	}
	fmt.Printf("server %q deleted\n", c.Name)
	return nil
}

type serverListCmd struct{}

func (serverListCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	warnVersionSkew(s)
	if err := requireCurrentDaemon(s); err != nil {
		return err
	}
	if len(s.Servers) == 0 {
		fmt.Println("no servers — add one with `pmon server set --url <control-plane-url>`")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tURL\tLOGIN")
	for _, srv := range s.Servers {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", srv.Name, srv.ControlPlane, loginSummary(srv))
	}
	return tw.Flush()
}

// loginSummary is a server's login state in one line.
func loginSummary(srv control.ServerInfo) string {
	switch {
	case !srv.LoggedIn:
		return "not logged in"
	case srv.ReauthRequired:
		return srv.Principal + " — reauth REQUIRED"
	default:
		return srv.Principal + " — token " + expiryLine(srv.ExpiresAt)
	}
}

// loginHint is the command that logs in to server.
func loginHint(server string) string {
	if server == state.DefaultServer {
		return "pmon login"
	}
	return "pmon login " + server
}
