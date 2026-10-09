package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// serverCmd manages the control planes pmon logs in to. A command that names no server addresses the default one.
type serverCmd struct {
	Set     serverSetCmd     `cmd:"" help:"Create a server or change its URL (logs it out if the URL changes)."`
	Unset   serverUnsetCmd   `cmd:"" help:"Log a server out and delete it."`
	Default serverDefaultCmd `cmd:"" help:"Print the default server, or make another one the default."`
	List    serverListCmd    `cmd:"" default:"withargs" help:"List the servers."`
}

type serverSetCmd struct {
	Name string `arg:"" optional:"" help:"Server name (default: the server at this URL, else the name the server advertises)."`
	URL  string `required:"" help:"Control-plane base URL."`
}

func (c *serverSetCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if err := requireNamingDaemon(s, c.Name); err != nil {
		return err
	}
	res, err := client.SetServer(ctx, control.SetServerRequest{Name: c.Name, ControlPlane: c.URL})
	if err != nil {
		return err
	}
	if res.Name == "" { // a daemon that predates reporting it; requireNamingDaemon made sure c.Name is set
		res.Name, res.Default = c.Name, c.Name == s.DefaultServer
	}
	if res.NotEndedOnServer {
		warnNotEnded(res.Name)
	}
	hint := loginHint(res.Name, res.Default)
	switch {
	case res.Created:
		fmt.Printf("server %q set to %s — run `%s` to log in\n", res.Name, c.URL, hint)
	case res.LoggedOut:
		fmt.Printf("server %q moved to %s and logged out — run `%s` to log in\n", res.Name, c.URL, hint)
	case res.Changed:
		fmt.Printf("server %q set to %s\n", res.Name, c.URL)
	default:
		fmt.Printf("server %q is already %s\n", res.Name, c.URL)
	}
	return nil
}

type serverUnsetCmd struct {
	Name  string `arg:"" optional:"" help:"Server name (default: the default server)."`
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
	name, err := serverOrDefault(s, c.Name)
	if err != nil {
		return err
	}
	if !c.Force && !confirmDrop(s.ServerLiveConns(name), "Delete the server anyway?") {
		fmt.Printf("left server %q in place\n", name)
		return nil
	}
	notEnded, err := client.UnsetServer(ctx, control.UnsetServerRequest{Name: name})
	if err != nil {
		return err
	}
	warnNotEnded(notEnded...)
	fmt.Printf("server %q deleted\n", name)
	return nil
}

// serverDefaultCmd is `pmon server default [name]`: the server a command addresses when it names none.
type serverDefaultCmd struct {
	Name string `arg:"" optional:"" help:"Server to make the default."`
}

func (c *serverDefaultCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	if c.Name == "" {
		s, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if s.Server(s.DefaultServer) == nil {
			return errors.New("no default server — pick one with `pmon server default <name>`")
		}
		fmt.Println(s.DefaultServer)
		return nil
	}
	if err := client.SetDefault(ctx, control.SetDefaultRequest{Name: c.Name}); errors.Is(err, control.ErrUnknownRoute) {
		return errors.New("the running daemon predates `pmon server default` — run `pmon restart`")
	} else if err != nil {
		return err
	}
	fmt.Printf("server %q is now the default\n", c.Name)
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
		name := srv.Name
		if srv.Default {
			name += " (default)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, srv.ControlPlane, loginSummary(srv))
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

func warnNotEnded(servers ...string) {
	for _, name := range servers {
		fmt.Fprintf(os.Stderr, "warning: could not end the %q login on the server; it stays valid there until its TTL ends\n", name)
	}
}

// requireNamingDaemon refuses a URL given without a server name to a daemon that predates naming a server after
// its instance: that daemon reads it as the server called default, and would move that server and log it out.
func requireNamingDaemon(s *control.Status, name string) error {
	if name == "" && s.FixedDefault {
		return errors.New("the running daemon predates naming a server after its instance — name the server, or run `pmon restart`")
	}
	return nil
}

// serverOrDefault is name, or the default server when name is empty, as long as it is configured.
func serverOrDefault(s *control.Status, name string) (string, error) {
	switch {
	case name == "" && s.Server(s.DefaultServer) == nil:
		return "", errors.New("no default server — name one, or pick one with `pmon server default <name>`")
	case name == "":
		return s.DefaultServer, nil
	case s.Server(name) == nil:
		return "", fmt.Errorf("unknown server %q", name)
	}
	return name, nil
}

// loginHint is the command that logs in to server; the default server needs no name.
func loginHint(server string, isDefault bool) string {
	if isDefault {
		return "pmon login"
	}
	return "pmon login " + server
}
