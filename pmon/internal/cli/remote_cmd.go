package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

// remoteCmd manages the remotes: machines whose pmon daemons this daemon keeps an SSH connection to.
type remoteCmd struct {
	Add    remoteAddCmd    `cmd:"" help:"Reach the pmon daemon on an SSH target (a Host alias, host, or user@host)."`
	Remove remoteRemoveCmd `cmd:"" help:"Close a remote's SSH connection and forget it."`
	List   remoteListCmd   `cmd:"" default:"withargs" help:"List the remotes."`
}

type remoteAddCmd struct {
	Target string `arg:"" help:"SSH target; it is also the remote's name."`
}

func (c *remoteAddCmd) Run() error {
	ctx := context.Background()
	client, err := control.EnsureDaemon(ctx)
	if err != nil {
		return err
	}
	if err := client.AddRemote(ctx, c.Target); err != nil {
		return err
	}
	fmt.Printf("remote %q added — `pmon remote` shows when it connects\n", c.Target)
	return nil
}

type remoteRemoveCmd struct {
	Target string `arg:"" help:"SSH target of the remote."`
}

func (c *remoteRemoveCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		return err
	}
	if err := client.RemoveRemote(ctx, c.Target); err != nil {
		return err
	}
	fmt.Printf("remote %q removed\n", c.Target)
	return nil
}

type remoteListCmd struct{}

func (c *remoteListCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		return err
	}
	s, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if len(s.Remotes) == 0 {
		fmt.Println("no remotes — `pmon remote add <ssh-target>` adds one")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REMOTE\tSTATE\tDETAIL")
	for _, r := range s.Remotes {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Target, r.State, r.Error)
	}
	return w.Flush()
}

type socketCmd struct{}

func (c *socketCmd) Run() error {
	p, err := state.SocketPath()
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}
