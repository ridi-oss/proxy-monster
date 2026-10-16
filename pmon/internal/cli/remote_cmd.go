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
	Add       remoteAddCmd       `cmd:"" help:"Reach the pmon daemon on an SSH target (a Host alias, host, or user@host)."`
	Remove    remoteRemoveCmd    `cmd:"" help:"Close a remote's SSH connection and forget it."`
	Reconnect remoteReconnectCmd `cmd:"" help:"Try a remote that is not connected now, instead of after its wait."`
	List      remoteListCmd      `cmd:"" default:"withargs" help:"List the remotes."`
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

type remoteReconnectCmd struct {
	Target string `arg:"" help:"SSH target of the remote."`
}

func (c *remoteReconnectCmd) Run() error {
	ctx := context.Background()
	client, err := control.Connect(ctx)
	if err != nil {
		return err
	}
	if err := client.ReconnectRemote(ctx, c.Target); err != nil {
		return err
	}
	fmt.Printf("reconnecting to %q — `pmon remote` shows when it connects\n", c.Target)
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

// remoteTarget is the SSH target under --remote, else "".
var remoteTarget string

// self is how hints name this program: "pmon", or "pmon --remote <target>" for a command run against a remote.
var self = "pmon"

// useRemote points this command at the daemon on target, through the forwarded socket this machine's daemon
// keeps for it.
func useRemote(target string) error {
	if !control.ValidTarget(target) {
		return fmt.Errorf("%q is not an ssh target", target)
	}
	ctx := context.Background()
	local, err := control.Connect(ctx)
	if err != nil {
		return fmt.Errorf("--remote needs this machine's daemon, which keeps the ssh connection: %w", err)
	}
	s, err := local.Status(ctx)
	if err != nil {
		return err
	}
	for _, r := range s.Remotes {
		if r.Target != target {
			continue
		}
		switch r.State {
		case control.RemoteConnected, control.RemoteNoDaemon, control.RemoteNoPmon:
			control.UseRemote(r)
			self = "pmon --remote " + target
			remoteTarget = target
			return nil
		case control.RemoteConnecting:
			return fmt.Errorf("remote %q is still connecting — try again in a moment", target)
		default:
			return fmt.Errorf("remote %q is %s: %s", target, r.State, r.Error)
		}
	}
	return fmt.Errorf("%q is not a remote — `pmon remote add %s` adds it", target, target)
}
