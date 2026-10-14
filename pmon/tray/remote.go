package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// remoteWatcher follows one remote daemon through its forwarded socket.
type remoteWatcher struct {
	socket string
	stop   context.CancelFunc
}

// noticeRemoteDrops notifies once when a remote that was connected loses its connection.
func (a *app) noticeRemoteDrops(s *control.Status) {
	now := map[string]control.RemoteInfo{}
	if s != nil {
		for _, r := range s.Remotes {
			now[r.Target] = r
		}
	}
	a.mu.Lock()
	prev := a.remoteStates
	a.remoteStates = map[string]control.RemoteState{}
	for target, r := range now {
		a.remoteStates[target] = r.State
	}
	a.mu.Unlock()
	for target, r := range now {
		if prev[target] == control.RemoteConnected && (r.State == control.RemoteDown || r.State == control.RemoteConnecting) {
			notify(T("n.remoteDown", "remote", target), r.Error)
		}
	}
}

// watchRemotes runs one watcher per remote whose socket is forwarded, and drops the rest with their status.
func (a *app) watchRemotes(s *control.Status) {
	want := map[string]string{}
	if s != nil {
		for _, r := range s.Remotes {
			if r.Socket != "" {
				want[r.Target] = r.Socket
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.remoteWatch == nil {
		a.remoteWatch, a.remotes = map[string]remoteWatcher{}, map[string]*control.Status{}
	}
	for target, w := range a.remoteWatch {
		if want[target] != w.socket {
			w.stop()
			delete(a.remoteWatch, target)
			delete(a.remotes, target)
		}
	}
	for target, socket := range want {
		if _, ok := a.remoteWatch[target]; ok {
			continue
		}
		ctx, stop := context.WithCancel(a.ctx)
		a.remoteWatch[target] = remoteWatcher{socket: socket, stop: stop}
		go a.followRemote(ctx, target, socket)
	}
}

// followRemote keeps a remote's status current from its event stream, retrying while its daemon is down.
func (a *app) followRemote(ctx context.Context, target, socket string) {
	for ctx.Err() == nil {
		_ = control.NewClientAt(socket).Events(ctx, func(ev control.Event) {
			switch {
			case ev.Kind == "status" && ev.Status != nil:
				a.setRemoteStatus(ctx, target, ev.Status)
			case ev.Kind == "shutdown":
				a.setRemoteStatus(ctx, target, nil)
			default:
				if s, err := control.NewClientAt(socket).Status(ctx); err == nil {
					a.setRemoteStatus(ctx, target, s)
				}
			}
		})
		if ctx.Err() != nil {
			return
		}
		a.setRemoteStatus(ctx, target, nil)
		if !a.sleep(reconnectDelay) {
			return
		}
	}
}

func (a *app) setRemoteStatus(ctx context.Context, target string, s *control.Status) {
	a.renderMu.Lock()
	defer a.renderMu.Unlock()
	a.mu.Lock()
	if ctx.Err() == nil && a.remotes != nil {
		if s == nil {
			delete(a.remotes, target)
		} else {
			a.remotes[target] = s
		}
	}
	a.mu.Unlock()
	a.redraw()
}

// remoteClient is a client of a remote daemon through the socket this machine's daemon forwards for it.
func (a *app) remoteClient(target string) (*control.Client, error) {
	a.mu.Lock()
	s := a.status
	a.mu.Unlock()
	return remoteClientIn(s, target)
}

// remoteClientIn is remoteClient for the remotes of status s.
func remoteClientIn(s *control.Status, target string) (*control.Client, error) {
	if s != nil {
		for _, r := range s.Remotes {
			if r.Target == target && r.Socket != "" {
				return control.NewRemoteClient(r), nil
			}
		}
	}
	return nil, fmt.Errorf("%s is not connected", target)
}

// clientFor is the client of the daemon an action goes to: this machine's, started if needed, or a remote's.
func (a *app) clientFor(remote string) (*control.Client, error) {
	if remote == "" {
		return control.EnsureDaemon(a.ctx)
	}
	return a.remoteClient(remote)
}

// refreshFor re-reads the status of the daemon an action went to.
func (a *app) refreshFor(remote string, client *control.Client) {
	if remote == "" {
		a.refresh(client)
		return
	}
	if s, err := client.Status(a.ctx); err == nil {
		a.setRemoteStatus(a.ctx, remote, s)
	} else if errors.Is(err, control.ErrDaemonNotRunning) {
		a.setRemoteStatus(a.ctx, remote, nil)
	}
}
