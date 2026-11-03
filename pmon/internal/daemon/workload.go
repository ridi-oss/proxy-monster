package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/login"
	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
	"github.com/ridi-oss/proxy-monster/pmon/internal/workload"
)

var parseWorkloadSource = workload.Parse

func (d *Daemon) exchangeWorkload(ctx context.Context, srv *state.Server, spec, audience string) (*login.WorkloadResult, error) {
	source, err := parseWorkloadSource(spec)
	if err != nil {
		return nil, err
	}
	if audience == "" {
		if audience, err = workload.Audience(srv.ControlPlane); err != nil {
			return nil, err
		}
	}
	jwt, err := source.Token(ctx, audience)
	if err != nil {
		return nil, err
	}
	return login.ExchangeWorkload(ctx, d.httpClient, srv.ControlPlane, jwt)
}

func (d *Daemon) workloadLogin(ctx context.Context, name string, srv *state.Server, req control.LoginRequest, onEvent func(control.LoginEvent)) error {
	res, err := d.exchangeWorkload(ctx, srv, req.Workload, req.Audience)
	if err != nil {
		return err
	}
	serverMu := lockOf(&d.serverMus, name)
	serverMu.Lock()
	err = d.commit(func(c *state.Config) error {
		live := c.Servers[name]
		if live == nil || live.ID != srv.ID || live.ControlPlane != srv.ControlPlane {
			return fmt.Errorf("server %q changed while logging in; log in again", name)
		}
		live.ClearLogin()
		live.Principal = res.Principal()
		live.Token = res.Token
		live.ExpiresAt = res.ExpiresAt
		live.IssuedAt = time.Now().UTC().Format(time.RFC3339)
		live.Workload = req.Workload
		live.Audience = req.Audience
		return nil
	})
	if err == nil {
		d.mu.Lock()
		delete(d.reauthRequired, name)
		d.mu.Unlock()
	}
	serverMu.Unlock()
	if err != nil {
		return fmt.Errorf("could not save the login: %w", err)
	}
	replacedEnded := srv.RenewalToken == "" || d.endOnServer(srv, true)
	onEvent(control.LoginEvent{Kind: "done", Server: name, Principal: res.Principal(), ExpiresAt: res.ExpiresAt,
		ReplacedNotEndedOnServer: !replacedEnded})
	d.openListeners(ctx)
	d.publishStatus()
	return nil
}

func (d *Daemon) renewWorkload(ctx context.Context, name string, srv state.Server) {
	res, err := d.exchangeWorkload(ctx, &srv, srv.Workload, srv.Audience)
	if err != nil {
		var apiErr *login.APIError
		if errors.As(err, &apiErr) {
			err = fmt.Errorf("%w (%s)", err, cmp.Or(apiErr.Code, "no code"))
		}
		fmt.Fprintf(os.Stderr, "workload token renewal for %q failed (will retry): %v\n", name, err)
		return
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339)
	if err := d.commit(func(c *state.Config) error {
		s := c.Servers[name]
		if !state.SameSession(&srv, s) {
			return nil
		}
		s.Principal = res.Principal()
		s.Token = res.Token
		s.ExpiresAt = res.ExpiresAt
		s.IssuedAt = issuedAt
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, "could not save the renewed token:", err)
		return
	}
	d.publishStatus()
}
