package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/ridi-oss/proxy-monster/pmon/internal/daemon"
)

// daemonCmd runs the daemon in the foreground. It is the exec target of `pmon start` (which spawns it
// detached) and the entry point for anyone who wants to supervise pmon themselves — a systemd unit, a
// container, or a terminal to watch it in.
type daemonCmd struct{}

func (daemonCmd) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return daemon.New(FullVersion()).Run(ctx)
}
