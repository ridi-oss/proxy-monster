// Command controlplane is the proxy-monster control plane — the Go port of Kotlin's `Main.kt`.
//
// It reads the PM_* environment contract, migrates its Postgres store, builds the ONE shared
// enforcement graph, and serves two surfaces from one process: gRPC on PM_GRPC_PORT for the proxy,
// and HTTP on PM_HTTP_PORT for the console.
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §2.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/app"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/config"
)

// shutdownGrace bounds the HTTP drain on SIGTERM. The gRPC side has its own, larger, two-stage drain
// (grpcsvc.ShutdownGrace) because a long-lived Events stream never finishes on its own.
const shutdownGrace = 10 * time.Second

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// STEP 1 — the environment contract, read ONCE through the injected lookup. config.OSEnv is the
	// only adapter that touches the real process environment; nothing below reads os.Getenv.
	cfg, err := config.FromEnv(config.OSEnv)
	if err != nil {
		// All eleven validation rules FAIL STARTUP. In particular V5 refuses to boot with the auth
		// bypass on in a production-LOOKING context, which is the guard on PM_AUTH_DEBUG's default-true.
		log.Error("configuration rejected", "err", err)
		os.Exit(1)
	}

	// STEPS 2-5. 🔒 INV-A1-2 — a gRPC bind failure is FATAL and lands here, not in a warning: a control
	// plane that cannot bind its gRPC port must not come up serving only HTTP with the data plane
	// silently dead.
	a, err := app.Boot(cfg, app.Options{Log: log})
	if err != nil {
		log.Error("control-plane boot failed", "err", err)
		os.Exit(1)
	}

	// The shutdown hook Main.kt registers around the gRPC server, widened to the whole App. Kotlin
	// registers it right after start(); the equivalent here is the signal watcher, installed before
	// step 6 blocks.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-stop
		log.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		a.Shutdown(ctx)
	}()

	// STEP 6 — the HTTP server, blocking.
	if err := a.ServeHTTP(); err != nil {
		log.Error("control-plane HTTP server failed", "err", err)
		a.Shutdown(context.Background())
		os.Exit(1)
	}
}
