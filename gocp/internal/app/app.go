// Package app is A1's composition root — `Main.kt` plus the parts of `App.kt` this increment lands.
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §2.
//
// # The boot sequence is CONTRACTUAL
//
//  1. Config.fromEnv()
//  2. the auth-debug banner, when PM_AUTH_DEBUG is on
//  3. Db(config), then db.migrate()
//  4. ControlPlaneCore(db), then core.accessStore.reconcileOrphanedExecutions()
//  5. GrpcServer(grpcPort, ControlPlaneGrpcService(core, runStreamTimeoutMs), secretToken).start(),
//     plus a shutdown hook
//  6. the HTTP server on httpPort, blocking
//
// 🔒 INV-A1-2 / INV-A10-5 — STEP 5 FAILING IS FATAL. A control plane that cannot bind its gRPC port
// must not come up serving only HTTP while the data plane is silently dead. [Boot] returns the error
// and never falls through to step 6.
//
// 🔒 INV-A1-1 — ONE [core.ControlPlaneCore] serves BOTH surfaces. [App.Core] is handed to the gRPC
// service and to the HTTP mux; nothing here may construct a second.
//
// INV-A1-3 — reconcileOrphanedExecutions runs TWICE in the Kotlin (Main.kt:50 and App.kt:351). It is
// idempotent by design and the App.kt call is what makes `testApplication { module() }` exercise it.
// Reproduced: [Boot] runs it, and [NewHTTPServer] runs it again.
//
// # HTTP scope in this increment
//
// Two routes, the ones the proxy and an operator cannot work without:
//
//	GET  /health              — status + diagnostics
//	POST /api/ingest/decision — the proxy's audit ingest, X-PM-Ingest-Token gated when the secret is set
//
// The other ~118 routes are later increments and are listed as TODO(A3)…TODO(A14) in http.go.
package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/ridi-oss/proxy-monster/gocp/internal/oidc"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ridi-oss/proxy-monster/gocp/internal/config"
	"github.com/ridi-oss/proxy-monster/gocp/internal/core"
	"github.com/ridi-oss/proxy-monster/gocp/internal/grpcsvc"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// App is the booted process: the shared core plus the two servers.
type App struct {
	Config config.Config
	Db     *store.Db
	Core   *core.ControlPlaneCore
	Grpc   *grpcsvc.Server
	HTTP   *http.Server
	// Surface is what `Application.module` built. It is here so a caller can reach the request-time
	// singletons the route groups share — in particular [HTTPSurface.RunExec], which A1's still-TODO
	// purge loop sweeps and which a fake-proxy DB test drives directly.
	Surface *HTTPSurface

	httpListener net.Listener
	httpDone     chan error
	// stopSweeps cancels the background timer loops; nil until StartLivenessSweep runs.
	stopSweeps context.CancelFunc
	sweepsDone chan struct{}
	log        *slog.Logger
}

// Options are the seams [Boot] needs and the env contract does not carry.
type Options struct {
	// Log defaults to slog.Default().
	Log *slog.Logger
	// BootTimeout bounds steps 3-4 (pool connect + migrate + core construction). Zero means 60s.
	// HikariCP's own connectionTimeout has no direct analogue; internal/store makes the caller own
	// the deadline, so this is where the process-level one is chosen.
	BootTimeout time.Duration
}

// Boot runs steps 1-5 of the sequence and returns the started App. The HTTP server is CONSTRUCTED
// but not serving; call [App.ServeHTTP] (step 6) or [App.StartHTTP] for a test.
//
// On any error every resource opened so far is released, so a caller that logs and exits leaks
// nothing and — more importantly — a half-booted process never lingers with a bound gRPC port.
func Boot(cfg config.Config, opts Options) (*App, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	bootTimeout := opts.BootTimeout
	if bootTimeout <= 0 {
		bootTimeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), bootTimeout)
	defer cancel()

	// STEP 2 — the auth-debug banner.
	if cfg.AuthDebug {
		logAuthDebugBanner(log)
	}

	// STEP 3 — Db, then migrate. Construction is EAGER (internal/store pings), so an unreachable
	// database fails HERE rather than at the first query, which is what makes the boot log honest.
	db, err := store.New(ctx, store.Config{DBURL: cfg.DBURL, DBUser: cfg.DBUser, DBPassword: cfg.DBPassword})
	if err != nil {
		return nil, fmt.Errorf("boot: database: %w", err)
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: migrate: %w", err)
	}

	// STEP 4 — the ONE shared graph, then the orphan reconcile.
	// 🔒 INV-A5-55 — the system-classification manifests load HERE, and a malformed one aborts the
	// boot exactly like a failed migration.
	c, err := core.New(db, core.Options{Log: log})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: control-plane core: %w", err)
	}
	if err := c.AccessStore.ReconcileOrphanedExecutions(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: reconcile orphaned executions: %w", err)
	}

	// STEP 5 — the gRPC surface.
	// 🔒 The run-stream cap is derived here, not defaulted: max(15min, dial + exchange + 30s). Leaving
	// the dial out makes the cap fall short of the work it wraps once PM_QUERY_TIMEOUT is large, and
	// the stream then dies under a statement that is still legitimately running.
	runStreamTimeout := time.Duration(config.RunStreamTimeoutMS(cfg.QueryExchangeTimeoutMS())) * time.Millisecond
	svc := grpcsvc.NewService(c, runStreamTimeout, log)
	grpcServer := grpcsvc.NewServer(cfg.GRPCPort, svc, cfg.SecretToken, log)
	if err := grpcServer.Start(); err != nil {
		db.Close()
		// 🔒 INV-A1-2 — FATAL. Never degrade this to a warning and continue to step 6.
		return nil, err
	}

	app := &App{
		Config: cfg,
		Db:     db,
		Core:   c,
		Grpc:   grpcServer,
		log:    log,
	}
	// 🔒 `installMcp`'s capability verification runs in here and IS FATAL (INV-A11-1) — the same
	// disposition as a failed migration. The gRPC surface is already bound at this point, so it has to
	// come down with everything else rather than being left listening under a half-built process.
	srv, surface, err := NewHTTPServer(ctx, cfg, c, log)
	if err != nil {
		grpcServer.Shutdown()
		db.Close()
		return nil, err
	}
	app.HTTP = srv
	app.Surface = surface
	return app, nil
}

// StartHTTP binds the HTTP port and serves in the background. It is step 6 for a caller that wants
// the process to stay in control (a test, or a main that installs its own signal handler).
//
// The listener is bound SYNCHRONOUSLY so a taken HTTP port is an error the caller sees, and so
// [App.HTTPPort] is valid on return when the configured port was 0.
func (a *App) StartHTTP() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", a.Config.HTTPPort))
	if err != nil {
		return fmt.Errorf("control-plane HTTP bind :%d: %w", a.Config.HTTPPort, err)
	}
	a.httpListener = ln
	a.httpDone = make(chan error, 1)
	a.log.Info("control-plane HTTP listening", "port", a.HTTPPort())
	go func() {
		err := a.HTTP.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		a.httpDone <- err
	}()
	return nil
}

// StartLivenessSweep starts App.kt:430-443's loop 2: every `config.idpRecheckIntervalSeconds`, one
// [oidc.SweepSessionLiveness] pass, cancelled on [App.Shutdown].
//
// 🔒 WITHOUT THIS TIMER THE SWEEP IS DEAD CODE, and its absence is the security hole: a principal
// deprovisioned at the IdP — removed from a group, refresh token revoked, account disabled — keeps a
// live proxy-monster session until its own absolute window closes. Everything else in A4 enforces
// windows; only this observes the outside world.
//
// It is a NO-OP when no IdP is configured, matching sweepSessionLiveness's own `config.oidc == null`
// guard rather than spinning a ticker that would return immediately.
//
// ⚠️ THE FIRST PASS IS ONE INTERVAL IN, not at boot — Kotlin's loop is `while (true) { delay(i); … }`,
// delay FIRST. Sweeping at startup would put an IdP round-trip per live session on the boot path.
func (a *App) StartLivenessSweep() {
	if a.Surface == nil || a.Surface.Liveness == nil {
		return
	}
	interval := time.Duration(a.Config.IdpRecheckIntervalSeconds) * time.Second
	if interval <= 0 {
		// Config validation guarantees a positive value; a zero here would busy-loop the IdP.
		a.log.Warn("IdP recheck interval is not positive; liveness sweep not started",
			"seconds", a.Config.IdpRecheckIntervalSeconds)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.stopSweeps = cancel
	a.sweepsDone = make(chan struct{})
	deps := *a.Surface.Liveness
	go func() {
		defer close(a.sweepsDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// SweepSessionLiveness already isolates each row; this outer recover covers the pass
				// itself, so one bad tick can never kill the loop for the process's lifetime.
				func() {
					defer func() {
						if r := recover(); r != nil {
							a.log.Warn("session liveness sweep failed", "panic", r)
						}
					}()
					oidc.SweepSessionLiveness(ctx, deps)
				}()
			}
		}
	}()
	a.log.Info("IdP liveness sweep started", "intervalSeconds", a.Config.IdpRecheckIntervalSeconds)
}

// HTTPPort is the actually-bound HTTP port, valid after StartHTTP.
func (a *App) HTTPPort() int {
	if a.httpListener == nil {
		return a.Config.HTTPPort
	}
	if addr, ok := a.httpListener.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return a.Config.HTTPPort
}

// ServeHTTP is step 6 for main(): start and block until the server stops.
func (a *App) ServeHTTP() error {
	if err := a.StartHTTP(); err != nil {
		return err
	}
	return <-a.httpDone
}

// Shutdown is the reverse of Boot: drain HTTP, then the gRPC surface, then the pool.
//
// 🔒 The gRPC drain is graceful-then-FORCE (INV-A10-6): a long-lived Events stream never finishes on
// its own, so a graceful-only stop hangs forever.
func (a *App) Shutdown(ctx context.Context) {
	if a.stopSweeps != nil {
		a.stopSweeps()
		<-a.sweepsDone
		a.stopSweeps = nil
	}
	if a.httpListener != nil {
		if err := a.HTTP.Shutdown(ctx); err != nil {
			a.log.Warn("HTTP shutdown", "err", err)
		}
		<-a.httpDone
	}
	if a.Grpc != nil {
		a.Grpc.Shutdown()
	}
	if a.Db != nil {
		a.Db.Close()
	}
}

// logAuthDebugBanner is Main.kt:33-41's boxed multi-line warning.
//
// It is loud on purpose: PM_AUTH_DEBUG DEFAULTS TO TRUE and is a FULL AUTHENTICATION BYPASS. Config
// validation rule V5 is what stops it reaching a production-looking context; this banner is what
// stops it going unnoticed in every other one.
func logAuthDebugBanner(log *slog.Logger) {
	for _, line := range []string{
		"************************************************************",
		"*  PM_AUTH_DEBUG IS ON — AUTHENTICATION IS BYPASSED.        *",
		"*  Every API caller is treated as an authenticated admin.   *",
		"*  NEVER set this in production.                            *",
		"************************************************************",
	} {
		log.Warn(line)
	}
}
