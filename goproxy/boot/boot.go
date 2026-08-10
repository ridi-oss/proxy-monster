// Package boot runs the dialect-neutral data-plane process after the executable injects a provider registry.
package boot

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/drain"
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/proxytls"
	"github.com/ridi-oss/proxy-monster/goproxy/run"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const bootRegisterAttempts = 3
const ambientRefreshInterval = 12 * time.Minute

// drainTimeout bounds the graceful shutdown: in-flight statements finish and idle connections get a
// protocol-level shutdown notice, then any connection still live is force-closed and the process exits.
const drainTimeout = 10 * time.Second

// runDrainTimeout bounds how long shutdown waits for an in-flight editor/approval query to finish before
// closing the control-plane clients its runExec stream rides — the run-stream analogue of drainTimeout.
const runDrainTimeout = 10 * time.Second

var refreshMu sync.Mutex

// Run is the dialect-neutral boot consumer. The executable composition root injects the provider registry;
// this package imports only the SPI, never the concrete dialect wiring package.
func Run(registry spi.Registry) error {
	if registry == nil {
		return fmt.Errorf("provider registry is required")
	}
	cfg, err := config.Load(registry)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	enforcementClient, err := cp.New(cfg.ControlPlaneGrpcTarget, cfg.SecretToken, cfg.DatasourceName)
	if err != nil {
		return fmt.Errorf("failed to create enforcement control-plane client: %w", err)
	}
	defer enforcementClient.Close()
	configClient, err := cp.New(cfg.ControlPlaneGrpcTarget, cfg.SecretToken, cfg.DatasourceName)
	if err != nil {
		return fmt.Errorf("failed to create config control-plane client: %w", err)
	}
	defer configClient.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	provider := cfg.Provider
	dbImpl := provider.NewDb()
	backend := spi.BackendTarget{
		Host:     cfg.TargetHost,
		Port:     cfg.TargetPort,
		Db:       cfg.TargetDb,
		User:     cfg.TargetUser,
		Password: cfg.TargetPassword,
	}

	// Build the client-facing TLS config BEFORE registering, so the proxy can advertise the certificate chain
	// a client should trust alongside its address. certChain is re-read at every (re)register, so a rotated
	// cert re-advertises itself on the next reconnect resync (full rotation-refresh is a follow-up,
	// docs/backlog.md). Whether TLS is served at all goes out separately, from cfg.TLSEnabled().
	// nil = "no opinion, keep whatever the control plane already stores"; a non-nil pointer is authoritative,
	// and an empty string in it CLEARS the stored chain.
	certChain := func() *string { return nil }
	var tlsProvider func() (*tls.Config, error)
	if cfg.TLSEnabled() {
		reloading := proxytls.NewReloading(cfg.TLSCertPath, cfg.TLSKeyPath)
		if _, err := reloading.Current(); err != nil {
			return fmt.Errorf("failed to build TLS config: %w", err)
		}
		tlsProvider = reloading.Current
		// Only a cert that cannot be READ is fatal here. Whether the chain is usable as a client's trust anchor
		// is the client's verification to make and is merely reported (see proxytls.TrustChain) — refusing to
		// boot over it would take the datasource down for a problem only one client might have.
		bootChain, err := reloading.TrustChain()
		if err != nil {
			return fmt.Errorf("proxy TLS is enabled but its certificate could not be read: %w", err)
		}
		// A certificate that does not cover the advertised address fails for every verify-full client, so say so
		// at boot where an operator can act on it, rather than leaving it to be discovered per client.
		if reason, addrErr := reloading.AddressShortcoming(cfg.AdvertiseAddr); addrErr == nil && reason != "" {
			slog.Warn("the wire cert does not match the advertised address", "advertise_addr", cfg.AdvertiseAddr, "reason", reason)
		}
		public, _ := reloading.PubliclyTrusted()
		if cfg.TLSNoAdvertise {
			// The operator has chosen to publish nothing: clients verify against their own trust store, and the
			// control plane holds no certificate for this datasource. pmon then falls through to system trust,
			// and the console offers no download.
			slog.Info("PM_TLS_NO_ADVERTISE is set; publishing no wire cert chain (clients use their own trust store)",
				"publicly_trusted", public)
		} else {
			slog.Info("advertising the wire cert chain for clients",
				"certificates", strings.Count(bootChain, "BEGIN CERTIFICATE"),
				// A publicly-trusted leaf needs nothing from us; the chain is advertised anyway so an operator
				// can inspect and distribute what the proxy actually presents.
				"publicly_trusted", public)
		}
		// Re-read at every (re)register, so a rotated certificate re-advertises itself on the next reconnect
		// resync. The two empty cases are deliberately NOT the same: NO_ADVERTISE sends an explicit empty string
		// (authoritative — clear whatever is stored, so a rotation to a publicly-trusted cert cannot leave
		// clients verifying against dead roots), while a transient read error sends nil ("no opinion"), which
		// preserves the last good chain until the next register succeeds.
		certChain = func() *string {
			if cfg.TLSNoAdvertise {
				empty := ""
				return &empty
			}
			chain, err := reloading.TrustChain()
			if err != nil {
				slog.Warn("could not read the wire cert chain on re-register; keeping the last advertised chain", "error", err)
				return nil
			}
			return &chain
		}
		slog.Info("proxy TLS enabled (reloads on file change)", "cert", cfg.TLSCertPath)
	} else {
		slog.Info("proxy TLS disabled — plaintext (trusted tailnet only); set PM_TLS_CERT + PM_TLS_KEY to enable")
	}

	// Track in-flight run executions with the same drain primitive the wire server uses, so shutdown lets an
	// executing editor/approval query finish and idle sessions return. Every open still dials back (spawns
	// Run): a refusal would strand the control-plane, which has already committed this proxy for the request
	// and would otherwise wait out its full dial timeout.
	runs := drain.New()
	// eventsCtx lets shutdown stop the Events loop — the source of new run dispatches — and wait for it to
	// return before draining the in-flight runs, so no dispatch can register a run after that wait sees zero.
	eventsCtx, eventsCancel := context.WithCancel(context.Background())
	defer eventsCancel() // covers the early serve-error return; the drain path cancels explicitly (idempotent)
	eventsDone := make(chan struct{})
	// A wire-protocol version skew is fatal: refuse to start rather than attach and stall the run channel.
	if err := registerAndPushCatalog(configClient, cfg, backend, provider, certChain); err != nil {
		slog.Error("refusing to start — deploy the proxy and control-plane from the same server-v* release", "error", err)
		return err
	}
	go func() {
		defer close(eventsDone)
		err := configClient.RunEventsLoop(
			eventsCtx,
			func() {
				// A re-register (reconnect) that finds a now-incompatible control-plane is equally fatal:
				// exit so the supervisor replaces this proxy rather than run against a version it cannot speak.
				if err := registerAndPushCatalog(configClient, cfg, backend, provider, certChain); err != nil {
					slog.Error("control-plane became version-incompatible on reconnect — exiting", "error", err)
					os.Exit(1)
				}
			},
			func() { refreshCatalog(configClient, provider, backend) },
			func(open spi.RunOpen) {
				runs.Add()
				go func() {
					defer runs.Done()
					run.NewRunner(enforcementClient, dbImpl, backend, provider, cfg.QueryTimeout).Run(open, runs.Signal())
				}()
			},
			func(sessionID, schema, table string) {
				go run.NewTableDetailRunner(configClient, backend, provider).Run(sessionID, schema, table)
			},
		)
		// A version rejection on the events stream is fatal even when a resync Register races to a still-
		// compatible instance behind a load balancer: exit so the supervisor replaces this proxy rather than
		// keep it serving against a control-plane it cannot speak to. A nil return is the normal ctx-cancel stop.
		if err != nil {
			slog.Error("control-plane rejected the events stream on a version skew — exiting", "error", err)
			os.Exit(1)
		}
	}()
	go func() {
		for {
			time.Sleep(ambientRefreshInterval)
			refreshCatalog(configClient, provider, backend)
		}
	}()

	server := provider.NewWireServer(cfg.ProxyPort, backend, enforcementClient, dbImpl, tlsProvider)
	slog.Info("starting proxy-monster data plane", "engine", cfg.Engine, "control_plane", cfg.ControlPlaneGrpcTarget)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Start() }()

	select {
	case err := <-serveErr:
		// The server stopped on its own (bind failure, accept error) without a shutdown signal.
		return err
	case <-sigCh:
	}

	// On SIGTERM (a rolling redeploy), drain gracefully: stop accepting, let in-flight statements finish,
	// send idle clients a protocol-level shutdown notice, then close the control-plane clients and exit.
	// The replacement task is already fronted by the NLB, so reconnects land there.
	slog.Info("shutting down, draining client connections", "timeout", drainTimeout)
	gracefulDrain(runs, eventsCancel, eventsDone, server.Drain)
	// Serve returns nil once Drain closes the listener. A non-nil error is a genuine serve failure (e.g. a bind
	// error that raced the signal, which select may pick over the serveErr case); surface it AND exit non-zero
	// so a supervisor keying on exit code sees it. A clean signalled shutdown (nil) stays exit 0.
	serveExitErr := <-serveErr
	if serveExitErr != nil {
		slog.Error("data plane serve error during shutdown", "error", serveExitErr)
	}
	_ = enforcementClient.Close()
	_ = configClient.Close()
	if serveExitErr != nil {
		os.Exit(1)
	}
	os.Exit(0)
	return nil
}

// gracefulDrain performs the ordered shutdown so a rolling redeploy loses no in-flight work. It signals the
// run streams (idle editor sessions return so the editor re-homes; an executing query finishes) and stops the
// Events loop, then drains the wire IMMEDIATELY: the wire is independent of that loop, so it must not wait
// behind a loop that may still be inside a synchronous catalog refresh (introspection bounded only by its own
// query timeouts) — closing the listener now stops new connections at once. Only the RUN drain waits
// UNCONDITIONALLY for the Events loop to return: that loop is the only source of new run dispatches, so
// runs.Wait must not run until it is gone — otherwise a late dispatch could register a run the wait already
// counted out, and the client close would then strand it on the control-plane's dial timeout. That wait is
// unbounded on purpose: a loop that never returns after its context is cancelled is a wedged process, left to
// the stop timeout's SIGKILL like any other. Both drains are bounded, so the caller can close the
// control-plane clients those run streams ride without cutting one. Split from Run so this ordering is
// unit-testable.
func gracefulDrain(
	runs *drain.Tracker,
	eventsCancel context.CancelFunc,
	eventsDone <-chan struct{},
	drainWire func(context.Context),
) {
	runs.Begin()
	eventsCancel()
	wireCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	drainWire(wireCtx)
	<-eventsDone
	runCtx, runCancel := context.WithTimeout(context.Background(), runDrainTimeout)
	defer runCancel()
	if !runs.Wait(runCtx) {
		slog.Warn("in-flight run drain timed out; proceeding", "timeout", runDrainTimeout)
	}
}

// registerAndPushCatalog registers the datasource and pushes its catalog, retrying transient failures. It
// returns cp.ErrIncompatibleControlPlane — and only that — as a FATAL error: a wire-protocol version skew is
// permanent, so retrying cannot fix it and attaching anyway would stall the run channel. Every other failure
// stays non-fatal (returns nil after the attempts): the proxy starts and fails decisions closed until the
// control plane has the catalog, so a briefly-unreachable control plane self-heals on reconnect.
func registerAndPushCatalog(
	configClient *cp.Client, cfg *config.Config, backend spi.BackendTarget, provider spi.Provider,
	certChain func() *string,
) error {
	for attempt := 0; attempt < bootRegisterAttempts; attempt++ {
		err := configClient.Register(provider.Dialect().Proto(), backend.Host, backend.Port, backend.Db, cfg.DatasourceTags, cfg.AdvertiseAddr, certChain(), cfg.TLSEnabled())
		if errors.Is(err, cp.ErrIncompatibleControlPlane) {
			return err
		}
		if err != nil {
			slog.Warn("datasource registration failed", "attempt", attempt+1, "of", bootRegisterAttempts, "error", err)
		} else if refreshCatalog(configClient, provider, backend) {
			slog.Info("datasource registered + catalog pushed", "datasource", cfg.DatasourceName)
			return nil
		}
		if attempt < bootRegisterAttempts-1 {
			backoff := time.Duration(attempt+1) * 2 * time.Second
			slog.Warn("register/push attempt failed; retrying", "attempt", attempt+1, "of", bootRegisterAttempts, "retry_in", backoff)
			time.Sleep(backoff)
		}
	}
	slog.Error("could not register + push catalog after all attempts — starting anyway; decisions fail closed until the control plane has this datasource's catalog", "attempts", bootRegisterAttempts)
	return nil
}

func refreshCatalog(configClient *cp.Client, provider spi.Provider, backend spi.BackendTarget) bool {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	catalog, err := introspect.Run(provider, backend)
	if err != nil {
		slog.Warn("catalog refresh failed", "error", err)
		return false
	}
	if err := configClient.PushCatalog(catalog); err != nil {
		slog.Warn("catalog refresh failed", "error", err)
		return false
	}
	return true
}
