// Package boot runs the dialect-neutral data-plane process after the executable injects a provider registry.
package boot

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/proxytls"
	"github.com/ridi-oss/proxy-monster/goproxy/run"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const bootRegisterAttempts = 3

// ambientRefreshInterval is the fallback tick for a control plane that does not drive re-measurement
// itself. The manager owns the per-schema clocks and nudges for exactly the schemas that are due, so a
// proxy paired with one that does so never needs this — but the two ship independently, and a
// datasource left with neither a ticker nor a nudging manager would go unmeasured entirely. The ticker
// therefore stands down the moment a scoped nudge proves the control plane is driving.
const ambientRefreshInterval = 12 * time.Minute

var refreshMu sync.Mutex

// managerDrivesRefresh latches on the first scoped nudge, which only a control plane that keeps the
// per-schema clocks can send. Latched rather than re-evaluated per tick because the evidence is an
// event, not a state: the manager sends nothing at all when nothing is due, so a proxy that unlatched
// on quiet would resume full scans exactly when there was nothing to measure.
var managerDrivesRefresh atomic.Bool

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
	go func() {
		<-sigCh
		slog.Info("shutting down")
		_ = enforcementClient.Close()
		_ = configClient.Close()
		os.Exit(0)
	}()

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

	registerAndPushCatalog(configClient, cfg, backend, provider, certChain)
	go configClient.RunEventsLoop(
		func() { registerAndPushCatalog(configClient, cfg, backend, provider, certChain) },
		func(schemas []string) { refreshCatalogFor(configClient, provider, backend, schemas) },
		func(open spi.RunOpen) {
			go run.NewRunner(enforcementClient, dbImpl, backend, provider, cfg.QueryTimeout).Run(open)
		},
		func(sessionID, schema, table string) {
			go run.NewTableDetailRunner(configClient, backend, provider).Run(sessionID, schema, table)
		},
	)
	go func() {
		for {
			time.Sleep(ambientRefreshInterval)
			if managerDrivesRefresh.Load() {
				continue
			}
			refreshCatalog(configClient, provider, backend)
		}
	}()

	server := provider.NewWireServer(cfg.ProxyPort, backend, enforcementClient, dbImpl, tlsProvider)
	slog.Info("starting proxy-monster data plane", "engine", cfg.Engine, "control_plane", cfg.ControlPlaneGrpcTarget)
	return server.Start()
}

func registerAndPushCatalog(
	configClient *cp.Client, cfg *config.Config, backend spi.BackendTarget, provider spi.Provider,
	certChain func() *string,
) {
	for attempt := 0; attempt < bootRegisterAttempts; attempt++ {
		if err := configClient.Register(provider.Dialect().Proto(), backend.Host, backend.Port, backend.Db, cfg.DatasourceTags, cfg.AdvertiseAddr, certChain(), cfg.TLSEnabled()); err != nil {
			slog.Warn("datasource registration failed", "attempt", attempt+1, "of", bootRegisterAttempts, "error", err)
		} else if refreshCatalog(configClient, provider, backend) {
			slog.Info("datasource registered + catalog pushed", "datasource", cfg.DatasourceName)
			return
		}
		if attempt < bootRegisterAttempts-1 {
			backoff := time.Duration(attempt+1) * 2 * time.Second
			slog.Warn("register/push attempt failed; retrying", "attempt", attempt+1, "of", bootRegisterAttempts, "retry_in", backoff)
			time.Sleep(backoff)
		}
	}
	slog.Error("could not register + push catalog after all attempts — starting anyway; decisions fail closed until the control plane has this datasource's catalog", "attempts", bootRegisterAttempts)
}

// refreshCatalogFor answers one RefreshCatalog nudge. An empty schema set is the whole-server admin
// refresh; a non-empty one names the schemas whose re-measure clocks expired, and those are answered by
// hashes alone — the manager replies with the subset it holds no content for, and only those schemas'
// columns are then read. On the common no-change nudge the backend does one grouped hash scan and the
// wire carries a few hundred bytes instead of the whole catalog.
func refreshCatalogFor(configClient *cp.Client, provider spi.Provider, backend spi.BackendTarget, schemas []string) bool {
	if len(schemas) == 0 {
		return refreshCatalog(configClient, provider, backend)
	}
	// A scoped nudge is something only a control plane that owns the per-schema clocks sends, so the
	// proxy's own fixed ticker has nothing left to do.
	managerDrivesRefresh.Store(true)
	refreshMu.Lock()
	defer refreshMu.Unlock()
	if err := introspect.RunScoped(provider, backend, schemas, configClient.PushCatalogFor); err != nil {
		// The schemas stay due, so the next nudge retries. Enforcement never depended on this path: the
		// per-connection staleness bound still forces its own re-checks, and the stored catalog merely ages.
		slog.Warn("scoped catalog re-measure failed", "schemas", len(schemas), "error", err)
		return false
	}
	return true
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
