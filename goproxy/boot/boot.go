// Package boot runs the dialect-neutral data-plane process after the executable injects a provider registry.
package boot

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/proxytls"
	"github.com/ridi-oss/proxy-monster/goproxy/run"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const ambientRefreshInterval = 12 * time.Minute

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

	reconciler := newDatasourceReconciler(
		configClient,
		cfg,
		backend,
		provider,
		certChain,
		maxResyncConcurrency,
	)
	reconciler.registerAndPushCatalog()
	go configClient.RunEventsLoop(
		reconciler.tryRegisterAndPushCatalog,
		func() { reconciler.refreshCatalog() },
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
			reconciler.refreshCatalog()
		}
	}()

	server := provider.NewWireServer(cfg.ProxyPort, backend, enforcementClient, dbImpl, tlsProvider)
	slog.Info("starting proxy-monster data plane", "engine", cfg.Engine, "control_plane", cfg.ControlPlaneGrpcTarget)
	return server.Start()
}
