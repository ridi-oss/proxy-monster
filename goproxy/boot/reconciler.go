package boot

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
	"github.com/ridi-oss/proxy-monster/goproxy/introspect"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const bootRegisterAttempts = 3
const maxResyncConcurrency = 1

type datasourceReconciler struct {
	configClient  *cp.Client
	cfg           *config.Config
	backend       spi.BackendTarget
	provider      spi.Provider
	certChain     func() *string
	registerSlots chan struct{}
	refreshBatch  atomic.Pointer[refreshBatch]
}

type refreshBatch struct {
	done chan struct{}
	ok   bool
}

func newDatasourceReconciler(configClient *cp.Client, cfg *config.Config, backend spi.BackendTarget, provider spi.Provider, certChain func() *string, resyncConcurrency int) *datasourceReconciler {
	return &datasourceReconciler{
		configClient:  configClient,
		cfg:           cfg,
		backend:       backend,
		provider:      provider,
		certChain:     certChain,
		registerSlots: make(chan struct{}, resyncConcurrency),
	}
}

func (d *datasourceReconciler) tryRegisterAndPushCatalog() {
	if !tryRun(d.registerSlots, d.registerAndPushCatalog) {
		slog.Debug("skipping register/push catalog; another attempt is already in progress")
	}
}

func (d *datasourceReconciler) registerAndPushCatalog() {
	for attempt := 0; attempt < bootRegisterAttempts; attempt++ {
		if err := d.configClient.Register(d.provider.Dialect().Proto(), d.backend.Host, d.backend.Port, d.backend.Db, d.cfg.DatasourceTags, d.cfg.AdvertiseAddr, d.certChain(), d.cfg.TLSEnabled()); err != nil {
			slog.Warn("datasource registration failed", "attempt", attempt+1, "of", bootRegisterAttempts, "error", err)
		} else if d.refreshCatalog() {
			slog.Info("datasource registered + catalog pushed", "datasource", d.cfg.DatasourceName)
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

func (d *datasourceReconciler) refreshCatalog() bool {
	return runMergedRefresh(&d.refreshBatch, d.refreshCatalogNow)
}

func (d *datasourceReconciler) refreshCatalogNow() bool {
	catalog, err := introspect.Run(d.provider, d.backend)
	if err == nil {
		err = d.configClient.PushCatalog(catalog)
	}

	if err != nil {
		slog.Warn("catalog refresh failed", "error", err)
		return false
	}
	return true
}

func tryRun(slots chan struct{}, run func()) bool {
	select {
	case slots <- struct{}{}:
	default:
		return false
	}
	defer func() { <-slots }()
	run()
	return true
}

func runMergedRefresh(active *atomic.Pointer[refreshBatch], run func() bool) bool {
	for {
		batch := active.Load()
		if batch != nil {
			<-batch.done
			return batch.ok
		}

		batch = &refreshBatch{done: make(chan struct{})}
		if !active.CompareAndSwap(nil, batch) {
			continue
		}

		defer func() {
			active.CompareAndSwap(batch, nil)
			// Closing done publishes batch.ok to every caller that joined this batch.
			close(batch.done)
		}()
		batch.ok = run()
		return batch.ok
	}
}
