package run

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/cp"
)

const bootRegisterAttempts = 3
const maxResyncConcurrency = 1

type refreshBatch struct {
	done chan struct{}
	ok   bool
}

// TryRegisterAndPushCatalog is RegisterAndPushCatalog unless another attempt is already running.
func (r *Runner) TryRegisterAndPushCatalog(cfg *config.Config, engine *engines.Engine, certChain func() *string) error {
	var err error
	if !tryRun(r.registerSlots, func() { err = r.RegisterAndPushCatalog(cfg, engine, certChain) }) {
		slog.Debug("skipping register/push catalog; another attempt is already in progress")
	}
	return err
}

// RegisterAndPushCatalog registers the datasource and pushes its catalog, retrying transient failures. A
// control-plane protocol-version mismatch is permanent, so it is the only error returned to make boot or a
// reconnect exit; all other failures leave the proxy running fail-closed until the next resync can recover.
func (r *Runner) RegisterAndPushCatalog(cfg *config.Config, engine *engines.Engine, certChain func() *string) error {
	for attempt := 0; attempt < bootRegisterAttempts; attempt++ {
		targetConfig := r.target.Config()
		err := r.client.Register(engine.Proto, targetConfig.Host, targetConfig.Port, targetConfig.Db, cfg.DatasourceTags, cfg.AdvertiseAddr, certChain(), cfg.TLSEnabled(), r.target.ConnectionInfo(), &cfg.DatasourceDescription)
		if errors.Is(err, cp.ErrIncompatibleControlPlane) {
			return err
		}
		if err != nil {
			slog.Warn("datasource registration failed", "attempt", attempt+1, "of", bootRegisterAttempts, "error", err)
		} else if r.RefreshCatalog() {
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

// RefreshCatalog introspects the target and pushes the catalog; concurrent callers share one refresh.
func (r *Runner) RefreshCatalog() bool {
	return runMergedRefresh(&r.refreshBatch, r.refreshCatalogNow)
}

func (r *Runner) refreshCatalogNow() bool {
	catalog, err := r.target.Introspect(context.Background())
	if err == nil {
		err = r.client.PushCatalog(catalog)
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
