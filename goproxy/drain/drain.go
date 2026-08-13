// Package drain is the protocol-agnostic core of a graceful shutdown drain, shared by the wire brokers and
// the run subsystem. A Tracker holds the draining signal and counts in-flight work so shutdown can wait it
// out; the transport-specific parts — how idle work is unblocked (a forced read deadline on a socket, a
// channel select in the run loop) and how a straggler is force-closed — stay with each caller.
package drain

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// pollInterval is how often Wait rechecks whether every in-flight unit has finished.
const pollInterval = 20 * time.Millisecond

// Tracker is safe for concurrent use. Construct with New; the zero value is not usable (its signal channel
// would be nil, so Signal would block forever and Begin would never close it).
type Tracker struct {
	signal   chan struct{}
	begun    sync.Once
	draining atomic.Bool // mirrors signal's closed state for a lock-free hot-path read
	mu       sync.Mutex
	active   int
}

func New() *Tracker { return &Tracker{signal: make(chan struct{})} }

// Add registers one in-flight unit; Done releases it. Callers balance the two (typically Done deferred).
func (t *Tracker) Add() { t.mu.Lock(); t.active++; t.mu.Unlock() }

func (t *Tracker) Done() { t.mu.Lock(); t.active--; t.mu.Unlock() }

// Begin enters drain mode: it sets Draining and closes Signal so idle work winds down. Idempotent.
func (t *Tracker) Begin() {
	t.begun.Do(func() {
		t.draining.Store(true)
		close(t.signal)
	})
}

// Signal is closed once Begin has run — select on it to unblock work idling between units.
func (t *Tracker) Signal() <-chan struct{} { return t.signal }

// Draining reports whether Begin has run, lock-free, so it is cheap on a per-operation hot path.
func (t *Tracker) Draining() bool { return t.draining.Load() }

// Wait blocks until every in-flight unit has finished, or ctx is done; it reports whether the count reached
// zero in time. A straggler still live when ctx is done is left to the caller's own force path.
func (t *Tracker) Wait(ctx context.Context) bool {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		t.mu.Lock()
		n := t.active
		t.mu.Unlock()
		if n == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
