package boot

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunMergedRefreshBroadcastsResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{name: "success", want: true},
		{name: "failure", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var active atomic.Pointer[refreshBatch]
			batch := &refreshBatch{done: make(chan struct{})}
			active.Store(batch)

			const waiters = 8
			results := make(chan bool, waiters)
			var runs atomic.Int32
			var wg sync.WaitGroup
			for range waiters {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results <- runMergedRefresh(&active, func() bool {
						runs.Add(1)
						return !tc.want
					})
				}()
			}

			batch.ok = tc.want
			close(batch.done)
			wg.Wait()

			for range waiters {
				if got := <-results; got != tc.want {
					t.Fatalf("joined refresh = %t, want %t", got, tc.want)
				}
			}
			if got := runs.Load(); got != 0 {
				t.Fatalf("joined refresh ran %d times, want 0", got)
			}
		})
	}
}

func TestRunMergedRefreshRunsAndClearsBatch(t *testing.T) {
	var active atomic.Pointer[refreshBatch]
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan bool, 1)

	go func() {
		result <- runMergedRefresh(&active, func() bool {
			close(started)
			<-release
			return true
		})
	}()

	<-started
	if active.Load() == nil {
		t.Fatal("active batch was cleared before refresh completed")
	}
	close(release)

	select {
	case got := <-result:
		if !got {
			t.Fatal("refresh result = false, want true")
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not complete")
	}
	if active.Load() != nil {
		t.Fatal("active batch was not cleared")
	}
}

func TestTryRunDropsWhenAllSlotsAreHeld(t *testing.T) {
	slots := make(chan struct{}, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	first := make(chan bool, 1)

	go func() {
		first <- tryRun(slots, func() {
			close(started)
			<-release
		})
	}()
	<-started

	var skippedRuns atomic.Int32
	if tryRun(slots, func() { skippedRuns.Add(1) }) {
		t.Fatal("second run acquired a full slot")
	}
	if got := skippedRuns.Load(); got != 0 {
		t.Fatalf("skipped run executed %d times", got)
	}

	close(release)
	select {
	case got := <-first:
		if !got {
			t.Fatal("first run did not acquire a slot")
		}
	case <-time.After(time.Second):
		t.Fatal("first run did not complete")
	}
	if !tryRun(slots, func() {}) {
		t.Fatal("slot was not released after the first run")
	}
}
