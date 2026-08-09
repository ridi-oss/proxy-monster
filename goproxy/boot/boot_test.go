package boot

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/drain"
)

// gracefulDrain must drain the wire IMMEDIATELY (independent of the Events loop, so a loop still winding down
// — e.g. mid catalog refresh — cannot delay closing the listener), yet still gate the RUN drain on the Events
// loop's return so no dispatch that lands late is missed, and it must not return until the in-flight runs
// finish. This guards both the Wait-vs-late-Add race and the wire-must-not-wait-behind-events ordering.
func TestGracefulDrainDrainsWireBeforeTheRunBarrier(t *testing.T) {
	runs := drain.New()
	runs.Add() // one in-flight run, not yet finished

	cancelled := make(chan struct{})
	eventsDone := make(chan struct{})
	eventsCancel := func() { close(cancelled) }

	// Record whether the Events loop was still winding down (eventsDone open) when the wire was drained — it
	// must be, so the wire never waits behind a loop stuck in a synchronous refresh.
	wireDrainedBeforeEvents := make(chan bool, 1)
	drainWire := func(context.Context) {
		select {
		case <-eventsDone:
			wireDrainedBeforeEvents <- false
		default:
			wireDrainedBeforeEvents <- true
		}
	}

	done := make(chan struct{})
	go func() { gracefulDrain(runs, eventsCancel, eventsDone, drainWire); close(done) }()

	// It signals draining and cancels the Events loop up front.
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("gracefulDrain did not cancel the events loop")
	}
	if !runs.Draining() {
		t.Fatal("gracefulDrain did not begin draining before stopping the events loop")
	}

	// The wire is drained before the Events loop is even done — not blocked behind it.
	select {
	case got := <-wireDrainedBeforeEvents:
		if !got {
			t.Fatal("wire was drained only after the events loop stopped — it must not wait behind it")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wire was never drained")
	}

	// But the RUN drain must still wait for the Events loop: gracefulDrain must NOT return yet.
	select {
	case <-done:
		t.Fatal("gracefulDrain returned before the events loop stopped — the run barrier is violated")
	case <-time.After(100 * time.Millisecond):
	}

	// A dispatch that lands while the Events loop is still winding down (before eventsDone) must still be
	// counted — the whole point of awaiting eventsDone before runs.Wait. Register it now.
	runs.Add()

	// Release the Events loop; now it waits for BOTH in-flight runs — still live.
	close(eventsDone)
	select {
	case <-done:
		t.Fatal("gracefulDrain returned before the in-flight runs finished")
	case <-time.After(100 * time.Millisecond):
	}

	// Finishing both runs lets it return.
	runs.Done()
	runs.Done()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gracefulDrain did not return after the in-flight runs finished")
	}
}
