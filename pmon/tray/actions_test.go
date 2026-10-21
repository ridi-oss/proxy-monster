package main

import (
	"testing"
	"time"
)

// TestALongActionCannotWedgeTheMenu is the guard for a real wedge: the lifecycle lock used to be a plain mutex
// held across the whole device-auth flow, which runs until the control plane's device TTL (~10 min) if the user
// never finishes in the browser. Every other action blocked for that window, and cancelling the app context did
// not free it — a mutex is not context-aware — so the menu was unresponsive and could not even be quit.
func TestALongActionCannotWedgeTheMenu(t *testing.T) {
	a := &app{}

	if !a.tryLockAction() {
		t.Fatal("the lock was not free on a fresh app")
	}
	// A second action must be REFUSED immediately, not queued behind the first.
	done := make(chan bool, 1)
	go func() { done <- a.tryLockAction() }()
	select {
	case got := <-done:
		if got {
			t.Error("two actions held the lock at once")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a second action blocked instead of being refused; the menu would be unresponsive")
	}

	a.unlockAction()
	if !a.tryLockAction() {
		t.Error("the lock was not released")
	}
	a.unlockAction()
}
