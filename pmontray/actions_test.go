package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

func TestConnectionDropConfirmationFailsClosedWhenStatusIsUnknown(t *testing.T) {
	originalConnect := connectForConfirmation
	originalStatus := statusForConfirmation
	originalDaemonRunning := daemonRunningForConfirmation
	originalConfirm := confirmConnectionDrop
	t.Cleanup(func() {
		connectForConfirmation = originalConnect
		statusForConfirmation = originalStatus
		daemonRunningForConfirmation = originalDaemonRunning
		confirmConnectionDrop = originalConfirm
	})

	unknownErr := errors.New("status unavailable")
	for _, tc := range []struct {
		name             string
		connectErr       error
		status           *control.Status
		statusErr        error
		daemonRunning    bool
		daemonRunningErr error
		confirmResult    bool
		wantConfirm      bool
		wantResult       bool
		wantMessage      string
	}{
		{name: "not running", connectErr: control.ErrDaemonNotRunning, wantResult: true},
		{name: "unreachable", connectErr: control.ErrDaemonUnreachable, wantConfirm: true, wantMessage: "cannot be read"},
		{
			name:          "unreachable approved",
			connectErr:    control.ErrDaemonUnreachable,
			confirmResult: true,
			wantConfirm:   true,
			wantResult:    true,
			wantMessage:   "cannot be read",
		},
		{name: "unexpected connect error", connectErr: unknownErr, wantConfirm: true, wantMessage: "cannot be read"},
		{name: "daemon exits before status", statusErr: control.ErrDaemonNotRunning, wantResult: true},
		{
			name:          "status closes while pid lock is held",
			statusErr:     control.ErrDaemonNotRunning,
			daemonRunning: true,
			wantConfirm:   true,
			wantMessage:   "cannot be read",
		},
		{
			name:             "status closes while pid lock cannot be inspected",
			statusErr:        control.ErrDaemonNotRunning,
			daemonRunningErr: unknownErr,
			wantConfirm:      true,
			wantMessage:      "cannot be read",
		},
		{name: "status read error", statusErr: unknownErr, wantConfirm: true, wantMessage: "cannot be read"},
		{name: "no live connections", status: &control.Status{}, wantResult: true},
		{
			name:        "live connections",
			status:      &control.Status{Datasources: []control.Datasource{{LiveConns: 2}}},
			wantConfirm: true,
			wantMessage: "2 active database connection(s)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connectForConfirmation = func(context.Context) (*control.Client, error) {
				return &control.Client{}, tc.connectErr
			}
			statusForConfirmation = func(*control.Client, context.Context) (*control.Status, error) {
				if tc.status != nil {
					return tc.status, tc.statusErr
				}
				return &control.Status{}, tc.statusErr
			}
			daemonRunningForConfirmation = func(context.Context) (bool, error) {
				return tc.daemonRunning, tc.daemonRunningErr
			}
			confirmCalls := 0
			confirmConnectionDrop = func(title, message, label string) bool {
				confirmCalls++
				if title != "Stop proxy-monster?" || label != "Stop" {
					t.Errorf("confirmation = title %q label %q", title, label)
				}
				if !strings.Contains(message, tc.wantMessage) {
					t.Errorf("confirmation message = %q, want %q", message, tc.wantMessage)
				}
				return tc.confirmResult
			}

			got := (&app{ctx: context.Background()}).confirmDroppingConns("Stop")
			if got != tc.wantResult {
				t.Errorf("confirmDroppingConns = %t, want %t", got, tc.wantResult)
			}
			if gotConfirm := confirmCalls > 0; gotConfirm != tc.wantConfirm {
				t.Errorf("confirmation called = %t, want %t", gotConfirm, tc.wantConfirm)
			}
		})
	}
}

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
