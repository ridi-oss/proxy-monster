package singleinstance

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDaemonClientLifecycle(t *testing.T) {
	instance := New(t.TempDir()+"/instance.lock", time.Second)
	client := instance.Client()
	if running, err := client.Running(context.Background()); err != nil || running {
		t.Fatalf("Running before acquire = %t, %v; want false, nil", running, err)
	}

	daemon, acquired, err := instance.Acquire(context.Background())
	if err != nil || !acquired {
		t.Fatalf("Acquire = %t, %v; want true, nil", acquired, err)
	}
	owner, err := client.Owner(context.Background())
	if err != nil || owner == nil || owner.PID() != os.Getpid() {
		t.Fatalf("Owner = %#v, %v; want pid %d", owner, err, os.Getpid())
	}
	if current, err := owner.Current(context.Background()); err != nil || !current {
		t.Fatalf("Current = %t, %v; want true, nil", current, err)
	}
	if err := owner.Signal(context.Background(), 0); err != nil {
		t.Fatalf("Signal(0): %v", err)
	}
	if other, acquired, err := instance.Acquire(context.Background()); err != nil || acquired || other != nil {
		t.Fatalf("second Acquire = %#v, %t, %v; want nil, false, nil", other, acquired, err)
	}

	if err := daemon.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := owner.WaitExit(context.Background(), time.Second); err != nil {
		t.Fatalf("WaitExit: %v", err)
	}
	if running, err := client.Running(context.Background()); err != nil || running {
		t.Fatalf("Running after close = %t, %v; want false, nil", running, err)
	}
}

func TestPinnedOwnerDetectsReplacement(t *testing.T) {
	instance := New(t.TempDir()+"/instance.lock", time.Second)
	client := instance.Client()
	first, acquired, err := instance.Acquire(context.Background())
	if err != nil || !acquired {
		t.Fatalf("first Acquire = %t, %v; want true, nil", acquired, err)
	}
	owner, err := client.Owner(context.Background())
	if err != nil || owner == nil {
		t.Fatalf("Owner = %#v, %v; want owner", owner, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first owner: %v", err)
	}

	path := instance.path
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock: %v", err)
	}
	transitionFile, err := lockTransition(context.Background(), path, syscall.LOCK_EX)
	if err != nil {
		file.Close()
		t.Fatalf("lock transition: %v", err)
	}
	t.Cleanup(func() {
		_ = unlockAndClose(file)
		_ = unlockAndClose(transitionFile)
	})
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("lock replacement: %v", err)
	}
	if err := writePID(file, owner.PID()+1); err != nil {
		t.Fatalf("write replacement pid: %v", err)
	}
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("publish replacement: %v", err)
	}

	if current, err := owner.Current(context.Background()); !errors.Is(err, ErrOwnerReplaced) || current {
		t.Fatalf("Current after replacement = %t, %v; want false, ErrOwnerReplaced", current, err)
	}
	if err := owner.Signal(context.Background(), 0); !errors.Is(err, ErrOwnerReplaced) {
		t.Fatalf("Signal after replacement = %v, want ErrOwnerReplaced", err)
	}
	if err := owner.WaitExit(context.Background(), time.Second); !errors.Is(err, ErrOwnerReplaced) {
		t.Fatalf("WaitExit after replacement = %v, want ErrOwnerReplaced", err)
	}
}

func TestPinnedOwnerWaitExitTimesOut(t *testing.T) {
	instance := New(t.TempDir()+"/instance.lock", time.Second)
	daemon, acquired, err := instance.Acquire(context.Background())
	if err != nil || !acquired {
		t.Fatalf("Acquire = %t, %v; want true, nil", acquired, err)
	}
	t.Cleanup(func() { _ = daemon.Close() })
	owner, err := instance.Client().Owner(context.Background())
	if err != nil || owner == nil {
		t.Fatalf("Owner = %#v, %v; want owner", owner, err)
	}

	err = owner.WaitExit(context.Background(), 50*time.Millisecond)
	if !errors.Is(err, ErrOwnerExitTimeout) {
		t.Fatalf("WaitExit = %v, want ErrOwnerExitTimeout", err)
	}
}

func TestClientBoundsTransitionWait(t *testing.T) {
	path := t.TempDir() + "/instance.lock"
	transitionFile, err := os.OpenFile(transitionPath(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open transition lock: %v", err)
	}
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		transitionFile.Close()
		t.Fatalf("lock transition: %v", err)
	}
	t.Cleanup(func() { _ = unlockAndClose(transitionFile) })

	client := New(path, 50*time.Millisecond).Client()
	if _, err := client.Running(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Running = %v, want context deadline exceeded", err)
	}
}
