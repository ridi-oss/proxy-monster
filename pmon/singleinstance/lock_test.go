package singleinstance

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func acquire(path string) (*fileLock, bool, error) {
	return acquireLock(context.Background(), path)
}

func held(path string) (bool, error) {
	return lockHeld(context.Background(), path)
}

func ownerPID(path string) (int, bool, error) {
	return lockOwnerPID(context.Background(), path)
}

func transitionLock(path string, mode int) (*os.File, error) {
	return lockTransition(context.Background(), path, mode)
}

type transitionWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (ctx *transitionWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestLockLifecycle(t *testing.T) {
	path := t.TempDir() + "/instance.lock"

	if held, err := held(path); err != nil || held {
		t.Fatalf("Held before acquire = %v, %v; want false, nil", held, err)
	}
	lock, acquired, err := acquire(path)
	if err != nil || !acquired {
		t.Fatalf("Acquire = %v, %v; want lock, true, nil", acquired, err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat acquired lock: %v", err)
	}
	transitionBefore, err := os.Stat(transitionPath(path))
	if err != nil {
		t.Fatalf("stat acquired transition lock: %v", err)
	}
	if held, err := held(path); err != nil || !held {
		t.Fatalf("Held after acquire = %v, %v; want true, nil", held, err)
	}
	if pid, held, err := ownerPID(path); err != nil || !held || pid != os.Getpid() {
		t.Fatalf("OwnerPID = %d, %v, %v; want %d, true, nil", pid, held, err, os.Getpid())
	}
	if other, acquired, err := acquire(path); err != nil || acquired || other != nil {
		t.Fatalf("second Acquire = %v, %v, %v; want nil, false, nil", other, acquired, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if held, err := held(path); err != nil || held {
		t.Fatalf("Held after close = %v, %v; want false, nil", held, err)
	}
	if pid, held, err := ownerPID(path); err != nil || held || pid != 0 {
		t.Fatalf("OwnerPID after close = %d, %v, %v; want 0, false, nil", pid, held, err)
	}

	lock, acquired, err = acquire(path)
	if err != nil || !acquired {
		t.Fatalf("reacquire = %v, %v; want lock, true, nil", acquired, err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat reacquired lock: %v", err)
	}
	transitionAfter, err := os.Stat(transitionPath(path))
	if err != nil {
		t.Fatalf("stat reacquired transition lock: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("reacquire replaced the lock inode")
	}
	if !os.SameFile(transitionBefore, transitionAfter) {
		t.Fatal("reacquire replaced the transition-lock inode")
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("close reacquired lock: %v", err)
	}
}

func TestSharedProbeLockDoesNotReportAnOwner(t *testing.T) {
	path := t.TempDir() + "/instance.lock"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock: %v", err)
	}
	t.Cleanup(func() {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	})
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		t.Fatalf("take shared probe lock: %v", err)
	}

	if held, err := held(path); err != nil || held {
		t.Fatalf("Held behind another probe = %v, %v; want false, nil", held, err)
	}
	if pid, held, err := ownerPID(path); err != nil || held || pid != 0 {
		t.Fatalf("OwnerPID behind another probe = %d, %v, %v; want 0, false, nil", pid, held, err)
	}
}

func TestProbesWithMissingParent(t *testing.T) {
	path := t.TempDir() + "/missing/instance.lock"
	if held, err := held(path); err != nil || held {
		t.Fatalf("Held = %v, %v; want false, nil", held, err)
	}
	if pid, held, err := ownerPID(path); err != nil || held || pid != 0 {
		t.Fatalf("OwnerPID = %d, %v, %v; want 0, false, nil", pid, held, err)
	}
}

func TestOperationsHonorDeadlineWhileTransitionIslockHeld(t *testing.T) {
	path := t.TempDir() + "/instance.lock"
	transitionFile, err := os.OpenFile(transitionPath(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open transition lock: %v", err)
	}
	if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		transitionFile.Close()
		t.Fatalf("lock transition: %v", err)
	}
	t.Cleanup(func() {
		syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
		transitionFile.Close()
	})

	operations := map[string]func(context.Context) error{
		"Acquire": func(ctx context.Context) error {
			lock, _, err := acquireLock(ctx, path)
			if lock != nil {
				_ = lock.Close()
			}
			return err
		},
		"Held": func(ctx context.Context) error {
			_, err := lockHeld(ctx, path)
			return err
		},
		"OwnerPID": func(ctx context.Context) error {
			_, _, err := lockOwnerPID(ctx, path)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			started := time.Now()
			if err := operation(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("operation error = %v, want context deadline exceeded", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("operation took %s, want at most 1s", elapsed)
			}
		})
	}
}

func TestLockAcrossProcesses(t *testing.T) {
	path := t.TempDir() + "/instance.lock"
	lock, acquired, err := acquire(path)
	if err != nil || !acquired {
		t.Fatalf("Acquire = %v, %v; want lock, true, nil", acquired, err)
	}
	runLockHelper(t, path, "blocked")
	if err := lock.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	runLockHelper(t, path, "acquired")
	lock, acquired, err = acquire(path)
	if err != nil || !acquired {
		t.Fatalf("Acquire after helper exit = %v, %v; want lock, true, nil", acquired, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("final Close: %v", err)
	}
}

func TestLockHelperProcess(t *testing.T) {
	path := os.Getenv("PM_SINGLEINSTANCE_HELPER_PATH")
	if path == "" {
		return
	}
	want := os.Getenv("PM_SINGLEINSTANCE_HELPER_WANT")
	lock, acquired, err := acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	switch want {
	case "blocked":
		if acquired || lock != nil {
			_ = lock.Close()
			t.Fatal("Acquire succeeded while the parent held the lock")
		}
	case "acquired":
		if !acquired || lock == nil {
			t.Fatal("Acquire did not succeed after the parent released the lock")
		}
	default:
		t.Fatalf("unknown expectation %q", want)
	}
}

func runLockHelper(t *testing.T, path, want string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	command.Env = append(os.Environ(),
		"PM_SINGLEINSTANCE_HELPER_PATH="+path,
		"PM_SINGLEINSTANCE_HELPER_WANT="+want,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper expecting %s: %v\n%s", want, err, output)
	}
}

func TestProbesWaitForOwnershipPublication(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe func(context.Context, string) (bool, error)
	}{
		{name: "Held", probe: lockHeld},
		{name: "OwnerPID", probe: func(ctx context.Context, path string) (bool, error) {
			pid, held, err := lockOwnerPID(ctx, path)
			if err == nil && held && pid != os.Getpid() {
				return false, errors.New("OwnerPID returned the wrong pid")
			}
			return held, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/instance.lock"
			file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatalf("open lock: %v", err)
			}
			transitionFile, err := transitionLock(path, syscall.LOCK_EX)
			if err != nil {
				file.Close()
				t.Fatalf("lock transition: %v", err)
			}
			t.Cleanup(func() {
				syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
				file.Close()
				transitionFile.Close()
			})
			if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatalf("lock: %v", err)
			}
			if err := writePID(file, 1); err != nil {
				t.Fatalf("write retained metadata: %v", err)
			}

			waitCtx := &transitionWaitContext{Context: context.Background(), waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				held, err := tc.probe(waitCtx, path)
				if err == nil && !held {
					err = errors.New("probe did not report the held lock")
				}
				result <- err
			}()
			select {
			case <-waitCtx.waiting:
			case <-time.After(time.Second):
				t.Fatal("probe never reached transition-lock contention")
			}
			select {
			case err := <-result:
				t.Fatalf("probe returned before ownership was published: %v", err)
			default:
			}

			if err := writePID(file, os.Getpid()); err != nil {
				t.Fatalf("publish pid: %v", err)
			}
			if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN); err != nil {
				t.Fatalf("unlock transition: %v", err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("probe did not resume after ownership was published")
			}
		})
	}
}

func TestProbesWaitForFirstOwnershipPublication(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe func(context.Context, string) (bool, error)
	}{
		{name: "Held", probe: lockHeld},
		{name: "OwnerPID", probe: func(ctx context.Context, path string) (bool, error) {
			pid, held, err := lockOwnerPID(ctx, path)
			if err == nil && held && pid != os.Getpid() {
				return false, errors.New("OwnerPID returned the wrong pid")
			}
			return held, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/instance.lock"
			transitionFile, err := transitionLock(path, syscall.LOCK_EX)
			if err != nil {
				t.Fatalf("lock transition: %v", err)
			}
			var file *os.File
			t.Cleanup(func() {
				if file != nil {
					syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
					file.Close()
				}
				syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
				transitionFile.Close()
			})

			waitCtx := &transitionWaitContext{Context: context.Background(), waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				held, err := tc.probe(waitCtx, path)
				if err == nil && !held {
					err = errors.New("probe did not report the held lock")
				}
				result <- err
			}()
			select {
			case <-waitCtx.waiting:
			case <-time.After(time.Second):
				t.Fatal("probe never reached first-publication contention")
			}
			select {
			case err := <-result:
				t.Fatalf("probe returned before first ownership was published: %v", err)
			default:
			}

			file, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatalf("open lock: %v", err)
			}
			if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatalf("lock: %v", err)
			}
			if err := writePID(file, os.Getpid()); err != nil {
				t.Fatalf("publish pid: %v", err)
			}
			if err := syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN); err != nil {
				t.Fatalf("unlock transition: %v", err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("probe did not resume after first ownership was published")
			}
		})
	}
}

func TestOwnerPIDRejectsInvalidMetadata(t *testing.T) {
	for name, contents := range map[string]string{
		"empty":              "",
		"not-pid":            "pmon",
		"zero":               "0",
		"negative":           "-1",
		"pid-t-overflow":     "2147483648",
		"kill-all-wrap":      "4294967295",
		"process-group-wrap": "4294967296",
		"too-long":           strings.Repeat("1", maxPIDBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir() + "/instance.lock"
			file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatalf("open lock: %v", err)
			}
			transitionFile, err := os.OpenFile(transitionPath(path), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				file.Close()
				t.Fatalf("open transition lock: %v", err)
			}
			t.Cleanup(func() {
				syscall.Flock(int(transitionFile.Fd()), syscall.LOCK_UN)
				syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				transitionFile.Close()
				file.Close()
			})
			if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatalf("lock: %v", err)
			}
			if _, err := file.WriteString(contents); err != nil {
				t.Fatalf("write metadata: %v", err)
			}

			pid, held, err := ownerPID(path)
			if err == nil || !held || pid != 0 {
				t.Fatalf("OwnerPID = %d, %v, %v; want 0, true, error", pid, held, err)
			}
		})
	}
}
