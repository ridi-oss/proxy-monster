package singleinstance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

const ownerPollGap = 50 * time.Millisecond

var (
	ErrOwnerReplaced    = errors.New("single-instance owner changed")
	ErrOwnerExitTimeout = errors.New("single-instance owner did not exit")
)

type Instance struct {
	path             string
	operationTimeout time.Duration
}

func New(path string, operationTimeout time.Duration) *Instance {
	return &Instance{path: path, operationTimeout: operationTimeout}
}

func (instance *Instance) Acquire(ctx context.Context) (*Daemon, bool, error) {
	ctx, cancel := instance.operationContext(ctx)
	defer cancel()
	lock, acquired, err := acquireLock(ctx, instance.path)
	if err != nil || !acquired {
		return nil, acquired, err
	}
	return &Daemon{lock: lock}, true, nil
}

func (instance *Instance) Client() *Client {
	return &Client{instance: instance}
}

func (instance *Instance) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, instance.operationTimeout)
}

type Daemon struct {
	mu   sync.Mutex
	lock *fileLock
}

func (daemon *Daemon) Close() error {
	if daemon == nil {
		return nil
	}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if daemon.lock == nil {
		return nil
	}
	lock := daemon.lock
	daemon.lock = nil
	return lock.Close()
}

type Client struct {
	instance *Instance
}

func (client *Client) Running(ctx context.Context) (bool, error) {
	ctx, cancel := client.instance.operationContext(ctx)
	defer cancel()
	return lockHeld(ctx, client.instance.path)
}

func (client *Client) Owner(ctx context.Context) (*Owner, error) {
	ctx, cancel := client.instance.operationContext(ctx)
	defer cancel()
	pid, held, err := lockOwnerPID(ctx, client.instance.path)
	if err != nil || !held {
		return nil, err
	}
	return &Owner{pid: pid, client: client}, nil
}

type Owner struct {
	pid    int
	client *Client
}

func (owner *Owner) PID() int {
	return owner.pid
}

func (owner *Owner) Current(ctx context.Context) (bool, error) {
	current, err := owner.client.Owner(ctx)
	if err != nil {
		return false, err
	}
	if current == nil {
		return false, nil
	}
	if current.pid != owner.pid {
		return false, ErrOwnerReplaced
	}
	return true, nil
}

func (owner *Owner) Signal(ctx context.Context, signal syscall.Signal) error {
	current, err := owner.Current(ctx)
	if err != nil || !current {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return syscall.Kill(owner.pid, signal)
}

func (owner *Owner) WaitExit(ctx context.Context, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		current, err := owner.Current(waitCtx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, ErrOwnerReplaced) {
				return err
			}
			if waitCtx.Err() != nil {
				return fmt.Errorf("%w: pid %d after %s", ErrOwnerExitTimeout, owner.pid, timeout)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			return err
		}
		if !current {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waitCtx.Done():
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("%w: pid %d after %s", ErrOwnerExitTimeout, owner.pid, timeout)
		case <-time.After(ownerPollGap):
		}
	}
}
