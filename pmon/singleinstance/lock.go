// Package singleinstance coordinates one daemon process and its clients.
package singleinstance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxPIDBytes       = 64
	transitionPollGap = 10 * time.Millisecond
)

type fileLock struct {
	file *os.File
}

func acquireLock(ctx context.Context, path string) (*fileLock, bool, error) {
	transitionFile, err := lockTransition(ctx, path, syscall.LOCK_EX)
	if err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, errors.Join(err, unlockAndClose(transitionFile))
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		closeErr := errors.Join(file.Close(), unlockAndClose(transitionFile))
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, false, closeErr
		}
		return nil, false, errors.Join(err, closeErr)
	}
	// The transition lock makes retained metadata unreadable until this replacement completes.
	if err := writePID(file, os.Getpid()); err != nil {
		return nil, false, errors.Join(err, unlockAndClose(file), unlockAndClose(transitionFile))
	}
	if err := unlockAndClose(transitionFile); err != nil {
		return nil, false, errors.Join(err, unlockAndClose(file))
	}
	return &fileLock{file: file}, true, nil
}

func (lock *fileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	return unlockAndClose(file)
}

func lockHeld(ctx context.Context, path string) (held bool, err error) {
	transitionFile, err := lockTransition(ctx, path, syscall.LOCK_SH)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return false, unlockAndClose(transitionFile)
	}
	if err != nil {
		return false, errors.Join(err, unlockAndClose(transitionFile))
	}
	defer func() {
		err = errors.Join(err, file.Close(), unlockAndClose(transitionFile))
	}()
	return fileHeld(file)
}

func lockOwnerPID(ctx context.Context, path string) (pid int, held bool, err error) {
	transitionFile, err := lockTransition(ctx, path, syscall.LOCK_SH)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, unlockAndClose(transitionFile)
	}
	if err != nil {
		return 0, false, errors.Join(err, unlockAndClose(transitionFile))
	}
	defer func() {
		err = errors.Join(err, file.Close(), unlockAndClose(transitionFile))
	}()
	held, err = fileHeld(file)
	if err != nil || !held {
		return 0, held, err
	}
	pid, err = readPID(file)
	if err != nil {
		return 0, true, err
	}
	held, err = fileHeld(file)
	if err != nil || !held {
		return 0, held, err
	}
	return pid, true, nil
}

func writePID(file *os.File, pid int) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	data := fmt.Appendf(nil, "%d", pid)
	written, err := file.WriteAt(data, 0)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func readPID(file *os.File) (int, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPIDBytes+1))
	if err != nil {
		return 0, err
	}
	if len(data) > maxPIDBytes {
		return 0, errors.New("owner pid is too long")
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid owner pid %q", data)
	}
	return int(pid), nil
}

func transitionPath(path string) string {
	return path + ".transition"
}

func lockTransition(ctx context.Context, path string, mode int) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(transitionPath(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(file.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, errors.Join(err, file.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(fmt.Errorf("wait for lock transition: %w", ctx.Err()), file.Close())
		case <-time.After(transitionPollGap):
		}
	}
}

func fileHeld(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			return false, err
		}
		return false, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return true, nil
	}
	return false, err
}

func unlockAndClose(file *os.File) error {
	return errors.Join(
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN),
		file.Close(),
	)
}
