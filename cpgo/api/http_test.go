package api

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestJavaInstant(t *testing.T) {
	for in, want := range map[string]string{
		"2026-10-09T03:10:45Z":           "2026-10-09T03:10:45Z",
		"2026-10-09T03:10:45.12Z":        "2026-10-09T03:10:45.120Z",
		"2026-10-09T03:10:45.123456Z":    "2026-10-09T03:10:45.123456Z",
		"2026-10-09T03:10:45.000100Z":    "2026-10-09T03:10:45.000100Z",
		"2026-10-09T12:10:45.5+09:00":    "2026-10-09T03:10:45.500Z",
		"2026-10-09T03:10:45.123456789Z": "2026-10-09T03:10:45.123456789Z",
	} {
		ts, _ := time.Parse(time.RFC3339Nano, in)
		if got := JavaInstant(ts); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestNotifyOutlivesTheRequestAndRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := notify(ctx, func(ctx context.Context) error {
		calls++
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if calls == 1 {
			return errors.New("kotlin busy")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("err %v after %d calls, want nil after 2", err, calls)
	}
	if err := notify(context.Background(), func(context.Context) error { return errors.New("down") }); err == nil {
		t.Fatal("a signal that never lands must report its error")
	}
}
