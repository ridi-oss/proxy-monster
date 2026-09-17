package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/providers"
)

type countedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestTrackedConnectionClosesAndDeregistersOnce(t *testing.T) {
	d := New("test", providers.Builtins())
	local, remote := net.Pipe()
	defer remote.Close()
	counted := &countedConn{Conn: local}
	tracked := d.trackConn("test", counted)
	if got := liveConnections(d); got != 1 {
		t.Fatalf("connection count = %d", got)
	}
	var calls sync.WaitGroup
	for range 16 {
		calls.Go(func() { _ = tracked.Close() })
	}
	calls.Wait()
	if got := counted.closes.Load(); got != 1 {
		t.Fatalf("underlying close calls = %d, want 1", got)
	}
	if got := liveConnections(d); got != 0 {
		t.Fatalf("connection count after close = %d", got)
	}
}

type delayedAccept struct {
	conn    net.Conn
	entered chan struct{}
	release chan struct{}
}

func (l delayedAccept) Accept() (net.Conn, error) {
	close(l.entered)
	<-l.release
	return l.conn, nil
}

func (delayedAccept) Close() error   { return nil }
func (delayedAccept) Addr() net.Addr { return &net.TCPAddr{} }

func TestListenerRejectsAnAcceptCompletedAfterClose(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	underlying := delayedAccept{conn: local, entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tracked atomic.Int32
	listener := &brokerListener{
		Listener: underlying, ctx: ctx, cancel: cancel,
		track: func(conn net.Conn) net.Conn { tracked.Add(1); return conn },
	}
	done := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		done <- err
	}()
	<-underlying.entered
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	close(underlying.release)
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("accept error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accept did not finish")
	}
	if tracked.Load() != 0 || ctx.Err() == nil {
		t.Fatal("closed listener registered a late connection or kept its context alive")
	}
}
