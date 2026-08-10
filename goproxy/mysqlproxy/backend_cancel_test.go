package mysqlproxy

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// TestDialBackendAuthIDAbortsOnContextCancel proves the real MySQL dial honors the target-DB open context: a
// backend that accepts the TCP connection but never sends its greeting stalls the auth read, and cancelling
// the context must close the conn and return at once — not block until backendHandshakeTimeout. This is the
// mechanism the run target-DB open relies on; the runner-level tests exercise only the fake provider, so a
// regression that dropped DialContext or the auth AfterFunc would not surface there.
func TestDialBackendAuthIDAbortsOnContextCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stalling backend: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn // hold it open; never write the greeting
	}()

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	target := spi.BackendTarget{Host: host, Port: port, User: "u", Password: "p", Db: "d"}

	ctx, cancel := context.WithCancel(context.Background())
	dialErr := make(chan error, 1)
	go func() {
		_, _, err := dialBackendAuthID(ctx, target, true)
		dialErr <- err
	}()

	// The dial must connect and block reading the greeting before we cancel, so the return is attributable to
	// the cancel unwinding the read rather than a failed connect.
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not connect to the stalling backend")
	}

	start := time.Now()
	cancel()
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("dial returned nil error after context cancel; want the aborted handshake to fail")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("dial returned %s after cancel; want a prompt abort, not the %s handshake timeout", elapsed, backendHandshakeTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not abort promptly on context cancel")
	}
}
