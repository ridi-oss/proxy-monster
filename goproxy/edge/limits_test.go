package edge

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

var otherClient = &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40999}

func dialEdgeFrom(t *testing.T, mem *memNet, addr string, source *net.TCPAddr) net.Conn {
	t.Helper()
	conn := dialEdge(t, mem, addr, false)
	if _, err := proxyproto.HeaderProxyFromAddrs(2, source, entryAddr).WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	return conn
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sourcesInHandshake(s *Server) int {
	s.sourcesMu.Lock()
	defer s.sourcesMu.Unlock()
	total := 0
	for _, n := range s.sources {
		total += n
	}
	return total
}

func expectRoutedTo(t *testing.T, f edgeFixture, conn net.Conn, host, want string) {
	t.Helper()
	client := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: f.roots})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake through the edge: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("reading the backend's name: %v", err)
	}
	if string(got) != want {
		t.Fatalf("reached %q, want %q", got, want)
	}
	if hit := <-f.backends[host].hits; hit.err != nil {
		t.Fatalf("backend: %v", hit.err)
	}
}

func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("edge kept the connection open")
	}
}

func TestEdgeCapsHandshakesFromOneSource(t *testing.T) {
	f := startEdge(t, drivers[2], "127.0.0.1/32")
	f.server.perSourceCap = 1
	_ = dialEdgeFrom(t, f.mem, f.addr, originalClient)
	waitFor(t, "the stalled handshake to claim its source", func() bool { return sourcesInHandshake(f.server) == 1 })

	expectClosed(t, dialEdgeFrom(t, f.mem, f.addr, originalClient))
	expectRoutedTo(t, f, dialEdgeFrom(t, f.mem, f.addr, otherClient), hostA, "backend-a")
}

func TestEdgeCapsConcurrentHandshakes(t *testing.T) {
	f := startEdge(t, drivers[2], "127.0.0.1/32")
	f.server.handshakes = make(chan struct{}, 1)
	stalled := dialEdgeFrom(t, f.mem, f.addr, originalClient)
	waitFor(t, "the stalled handshake to hold the slot", func() bool { return sourcesInHandshake(f.server) == 1 })

	expectClosed(t, dialEdge(t, f.mem, f.addr, false))

	_ = stalled.Close()
	waitFor(t, "the handshake slot to free", func() bool { return len(f.server.handshakes) == 0 })
	conn := dialEdgeFrom(t, f.mem, f.addr, otherClient)
	expectRoutedTo(t, f, conn, hostA, "backend-a")
	if n := len(f.server.handshakes); n != 0 {
		t.Fatalf("a spliced session holds %d handshake slot(s)", n)
	}
}

func TestEdgeSendsUnrecognizedNameForAnUnroutedHost(t *testing.T) {
	for _, d := range drivers {
		t.Run(string(d.kind), func(t *testing.T) {
			f := startEdge(t, d, "127.0.0.1/32")
			conn := dialEdge(t, f.mem, f.addr, true)
			if err := d.clientOpen(conn); err != nil {
				t.Fatal(err)
			}
			err := tls.Client(conn, &tls.Config{ServerName: "unknown.edge.test", RootCAs: f.roots}).Handshake()
			if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
				t.Fatalf("handshake error = %v, want an unrecognized_name alert", err)
			}
		})
	}
}

func TestEdgeRefusesABackendGreetingThatOffersLessThanTheEdge(t *testing.T) {
	d := drivers[0]
	d.backendOpen = func(conn net.Conn) error {
		scramble, err := mysqlwire.Scramble()
		if err != nil {
			return err
		}
		return mysqlwire.WritePacket(conn, 0, mysqlwire.ServerGreetingSSL(7, scramble, "8.0.40-backend", false))
	}
	f := startEdge(t, d, "127.0.0.1/32")
	conn := dialEdge(t, f.mem, f.addr, true)
	if err := d.clientOpen(conn); err != nil {
		t.Fatal(err)
	}
	err := tls.Client(conn, &tls.Config{ServerName: hostA, RootCAs: f.roots}).Handshake()
	if err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("handshake error = %v, want an internal_error alert", err)
	}
}

func TestSpliceTreatsAResetAfterACleanCloseAsClosed(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	if err := spliceErrors(nil, reset); err != nil {
		t.Fatalf("reset after the client finished = %v, want nil", err)
	}
	if err := spliceErrors(reset, nil); err != nil {
		t.Fatalf("reset after the backend finished = %v, want nil", err)
	}
	if err := spliceErrors(reset, net.ErrClosed); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("reset that cut the session = %v, want ECONNRESET", err)
	}
}

func TestSampledLogAllowsOneLinePerInterval(t *testing.T) {
	var l sampledLog
	start := time.Unix(0, 0)
	if ok, n := l.allow(start); !ok || n != 0 {
		t.Fatalf("first = %v, %d", ok, n)
	}
	for i := range 3 {
		if ok, _ := l.allow(start.Add(time.Duration(i+1) * 100 * time.Millisecond)); ok {
			t.Fatalf("line %d inside the interval was allowed", i)
		}
	}
	if ok, n := l.allow(start.Add(rejectLogInterval + time.Millisecond)); !ok || n != 3 {
		t.Fatalf("after the interval = %v, %d suppressed, want true, 3", ok, n)
	}
}

func TestNewClampsHandshakeLimitsToTheConnectionLimit(t *testing.T) {
	s, err := New(&Config{MaxConnections: 4, MaxHandshakes: 10, MaxHandshakesPerSource: 10})
	if err != nil {
		t.Fatal(err)
	}
	if cap(s.handshakes) != 4 || s.perSourceCap != 4 {
		t.Fatalf("handshakes = %d, per source = %d, want 4, 4", cap(s.handshakes), s.perSourceCap)
	}
}
