package listen

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var tailnetClient = &net.TCPAddr{IP: net.ParseIP("100.64.0.7"), Port: 51234}

func mergedOnLoopback(t *testing.T, trusted string) (ln net.Listener, plainAddr, proxiedAddr string) {
	t.Helper()
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err = Merge(plain, proxied, spi.Listen{TrustedProxies: []netip.Prefix{netip.MustParsePrefix(trusted)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, plain.Addr().String(), proxied.Addr().String()
}

func acceptWithin(t *testing.T, ln net.Listener, d time.Duration) (net.Conn, bool) {
	t.Helper()
	result := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(result)
			return
		}
		result <- conn
	}()
	select {
	case conn, ok := <-result:
		if ok {
			t.Cleanup(func() { _ = conn.Close() })
		}
		return conn, ok
	case <-time.After(d):
		return nil, false
	}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sendHeader(t *testing.T, conn net.Conn) {
	t.Helper()
	header := proxyproto.HeaderProxyFromAddrs(2, tailnetClient, conn.RemoteAddr())
	if _, err := header.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedSenderHeaderBecomesTheClientAddress(t *testing.T) {
	ln, _, proxied := mergedOnLoopback(t, "127.0.0.1/32")
	client := dial(t, proxied)
	sendHeader(t, client)
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}

	conn, ok := acceptWithin(t, ln, time.Second)
	if !ok {
		t.Fatal("trusted connection was not accepted")
	}
	if got := conn.RemoteAddr().String(); got != tailnetClient.String() {
		t.Fatalf("RemoteAddr = %s, want the header source %s", got, tailnetClient)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("payload after the header = %q, %v; want ping", buf, err)
	}
}

func TestTrustedSenderWithoutHeaderIsRefused(t *testing.T) {
	ln, _, proxied := mergedOnLoopback(t, "127.0.0.1/32")
	client := dial(t, proxied)
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	conn, ok := acceptWithin(t, ln, time.Second)
	if !ok {
		t.Fatal("connection was not handed to the broker")
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, proxyproto.ErrNoProxyProtocol) {
		t.Fatalf("Read without a header = %v, want ErrNoProxyProtocol", err)
	}
	if got := conn.RemoteAddr().String(); got == tailnetClient.String() {
		t.Fatalf("RemoteAddr = %s, an address no header asserted", got)
	}
}

func TestUntrustedSenderIsDroppedAtAccept(t *testing.T) {
	ln, _, proxied := mergedOnLoopback(t, "10.0.0.0/8")
	client := dial(t, proxied)
	sendHeader(t, client)

	if conn, ok := acceptWithin(t, ln, 300*time.Millisecond); ok {
		t.Fatalf("untrusted sender reached the broker as %s", conn.RemoteAddr())
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("untrusted connection is still open")
	}
}

func TestPlainPortNeverParsesAHeader(t *testing.T) {
	ln, plain, _ := mergedOnLoopback(t, "127.0.0.1/32")
	client := dial(t, plain)
	sendHeader(t, client)

	conn, ok := acceptWithin(t, ln, time.Second)
	if !ok {
		t.Fatal("plain connection was not accepted")
	}
	if got := conn.RemoteAddr().String(); got != client.LocalAddr().String() {
		t.Fatalf("RemoteAddr = %s, want the socket peer %s", got, client.LocalAddr())
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if want := "\r\n\r\n\x00\r\nQUIT\n"; string(buf) != want {
		t.Fatalf("plain port consumed the header: first bytes %q, want %q", buf, want)
	}
}

func TestMergeRefusesAProxyPortWithNoTrustedSender(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	proxied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxied.Close()
	if _, err := Merge(plain, proxied, spi.Listen{}); err == nil {
		t.Fatal("Merge accepted a PROXY port that no sender could use")
	}
}

func TestCloseEndsAcceptWithErrClosed(t *testing.T) {
	ln, _, _ := mergedOnLoopback(t, "127.0.0.1/32")
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	_ = ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

func TestOpenWithoutAProxyPortBindsOnlyThePlainPort(t *testing.T) {
	ln, err := Open(spi.Listen{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, isMerged := ln.(*merged); isMerged {
		t.Fatal("Open bound a PROXY port that was not configured")
	}
}
