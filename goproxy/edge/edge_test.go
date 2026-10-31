package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/pires/go-proxyproto"
	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

const (
	hostA       = "a.edge.test"
	hostB       = "b.edge.test"
	testTimeout = 5 * time.Second
)

var (
	originalClient  = &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40123}
	entryAddr       = &net.TCPAddr{IP: net.ParseIP("100.100.1.1"), Port: 3306}
	tailscaleSocket = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51000}
	edgeSocket      = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 52000}
)

type kindDriver struct {
	kind            Kind
	backendOpen     func(conn net.Conn) error
	clientOpen      func(conn net.Conn) error
	clientPlaintext func(t *testing.T, conn net.Conn) []byte
}

var drivers = []kindDriver{
	{
		kind: KindMySQL,
		backendOpen: func(conn net.Conn) error {
			scramble, err := mysqlwire.Scramble()
			if err != nil {
				return err
			}
			if err := mysqlwire.WritePacket(conn, 0, mysqlwire.ServerGreetingSSL(7, scramble, "8.0.40-backend", true)); err != nil {
				return err
			}
			seq, payload, err := mysqlwire.ReadPacket(conn)
			if err != nil {
				return err
			}
			if seq != 1 || !mysqlwire.LooksLikeSSLRequest(payload) {
				return errors.New("backend did not receive the client's SSLRequest at sequence 1")
			}
			return nil
		},
		clientOpen: func(conn net.Conn) error {
			_, greeting, err := mysqlwire.ReadPacket(conn)
			if err != nil {
				return err
			}
			if !mysqlwire.GreetingOffersSSL(greeting) {
				return errors.New("edge greeting does not offer SSL")
			}
			caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSSL | mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth)
			return mysqlwire.WritePacket(conn, 1, mysqlwire.SSLRequest(caps))
		},
		clientPlaintext: func(t *testing.T, conn net.Conn) []byte {
			t.Helper()
			if _, _, err := mysqlwire.ReadPacket(conn); err != nil {
				t.Fatal(err)
			}
			caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth)
			if err := mysqlwire.WritePacket(conn, 1, mysqlwire.ClientHandshakeResponse(caps, "alice", nil)); err != nil {
				t.Fatal(err)
			}
			seq, payload, err := mysqlwire.ReadPacket(conn)
			if err != nil {
				t.Fatal(err)
			}
			if seq != 2 {
				t.Fatalf("error packet sequence = %d, want 2", seq)
			}
			return payload
		},
	},
	{
		kind: KindPostgres,
		backendOpen: func(conn net.Conn) error {
			code, err := readPostgresStartup(conn)
			if err != nil {
				return err
			}
			if code != postgresSSLRequestCode {
				return errors.New("backend did not receive an SSLRequest")
			}
			_, err = conn.Write([]byte{'S'})
			return err
		},
		clientOpen: func(conn net.Conn) error {
			request, err := (&pgproto3.SSLRequest{}).Encode(nil)
			if err != nil {
				return err
			}
			if _, err := conn.Write(request); err != nil {
				return err
			}
			var answer [1]byte
			if _, err := io.ReadFull(conn, answer[:]); err != nil {
				return err
			}
			if answer[0] != 'S' {
				return errors.New("edge refused TLS")
			}
			return nil
		},
		clientPlaintext: func(t *testing.T, conn net.Conn) []byte {
			t.Helper()
			startup, err := (&pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersion30,
				Parameters:      map[string]string{"user": "alice", "database": "app"},
			}).Encode(nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(startup); err != nil {
				t.Fatal(err)
			}
			answer, err := io.ReadAll(conn)
			if err != nil && !isClosed(err) {
				t.Fatal(err)
			}
			if len(answer) == 0 || answer[0] != 'E' {
				t.Fatalf("edge answered %q, want an ErrorResponse", answer)
			}
			return answer
		},
	},
	{
		kind:        KindHTTPS,
		backendOpen: func(net.Conn) error { return nil },
		clientOpen:  func(net.Conn) error { return nil },
	},
}

type testCert struct {
	pair tls.Certificate
	leaf *x509.Certificate
}

func newTestCert(t *testing.T, host string) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{pair: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf: leaf}
}

type backendHit struct {
	source  string
	version byte
	err     error
}

type fakeBackend struct {
	addr string
	hits chan backendHit
}

type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.local }
func (c addrConn) RemoteAddr() net.Addr { return c.remote }

type memListener struct {
	addr      *net.TCPAddr
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return l.addr }

type memNet struct {
	mu        sync.Mutex
	listeners map[string]*memListener
	nextPort  int
}

func newMemNet() *memNet { return &memNet{listeners: map[string]*memListener{}, nextPort: 20000} }

func (n *memNet) listen() *memListener {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextPort++
	l := &memListener{
		addr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: n.nextPort},
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
	n.listeners[l.addr.String()] = l
	return l
}

func (n *memNet) dialFrom(ctx context.Context, peer *net.TCPAddr, address string) (net.Conn, error) {
	n.mu.Lock()
	l, ok := n.listeners[address]
	n.mu.Unlock()
	if !ok {
		return nil, errors.New("connection refused")
	}
	near, far := net.Pipe()
	select {
	case l.conns <- addrConn{Conn: far, local: l.addr, remote: peer}:
		return addrConn{Conn: near, local: peer, remote: l.addr}, nil
	case <-l.closed:
		return nil, errors.New("connection refused")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *memNet) dialer(peer *net.TCPAddr) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, address string) (net.Conn, error) { return n.dialFrom(ctx, peer, address) }
}

func startBackend(t *testing.T, mem *memNet, d kindDriver, name string, cert testCert) *fakeBackend {
	t.Helper()
	raw := mem.listen()
	trust, err := proxyproto.TrustProxyHeaderFromRanges([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	ln := &proxyproto.Listener{Listener: raw, ConnPolicy: trust}
	t.Cleanup(func() { _ = ln.Close() })
	b := &fakeBackend{addr: raw.Addr().String(), hits: make(chan backendHit, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(d, name, cert, conn)
		}
	}()
	return b
}

func (b *fakeBackend) serve(d kindDriver, name string, cert testCert, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	hit := backendHit{}
	defer func() { b.hits <- hit }()
	header := conn.(*proxyproto.Conn).ProxyHeader()
	if header == nil {
		hit.err = errors.New("backend received no PROXY header")
		return
	}
	hit.source = header.SourceAddr.String()
	hit.version = header.Version
	if err := d.backendOpen(conn); err != nil {
		hit.err = err
		return
	}
	server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert.pair}})
	if err := server.Handshake(); err != nil {
		hit.err = err
		return
	}
	if _, err := server.Write([]byte(name)); err != nil {
		hit.err = err
	}
}

type edgeFixture struct {
	mem      *memNet
	addr     string
	roots    *x509.CertPool
	backends map[string]*fakeBackend
}

func startEdge(t *testing.T, d kindDriver, trusted string) edgeFixture {
	t.Helper()
	mem := newMemNet()
	certA, certB := newTestCert(t, hostA), newTestCert(t, hostB)
	backendA := startBackend(t, mem, d, "backend-a", certA)
	backendB := startBackend(t, mem, d, "backend-b", certB)
	roots := x509.NewCertPool()
	roots.AddCert(certA.leaf)
	roots.AddCert(certB.leaf)

	server, err := New(&Config{
		Listeners:      []Listener{{Kind: d.kind, Port: 1}},
		Routes:         map[string]string{hostA: backendA.addr, hostB: backendB.addr},
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix(trusted)},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.handshakeTimeout = 2 * time.Second
	server.dial = mem.dialer(edgeSocket)
	ln := mem.listen()
	served := make(chan error, 1)
	go func() { served <- server.Serve(d.kind, ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		server.Shutdown(ctx)
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return edgeFixture{
		mem:      mem,
		addr:     ln.Addr().String(),
		roots:    roots,
		backends: map[string]*fakeBackend{hostA: backendA, hostB: backendB},
	}
}

func dialEdge(t *testing.T, mem *memNet, addr string, withHeader bool) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	conn, err := mem.dialFrom(ctx, tailscaleSocket, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	if withHeader {
		if _, err := proxyproto.HeaderProxyFromAddrs(2, originalClient, entryAddr).WriteTo(conn); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

func isClosed(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && strings.Contains(opErr.Err.Error(), "reset")
}

func expectNoBackendHit(t *testing.T, f edgeFixture) {
	t.Helper()
	for host, b := range f.backends {
		select {
		case hit := <-b.hits:
			t.Fatalf("backend %s was dialed: %+v", host, hit)
		default:
		}
	}
}

func TestEdgeRoutesBySNIToTheMatchingBackend(t *testing.T) {
	for _, d := range drivers {
		t.Run(string(d.kind), func(t *testing.T) {
			f := startEdge(t, d, "127.0.0.1/32")
			for host, want := range map[string]string{hostA: "backend-a", hostB: "backend-b"} {
				conn := dialEdge(t, f.mem, f.addr, true)
				if err := d.clientOpen(conn); err != nil {
					t.Fatalf("%s: client pre-TLS exchange: %v", host, err)
				}
				client := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: f.roots})
				if err := client.Handshake(); err != nil {
					t.Fatalf("%s: TLS handshake through the edge: %v", host, err)
				}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(client, got); err != nil {
					t.Fatalf("%s: reading the backend's name: %v", host, err)
				}
				if string(got) != want {
					t.Fatalf("%s reached %q, want %q", host, got, want)
				}
				hit := <-f.backends[host].hits
				if hit.err != nil {
					t.Fatalf("%s: backend: %v", host, hit.err)
				}
				if hit.version != 2 {
					t.Fatalf("%s: backend PROXY header version = %d, want 2", host, hit.version)
				}
				if hit.source != originalClient.String() {
					t.Fatalf("%s: backend saw source %s, want %s", host, hit.source, originalClient)
				}
				_ = client.Close()
			}
		})
	}
}

func TestEdgeClosesUnknownSNI(t *testing.T) {
	for _, d := range drivers {
		t.Run(string(d.kind), func(t *testing.T) {
			f := startEdge(t, d, "127.0.0.1/32")
			conn := dialEdge(t, f.mem, f.addr, true)
			if err := d.clientOpen(conn); err != nil {
				t.Fatal(err)
			}
			client := tls.Client(conn, &tls.Config{ServerName: "unknown.edge.test", RootCAs: f.roots})
			if err := client.Handshake(); err == nil {
				t.Fatal("TLS handshake for an unrouted host succeeded")
			}
			expectNoBackendHit(t, f)
		})
	}
}

func TestEdgeClosesMissingSNI(t *testing.T) {
	d := drivers[2]
	f := startEdge(t, d, "127.0.0.1/32")
	conn := dialEdge(t, f.mem, f.addr, true)
	client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := client.Handshake(); err == nil {
		t.Fatal("TLS handshake without SNI succeeded")
	}
	expectNoBackendHit(t, f)
}

func TestEdgeRefusesPlaintextLogin(t *testing.T) {
	for _, d := range drivers {
		if d.clientPlaintext == nil {
			continue
		}
		t.Run(string(d.kind), func(t *testing.T) {
			f := startEdge(t, d, "127.0.0.1/32")
			conn := dialEdge(t, f.mem, f.addr, true)
			answer := d.clientPlaintext(t, conn)
			if !bytes.Contains(answer, []byte("TLS required")) {
				t.Fatalf("edge answered %q, want a TLS-required error", answer)
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("edge kept the plaintext connection open")
			}
			expectNoBackendHit(t, f)
		})
	}
}

func TestEdgeRejectsUntrustedPeer(t *testing.T) {
	for _, d := range drivers {
		t.Run(string(d.kind), func(t *testing.T) {
			f := startEdge(t, d, "192.0.2.0/24")
			conn := dialEdge(t, f.mem, f.addr, false)
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("edge answered a peer outside PM_TRUSTED_PROXIES")
			}
			expectNoBackendHit(t, f)
		})
	}
}

func TestEdgeRejectsTrustedPeerWithoutHeader(t *testing.T) {
	for _, d := range drivers {
		t.Run(string(d.kind), func(t *testing.T) {
			f := startEdge(t, d, "127.0.0.1/32")
			conn := dialEdge(t, f.mem, f.addr, false)
			if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("edge answered a connection without a PROXY header")
			}
			expectNoBackendHit(t, f)
		})
	}
}

func TestEdgeHealthPortAcceptsAndCloses(t *testing.T) {
	server, err := New(&Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	mem := newMemNet()
	ln := mem.listen()
	served := make(chan error, 1)
	go func() { served <- server.ServeHealth(ln) }()
	conn := dialEdge(t, mem, ln.Addr().String(), false)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("health read = %v, want EOF", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	server.Shutdown(ctx)
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
