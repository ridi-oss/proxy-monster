package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
)

const (
	handshakeTimeout         = 15 * time.Second
	drainTimeout             = 10 * time.Second
	maxConcurrentConnections = 256
)

var (
	errPlaintext    = errors.New("client did not request TLS")
	errBackendNoTLS = errors.New("backend does not offer TLS")
)

type opening struct {
	serverName string
	hello      []byte
	prepare    func(backend net.Conn) error
}

type Server struct {
	config           *Config
	trust            proxyproto.ConnPolicyFunc
	dial             func(ctx context.Context, network, address string) (net.Conn, error)
	handshakeTimeout time.Duration
	slots            chan struct{}
	connID           atomic.Uint32

	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	conns     map[net.Conn]struct{}
	active    sync.WaitGroup
}

func New(config *Config) (*Server, error) {
	trusted := make([]string, len(config.TrustedProxies))
	for i, prefix := range config.TrustedProxies {
		trusted[i] = prefix.String()
	}
	trust, err := proxyproto.TrustProxyHeaderFromRanges(trusted)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:           config,
		trust:            trust,
		dial:             (&net.Dialer{}).DialContext,
		handshakeTimeout: handshakeTimeout,
		slots:            make(chan struct{}, maxConcurrentConnections),
		listeners:        map[net.Listener]struct{}{},
		conns:            map[net.Conn]struct{}{},
	}, nil
}

func Run() error {
	config, err := Load()
	if err != nil {
		return err
	}
	server, err := New(config)
	if err != nil {
		return err
	}
	type bound struct {
		kind Kind
		ln   net.Listener
	}
	var listeners []bound
	closeAll := func() {
		for _, b := range listeners {
			_ = b.ln.Close()
		}
	}
	for _, l := range config.Listeners {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", l.Port))
		if err != nil {
			closeAll()
			return fmt.Errorf("edge: listening for %s on port %d: %w", l.Kind, l.Port, err)
		}
		listeners = append(listeners, bound{l.Kind, ln})
	}
	var health net.Listener
	if config.HealthPort != 0 {
		health, err = net.Listen("tcp", fmt.Sprintf(":%d", config.HealthPort))
		if err != nil {
			closeAll()
			return fmt.Errorf("edge: listening for health checks on port %d: %w", config.HealthPort, err)
		}
	}

	errs := make(chan error, len(listeners)+1)
	for _, b := range listeners {
		slog.Info("edge listening", "kind", string(b.kind), "addr", b.ln.Addr().String())
		go func() { errs <- server.Serve(b.kind, b.ln) }()
	}
	if health != nil {
		go func() { errs <- server.ServeHealth(health) }()
	}
	slog.Info("starting proxy-monster edge router", "routes", len(config.Routes), "health_port", config.HealthPort)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		slog.Info("shutting down the edge router", "timeout", drainTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	case err := <-errs:
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		server.Shutdown(ctx)
		if err == nil {
			err = errors.New("edge: a listener stopped unexpectedly")
		}
		return err
	}
}

func (s *Server) Serve(kind Kind, ln net.Listener) error {
	proxied := &proxyproto.Listener{Listener: ln, ConnPolicy: s.policy, ReadHeaderTimeout: s.handshakeTimeout}
	if !s.trackListener(proxied) {
		return nil
	}
	for {
		conn, err := proxied.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !s.acquire() {
			_ = conn.Close()
			continue
		}
		if !s.trackConn(conn) {
			s.release()
			_ = conn.Close()
			return nil
		}
		go func() {
			defer s.release()
			defer s.untrackConn(conn)
			s.handle(kind, conn)
		}()
	}
}

func (s *Server) ServeHealth(ln net.Listener) error {
	if !s.trackListener(ln) {
		return nil
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		_ = conn.Close()
	}
}

func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.closed = true
	listeners := make([]net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		listeners = append(listeners, ln)
	}
	s.mu.Unlock()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	done := make(chan struct{})
	go func() {
		s.active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-ctx.Done():
	}
	s.mu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	<-done
}

func (s *Server) policy(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
	policy, err := s.trust(opts)
	if err != nil {
		slog.Info("edge connection", "client", opts.Upstream.String(), "outcome", "untrusted_peer")
	}
	return policy, err
}

func (s *Server) acquire() bool {
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) release() { <-s.slots }

func (s *Server) trackListener(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = ln.Close()
		return false
	}
	s.listeners[ln] = struct{}{}
	return true
}

func (s *Server) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	s.active.Add(1)
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	s.active.Done()
}

func (s *Server) addBackend(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) removeBackend(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

type connRecord struct {
	kind       Kind
	client     string
	serverName string
	backend    string
	bytesUp    int64
	bytesDown  int64
	outcome    string
	err        error
}

func (r *connRecord) fail(outcome string, err error) {
	r.outcome = outcome
	r.err = err
}

func (r *connRecord) log(duration time.Duration) {
	attrs := []any{
		"client", r.client,
		"kind", string(r.kind),
		"sni", r.serverName,
		"backend", r.backend,
		"bytes_up", r.bytesUp,
		"bytes_down", r.bytesDown,
		"duration", duration,
		"outcome", r.outcome,
	}
	if r.err != nil {
		attrs = append(attrs, "error", r.err.Error())
	}
	level := slog.LevelInfo
	if strings.HasPrefix(r.outcome, "backend_") {
		level = slog.LevelWarn
	}
	slog.Log(context.Background(), level, "edge connection", attrs...)
}

func (s *Server) handle(kind Kind, conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	record := &connRecord{kind: kind, client: socketPeer(conn)}
	defer func() { record.log(time.Since(start)) }()

	deadline := start.Add(s.handshakeTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		record.fail("client_error", err)
		return
	}
	header := proxyHeader(conn)
	if header == nil {
		record.outcome = "no_proxy_header"
		return
	}
	record.client = header.SourceAddr.String()

	var open opening
	var err error
	switch kind {
	case KindMySQL:
		open, err = openMySQL(conn, s.connID.Add(1))
	case KindPostgres:
		open, err = openPostgres(conn)
	case KindHTTPS:
		open.serverName, open.hello, err = peekClientHello(conn)
	default:
		err = fmt.Errorf("unknown listener kind %q", kind)
	}
	switch {
	case errors.Is(err, errPlaintext):
		record.fail("plaintext_refused", nil)
		return
	case errors.Is(err, errCancelRequest):
		record.fail("cancel_not_routed", nil)
		return
	case err != nil:
		record.fail("client_error", err)
		return
	}
	record.serverName = open.serverName
	if open.serverName == "" {
		record.outcome = "no_sni"
		return
	}
	backendAddr, ok := s.config.Routes[strings.ToLower(open.serverName)]
	if !ok {
		record.outcome = "unknown_sni"
		return
	}
	record.backend = backendAddr

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	backend, err := s.dial(ctx, "tcp", backendAddr)
	cancel()
	if err != nil {
		record.fail("backend_unreachable", err)
		return
	}
	defer backend.Close()
	if !s.addBackend(backend) {
		record.outcome = "shutting_down"
		return
	}
	defer s.removeBackend(backend)
	if err := backend.SetDeadline(deadline); err != nil {
		record.fail("backend_error", err)
		return
	}
	forwarded := proxyproto.HeaderProxyFromAddrs(2, header.SourceAddr, header.DestinationAddr)
	if _, err := forwarded.WriteTo(backend); err != nil {
		record.fail("backend_error", err)
		return
	}
	if open.prepare != nil {
		if err := open.prepare(backend); err != nil {
			record.fail("backend_error", err)
			return
		}
	}
	if _, err := backend.Write(open.hello); err != nil {
		record.fail("backend_error", err)
		return
	}
	if err := errors.Join(conn.SetDeadline(time.Time{}), backend.SetDeadline(time.Time{})); err != nil {
		record.fail("client_error", err)
		return
	}
	record.bytesUp, record.bytesDown = splice(conn, backend)
	record.outcome = "closed"
}

func proxyHeader(conn net.Conn) *proxyproto.Header {
	proxied, ok := conn.(*proxyproto.Conn)
	if !ok {
		return nil
	}
	header := proxied.ProxyHeader()
	if header == nil || !header.Command.IsProxy() || header.SourceAddr == nil || header.DestinationAddr == nil {
		return nil
	}
	return header
}

func socketPeer(conn net.Conn) string {
	if proxied, ok := conn.(*proxyproto.Conn); ok {
		return proxied.Raw().RemoteAddr().String()
	}
	return conn.RemoteAddr().String()
}

func splice(client, backend net.Conn) (up, down int64) {
	upDone := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(backend, client)
		_ = backend.Close()
		_ = client.Close()
		upDone <- n
	}()
	down, _ = io.Copy(client, backend)
	_ = client.Close()
	_ = backend.Close()
	return <-upDone, down
}
