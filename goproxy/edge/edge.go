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
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
)

const (
	handshakeTimeout   = 15 * time.Second
	minAcceptBackoff   = 5 * time.Millisecond
	maxAcceptBackoff   = time.Second
	rejectLogInterval  = time.Second
	tlsAlertRecord     = 21
	tlsAlertFatal      = 2
	alertInternalError = 80
	alertUnrecognized  = 112
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
	handshakes       chan struct{}
	perSourceCap     int
	connID           atomic.Uint32
	rejectLog        sampledLog
	untrustedLog     sampledLog

	sourcesMu sync.Mutex
	sources   map[string]int

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
	maxConnections := max(config.MaxConnections, 1)
	maxHandshakes := maxConnections
	if config.MaxHandshakes > 0 {
		maxHandshakes = min(config.MaxHandshakes, maxConnections)
	}
	perSourceCap := maxHandshakes
	if config.MaxHandshakesPerSource > 0 {
		perSourceCap = min(config.MaxHandshakesPerSource, maxHandshakes)
	}
	return &Server{
		config:           config,
		trust:            trust,
		dial:             (&net.Dialer{}).DialContext,
		handshakeTimeout: handshakeTimeout,
		slots:            make(chan struct{}, maxConnections),
		handshakes:       make(chan struct{}, maxHandshakes),
		perSourceCap:     perSourceCap,
		sources:          map[string]int{},
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
		slog.Info("shutting down the edge router", "timeout", config.DrainTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), config.DrainTimeout)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	case err := <-errs:
		ctx, cancel := context.WithTimeout(context.Background(), config.DrainTimeout)
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
	var backoff time.Duration
	for {
		conn, err := proxied.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = s.acceptFailed(kind, err, backoff)
			continue
		}
		backoff = 0
		if !s.acquire() {
			s.logRejected(conn, kind, "at_capacity", "max_connections", cap(s.slots))
			_ = conn.Close()
			continue
		}
		if !s.acquireHandshake() {
			s.release()
			s.logRejected(conn, kind, "handshakes_at_capacity", "max_handshakes", cap(s.handshakes))
			_ = conn.Close()
			continue
		}
		if !s.trackConn(conn) {
			s.releaseHandshake()
			s.release()
			_ = conn.Close()
			return nil
		}
		go func() {
			ticket := &handshakeTicket{server: s}
			defer s.release()
			defer ticket.end()
			defer s.untrackConn(conn)
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = conn.Close()
					slog.Error("edge connection handler panicked", "client", socketPeer(conn), "kind", string(kind), "panic", recovered, "stack", string(debug.Stack()))
				}
			}()
			s.handle(kind, conn, ticket)
		}()
	}
}

func (s *Server) ServeHealth(ln net.Listener) error {
	if !s.trackListener(ln) {
		return nil
	}
	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = s.acceptFailed("health", err, backoff)
			continue
		}
		backoff = 0
		_ = conn.Close()
	}
}

func (s *Server) acceptFailed(kind Kind, err error, previous time.Duration) time.Duration {
	backoff := min(max(previous*2, minAcceptBackoff), maxAcceptBackoff)
	slog.Warn("edge accept failed; retrying", "kind", string(kind), "error", err.Error(), "retry_in", backoff)
	time.Sleep(backoff)
	return backoff
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
		if ok, suppressed := s.untrustedLog.allow(time.Now()); ok {
			slog.Warn("edge connection", "peer", opts.Upstream.String(), "outcome", "untrusted_peer", "suppressed", suppressed)
		}
	}
	return policy, err
}

func (s *Server) logRejected(conn net.Conn, kind Kind, outcome string, attrs ...any) {
	ok, suppressed := s.rejectLog.allow(time.Now())
	if !ok {
		return
	}
	attrs = append([]any{"peer", socketPeer(conn), "kind", string(kind), "outcome", outcome, "suppressed", suppressed}, attrs...)
	slog.Warn("edge connection", attrs...)
}

type sampledLog struct {
	mu         sync.Mutex
	next       time.Time
	suppressed int
}

func (l *sampledLog) allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.next) {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.next = now.Add(rejectLogInterval)
	return true, suppressed
}

func (s *Server) acquireHandshake() bool {
	select {
	case s.handshakes <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseHandshake() { <-s.handshakes }

type handshakeTicket struct {
	server *Server
	source string
	ended  bool
}

func (t *handshakeTicket) claimSource(source string) bool {
	s := t.server
	s.sourcesMu.Lock()
	defer s.sourcesMu.Unlock()
	if s.sources[source] >= s.perSourceCap {
		return false
	}
	s.sources[source]++
	t.source = source
	return true
}

func (t *handshakeTicket) end() {
	if t.ended {
		return
	}
	t.ended = true
	s := t.server
	if t.source != "" {
		s.sourcesMu.Lock()
		if s.sources[t.source]--; s.sources[t.source] <= 0 {
			delete(s.sources, t.source)
		}
		s.sourcesMu.Unlock()
	}
	s.releaseHandshake()
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

func (s *Server) handle(kind Kind, conn net.Conn, ticket *handshakeTicket) {
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
	if !ticket.claimSource(sourceHost(header.SourceAddr)) {
		record.outcome = "source_at_capacity"
		return
	}

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
	refuse := func(outcome string, err error, alert byte) {
		record.fail(outcome, err)
		sendTLSAlert(conn, alert)
	}
	if open.serverName == "" {
		refuse("no_sni", nil, alertUnrecognized)
		return
	}
	route, ok := s.config.Routes[normalizeHost(open.serverName)]
	if !ok {
		refuse("unknown_sni", nil, alertUnrecognized)
		return
	}
	record.backend = route.Backend
	if route.Kind != kind {
		refuse("wrong_engine", fmt.Errorf("host is routed to a %s backend", route.Kind), alertUnrecognized)
		return
	}
	backendAddr := route.Backend

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	backend, err := s.dial(ctx, "tcp", backendAddr)
	cancel()
	if err != nil {
		refuse("backend_unreachable", err, alertInternalError)
		return
	}
	defer backend.Close()
	if !s.addBackend(backend) {
		refuse("shutting_down", nil, alertInternalError)
		return
	}
	defer s.removeBackend(backend)
	if err := backend.SetDeadline(deadline); err != nil {
		refuse("backend_error", err, alertInternalError)
		return
	}
	forwarded := proxyproto.HeaderProxyFromAddrs(2, header.SourceAddr, header.DestinationAddr)
	if _, err := forwarded.WriteTo(backend); err != nil {
		refuse("backend_error", err, alertInternalError)
		return
	}
	if open.prepare != nil {
		if err := open.prepare(backend); err != nil {
			refuse("backend_error", err, alertInternalError)
			return
		}
	}
	if _, err := backend.Write(open.hello); err != nil {
		refuse("backend_error", err, alertInternalError)
		return
	}
	if err := errors.Join(conn.SetDeadline(time.Time{}), backend.SetDeadline(time.Time{})); err != nil {
		record.fail("client_error", err)
		return
	}
	ticket.end()
	var spliceErr error
	record.bytesUp, record.bytesDown, spliceErr = splice(conn, backend)
	if spliceErr != nil {
		record.fail("reset", spliceErr)
		return
	}
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

func sourceHost(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap().String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func sendTLSAlert(conn net.Conn, description byte) {
	_, _ = conn.Write([]byte{tlsAlertRecord, 3, 3, 0, 2, tlsAlertFatal, description})
}

func socketPeer(conn net.Conn) string {
	if proxied, ok := conn.(*proxyproto.Conn); ok {
		return proxied.Raw().RemoteAddr().String()
	}
	return conn.RemoteAddr().String()
}

func splice(client, backend net.Conn) (up, down int64, err error) {
	type copied struct {
		n   int64
		err error
	}
	upDone := make(chan copied, 1)
	go func() {
		n, err := io.Copy(backend, client)
		finishDirection(backend, client, err)
		upDone <- copied{n, err}
	}()
	down, downErr := io.Copy(client, backend)
	finishDirection(client, backend, downErr)
	upResult := <-upDone
	_ = client.Close()
	_ = backend.Close()
	return upResult.n, down, spliceErrors(upResult.err, downErr)
}

func spliceErrors(upErr, downErr error) error {
	if upErr == nil && errors.Is(downErr, syscall.ECONNRESET) {
		downErr = nil
	}
	if downErr == nil && errors.Is(upErr, syscall.ECONNRESET) {
		upErr = nil
	}
	return errors.Join(spliceError(upErr), spliceError(downErr))
}

func finishDirection(dst, src net.Conn, err error) {
	if err == nil && closeWrite(dst) == nil {
		return
	}
	_ = dst.Close()
	_ = src.Close()
}

func closeWrite(conn net.Conn) error {
	if proxied, ok := conn.(*proxyproto.Conn); ok {
		conn = proxied.Raw()
	}
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return errors.ErrUnsupported
}

func spliceError(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}
