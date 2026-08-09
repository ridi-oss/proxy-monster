// Package wire is the protocol-agnostic core of the native-wire brokers: the accept loop, connection
// tracking, the bounded slot pool, the listener lifecycle, and the graceful drain. A protocol (MySQL,
// PostgreSQL) supplies only its per-connection handler and shutdown notice; everything else — being merely
// protocol — lives here once instead of copied per broker.
package wire

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/drain"
)

const (
	maxConcurrentConnections = 256
	// maxBackendGeneration is the signed-range ceiling the control plane accepts for a backend generation;
	// the counter starts at 1 and can only reach this after 2^63 connections, so the guard is pure
	// defense-in-depth.
	maxBackendGeneration = uint64(1<<63 - 1)
	// serveExitWait caps how long Drain waits for the accept loop to end. The loop returns within microseconds
	// of the listener closing, so this only bounds the case where Serve never ran (a bind error raced the
	// signal), keeping that pathological path off the full drain budget.
	serveExitWait = 1 * time.Second
)

// backendGeneration is a monotonic counter shared across every wire connection of both engines; each run's
// refetcher keys on its value to invalidate a stale schema fetch.
var backendGeneration atomic.Uint64

// NextBackendGeneration returns the next backend generation and whether it is within range. Out of range is
// unreachable in practice (2^63 connections) and reported so the caller can fail closed rather than reuse 0.
func NextBackendGeneration() (uint64, bool) {
	g := backendGeneration.Add(1)
	return g, g != 0 && g <= maxBackendGeneration
}

// Server is a blocking goroutine-per-connection wire broker. It owns the connection lifecycle and the drain;
// the protocol supplies its per-connection handler via [New].
type Server struct {
	name   string
	port   int
	handle func(net.Conn)

	mu          sync.Mutex
	ln          net.Listener
	closed      bool
	conns       map[net.Conn]struct{}
	connSlots   chan struct{}
	draining    *drain.Tracker
	serveExited chan struct{} // closed when Serve's accept loop returns, so Drain can wait for every accepted conn to register
}

// New constructs a wire broker for one backend datasource. name prefixes its errors and logs; handle runs
// per accepted connection on its own goroutine.
func New(port int, name string, handle func(net.Conn)) *Server {
	return &Server{
		name:        name,
		port:        port,
		handle:      handle,
		connSlots:   make(chan struct{}, maxConcurrentConnections),
		draining:    drain.New(),
		serveExited: make(chan struct{}),
	}
}

// Draining reports whether a drain has begun — the protocol's handler checks it to send a shutdown notice.
func (s *Server) Draining() bool { return s.draining.Draining() }

// Listen binds the configured TCP port. Port zero requests an ephemeral port for tests.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A Drain/Shutdown that won the startup race (SIGTERM arriving before this goroutine bound the port) has
	// already marked the server closed. Binding now would strand a listener with no Serve loop coming for it,
	// and boot — waiting on Serve to return — would hang until SIGKILL. bind and Shutdown's close both hold
	// s.mu, so this either binds before a concurrent Shutdown (which then closes the listener) or observes
	// closed and does not bind.
	if s.closed {
		return nil
	}
	if s.ln != nil {
		return fmt.Errorf("%s: already listening", s.name)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Serve accepts client connections and handles each on its own goroutine. The bounded slot pool prevents
// unauthenticated sockets from creating an unbounded goroutine population.
func (s *Server) Serve() error {
	// Signal Drain that the accept loop has ended, so it can conclude every accepted socket is now tracked.
	defer close(s.serveExited)
	s.mu.Lock()
	ln := s.ln
	closed := s.closed
	s.mu.Unlock()
	if ln == nil {
		// A Shutdown/Drain that raced ahead of Serve nulls the listener; that is a clean stop, not a
		// missing Listen call.
		if closed {
			return nil
		}
		return fmt.Errorf("%s: Listen must be called before Serve", s.name)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !s.acquireConnection() {
			_ = conn.Close()
			continue
		}
		s.trackConn(conn)
		go func() {
			defer s.releaseConnection()
			defer s.untrackConn(conn)
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = conn.Close()
					slog.Error(
						s.name+" connection handler panicked",
						"client", conn.RemoteAddr().String(),
						"panic", recovered,
						"stack", string(debug.Stack()),
					)
				}
			}()
			s.handle(conn)
		}()
	}
}

func (s *Server) acquireConnection() bool {
	select {
	case s.connSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseConnection() { <-s.connSlots }

// Start binds the configured port and blocks in the accept loop.
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Shutdown closes the listener. An accept loop blocked in Serve returns nil.
func (s *Server) Shutdown() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.closed = true
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// Drain gracefully winds the broker down for a rolling redeploy: it stops accepting new connections, lets
// in-flight statements finish, and unblocks every idle handler so it can forward a protocol-level shutdown
// notice (see each protocol's conn.go) and close. It waits for all handlers to return, bounded by ctx; any
// connection still live when ctx is done is force-closed. Forcing the client read deadline only interrupts a
// handler blocked reading the next command — an in-flight relay reads the backend and writes the client, so
// it is untouched and runs to completion.
func (s *Server) Drain(ctx context.Context) {
	s.Shutdown()
	s.draining.Begin()
	// Wait for the accept loop to end before treating the connection set as complete. A socket returned by
	// Accept just before Shutdown registers only after this point, so a wait that ran first could see zero,
	// report a clean drain, and let boot exit while that handler still holds an un-notified client.
	s.awaitServeExit(ctx)
	s.forEachConn(func(c net.Conn) { _ = c.SetReadDeadline(time.Now()) })
	if s.draining.Wait(ctx) {
		return
	}
	s.forEachConn(func(c net.Conn) { _ = c.Close() })
}

// awaitServeExit blocks until the accept loop has returned (every accepted connection is then registered), or
// ctx is done, or [serveExitWait] elapses. Serve always closes serveExited on return, including its early-out
// paths; the timer only matters when Serve never ran (a bind error that raced the signal).
func (s *Server) awaitServeExit(ctx context.Context) {
	t := time.NewTimer(serveExitWait)
	defer t.Stop()
	select {
	case <-s.serveExited:
	case <-ctx.Done():
	case <-t.C:
	}
}

func (s *Server) trackConn(c net.Conn) {
	// Count before the map insert (and Done after the delete, below) so the tracker's count is never below
	// len(conns): a drain Wait cannot then observe zero while a connection is still mid-registration.
	s.draining.Add()
	s.mu.Lock()
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[c] = struct{}{}
	draining := s.draining.Draining()
	s.mu.Unlock()
	// A drain that began between Accept and registration would otherwise miss this connection; unblock it
	// here so its handler still sees the drain rather than blocking out the full idle timeout.
	if draining {
		_ = c.SetReadDeadline(time.Now())
	}
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	s.draining.Done()
}

func (s *Server) forEachConn(fn func(net.Conn)) {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		fn(c)
	}
}

// Addr returns the bound listener address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}
