package wire

import (
	"net"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/drain"
)

const (
	frontendCommandIdleTimeout = 5 * time.Minute
	backendResponseIdleTimeout = 30 * time.Minute
)

// SocketWriteTimeout is the write-inactivity bound applied to every proxied socket. Exported so a protocol
// that sets a bare write deadline on a side connection (a PostgreSQL CancelRequest dial) uses the same value.
const SocketWriteTimeout = 30 * time.Second

// WrapClientConn bounds the client socket with the command-idle timeout and makes its reads drain-aware, so
// an idle handler returns promptly on shutdown to send its protocol notice rather than waiting out the idle
// timeout. Only the client-facing conn is wrapped this way; a backend read mid-relay must not be cut short.
func (s *Server) WrapClientConn(c net.Conn) net.Conn {
	return withDrainAwareIODeadlines(c, frontendCommandIdleTimeout, SocketWriteTimeout, s.draining)
}

// WrapBackendConn bounds the backend socket with the response-idle timeout; it is not drain-aware.
func (s *Server) WrapBackendConn(c net.Conn) net.Conn {
	return withIODeadlines(c, backendResponseIdleTimeout, SocketWriteTimeout)
}

// WithBackendReadTimeout bounds a proxy-dialed run-session backend connection with a caller-chosen read-idle
// timeout and the standard socket write timeout. Not drain-aware — the run drain is handled separately.
func WithBackendReadTimeout(conn net.Conn, readTimeout time.Duration) net.Conn {
	return withIODeadlines(conn, readTimeout, SocketWriteTimeout)
}

// WithIODeadlines bounds a connection with independent read/write inactivity timeouts. Not drain-aware;
// for a short-lived side connection (e.g. a MySQL KILL QUERY dial) whose write budget differs from the norm.
func WithIODeadlines(conn net.Conn, readTimeout, writeTimeout time.Duration) net.Conn {
	return withIODeadlines(conn, readTimeout, writeTimeout)
}

// deadlineConn bounds every blocking socket operation after authentication. The read deadline is
// refreshed whenever bytes make progress, so it is an inactivity bound rather than a total query limit.
type deadlineConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	draining     *drain.Tracker
}

func withIODeadlines(conn net.Conn, readTimeout, writeTimeout time.Duration) net.Conn {
	return withDrainAwareIODeadlines(conn, readTimeout, writeTimeout, nil)
}

// withDrainAwareIODeadlines is withIODeadlines plus a drain signal. Once draining is set, a read returns
// promptly instead of waiting out the idle timeout, so a handler blocked for the next command can send the
// shutdown notice and close without depending on the drainer having already forced the socket deadline.
func withDrainAwareIODeadlines(conn net.Conn, readTimeout, writeTimeout time.Duration, draining *drain.Tracker) net.Conn {
	if readTimeout <= 0 && writeTimeout <= 0 && draining == nil {
		return conn
	}
	return &deadlineConn{Conn: conn, readTimeout: readTimeout, writeTimeout: writeTimeout, draining: draining}
}

func (c *deadlineConn) Read(payload []byte) (int, error) {
	if c.draining != nil && c.draining.Draining() {
		_ = c.SetReadDeadline(time.Now())
		return c.Conn.Read(payload)
	}
	if c.readTimeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return 0, err
		}
		// A drain that set the flag after the check above would have its forced deadline overwritten by the
		// idle one just set, leaving this read blocked for the full idle timeout. Re-check and force it now.
		if c.draining != nil && c.draining.Draining() {
			_ = c.SetReadDeadline(time.Now())
		}
	}
	return c.Conn.Read(payload)
}

func (c *deadlineConn) Write(payload []byte) (int, error) {
	if c.writeTimeout > 0 {
		if err := c.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(payload)
}
