package mysqlproxy

import (
	"net"
	"sync/atomic"
	"time"
)

const (
	frontendCommandIdleTimeout = 5 * time.Minute
	backendResponseIdleTimeout = 30 * time.Minute
	socketWriteTimeout         = 30 * time.Second
)

// deadlineConn bounds every blocking socket operation after authentication. The read deadline is
// refreshed whenever bytes make progress, so it is an inactivity bound rather than a total query limit.
type deadlineConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	draining     *atomic.Bool
}

func withIODeadlines(conn net.Conn, readTimeout, writeTimeout time.Duration) net.Conn {
	return withDrainAwareIODeadlines(conn, readTimeout, writeTimeout, nil)
}

// withDrainAwareIODeadlines is withIODeadlines plus a drain signal. Once draining is set, a read returns
// promptly instead of waiting out the idle timeout, so a handler blocked for the next command can send the
// shutdown notice and close without depending on the drainer having already forced the socket deadline.
// Only the client-facing conn is wrapped this way; a backend read mid-relay must not be cut short.
func withDrainAwareIODeadlines(conn net.Conn, readTimeout, writeTimeout time.Duration, draining *atomic.Bool) net.Conn {
	if readTimeout <= 0 && writeTimeout <= 0 && draining == nil {
		return conn
	}
	return &deadlineConn{Conn: conn, readTimeout: readTimeout, writeTimeout: writeTimeout, draining: draining}
}

func (c *deadlineConn) Read(payload []byte) (int, error) {
	if c.draining != nil && c.draining.Load() {
		_ = c.SetReadDeadline(time.Now())
		return c.Conn.Read(payload)
	}
	if c.readTimeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return 0, err
		}
		// A drain that set the flag after the check above would have its forced deadline overwritten by the
		// idle one just set, leaving this read blocked for the full idle timeout. Re-check and force it now.
		if c.draining != nil && c.draining.Load() {
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
