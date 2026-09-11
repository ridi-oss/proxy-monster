package daemon

import (
	"context"
	"net"
	"sync"
)

type brokerListener struct {
	net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	engine   string
	routeKey string
	track    func(net.Conn) net.Conn
	mu       sync.Mutex
	closed   bool
}

func (l *brokerListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	return l.track(conn), nil
}

func (l *brokerListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.cancel()
	return l.Listener.Close()
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	untrack func()
	err     error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.untrack()
	})
	return c.err
}

func (d *Daemon) trackConn(name string, conn net.Conn) net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.nextConnID
	d.nextConnID++
	tracked := &trackedConn{Conn: conn, untrack: func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.liveConns[name], id)
		if len(d.liveConns[name]) == 0 {
			delete(d.liveConns, name)
		}
	}}
	if d.liveConns[name] == nil {
		d.liveConns[name] = map[uint64]net.Conn{}
	}
	d.liveConns[name][id] = tracked
	return tracked
}
