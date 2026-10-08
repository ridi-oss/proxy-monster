package listen

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/pires/go-proxyproto"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func Open(spec spi.Listen) (net.Listener, error) {
	plain, err := net.Listen("tcp", fmt.Sprintf(":%d", spec.Port))
	if err != nil {
		return nil, err
	}
	if spec.ProxyProtocolPort == 0 {
		return plain, nil
	}
	proxied, err := net.Listen("tcp", fmt.Sprintf(":%d", spec.ProxyProtocolPort))
	if err != nil {
		_ = plain.Close()
		return nil, err
	}
	merged, err := Merge(plain, proxied, spec)
	if err != nil {
		_ = plain.Close()
		_ = proxied.Close()
		return nil, err
	}
	return merged, nil
}

func Merge(plain, proxied net.Listener, spec spi.Listen) (net.Listener, error) {
	if len(spec.TrustedProxies) == 0 {
		return nil, errors.New("listen: a PROXY protocol port needs at least one trusted proxy")
	}
	trusted := make([]string, len(spec.TrustedProxies))
	for i, prefix := range spec.TrustedProxies {
		trusted[i] = prefix.String()
	}
	policy, err := proxyproto.TrustProxyHeaderFromRanges(trusted)
	if err != nil {
		return nil, err
	}
	m := &merged{
		plain:    plain,
		proxied:  proxied,
		accepted: make(chan acceptResult),
		closed:   make(chan struct{}),
	}
	go m.pump(plain)
	go m.pump(&proxyproto.Listener{Listener: proxied, ConnPolicy: policy})
	return m, nil
}

type acceptResult struct {
	conn net.Conn
	err  error
}

type merged struct {
	plain, proxied net.Listener
	accepted       chan acceptResult
	closed         chan struct{}
	closeOnce      sync.Once
}

func (m *merged) pump(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		select {
		case m.accepted <- acceptResult{conn, err}:
		case <-m.closed:
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

func (m *merged) Accept() (net.Conn, error) {
	select {
	case r := <-m.accepted:
		return r.conn, r.err
	case <-m.closed:
		return nil, net.ErrClosed
	}
}

func (m *merged) Close() error {
	var err error
	m.closeOnce.Do(func() {
		close(m.closed)
		err = errors.Join(m.plain.Close(), m.proxied.Close())
	})
	return err
}

func (m *merged) Addr() net.Addr { return m.plain.Addr() }
