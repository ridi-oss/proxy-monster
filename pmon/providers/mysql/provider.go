package mysql

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 20 * time.Second
	acceptBackoff    = 50 * time.Millisecond
)

type Provider struct{}

func (Provider) UnavailableReason(endpoint driver.Endpoint) string {
	if endpoint.AdvertiseAddr == "" {
		return "no advertised proxy address"
	}
	return ""
}

// MySQL sessions retain their route; new connections resolve the latest advertisement.
func (Provider) RouteKey(driver.Endpoint) string { return "" }

func (p Provider) Serve(ctx context.Context, listener net.Listener, resolve driver.ResolveSession) error {
	for {
		local, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(acceptBackoff):
				continue
			}
		}
		go p.broker(local, resolve)
	}
}

func (Provider) broker(local net.Conn, resolve driver.ResolveSession) {
	defer local.Close()
	endpoint, credentials, ok := resolve()
	if !ok {
		_ = mysqlwire.WritePacket(local, 2, mysqlwire.ErrPacket(1045, "proxy-monster: datasource no longer available"))
		return
	}
	if err := brokerMySQL(local, endpoint.AdvertiseAddr, endpoint.CertChainPEM, endpoint.WireTLS,
		credentials.Principal, credentials.Token, credentials.LocalPassword); err != nil {
		fmt.Fprintf(os.Stderr, "broker %q: %v\n", endpoint.Name, err)
	}
}
