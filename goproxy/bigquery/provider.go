// Package bigquery is the BigQuery provider: the proxy serves the BigQuery REST API over HTTPS, asks the
// control plane what to do with each call, decides query SQL through Decide, and masks result pages inline.
package bigquery

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// Provider registers the BigQuery engine under PM_ENGINE=bigquery. OpenTarget scopes the target to Flags
// (PM_TARGET_DB is the default dataset) and pins the Google principal the credentials act as.
type Provider struct {
	Flags Flags
	// AdvertiseAddr is the host:port clients reach this proxy's HTTPS endpoint at.
	AdvertiseAddr string
}

func (Provider) Engine() *engines.Engine { return engines.BigQuery }

func (p Provider) OpenTarget() (spi.Target, error) {
	cfg, err := newSettings(p.Flags, p.AdvertiseAddr)
	if err != nil {
		return nil, err
	}
	credentials, token, err := findCredentials()
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	principal, err := credentialPrincipal(ctx, credentials.JSON, token, &http.Client{Transport: transport}, tokenInfoEndpoint)
	if err != nil {
		return nil, err
	}
	return newTarget(cfg, token, principal, transport)
}

func (t *target) NewWireServer(listen spi.Listen, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return newServer(t, listen, client, tlsProvider)
}

var _ spi.Provider = Provider{}
