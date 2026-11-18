// Package bigquery is the BigQuery provider: the proxy serves the BigQuery REST API over HTTPS, asks the
// control plane what to do with each call, decides query SQL through Decide, and masks result pages inline.
package bigquery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	principal, err := credentialPrincipal(ctx, credentials.JSON, token, &http.Client{Transport: http.DefaultTransport}, tokenInfoEndpoint)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.Flags.CAFile != "" {
		pem, err := os.ReadFile(p.Flags.CAFile)
		if err != nil {
			return nil, fmt.Errorf("bigquery: PM_BIGQUERY_CA_FILE: %w", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("bigquery: PM_BIGQUERY_CA_FILE holds no certificate")
		}
		transport.TLSClientConfig = tlsConfig.Clone()
	}
	conn, err := grpc.NewClient(cfg.storageEndpoint, grpc.WithTransportCredentials(grpccredentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(upstreamToken(token)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxStorageMessage)))
	if err != nil {
		return nil, fmt.Errorf("bigquery: PM_BIGQUERY_STORAGE_ENDPOINT: %w", err)
	}
	t, err := newTarget(cfg, token, principal, transport)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	t.storage, t.storageConn = storagepb.NewBigQueryReadClient(conn), conn
	return t, nil
}

// upstreamToken signs each Storage API call with the proxy's own Google credentials.
type upstreamToken TokenSource

func (u upstreamToken) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := u(ctx)
	if err != nil {
		return nil, fmt.Errorf("bigquery: access token: %w", err)
	}
	return map[string]string{"authorization": "Bearer " + token}, nil
}

func (upstreamToken) RequireTransportSecurity() bool { return true }

func (t *target) NewWireServer(listen spi.Listen, client spi.ControlPlane, tlsProvider func() (*tls.Config, error)) spi.WireServer {
	return newServer(t, listen, client, tlsProvider)
}

var _ spi.Provider = Provider{}
