// Package httpapi is what pmon's HTTP-API brokers share: the local server, the verified HTTPS hop to the
// datasource proxy, and the header filtering between them.
package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

// EndpointURL is the datasource proxy's advertised HTTPS root.
func EndpointURL(endpoint driver.Endpoint) (*url.URL, error) {
	if endpoint.ConnectionInfo == nil {
		return nil, errors.New("verified HTTPS proxy endpoint required")
	}
	u, err := url.Parse(endpoint.ConnectionInfo.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("verified HTTPS proxy endpoint required")
	}
	return u, nil
}

// TLSConfig trusts the advertised chain, or the system roots when none is advertised.
func TLSConfig(chain string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if chain != "" {
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM([]byte(chain)) {
			return nil, errors.New("invalid advertised certificate chain")
		}
	}
	return config, nil
}

// Unavailable says why an endpoint cannot be relayed to, or "" when it can.
func Unavailable(endpoint driver.Endpoint) string {
	if _, err := EndpointURL(endpoint); err != nil {
		return err.Error()
	}
	if _, err := TLSConfig(endpoint.CertChainPEM); err != nil {
		return err.Error()
	}
	return ""
}

// Serve runs handler on the daemon's listener until it closes or ctx ends.
func Serve(ctx context.Context, listener net.Listener, handler http.Handler) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Protocols:         new(http.Protocols),
	}
	// gRPC clients reach the local endpoint over cleartext HTTP/2.
	server.Protocols.SetHTTP1(true)
	server.Protocols.SetUnencryptedHTTP2(true)
	done := make(chan struct{})
	defer close(done)
	defer server.Close()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Upstream relays requests to the datasource proxy, rebuilding its transport when the trust chain changes.
type Upstream struct {
	mu        sync.Mutex
	trust     string
	transport *http.Transport
	// streams carries gRPC calls, over HTTP/2 only.
	streams *http.Transport
}

func (u *Upstream) transports(chain string) (*http.Transport, *http.Transport, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.transport == nil || u.trust != chain {
		config, err := TLSConfig(chain)
		if err != nil {
			return nil, nil, err
		}
		u.closeIdle()
		u.transport = &http.Transport{
			TLSClientConfig:       config,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: time.Minute,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    true,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   16,
		}
		u.streams = u.transport.Clone()
		u.streams.Protocols = new(http.Protocols)
		u.streams.Protocols.SetHTTP2(true)
		u.trust = chain
	}
	return u.transport, u.streams, nil
}

func (u *Upstream) client(chain string) (*http.Client, error) {
	transport, _, err := u.transports(chain)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (u *Upstream) closeIdle() {
	for _, transport := range []*http.Transport{u.transport, u.streams} {
		if transport != nil {
			transport.CloseIdleConnections()
		}
	}
}

func (u *Upstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closeIdle()
}

// Forward sends incoming with body to the same path and query under the endpoint, authenticated by token,
// and copies the response to w. An error means nothing was written.
func (u *Upstream) Forward(w http.ResponseWriter, incoming *http.Request, endpoint driver.Endpoint, token string, body io.Reader) error {
	target, err := EndpointURL(endpoint)
	if err != nil {
		return err
	}
	target.Path, target.RawPath, target.RawQuery = incoming.URL.Path, incoming.URL.RawPath, incoming.URL.RawQuery
	request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, target.String(), body)
	if err != nil {
		return err
	}
	request.Header = UpstreamHeaders(incoming.Header)
	request.Header.Set("Authorization", "Bearer "+token)
	request.GetBody = nil
	client, err := u.client(endpoint.CertChainPEM)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	maps.Copy(w.Header(), WithoutHopHeaders(response.Header))
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
	return nil
}
