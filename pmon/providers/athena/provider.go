package athena

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

const maxRequestBytes = 2 << 20

var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)

type Provider struct{}

func endpointURL(endpoint driver.Endpoint) (*url.URL, error) {
	if endpoint.ConnectionInfo == nil {
		return nil, errors.New("verified HTTPS proxy endpoint required")
	}
	address := endpoint.ConnectionInfo.Endpoint
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("verified HTTPS proxy endpoint required")
	}
	return u, nil
}

func (Provider) UnavailableReason(endpoint driver.Endpoint) string {
	if _, err := endpointURL(endpoint); err != nil {
		return err.Error()
	}
	if !regionPattern.MatchString(endpoint.ConnectionInfo.Properties["region"]) {
		return "Athena region required"
	}
	if _, err := upstreamTLS(endpoint.CertChainPEM); err != nil {
		return err.Error()
	}
	return ""
}

func (Provider) RouteKey(endpoint driver.Endpoint) string {
	data, _ := json.Marshal(endpoint)
	return string(data)
}

func (Provider) Serve(ctx context.Context, listener net.Listener, resolve driver.ResolveSession) error {
	handler := &broker{resolve: resolve}
	defer handler.close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
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

type broker struct {
	resolve   driver.ResolveSession
	mu        sync.Mutex
	trust     string
	transport *http.Transport
}

func upstreamTLS(chain string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if chain != "" {
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM([]byte(chain)) {
			return nil, errors.New("invalid advertised certificate chain")
		}
	}
	return config, nil
}

func (b *broker) client(chain string) (*http.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.transport == nil || b.trust != chain {
		config, err := upstreamTLS(chain)
		if err != nil {
			return nil, err
		}
		if b.transport != nil {
			b.transport.CloseIdleConnections()
		}
		b.transport = &http.Transport{
			TLSClientConfig:       config,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: time.Minute,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    true,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   16,
		}
		b.trust = chain
	}
	return &http.Client{
		Transport:     b.transport,
		Timeout:       2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (b *broker) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
}

func (b *broker) ServeHTTP(w http.ResponseWriter, incoming *http.Request) {
	endpoint, credentials, ok := b.resolve()
	if !ok || credentials.Principal == "" || credentials.Token == "" || credentials.LocalPassword == "" {
		writeError(w, http.StatusForbidden, "AccessDeniedException", "pmon.sessionUnavailable")
		return
	}
	if incoming.Method != http.MethodPost || incoming.URL.Path != "/" || incoming.URL.RawQuery != "" || incoming.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, "InvalidRequestException", "pmon.athena.invalidRequest")
		return
	}
	if (Provider{}).UnavailableReason(endpoint) != "" {
		writeError(w, http.StatusServiceUnavailable, "InternalServerException", "pmon.athena.endpointUnavailable")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, incoming.Body, maxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "InvalidRequestException", "pmon.athena.requestTooLarge")
		} else {
			writeError(w, http.StatusBadRequest, "InvalidRequestException", "pmon.athena.invalidRequest")
		}
		return
	}
	local := localCredentials(credentials.Principal, endpoint.Name, credentials.LocalPassword)
	if err := verifySignature(incoming, body, local, endpoint.ConnectionInfo.Properties["region"], time.Now()); err != nil {
		writeError(w, http.StatusForbidden, "UnrecognizedClientException", "pmon.athena.invalidSignature")
		return
	}
	upstream, _ := endpointURL(endpoint)
	request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, upstream.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "InternalServerException", "pmon.athena.upstreamUnavailable")
		return
	}
	request.Header = upstreamHeaders(incoming.Header)
	request.Header.Set("Authorization", "Bearer "+credentials.Token)
	request.GetBody = nil
	client, err := b.client(endpoint.CertChainPEM)
	if err != nil {
		writeError(w, http.StatusBadGateway, "InternalServerException", "pmon.athena.upstreamUnavailable")
		return
	}
	response, err := client.Do(request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "InternalServerException", "pmon.athena.upstreamUnavailable")
		return
	}
	defer response.Body.Close()
	for name, values := range withoutHopHeaders(response.Header) {
		w.Header()[name] = values
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func writeError(w http.ResponseWriter, status int, kind, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-Errortype", kind)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": kind, "Message": code})
}
