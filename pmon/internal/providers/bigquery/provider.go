// Package bigquery is pmon's BigQuery provider: it formats client configuration for a local BigQuery REST
// endpoint and relays those clients' requests to the datasource proxy with the current token.
package bigquery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers/httpapi"
)

const (
	maxRequestBytes  = 10 << 20
	defaultDiscovery = "https://bigquery.googleapis.com/$discovery/rest?version=v2"
)

// Provider brokers a local BigQuery endpoint: a client authenticates with its local bearer token, and pmon
// relays the request over verified HTTPS to the datasource proxy with the current proxy-monster token.
type Provider struct {
	// DiscoveryURL is where the bq CLI's discovery document is fetched; empty means Google's public one.
	DiscoveryURL string
}

func (Provider) Engine() string { return "bigquery" }

func (Provider) SupportedFormats() []driver.Format {
	return []driver.Format{driver.CLI, driver.URL, "python"}
}

func (Provider) DefaultFormat() driver.Format { return driver.CLI }

func (Provider) UnavailableReason(endpoint driver.Endpoint) string {
	if reason := httpapi.Unavailable(endpoint); reason != "" {
		return reason
	}
	if endpoint.ConnectionInfo.Properties["project"] == "" {
		return "BigQuery project required"
	}
	return ""
}

func (Provider) RouteKey(endpoint driver.Endpoint) string {
	data, _ := json.Marshal(endpoint)
	return string(data)
}

func (p Provider) Serve(ctx context.Context, listener net.Listener, resolve driver.ResolveSession) error {
	discovery := p.DiscoveryURL
	if discovery == "" {
		discovery = defaultDiscovery
	}
	handler := &broker{resolve: resolve, discoveryURL: discovery}
	defer handler.upstream.Close()
	return httpapi.Serve(ctx, listener, handler)
}

// localToken is the bearer a client presents to the local endpoint, bound to the principal and datasource.
func localToken(principal, datasource, password string) string {
	mac := hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write([]byte("pmon/bigquery/v1\x00" + strconv.Itoa(len(principal)) + ":" + principal + datasource))
	return "pmon-" + hex.EncodeToString(mac.Sum(nil))
}

type broker struct {
	resolve      driver.ResolveSession
	upstream     httpapi.Upstream
	discoveryURL string
	mu           sync.Mutex
	discovery    []byte
}

func (b *broker) ServeHTTP(w http.ResponseWriter, incoming *http.Request) {
	if incoming.Method == http.MethodGet && incoming.URL.Path == "/$discovery/rest" {
		b.serveDiscovery(w, incoming.Context())
		return
	}
	endpoint, credentials, ok := b.resolve()
	if !ok || credentials.Principal == "" || credentials.Token == "" || credentials.LocalPassword == "" {
		writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "pmon.sessionUnavailable")
		return
	}
	want := "Bearer " + localToken(credentials.Principal, endpoint.Name, credentials.LocalPassword)
	if subtle.ConstantTimeCompare([]byte(incoming.Header.Get("Authorization")), []byte(want)) != 1 {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "pmon.bigquery.invalidToken")
		return
	}
	if !strings.HasPrefix(incoming.URL.Path, "/bigquery/v2/") {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "pmon.bigquery.invalidRequest")
		return
	}
	if (Provider{}).UnavailableReason(endpoint) != "" {
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "pmon.bigquery.endpointUnavailable")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, incoming.Body, maxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "INVALID_ARGUMENT", "pmon.bigquery.requestTooLarge")
		} else {
			writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "pmon.bigquery.invalidRequest")
		}
		return
	}
	if err := b.upstream.Forward(w, incoming, endpoint, credentials.Token, bytes.NewReader(body)); err != nil {
		writeError(w, http.StatusBadGateway, "UNAVAILABLE", "pmon.bigquery.upstreamUnavailable")
	}
}

// serveDiscovery hands the bq CLI the public API description it fetches from its endpoint before any call.
func (b *broker) serveDiscovery(w http.ResponseWriter, ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.discovery == nil {
		document, err := fetch(ctx, b.discoveryURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, "UNAVAILABLE", "pmon.bigquery.discoveryUnavailable")
			return
		}
		b.discovery = document
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b.discovery)
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document: %s", response.Status)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes))
	if err != nil || !json.Valid(document) {
		return nil, errors.New("discovery document unreadable")
	}
	return document, nil
}

// writeError writes BigQuery's error shape; bq reads errors[0].reason and reports a body without it as malformed.
func writeError(w http.ResponseWriter, code int, status, message string) {
	reason := map[int]string{http.StatusUnauthorized: "authError", http.StatusForbidden: "accessDenied", http.StatusNotFound: "notFound"}[code]
	if reason == "" {
		reason = "backendError"
		if code < 500 {
			reason = "invalid"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "status": status, "message": message,
		"errors": []map[string]string{{"message": message, "domain": "global", "reason": reason}}}})
}
