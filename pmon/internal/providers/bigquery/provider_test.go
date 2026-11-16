package bigquery

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func testEndpoint(upstream *httptest.Server) driver.Endpoint {
	return driver.Endpoint{
		Name: "warehouse", Engine: "bigquery", AdvertiseAddr: strings.TrimPrefix(upstream.URL, "https://"), WireTLS: true,
		CertChainPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})),
		ConnectionInfo: &driver.ConnectionInfo{Endpoint: upstream.URL, Properties: map[string]string{"project": "proj", "location": "US", "dataset": "sales"}},
	}
}

func serveBroker(t *testing.T, provider Provider, resolve driver.ResolveSession) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- provider.Serve(ctx, listener, resolve) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop after cancellation")
		}
	})
	return "http://" + listener.Addr().String()
}

func call(t *testing.T, method, url, token, body string) (int, string) {
	t.Helper()
	request, _ := http.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("X-Goog-Api-Key", "client-key")
	request.Header.Set("X-Goog-User-Project", "proj")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data)
}

func TestBrokerRelaysWithTheCurrentToken(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer pmk_current" || r.Header.Get("X-Goog-Api-Key") != "" || r.Header.Get("X-Goog-User-Project") != "" {
			t.Errorf("upstream credentials = %q, api key %q, quota project %q", r.Header.Get("Authorization"), r.Header.Get("X-Goog-Api-Key"), r.Header.Get("X-Goog-User-Project"))
		}
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/bigquery/v2/projects/proj/jobs" || r.URL.RawQuery != "alt=json" || string(body) != `{"q":1}` {
			t.Errorf("relayed %s %s?%s %s", r.Method, r.URL.EscapedPath(), r.URL.RawQuery, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"kind":"bigquery#job"}`)
	}))
	defer upstream.Close()
	endpoint := testEndpoint(upstream)
	credentials := driver.Credentials{Principal: "alice", Token: "pmk_current", LocalPassword: "local-password"}
	local := serveBroker(t, Provider{}, func() (driver.Endpoint, driver.Credentials, bool) { return endpoint, credentials, true })
	token := localToken("alice", "warehouse", "local-password")

	if status, body := call(t, http.MethodPost, local+"/bigquery/v2/projects/proj/jobs?alt=json", token, `{"q":1}`); status != http.StatusCreated || body != `{"kind":"bigquery#job"}` {
		t.Fatalf("relay = %d %s", status, body)
	}
	for _, wrong := range []string{"", "pmk_current", localToken("bob", "warehouse", "local-password"), localToken("alice", "other", "local-password")} {
		if status, _ := call(t, http.MethodPost, local+"/bigquery/v2/projects/proj/jobs", wrong, `{}`); status != http.StatusUnauthorized {
			t.Errorf("token %q = %d", wrong, status)
		}
	}
	if status, _ := call(t, http.MethodGet, local+"/upload/bigquery/v2/projects/proj/jobs", token, ""); status != http.StatusNotFound {
		t.Errorf("path outside the API = %d", status)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
}

func TestBrokerRefusesWithoutASession(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("reached upstream") }))
	defer upstream.Close()
	local := serveBroker(t, Provider{}, func() (driver.Endpoint, driver.Credentials, bool) {
		return testEndpoint(upstream), driver.Credentials{}, false
	})
	if status, body := call(t, http.MethodGet, local+"/bigquery/v2/projects/proj/datasets", "anything", ""); status != http.StatusForbidden || !strings.Contains(body, "pmon.sessionUnavailable") {
		t.Fatalf("no session = %d %s", status, body)
	}
}

func TestBrokerServesTheDiscoveryDocumentOnce(t *testing.T) {
	var fetches atomic.Int32
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_, _ = io.WriteString(w, `{"name":"bigquery","version":"v2"}`)
	}))
	defer google.Close()
	local := serveBroker(t, Provider{DiscoveryURL: google.URL}, func() (driver.Endpoint, driver.Credentials, bool) {
		return driver.Endpoint{}, driver.Credentials{}, false
	})
	for range 2 {
		if status, body := call(t, http.MethodGet, local+"/$discovery/rest?version=v2", "", ""); status != http.StatusOK || body != `{"name":"bigquery","version":"v2"}` {
			t.Fatalf("discovery = %d %s", status, body)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("discovery fetched %d times", fetches.Load())
	}
}
