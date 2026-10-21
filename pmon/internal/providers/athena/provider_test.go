package athena

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

func testEndpoint(upstream *httptest.Server) driver.Endpoint {
	return driver.Endpoint{
		Name: "warehouse", Engine: "athena", AdvertiseAddr: strings.TrimPrefix(upstream.URL, "https://"), WireTLS: true,
		CertChainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})),
		ConnectionInfo: &driver.ConnectionInfo{Endpoint: upstream.URL, Properties: map[string]string{
			"region": "us-east-1", "workgroup": "primary", "catalog": "AwsDataCatalog", "database": "default",
		}},
	}
}

func serveBroker(t *testing.T, resolve driver.ResolveSession) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Provider{}).Serve(ctx, listener, resolve) }()
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

func TestNativeServeWithAthenaSDKAndFreshSessions(t *testing.T) {
	var mu sync.Mutex
	var tokens []string
	var bodies [][]byte
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Header.Get("X-Amz-Target") != "AmazonAthena.StartQueryExecution" {
			t.Errorf("operation = %q", r.Header.Get("X-Amz-Target"))
		}
		if r.Header.Get("X-Amz-Date") != "" || r.Header.Get("X-Amz-Security-Token") != "" {
			t.Error("local signing credentials reached upstream")
		}
		mu.Lock()
		tokens = append(tokens, r.Header.Get("Authorization"))
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"QueryExecutionId":"query-1"}`)
	}))
	defer upstream.Close()
	endpoint := testEndpoint(upstream)
	credentials := driver.Credentials{Principal: "alice", Token: "first-token", LocalPassword: "local-password"}
	available := true
	var resolved atomic.Int64
	local := serveBroker(t, func() (driver.Endpoint, driver.Credentials, bool) {
		resolved.Add(1)
		mu.Lock()
		defer mu.Unlock()
		return endpoint, credentials, available
	})
	static := localCredentials("alice", endpoint.Name, credentials.LocalPassword)
	client := awsa.NewFromConfig(aws.Config{
		Region: "us-east-1", RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return static, nil }),
	}, func(options *awsa.Options) { options.BaseEndpoint = aws.String(local) })
	input := &awsa.StartQueryExecutionInput{
		QueryString: aws.String("SELECT 1"), WorkGroup: aws.String("primary"),
		QueryExecutionContext: &types.QueryExecutionContext{Catalog: aws.String("AwsDataCatalog"), Database: aws.String("default")},
	}
	for i := 0; i < 2; i++ {
		output, err := client.StartQueryExecution(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(output.QueryExecutionId) != "query-1" {
			t.Fatalf("execution ID = %v", output.QueryExecutionId)
		}
		mu.Lock()
		credentials.Token = "renewed-token"
		mu.Unlock()
	}
	mu.Lock()
	if len(tokens) != 2 || tokens[0] != "Bearer first-token" || tokens[1] != "Bearer renewed-token" {
		t.Errorf("forwarded tokens = %v", tokens)
	}
	for _, body := range bodies {
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil || payload["QueryString"] != "SELECT 1" || payload["WorkGroup"] != "primary" {
			t.Errorf("forwarded body = %s, error = %v", body, err)
		}
	}
	credentials.Principal = "bob"
	mu.Unlock()
	if _, err := client.StartQueryExecution(context.Background(), input); err == nil {
		t.Error("saved Alice profile worked after login changed to Bob")
	}
	mu.Lock()
	available = false
	mu.Unlock()
	if _, err := client.StartQueryExecution(context.Background(), input); err == nil {
		t.Error("SDK request worked after session removal")
	}
	if got := resolved.Load(); got != 4 {
		t.Fatalf("ResolveSession calls = %d, want 4", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tokens) != 2 {
		t.Fatalf("unauthenticated requests reached upstream: %d", len(tokens))
	}
}

func TestNativeForwardPreservesFunctionalHeadersAndBody(t *testing.T) {
	body := []byte(" { \"QueryString\" : \"SELECT 1\", \"FutureField\" : true } \n")
	var received atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		data, _ := io.ReadAll(r.Body)
		if string(data) != string(body) {
			t.Errorf("body changed: %q", data)
		}
		for name, want := range map[string]string{
			"Authorization": "Bearer pm-token", "X-Amz-Expected-Bucket-Owner": "123456789012", "X-Amz-Request-Payer": "requester",
			"X-Amz-Checksum-Mode": "ENABLED", "X-Amz-Checksum-Crc32": "opaque-checksum", "Content-Md5": "opaque-md5",
			"X-Amzn-Trace-Id": "trace-1", "Amz-Sdk-Invocation-Id": "invocation-1", "X-Future-Option": "preserved",
		} {
			if got := r.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		for _, name := range []string{"Cookie", "X-Pm-Principal", "X-Pmon-Token", "X-Forwarded-For", "Forwarded", "X-Amz-Date", "X-Amz-Content-Sha256", "X-Hop-Only"} {
			if got := r.Header.Get(name); got != "" {
				t.Errorf("%s leaked upstream: %q", name, got)
			}
		}
		w.Header().Set("X-Amzn-Requestid", "request-1")
		w.Header().Set("X-Amz-Future-Response", "preserved")
		w.Header().Set("Connection", "X-Hop-Response")
		w.Header().Set("X-Hop-Response", "removed")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"__type":"TooManyRequestsException","Message":"throttled"}`)
	}))
	defer upstream.Close()
	endpoint := testEndpoint(upstream)
	credentials := driver.Credentials{Principal: "alice", Token: "pm-token", LocalPassword: "local-password"}
	local := serveBroker(t, func() (driver.Endpoint, driver.Credentials, bool) { return endpoint, credentials, true })
	request := signedRequest(t, local+"/", body, localCredentials(credentials.Principal, endpoint.Name, credentials.LocalPassword), "us-east-1", time.Now(), func(r *http.Request) {
		for name, value := range map[string]string{
			"X-Amz-Expected-Bucket-Owner": "123456789012", "X-Amz-Request-Payer": "requester", "X-Amz-Checksum-Mode": "ENABLED",
			"X-Amz-Checksum-Crc32": "opaque-checksum", "Content-Md5": "opaque-md5", "X-Amzn-Trace-Id": "trace-1",
			"Amz-Sdk-Invocation-Id": "invocation-1", "X-Future-Option": "preserved", "Cookie": "secret",
			"X-Pm-Principal": "forged", "X-Pmon-Token": "forged", "X-Forwarded-For": "192.0.2.1", "Forwarded": "for=192.0.2.1",
		} {
			r.Header.Set(name, value)
		}
	})
	request.Header.Set("Connection", "X-Hop-Only")
	request.Header.Set("X-Hop-Only", "removed")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusTooManyRequests || string(data) != `{"__type":"TooManyRequestsException","Message":"throttled"}` {
		t.Fatalf("native error changed: %d %s", response.StatusCode, data)
	}
	if response.Header.Get("X-Amzn-Requestid") != "request-1" || response.Header.Get("X-Amz-Future-Response") != "preserved" || response.Header.Get("X-Hop-Response") != "" {
		t.Fatalf("response headers = %v", response.Header)
	}
	if received.Load() != 1 {
		t.Fatal("upstream did not receive exactly one request")
	}
}

func TestUpstreamTLSAndRedirects(t *testing.T) {
	var redirected atomic.Int64
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	credentials := driver.Credentials{Principal: "alice", Token: "pm-token", LocalPassword: "local-password"}
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted no redirect", false: "untrusted certificate"}[trusted], func(t *testing.T) {
			endpoint := testEndpoint(upstream)
			if !trusted {
				endpoint.CertChainPEM = ""
			}
			local := serveBroker(t, func() (driver.Endpoint, driver.Credentials, bool) { return endpoint, credentials, true })
			request := signedRequest(t, local+"/", []byte(`{}`), localCredentials(credentials.Principal, endpoint.Name, credentials.LocalPassword), "us-east-1", time.Now(), nil)
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			want := http.StatusTemporaryRedirect
			if !trusted {
				want = http.StatusBadGateway
			}
			if response.StatusCode != want {
				t.Fatalf("status = %d, want %d", response.StatusCode, want)
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("PM token followed an upstream redirect")
	}
}

func TestNativeRejectsUnsignedOversizedAndNonRootRequests(t *testing.T) {
	var received atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer upstream.Close()
	endpoint := testEndpoint(upstream)
	credentials := driver.Credentials{Principal: "alice", Token: "pm-token", LocalPassword: "local-password"}
	local := serveBroker(t, func() (driver.Endpoint, driver.Credentials, bool) { return endpoint, credentials, true })
	for _, test := range []struct {
		name, path, body string
		sign             bool
		status           int
	}{
		{"unsigned", "/", `{}`, false, http.StatusForbidden},
		{"oversized", "/", strings.Repeat("x", maxRequestBytes+1), true, http.StatusRequestEntityTooLarge},
		{"nonroot", "/other", `{}`, true, http.StatusBadRequest},
		{"query credentials", "/?X-Amz-Credential=forged", `{}`, true, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := signedRequest(t, local+test.path, []byte(test.body), localCredentials(credentials.Principal, endpoint.Name, credentials.LocalPassword), "us-east-1", time.Now(), nil)
			if !test.sign {
				request.Header.Del("Authorization")
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
		})
	}
	if received.Load() != 0 {
		t.Fatal("invalid requests reached upstream")
	}
}

func TestEndpointSupportAndRouteKey(t *testing.T) {
	provider := Provider{}
	base := driver.Endpoint{Name: "warehouse", Engine: "athena", AdvertiseAddr: "proxy.example:443", ConnectionInfo: &driver.ConnectionInfo{Endpoint: "https://proxy.example/", Properties: map[string]string{"region": "us-east-1"}}}
	if reason := provider.UnavailableReason(base); reason != "" {
		t.Fatal(reason)
	}
	for _, address := range []string{"", "proxy.example:443", "http://proxy.example", "https://user:secret@proxy.example", "https://proxy.example/?", "https://proxy.example/?target=other", "https://proxy.example/#fragment", "https://proxy.example/other"} {
		endpoint := base.Clone()
		endpoint.ConnectionInfo.Endpoint = address
		if reason := provider.UnavailableReason(endpoint); reason == "" {
			t.Errorf("accepted endpoint %q", address)
		}
	}
	changed := base
	changed.ConnectionInfo = &driver.ConnectionInfo{Properties: map[string]string{"region": "us-west-2"}}
	if provider.RouteKey(base) == provider.RouteKey(changed) {
		t.Error("region change did not change route key")
	}
	changed = base
	changed.CertChainPEM = "not a certificate"
	if provider.UnavailableReason(changed) == "" || provider.RouteKey(base) == provider.RouteKey(changed) {
		t.Error("invalid certificate accepted or trust change did not change route key")
	}
	changed = base
	changed.ConnectionInfo = nil
	if provider.UnavailableReason(changed) == "" {
		t.Error("missing connection metadata accepted")
	}
}
