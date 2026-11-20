package bigquery

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
)

const readRows = "/google.cloud.bigquery.storage.v1.BigQueryRead/ReadRows"

// grpcCall sends one gRPC-framed call over cleartext HTTP/2, as a local gRPC client does, and returns the
// body and the grpc-status from the trailers, or from the headers of a trailers-only answer.
func grpcCall(t *testing.T, url, token, method string, payload []byte) (string, string) {
	t.Helper()
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	defer transport.CloseIdleConnections()
	frame := append([]byte{0, 0, 0, 0, byte(len(payload))}, payload...)
	request, _ := http.NewRequest(http.MethodPost, url+method, bytes.NewReader(frame))
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("Te", "trailers")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if code := response.Header.Get("Grpc-Status"); code != "" {
		return string(body), code
	}
	return string(body), response.Trailer.Get("Grpc-Status")
}

func TestBrokerRelaysStorageReadCalls(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.ProtoMajor != 2 || r.Header.Get("Authorization") != "Bearer pmk_current" || r.Header.Get("Te") != "trailers" ||
			r.URL.Path != readRows || !bytes.HasSuffix(body, []byte("stream-0")) {
			t.Errorf("relayed %s %s %v %q", r.Proto, r.URL.Path, r.Header, body)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		for _, part := range []string{"batch-1", "batch-2"} {
			_, _ = w.Write(append([]byte{0, 0, 0, 0, byte(len(part))}, part...))
			w.(http.Flusher).Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	endpoint := testEndpoint(upstream)
	credentials := driver.Credentials{Principal: "alice", Token: "pmk_current", LocalPassword: "local-password"}
	local := serveBroker(t, Provider{}, func() (driver.Endpoint, driver.Credentials, bool) { return endpoint, credentials, true })
	token := localToken("alice", "warehouse", "local-password")

	if body, code := grpcCall(t, local, token, readRows, []byte("stream-0")); code != "0" || !strings.Contains(body, "batch-1") || !strings.Contains(body, "batch-2") {
		t.Fatalf("relay = %q status %q", body, code)
	}
	if _, code := grpcCall(t, local, "pmk_current", readRows, nil); code != "16" {
		t.Errorf("proxy token at the local endpoint = %q", code)
	}
	if _, code := grpcCall(t, local, token, "/google.cloud.bigquery.storage.v1.BigQueryWrite/AppendRows", nil); code != "12" {
		t.Errorf("write API = %q", code)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
}
