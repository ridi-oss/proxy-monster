package athena

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestForwardRejectsCanceledOrMalformedRequestsBeforeAuthorization(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
		options.Authorize = func(context.Context, *http.Request, *Envelope) (*Envelope, error) {
			t.Error("invalid request reached authorization")
			return nil, ErrUnauthorized
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := forwarder.Forward(requestForTest("FutureOperation", `{}`).WithContext(ctx)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled request = %v", err)
	}
	for _, body := range []string{`{"QueryString":"one","QueryString":"two"}`, `{"n":1} {"n":2}`, `{"broken"}`} {
		if _, err := forwarder.Forward(requestForTest("FutureOperation", body)); err == nil {
			t.Errorf("malformed request accepted: %s", body)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests reached upstream: %d", calls.Load())
	}
}

func TestForwardRejectsSignerDestinationChanges(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, change := range []string{"host", "path", "query", "url host"} {
		t.Run(change, func(t *testing.T) {
			forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
				options.Sign = func(ctx context.Context, request *http.Request, body []byte) error {
					switch change {
					case "host":
						request.Host = "elsewhere.example"
					case "path":
						request.URL.Path = "/elsewhere"
					case "query":
						request.URL.RawQuery = "destination=elsewhere"
					case "url host":
						request.URL.Host = "elsewhere.example"
						request.Host = request.URL.Host
					}
					return signTestRequest(ctx, request, body)
				}
			})
			if _, err := forwarder.Forward(requestForTest("FutureOperation", `{}`)); err == nil {
				t.Fatal("changed destination accepted")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("changed requests reached upstream: %d", calls.Load())
	}
}

func TestForwardExposesTransportErrorsWithoutRetry(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer upstream.Close()
	forwarder := forwarderForTest(t, upstream, nil)
	request := requestForTest("StartQueryExecution", `{"QueryString":"SELECT 1","ClientRequestToken":"native-token"}`)
	request.Header.Set("Idempotency-Key", "caller-retry-key")
	response, err := forwarder.Forward(request)
	if response != nil || err == nil || !strings.Contains(err.Error(), "forward request") {
		t.Fatalf("transport result = %v, %v", response, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport attempts = %d, want 1", calls.Load())
	}
}
