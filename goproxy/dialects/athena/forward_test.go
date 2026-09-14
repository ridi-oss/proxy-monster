package athena

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func allowRequest(_ context.Context, _ *http.Request, envelope *Envelope) (*Envelope, error) {
	return envelope, nil
}

func signTestRequest(_ context.Context, request *http.Request, body []byte) error {
	request.Header.Set("Authorization", fmt.Sprintf("test-signature %x", sha256.Sum256(body)))
	return nil
}

func forwarderForTest(t *testing.T, server *httptest.Server, configure func(*ForwardOptions)) *Forwarder {
	t.Helper()
	options := ForwardOptions{
		Endpoint: server.URL, MaxBodyBytes: 1 << 20,
		Authorize: allowRequest, Sign: signTestRequest, Transport: server.Client().Transport,
	}
	if configure != nil {
		configure(&options)
	}
	forwarder, err := NewForwarder(options)
	if err != nil {
		t.Fatal(err)
	}
	return forwarder
}

func requestForTest(operation, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://client.example/", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "AmazonAthena."+operation)
	return request
}

func TestForwardPreservesNativeProtocol(t *testing.T) {
	for _, test := range []struct {
		operation string
		request   string
		response  string
		status    int
	}{
		{"FutureOperation", " {\n\"Unknown\":{\"N\":900719925474099312345,\"D\":1.2300e+50,\"S\":\"\\u0061<>&\"}} \n", `{"FutureResult":{"N":900719925474099312345}}`, 200},
		{"StartQueryExecution", `{"QueryString":"SELECT 1","ClientRequestToken":"same-native-token","ExecutionParameters":["1"],"FutureFlag":true}`, `{"QueryExecutionId":"native-query-id"}`, 200},
		{"GetQueryResults", `{"QueryExecutionId":"native-query-id","NextToken":"native-input-token"}`, `{"NextToken":"native-output-token","ResultSet":{"Rows":[{"Data":[{"VarCharValue":"900719925474099312345"}]}]}}`, 200},
		{"GetQueryExecution", `{"QueryExecutionId":"native-query-id"}`, `{"QueryExecution":{"QueryExecutionId":"native-query-id","FutureField":123}}`, 200},
		{"StartQueryExecution", `{"QueryString":"native error","ClientRequestToken":"same-native-token"}`, `{"__type":"InvalidRequestException","Message":"native error details","Extra":900719925474099312345}`, 400},
		{"FutureOperation", `{}`, `{"__type":"TooManyRequestsException","Message":"slow down"}`, 429},
	} {
		t.Run(test.operation+"/"+strconv.Itoa(test.status), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != test.request {
					t.Errorf("upstream body = %s, %v; want %s", body, err, test.request)
				}
				if r.Header.Get("X-Amz-Target") != "AmazonAthena."+test.operation {
					t.Errorf("operation changed: %v", r.Header)
				}
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.Header().Set("X-Amzn-Requestid", "native-request-id")
				w.Header().Set("X-Amzn-Errortype", "native-error-type")
				w.Header().Set("Retry-After", "7")
				w.Header().Add("X-Future-Header", "first")
				w.Header().Add("X-Future-Header", "second")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.response)
			}))
			defer upstream.Close()
			forwarder := forwarderForTest(t, upstream, nil)
			response, err := forwarder.Forward(requestForTest(test.operation, test.request))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != test.response || response.StatusCode != test.status {
				t.Fatalf("response = %d, %s, %v", response.StatusCode, body, err)
			}
			if response.Header.Get("X-Amzn-Requestid") != "native-request-id" || response.Header.Get("Retry-After") != "7" ||
				response.Header.Get("X-Amzn-Errortype") != "native-error-type" || len(response.Header.Values("X-Future-Header")) != 2 {
				t.Fatalf("native headers changed: %v", response.Header)
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream requests = %d, want 1", calls.Load())
			}
		})
	}
}

func TestForwardRewritesBeforeSigningAndDropsClientCredentials(t *testing.T) {
	body := ` {"QueryString" : "SELECT old", "ClientRequestToken":"unchanged", "Unknown":{"N":900719925474099312345,"S":"\u0061<>&"}} `
	want := strings.Replace(body, "SELECT old", "SELECT rewritten_column", 1)
	var upstreamHost string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual, err := io.ReadAll(r.Body)
		if err != nil || string(actual) != want {
			t.Errorf("body = %s, %v; want %s", actual, err, want)
		}
		if r.RequestURI != "/fixed" || r.Host != upstreamHost || r.ContentLength != int64(len(want)) {
			t.Errorf("destination/length = %s, %s, %d", r.RequestURI, r.Host, r.ContentLength)
		}
		if r.Header.Get("Authorization") != fmt.Sprintf("test-signature %x", sha256.Sum256([]byte(want))) ||
			r.Header.Get("X-Amz-Security-Token") != "upstream-session" || r.Header.Get("X-Amz-Date") != "upstream-date" {
			t.Errorf("upstream credentials = %v", r.Header)
		}
		for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Pm-Token", "X-Pmon-Token", "X-Forwarded-For", "Forwarded", "Connection", "X-Amz-User-Agent", "X-Amz-Content-Sha256", "X-Api-Key"} {
			if value := r.Header.Get(name); value != "" {
				t.Errorf("client header %s leaked: %s", name, value)
			}
		}
		if r.Header.Get("X-Amz-Target") != "AmazonAthena.StartQueryExecution" || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
			t.Errorf("protocol headers changed: %v", r.Header)
		}
		_, _ = io.WriteString(w, `{"QueryExecutionId":"native-id"}`)
	}))
	defer upstream.Close()
	upstreamHost = strings.TrimPrefix(upstream.URL, "https://")
	var authorized, signed bool
	forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
		options.Endpoint += "/fixed"
		options.Authorize = func(_ context.Context, request *http.Request, envelope *Envelope) (*Envelope, error) {
			authorized = true
			if request.Header.Get("Authorization") != "PM client-token" || request.Header.Get("Cookie") != "pm_session=private" {
				t.Error("authorization cannot see incoming client credentials")
			}
			return envelope.WithQueryString("SELECT rewritten_column")
		}
		options.Sign = func(ctx context.Context, request *http.Request, body []byte) error {
			signed = true
			if !authorized || string(body) != want || request.URL.String() != upstream.URL+"/fixed" || request.Host != upstreamHost {
				t.Errorf("signer did not receive final authorized request: %s, %s, %s", body, request.URL, request.Host)
			}
			if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("X-Amz-Security-Token") != "" {
				t.Error("client credentials reached signer")
			}
			if request.Header.Get("Content-Length") != "" || request.ContentLength != int64(len(want)) {
				t.Error("signer received stale body length")
			}
			request.Header.Set("X-Amz-Security-Token", "upstream-session")
			request.Header.Set("X-Amz-Date", "upstream-date")
			return signTestRequest(ctx, request, body)
		}
	})
	request := requestForTest("StartQueryExecution", body)
	request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	request.URL.Path = "/caller-selected-path"
	request.URL.RawQuery = "X-Amz-Credential=private"
	request.Header.Set("Authorization", "PM client-token")
	request.Header.Set("Cookie", "pm_session=private")
	for _, name := range []string{"Proxy-Authorization", "X-Pm-Token", "X-Pmon-Token", "X-Forwarded-For", "Forwarded", "X-Amz-Security-Token", "X-Amz-Date", "X-Amz-Content-Sha256", "X-Api-Key"} {
		request.Header.Set(name, "private")
	}
	request.Header.Set("X-Amz-User-Agent", "client-agent")
	request.Header.Set("Connection", "keep-alive, X-Amz-User-Agent")
	response, err := forwarder.Forward(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if !authorized || !signed {
		t.Fatal("authorization or signing was skipped")
	}
	if request.Header.Get("Authorization") != "PM client-token" {
		t.Fatal("forwarding mutated incoming headers")
	}
}

func TestForwardDenialCannotReachUpstream(t *testing.T) {
	denied := errors.New("denied")
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, test := range []struct {
		name      string
		authorize AuthorizeRequest
		sign      SignRequest
		want      error
	}{
		{"denied", func(context.Context, *http.Request, *Envelope) (*Envelope, error) { return nil, denied }, signTestRequest, denied},
		{"missing approval", func(context.Context, *http.Request, *Envelope) (*Envelope, error) { return nil, nil }, signTestRequest, ErrUnauthorized},
		{"empty approval", func(context.Context, *http.Request, *Envelope) (*Envelope, error) { return &Envelope{}, nil }, signTestRequest, ErrUnauthorized},
		{"signing denied", allowRequest, func(context.Context, *http.Request, []byte) error { return denied }, denied},
		{"unsigned", allowRequest, func(context.Context, *http.Request, []byte) error { return nil }, ErrUnsigned},
	} {
		t.Run(test.name, func(t *testing.T) {
			forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
				options.Authorize, options.Sign = test.authorize, test.sign
			})
			if _, err := forwarder.Forward(requestForTest("FutureOperation", `{}`)); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := (&Forwarder{}).Forward(requestForTest("FutureOperation", `{}`)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero forwarder error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("denied requests reached upstream: %d", calls.Load())
	}
}

func TestNewForwarderRequiresFixedSecureEndpointAndAuth(t *testing.T) {
	valid := ForwardOptions{Endpoint: "https://athena.example/", MaxBodyBytes: 1024, Authorize: allowRequest, Sign: signTestRequest}
	for _, endpoint := range []string{"", "/relative", "http://athena.example/", "https:///", "https://user:secret@athena.example/", "https://athena.example/?destination=elsewhere", "https://athena.example/?", "https://athena.example/#fragment"} {
		options := valid
		options.Endpoint = endpoint
		if _, err := NewForwarder(options); err == nil {
			t.Errorf("invalid endpoint accepted: %s", endpoint)
		}
	}
	options := valid
	options.Authorize = nil
	if _, err := NewForwarder(options); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("missing authorization = %v", err)
	}
	options = valid
	options.Sign = nil
	if _, err := NewForwarder(options); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("missing signing = %v", err)
	}
	for _, limit := range []int64{0, -1, 1<<63 - 1} {
		options := valid
		options.MaxBodyBytes = limit
		if _, err := NewForwarder(options); err == nil {
			t.Errorf("invalid body limit accepted: %d", limit)
		}
	}
}

func TestForwardBoundsIncomingAndRewrittenBodies(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, test := range []struct {
		name    string
		body    string
		chunked bool
		rewrite bool
	}{
		{"content length", `{"QueryString":"` + strings.Repeat("x", 100) + `"}`, false, false},
		{"chunked", `{"QueryString":"` + strings.Repeat("x", 100) + `"}`, true, false},
		{"rewritten", `{"QueryString":"x"}`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
				options.MaxBodyBytes = 64
				options.Authorize = func(_ context.Context, _ *http.Request, envelope *Envelope) (*Envelope, error) {
					if !test.rewrite {
						t.Error("oversized request reached authorization")
					}
					return envelope.WithQueryString(strings.Repeat("x", 100))
				}
				options.Sign = func(context.Context, *http.Request, []byte) error {
					t.Error("oversized body reached signer")
					return nil
				}
			})
			request := requestForTest("StartQueryExecution", test.body)
			if test.chunked {
				request.ContentLength = -1
			}
			if _, err := forwarder.Forward(request); !errors.Is(err, ErrBodyTooLarge) {
				t.Fatalf("error = %v, want body limit", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("oversized requests reached upstream: %d", calls.Load())
	}
}

func TestForwardPropagatesCancellation(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	forwarder := forwarderForTest(t, upstream, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		response, err := forwarder.Forward(requestForTest("FutureOperation", `{}`).WithContext(ctx))
		if response != nil {
			_ = response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("forward error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not stop on cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request context was not canceled")
	}
}

func TestForwardDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, `{"redirect":"native response"}`)
	}))
	defer upstream.Close()
	response, err := forwarderForTest(t, upstream, nil).Forward(requestForTest("FutureOperation", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || response.Header.Get("Location") != destination.URL || redirected.Load() != 0 {
		t.Fatalf("redirect response = %d, %v; followed = %d", response.StatusCode, response.Header, redirected.Load())
	}
}

func TestForwardPreservesEncodedStreamingResponse(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Trailer", "X-Final-Token")
		_, _ = w.Write([]byte{0x1f, 0x8b, 0x08})
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write(bytes.Repeat([]byte{0x42}, 1024))
		w.Header().Set("X-Final-Token", "native-trailer")
	}))
	defer upstream.Close()
	defer unblock()
	forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) { options.MaxBodyBytes = 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := forwarder.Forward(requestForTest("FutureOperation", `{}`).WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "gzip" || response.Uncompressed {
		t.Fatalf("response was decompressed: %v", response.Header)
	}
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(response.Body, prefix); err != nil || !bytes.Equal(prefix, []byte{0x1f, 0x8b, 0x08}) {
		t.Fatalf("response prefix = %v, %v", prefix, err)
	}
	unblock()
	rest, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(rest, bytes.Repeat([]byte{0x42}, 1024)) || response.Trailer.Get("X-Final-Token") != "native-trailer" {
		t.Fatalf("stream tail/trailer = %d bytes, %v, %v", len(rest), response.Trailer, err)
	}
}

func TestForwardRejectsAmbiguousOperation(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	forwarder := forwarderForTest(t, upstream, nil)
	request := requestForTest("GetQueryExecution", `{}`)
	request.Header.Add("X-Amz-Target", "AmazonAthena.StartQueryExecution")
	if _, err := forwarder.Forward(request); err == nil {
		t.Fatal("multiple operation headers accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("ambiguous operation reached upstream")
	}
}
