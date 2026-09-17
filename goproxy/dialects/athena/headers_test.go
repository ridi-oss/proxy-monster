package athena

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestForwardPreservesFunctionalHeaders(t *testing.T) {
	for _, rewrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "rewritten"}[rewrite], func(t *testing.T) {
			headers := http.Header{
				"Range":                       {"bytes=0-4095"},
				"If-Match":                    {`"native-etag"`},
				"If-None-Match":               {`"other-etag"`},
				"X-Amz-Checksum-Mode":         {"ENABLED"},
				"X-Amz-Expected-Bucket-Owner": {"123456789012"},
				"X-Amz-Request-Payer":         {"requester"},
				"X-Future-Feature":            {"first", "second"},
			}
			if !rewrite {
				headers.Set("Content-Md5", "native-md5")
				headers.Set("X-Amz-Checksum-Sha256", "native-sha256")
				headers.Set("X-Amz-Checksum-Future", "native-future-checksum")
			}
			var calls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for name, want := range headers {
					if got := r.Header.Values(name); !reflect.DeepEqual(got, want) {
						t.Errorf("upstream header %s = %v, want %v", name, got, want)
					}
				}
				body, err := io.ReadAll(r.Body)
				want := `{"QueryString":"SELECT old"}`
				if rewrite {
					want = `{"QueryString":"SELECT new"}`
				}
				if err != nil || string(body) != want {
					t.Errorf("upstream body = %s, %v; want %s", body, err, want)
				}
				_, _ = io.WriteString(w, `{}`)
			}))
			defer upstream.Close()
			forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
				options.Authorize = func(_ context.Context, request *http.Request, envelope *Envelope) (*Envelope, error) {
					for name, want := range headers {
						if got := request.Header.Values(name); !reflect.DeepEqual(got, want) {
							t.Errorf("authorization header %s = %v, want %v", name, got, want)
						}
					}
					if rewrite {
						return envelope.WithQueryString("SELECT new")
					}
					return envelope, nil
				}
			})
			request := requestForTest("StartQueryExecution", `{"QueryString":"SELECT old"}`)
			for name, values := range headers {
				request.Header[name] = append([]string(nil), values...)
			}
			response, err := forwarder.Forward(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if calls.Load() != 1 {
				t.Fatalf("upstream requests = %d, want 1", calls.Load())
			}
		})
	}
}

func TestForwardStripsCredentialsIdentityAndHopHeaders(t *testing.T) {
	blocked := []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Cookie2", "X-Pm-Token", "X-Pmon-Principal", "X-Proxy-Monster-Roles",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "True-Client-Ip", "X-Client-Ip",
		"X-Remote-User", "X-Authenticated-User", "X-Authenticated-Groups", "X-Auth-Request-User", "X-Amzn-Oidc-Data", "X-Amzn-Mtls-Clientcert",
		"X-Api-Key", "X-Auth-Token", "Date", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256", "X-Amz-Credential",
		"X-Amz-Signature", "X-Amz-Signedheaders", "X-Amz-Region-Set", "X-Amz-Sso-Bearer-Token",
		"Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-Connection-Scoped",
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range blocked {
			if name != "Authorization" && r.Header.Get(name) != "" {
				t.Errorf("blocked header %s reached upstream", name)
			}
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "test-signature ") {
			t.Error("upstream signature missing")
		}
		if r.Header.Get("X-Future-Feature") != "kept" {
			t.Error("functional header was removed")
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
		options.Authorize = func(_ context.Context, request *http.Request, envelope *Envelope) (*Envelope, error) {
			if request.Header.Get("Authorization") != "private" || request.Header.Get("X-Pmon-Principal") != "private" {
				t.Error("authorization lost original identity headers")
			}
			return envelope, nil
		}
		options.Sign = func(ctx context.Context, request *http.Request, body []byte) error {
			for _, name := range blocked {
				if request.Header.Get(name) != "" {
					t.Errorf("blocked header %s reached signer", name)
				}
			}
			return signTestRequest(ctx, request, body)
		}
	})
	request := requestForTest("FutureOperation", `{}`)
	for _, name := range blocked {
		request.Header.Set(name, "private")
	}
	request.Header.Set("Connection", "keep-alive, X-Connection-Scoped")
	request.Header.Set("X-Future-Feature", "kept")
	response, err := forwarder.Forward(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
}

func TestForwardRejectsStaleChecksumsAfterRewrite(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	forwarder := forwarderForTest(t, upstream, func(options *ForwardOptions) {
		options.Authorize = func(_ context.Context, _ *http.Request, envelope *Envelope) (*Envelope, error) {
			return envelope.WithQueryString("SELECT new")
		}
		options.Sign = func(context.Context, *http.Request, []byte) error {
			t.Error("stale checksum reached signer")
			return nil
		}
	})
	for _, header := range []string{"Content-Md5", "Digest", "Content-Digest", "Repr-Digest", "X-Amz-Checksum-Sha256", "X-Amz-Checksum-Future"} {
		request := requestForTest("StartQueryExecution", `{"QueryString":"SELECT old"}`)
		request.Header.Set(header, "checksum-of-original-body")
		if _, err := forwarder.Forward(request); err == nil || !strings.Contains(err.Error(), "cannot rewrite") {
			t.Errorf("rewrite with %s = %v", header, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("requests with stale checksums reached upstream: %d", calls.Load())
	}
}
