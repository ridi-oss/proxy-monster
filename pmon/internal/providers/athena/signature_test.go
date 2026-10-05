package athena

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var signingTime = time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)

func signedRequest(t *testing.T, endpoint string, body []byte, credentials aws.Credentials, region string, stamp time.Time, change func(*http.Request)) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "AmazonAthena.StartQueryExecution")
	if change != nil {
		change(request)
	}
	hash := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(request.Context(), credentials, request, hex.EncodeToString(hash[:]), "athena", region, stamp); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestSignatureFromAWSSigner(t *testing.T) {
	credentials := localCredentials("alice", "warehouse", "local-password")
	body := []byte(`{"QueryString":"SELECT 1"}`)
	for _, contentLengthSigned := range []bool{true, false} {
		request := signedRequest(t, "http://127.0.0.1:32123/", body, credentials, "us-east-1", signingTime, func(r *http.Request) {
			if !contentLengthSigned {
				r.ContentLength = -1
			}
			r.Header.Set("X-Amz-Expected-Bucket-Owner", "123456789012")
			r.Header.Set("X-Amz-Request-Payer", "requester")
			r.Header.Add("X-Custom", "one   two")
			r.Header.Add("X-Custom", "three")
		})
		request.ContentLength = int64(len(body))
		request.Header.Set("User-Agent", "ordinary-sdk/1.0")
		request.Header.Set("Accept-Encoding", "gzip")
		if err := verifySignature(request, body, credentials, "us-east-1", signingTime); err != nil {
			t.Fatalf("content-length signed=%v: %v", contentLengthSigned, err)
		}
	}
}

func TestSignatureRejectsChanges(t *testing.T) {
	credentials := localCredentials("alice", "warehouse", "local-password")
	body := []byte(`{"QueryString":"SELECT 1"}`)
	cases := map[string]func(*http.Request){
		"missing authorization":        func(r *http.Request) { r.Header.Del("Authorization") },
		"access key without signature": func(r *http.Request) { r.Header.Set("Authorization", credentials.AccessKeyID) },
		"bad signature":                func(r *http.Request) { r.Header.Set("Authorization", r.Header.Get("Authorization")+"0") },
		"duplicate authorization":      func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"body":                         func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"QueryString":"SELECT 2"}`)) },
		"operation":                    func(r *http.Request) { r.Header.Set("X-Amz-Target", "AmazonAthena.StopQueryExecution") },
		"duplicate operation":          func(r *http.Request) { r.Header.Add("X-Amz-Target", "AmazonAthena.StartQueryExecution") },
		"host":                         func(r *http.Request) { r.Host = "other.example" },
		"content type":                 func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
		"timestamp":                    func(r *http.Request) { r.Header.Set("X-Amz-Date", "20260914T100001Z") },
		"duplicate timestamp":          func(r *http.Request) { r.Header.Add("X-Amz-Date", r.Header.Get("X-Amz-Date")) },
		"scope date": func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/20260914/", "/20260913/", 1))
		},
		"scope service": func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/athena/", "/s3/", 1))
		},
		"scope region": func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/us-east-1/", "/us-west-2/", 1))
		},
		"scope terminator": func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/aws4_request", "/other", 1))
		},
		"unknown authorization field": func(r *http.Request) { r.Header.Set("Authorization", r.Header.Get("Authorization")+", Extra=one") },
		"duplicate signed header": func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "host;", "host;host;", 1))
		},
		"unsigned body marker": func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") },
		"session token":        func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "other-token") },
		"signed header":        func(r *http.Request) { r.Header.Set("X-Amz-Request-Payer", "other") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := signedRequest(t, "http://127.0.0.1:32123/", body, credentials, "us-east-1", signingTime, func(r *http.Request) {
				r.Header.Set("X-Amz-Request-Payer", "requester")
			})
			mutate(request)
			changedBody, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifySignature(request, changedBody, credentials, "us-east-1", signingTime); err == nil {
				t.Fatal("accepted modified signed request")
			}
		})
	}
}

func TestSignatureRejectsStaleAndFutureRequests(t *testing.T) {
	credentials := localCredentials("alice", "warehouse", "local-password")
	body := []byte(`{}`)
	for _, delta := range []time.Duration{-5*time.Minute - time.Second, 5*time.Minute + time.Second} {
		request := signedRequest(t, "http://127.0.0.1:32123/", body, credentials, "us-east-1", signingTime.Add(delta), nil)
		if err := verifySignature(request, body, credentials, "us-east-1", signingTime); err == nil {
			t.Fatalf("accepted clock delta %v", delta)
		}
	}
}

func TestSignatureRequiresSignedOperation(t *testing.T) {
	credentials := localCredentials("alice", "warehouse", "local-password")
	body := []byte(`{}`)
	request := signedRequest(t, "http://127.0.0.1:32123/", body, credentials, "us-east-1", signingTime, func(r *http.Request) {
		r.Header.Del("X-Amz-Target")
	})
	request.Header.Set("X-Amz-Target", "AmazonAthena.StartQueryExecution")
	if err := verifySignature(request, body, credentials, "us-east-1", signingTime); err == nil {
		t.Fatal("accepted unsigned operation")
	}
}

func TestLocalCredentialIdentityHasNoDelimiterCollision(t *testing.T) {
	first := localCredentials("alice\x00team", "warehouse", "local-password")
	second := localCredentials("alice", "team\x00warehouse", "local-password")
	if first.AccessKeyID == second.AccessKeyID || first.SecretAccessKey == second.SecretAccessKey {
		t.Fatal("different principal and datasource pairs share credentials")
	}
}

func TestLocalCredentialsArePrincipalAndDatasourceBound(t *testing.T) {
	credentials := localCredentials("alice", "warehouse", "local-password")
	if got := localCredentials("alice", "warehouse", "local-password"); got != credentials {
		t.Fatal("credentials are not stable")
	}
	body := []byte(`{}`)
	request := signedRequest(t, "http://127.0.0.1:32123/", body, credentials, "us-east-1", signingTime, nil)
	for _, other := range []aws.Credentials{
		localCredentials("bob", "warehouse", "local-password"),
		localCredentials("alice", "other", "local-password"),
		localCredentials("alice", "warehouse", "rotated-password"),
	} {
		if err := verifySignature(request, body, other, "us-east-1", signingTime); err == nil {
			t.Fatal("accepted saved profile under different identity or password")
		}
	}
}
