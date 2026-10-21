package workload_test

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/cpgo/routes/workload"
)

const audience = "https://pm.example.com"

// testIssuer is a loopback CI issuer publishing a GitHub-shaped discovery document and its JWKS.
type testIssuer struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	jwksCalls atomic.Int32
}

func newIssuer(t *testing.T) *testIssuer {
	t.Helper()
	ti := &testIssuer{key: rsaKey(t)}
	ti.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": ti.srv.URL, "jwks_uri": ti.srv.URL + "/jwks"})
		case "/jwks":
			ti.jwksCalls.Add(1)
			pub := ti.key.PublicKey
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "ci-kid", "use": "sig", "alg": "RS256",
				"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ti.srv.Close)
	return ti
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (ti *testIssuer) config() workload.Issuer {
	return workload.Issuer{Name: "github", URL: ti.srv.URL, Audience: audience}
}

func (ti *testIssuer) verifier() *workload.Verifier {
	return workload.NewVerifier([]workload.Issuer{ti.config()}, http.DefaultClient)
}

// claims is a GitHub Actions push token from this issuer; edit returns it changed.
func (ti *testIssuer) claims(edit func(map[string]any)) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{
		"iss": ti.srv.URL, "aud": audience, "sub": "repo:acme/shop:ref:refs/heads/main", "exp": now + 300, "iat": now,
		"repository": "acme/shop", "ref": "refs/heads/main", "event_name": "push", "runner_environment": "github-hosted",
	}
	if edit != nil {
		edit(c)
	}
	return c
}

func (ti *testIssuer) sign(claims map[string]any) string {
	return signRS256(map[string]any{"alg": "RS256", "kid": "ci-kid", "typ": "JWT"}, claims, ti.key)
}

func signRS256(header, claims map[string]any, key *rsa.PrivateKey) string {
	input := part(header) + "." + part(claims)
	digest := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	return input + "." + b64(sig)
}

func signHS256(claims map[string]any) string {
	input := part(map[string]any{"alg": "HS256", "kid": "ci-kid"}) + "." + part(claims)
	mac := hmac.New(sha256.New, make([]byte, 32))
	mac.Write([]byte(input))
	return input + "." + b64(mac.Sum(nil))
}

func part(v any) string {
	b, _ := json.Marshal(v)
	return b64(b)
}
