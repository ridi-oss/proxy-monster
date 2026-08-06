package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// The embedded fake IdP the ported suites run against.
//
// The Kotlin suites use `embeddedServer(Netty, port = ServerSocket(0).localPort)` and a real loopback
// socket, because Nimbus's RemoteJWKSet does its own raw HTTP outside the injected client
// (IdTokenValidatorTest's KDoc says so). Go's httptest.Server is the same thing with the port
// bookkeeping removed — a real socket on 127.0.0.1, which is what the JWKS fetch needs.
//
// D16 — the signed-JWT builder is go-jose/v4, the SAME dependency the production validator uses
// (99-library-decisions.md §1). One JOSE dependency, not two.

// fakeIdP serves `/.well-known/openid-configuration` and `/jwks`, and counts requests to each.
type fakeIdP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	// discoveryHits / jwksHits back OidcDiscoveryTest case 4's `AtomicInteger` and the
	// no-JWKS-cache assertion F36 requires.
	discoveryHits atomic.Int64
	jwksHits      atomic.Int64

	// mux is exposed so a suite can add routes (a /token endpoint, a second issuer path).
	mux *http.ServeMux
}

// newFakeIdP starts the server and generates one 2048-bit RSA key, matching
// `RSAKeyGenerator(2048).keyID(kid).generate()`.
func newFakeIdP(t *testing.T, kid string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	idp := &fakeIdP{t: t, key: key, kid: kid, mux: http.NewServeMux()}
	idp.server = httptest.NewServer(idp.mux)
	t.Cleanup(idp.server.Close)

	idp.mux.HandleFunc("GET "+WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		idp.discoveryHits.Add(1)
		idp.writeJSON(w, map[string]any{
			"issuer":                 idp.issuer(),
			"authorization_endpoint": idp.issuer() + "/authorize",
			"token_endpoint":         idp.issuer() + "/token",
			"userinfo_endpoint":      idp.issuer() + "/userinfo",
			"jwks_uri":               idp.issuer() + "/jwks",
			// Parsed by discovery and NEVER used — INV-A4-44 says the CP does not run the RFC 8628
			// client side against the IdP. Served here only so case 1 can assert it round-trips.
			"device_authorization_endpoint": idp.issuer() + "/device/authorize",
		})
	})
	idp.mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.jwksHits.Add(1)
		idp.writeJSON(w, idp.publicJWKS())
	})
	return idp
}

func (f *fakeIdP) issuer() string { return f.server.URL }

func (f *fakeIdP) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("fake IdP write: %v", err)
	}
}

func (f *fakeIdP) publicJWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &f.key.PublicKey,
		KeyID:     f.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
}

// claimsOpts mirrors IdTokenValidatorTest's `claims(...)` helper defaults exactly, so each ported case
// changes the same single field the Kotlin case changes.
type claimsOpts struct {
	subject          string
	audience         any // string, []any, or nil to omit
	issuer           string
	expiresInSeconds int64
	nonce            any // nil omits the claim; a non-string value exercises the safe cast
	email            any
	groups           any // nil omits; a non-list value is the F24 case
	omitSubject      bool
}

func (f *fakeIdP) defaultClaims(clientID string) claimsOpts {
	return claimsOpts{
		subject:          "user-123",
		audience:         clientID,
		issuer:           f.issuer(),
		expiresInSeconds: 300,
		nonce:            "the-nonce",
		email:            "alice@example.com",
		groups:           []any{"engineering", "eng-leads"},
	}
}

// sign builds and RS256-signs an id_token. key defaults to the IdP's own.
func (f *fakeIdP) sign(o claimsOpts, key *rsa.PrivateKey) string {
	f.t.Helper()
	if key == nil {
		key = f.key
	}
	claims := map[string]any{
		"iss": o.issuer,
		"exp": time.Now().Add(time.Duration(o.expiresInSeconds) * time.Second).Unix(),
	}
	if !o.omitSubject {
		claims["sub"] = o.subject
	}
	if o.audience != nil {
		claims["aud"] = o.audience
	}
	if o.nonce != nil {
		claims["nonce"] = o.nonce
	}
	if o.email != nil {
		claims["email"] = o.email
	}
	if o.groups != nil {
		claims["groups"] = o.groups
	}
	return signClaims(f.t, key, f.kid, claims)
}

// signClaims is the raw signer, exposed so a suite can sign a claim set this helper cannot express
// (an `alg: none` token, a claim map built by hand).
func signClaims(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized
}

// validatorFor wires a real Discovery + IDTokenValidator against the fake IdP, exactly as
// IdTokenValidatorTest's @BeforeAll does.
func (f *fakeIdP) validatorFor(clientID string) *IDTokenValidator {
	hc := NewHTTPClient()
	d := NewDiscovery(hc, f.issuer())
	return NewIDTokenValidator(d, f.issuer(), clientID, hc, discardLogger())
}

// nowPlus renders a NumericDate `exp` claim n seconds from now.
func nowPlus(n int64) int64 { return time.Now().Add(time.Duration(n) * time.Second).Unix() }

// hs256 builds an HS256-signed JWT with `secret` as the MAC key — the algorithm-confusion attack
// payload. It is hand-rolled rather than built with go-jose because go-jose refuses to sign with a
// key type that does not match the requested algorithm family, which is the very thing under test on
// the VERIFY side.
func hs256(t *testing.T, secret, payload []byte) string {
	t.Helper()
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signingInput := b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil))
}
