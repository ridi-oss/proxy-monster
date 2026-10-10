// Package fakeidp is an OIDC provider for tests: discovery, JWKS, and a token endpoint that signs RS256
// id_tokens for codes and refresh tokens the test registers.
package fakeidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Identity is who a code or refresh token signs in as.
type Identity struct {
	Subject string
	Email   string
	Groups  []string
	// Audience replaces the client id as the aud claim, with the client id as azp.
	Audience []string
}

// Refresh is how the token endpoint answers a refresh token.
type Refresh struct {
	Identity *Identity
	// Error is an OAuth error code (invalid_grant, invalid_client) answered with 400.
	Error string
	// Rotate is a new refresh token to return.
	Rotate string
	// Nonce is put in the refreshed id_token, as some providers repeat the login's.
	Nonce string
}

type grant struct {
	identity Identity
	nonce    string
	refresh  string
}

// IdP is a running fake provider.
type IdP struct {
	*httptest.Server
	ClientID, ClientSecret string
	// Issuer is what discovery and id_tokens name; the server URL unless a test overrides it.
	Issuer string
	key    *rsa.PrivateKey

	mu        sync.Mutex
	codes     map[string]grant
	refreshes map[string]Refresh
	// Forms are the token requests received, in order.
	Forms []map[string]string
}

func New(t *testing.T) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{ClientID: "pm-client", ClientSecret: "pm-secret", key: key, codes: map[string]grant{}, refreshes: map[string]Refresh{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.Issuer, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
			"jwks_uri": p.URL + "/jwks", "code_challenge_methods_supported": []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewServer(mux)
	p.Issuer = p.URL
	t.Cleanup(p.Close)
	return p
}

// Code registers an authorization code that signs in as id, echoing nonce, and returns refresh (if any).
func (p *IdP) Code(code string, id Identity, nonce, refresh string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[code] = grant{id, nonce, refresh}
}

// OnRefresh sets how a refresh token is answered.
func (p *IdP) OnRefresh(token string, r Refresh) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshes[token] = r
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := map[string]string{}
	for k := range r.PostForm {
		form[k] = r.PostForm.Get(k)
	}
	p.mu.Lock()
	p.Forms = append(p.Forms, form)
	defer p.mu.Unlock()
	fail := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if form["client_id"] != p.ClientID || form["client_secret"] != p.ClientSecret {
		fail("invalid_client")
		return
	}
	out := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300}
	switch form["grant_type"] {
	case "authorization_code":
		g, ok := p.codes[form["code"]]
		if !ok {
			fail("invalid_grant")
			return
		}
		delete(p.codes, form["code"])
		out["id_token"] = p.sign(g.identity, g.nonce)
		if g.refresh != "" {
			out["refresh_token"] = g.refresh
		}
	case "refresh_token":
		rf, ok := p.refreshes[form["refresh_token"]]
		if !ok || rf.Error != "" {
			code := rf.Error
			if code == "" {
				code = "invalid_grant"
			}
			fail(code)
			return
		}
		if rf.Identity != nil {
			out["id_token"] = p.sign(*rf.Identity, rf.Nonce)
		}
		if rf.Rotate != "" {
			out["refresh_token"] = rf.Rotate
		}
	default:
		fail("unsupported_grant_type")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// sign issues an RS256 id_token for id; an empty email or nonce leaves that claim out.
func (p *IdP) sign(id Identity, nonce string) string {
	return p.Sign(jose.RS256, id, nonce, time.Time{})
}

// Sign issues an id_token with alg, valid from notBefore when that is set.
func (p *IdP) Sign(alg jose.SignatureAlgorithm, id Identity, nonce string, notBefore time.Time) string {
	now := time.Now()
	claims := map[string]any{"iss": p.Issuer, "aud": p.ClientID, "sub": id.Subject, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	if id.Audience != nil {
		claims["aud"], claims["azp"] = id.Audience, p.ClientID
	}
	if id.Email != "" {
		claims["email"] = id.Email
	}
	if id.Groups != nil {
		claims["groups"] = id.Groups
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if !notBefore.IsZero() {
		claims["nbf"] = notBefore.Unix()
	}
	payload, _ := json.Marshal(claims)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	jws, _ := signer.Sign(payload)
	token, _ := jws.CompactSerialize()
	return token
}
