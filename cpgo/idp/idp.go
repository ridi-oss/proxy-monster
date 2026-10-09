// Package idp is the control plane's OIDC relying party: discovery, the authorization-code exchange,
// id_token validation, the refresh grant the liveness recheck uses, and JIT directory provisioning.
package idp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Config is the OIDC client, read from the same environment as the Kotlin control plane.
type Config struct {
	Issuer, ClientID, ClientSecret, RedirectURI, Scopes string
	Groups                                              GroupMapping
	// RecheckInterval is how stale a session's IdP check may get before the sweep refreshes it.
	RecheckInterval time.Duration
}

// ConfigFromEnv is nil when any of the four required PM_OIDC_* settings is missing.
func ConfigFromEnv() (*Config, error) {
	c := &Config{
		Issuer: os.Getenv("PM_OIDC_ISSUER"), ClientID: os.Getenv("PM_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("PM_OIDC_CLIENT_SECRET"), RedirectURI: os.Getenv("PM_OIDC_REDIRECT_URI"),
		Scopes: "openid profile email groups offline_access", RecheckInterval: 300 * time.Second,
		Groups: ParseGroupMapping(os.Getenv("PM_OIDC_GROUP_MAP"), os.Getenv("PM_OIDC_GROUP_PREFIX")),
	}
	if v, ok := os.LookupEnv("PM_OIDC_SCOPES"); ok {
		c.Scopes = v
	}
	if v := os.Getenv("PM_IDP_RECHECK_INTERVAL"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("PM_IDP_RECHECK_INTERVAL must be a positive number of seconds: %q", v)
		}
		c.RecheckInterval = time.Duration(n) * time.Second
	}
	if c.Issuer == "" || c.ClientID == "" || c.ClientSecret == "" || c.RedirectURI == "" {
		return nil, nil
	}
	return c, nil
}

// OfflineAccess is whether the configured scopes ask for a refresh token worth keeping.
func (c Config) OfflineAccess() bool {
	for _, s := range strings.Fields(c.Scopes) {
		if s == "offline_access" {
			return true
		}
	}
	return false
}

// GroupMapping turns IdP group names into local group names.
type GroupMapping struct {
	Map    map[string]string
	Prefix string
}

// ParseGroupMapping reads "idp=local,…"; an entry without "=" or with a blank side is dropped.
func ParseGroupMapping(mapEnv, prefix string) GroupMapping {
	g := GroupMapping{Map: map[string]string{}, Prefix: prefix}
	for _, entry := range strings.Split(mapEnv, ",") {
		idpName, local, ok := strings.Cut(entry, "=")
		idpName, local = strings.TrimSpace(idpName), strings.TrimSpace(local)
		if ok && idpName != "" && local != "" {
			g.Map[idpName] = local
		}
	}
	return g
}

// Resolve maps each IdP group: an exact map entry wins, else the prefix is stripped; an unmapped name
// that would claim a system: group is dropped. Order is kept and duplicates removed.
func (g GroupMapping) Resolve(groups []string) []string {
	var out []string
	for _, group := range groups {
		name, ok := g.Map[group]
		if !ok {
			name = group
			if g.Prefix != "" {
				name = strings.TrimPrefix(group, g.Prefix)
			}
			if strings.TrimSpace(name) == "" || strings.HasPrefix(strings.ToLower(name), "system:") {
				continue
			}
		}
		if !contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Crypto encrypts stored refresh tokens with PM_RESULT_KEY: a 12-byte IV, then AES-256-GCM ciphertext.
type Crypto struct{ aead cipher.AEAD }

// CryptoFromEnv is nil when PM_RESULT_KEY is unset, so no refresh token is stored.
func CryptoFromEnv() (*Crypto, error) {
	raw := os.Getenv("PM_RESULT_KEY")
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("PM_RESULT_KEY must be base64 of 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	return &Crypto{aead}, err
}

func (c *Crypto) Encrypt(plain string) []byte {
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	return c.aead.Seal(iv, iv, []byte(plain), nil)
}

func (c *Crypto) Decrypt(blob []byte) (string, error) {
	if len(blob) <= 12 {
		return "", errors.New("ciphertext too short")
	}
	plain, err := c.aead.Open(nil, blob[:12], blob[12:], nil)
	return string(plain), err
}

// Claims are what a login takes from a validated id_token.
type Claims struct {
	Subject string
	Email   *string
	Groups  []string
}

// Principal is the email when the IdP sends one, else the subject.
func (c Claims) Principal() string {
	if c.Email != nil {
		return *c.Email
	}
	return c.Subject
}

// Provider is the IdP, discovered on first use.
type Provider struct {
	cfg  Config
	http *http.Client

	mu        sync.Mutex
	discovery *oidc.DiscoveryConfiguration
	keys      oidc.KeySet
}

func NewProvider(cfg Config) *Provider {
	return &Provider{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

func (p *Provider) Config() Config { return p.cfg }

// Discovery is the issuer's discovery document, cached after the first success; its issuer must be ours.
func (p *Provider) Discovery(ctx context.Context) (*oidc.DiscoveryConfiguration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.discovery != nil {
		return p.discovery, nil
	}
	d, err := client.Discover(ctx, p.cfg.Issuer, p.http)
	if err != nil {
		return nil, err
	}
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(p.cfg.Issuer, "/") {
		return nil, errors.New("OIDC discovery issuer mismatch")
	}
	p.discovery, p.keys = d, rp.NewRemoteKeySet(p.http, d.JwksURI)
	return d, nil
}

// SupportsS256 is whether discovery advertises S256 PKCE.
func (p *Provider) SupportsS256(d *oidc.DiscoveryConfiguration) bool {
	for _, m := range d.CodeChallengeMethodsSupported {
		if strings.EqualFold(string(m), "S256") {
			return true
		}
	}
	return false
}

// AuthorizeURL is the authorization endpoint with Kotlin's parameter order.
func (p *Provider) AuthorizeURL(d *oidc.DiscoveryConfiguration, state, nonce, challenge string) string {
	q := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	u := d.AuthorizationEndpoint + "?client_id=" + q(p.cfg.ClientID) + "&response_type=code&scope=" + q(p.cfg.Scopes) +
		"&redirect_uri=" + q(p.cfg.RedirectURI) + "&state=" + q(state) + "&nonce=" + q(nonce)
	if challenge != "" {
		u += "&code_challenge=" + q(challenge) + "&code_challenge_method=S256"
	}
	return u
}

type tokenCaller struct {
	endpoint string
	http     *http.Client
}

func (t tokenCaller) TokenEndpoint() string    { return t.endpoint }
func (t tokenCaller) HttpClient() *http.Client { return t.http }

type codeRequest struct {
	GrantType    string `schema:"grant_type"`
	Code         string `schema:"code"`
	RedirectURI  string `schema:"redirect_uri"`
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
	CodeVerifier string `schema:"code_verifier,omitempty"`
}

type refreshRequest struct {
	GrantType    string `schema:"grant_type"`
	RefreshToken string `schema:"refresh_token"`
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
}

// Exchange redeems an authorization code, returning the id_token and refresh token (possibly empty).
func (p *Provider) Exchange(ctx context.Context, code, verifier string) (idToken, refresh string, err error) {
	d, err := p.Discovery(ctx)
	if err != nil {
		return "", "", err
	}
	tok, err := client.CallTokenEndpoint(ctx, codeRequest{"authorization_code", code, p.cfg.RedirectURI, p.cfg.ClientID, p.cfg.ClientSecret, verifier},
		tokenCaller{d.TokenEndpoint, p.http})
	if err != nil {
		return "", "", err
	}
	idToken, _ = tok.Extra("id_token").(string)
	if idToken == "" {
		return "", "", errors.New("token response has no id_token")
	}
	return idToken, tok.RefreshToken, nil
}

// Validate verifies an id_token's RS256 signature, issuer, audience and expiry, and its nonce when
// nonce is not empty.
func (p *Provider) Validate(ctx context.Context, idToken, nonce string) (*Claims, error) {
	if _, err := p.Discovery(ctx); err != nil {
		return nil, err
	}
	v := rp.NewIDTokenVerifier(p.cfg.Issuer, p.cfg.ClientID, p.keys,
		rp.WithNonce(func(context.Context) string { return nonce }), rp.WithSupportedSigningAlgorithms("RS256"))
	if nonce == "" {
		// The verifier otherwise demands an empty nonce claim; a refreshed id_token may still carry the login's.
		v.Nonce = nil
	}
	claims, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, idToken, v)
	if err != nil {
		return nil, err
	}
	// Nimbus accepts exactly our client id as the audience, not a list that merely contains it.
	if len(claims.Audience) != 1 {
		return nil, errors.New("id_token audience is not exactly the client id")
	}
	if nbf := claims.NotBefore.AsTime(); !nbf.IsZero() && nbf.After(time.Now().Add(v.Offset)) {
		return nil, errors.New("id_token is not valid yet")
	}
	out := &Claims{Subject: claims.Subject}
	if email, ok := claims.Claims["email"].(string); ok {
		out.Email = &email
	}
	if groups, ok := claims.Claims["groups"].([]any); ok {
		for _, g := range groups {
			if s, ok := g.(string); ok {
				out.Groups = append(out.Groups, s)
			}
		}
	}
	return out, nil
}

// RefreshOutcome is a refresh grant's verdict on one session.
type RefreshOutcome struct {
	// Inactive is set when the IdP answered invalid_grant: the refresh token or the account is gone.
	Inactive bool
	// Rotated is the new refresh token, when the IdP rotated it.
	Rotated string
	IDToken string
}

// Refresh runs the refresh grant. Only invalid_grant is Inactive; anything else that fails is an error,
// so a transient IdP or configuration problem never ends a session.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (RefreshOutcome, error) {
	d, err := p.Discovery(ctx)
	if err != nil {
		return RefreshOutcome{}, err
	}
	tok, err := client.CallTokenEndpoint(ctx, refreshRequest{"refresh_token", refreshToken, p.cfg.ClientID, p.cfg.ClientSecret},
		tokenCaller{d.TokenEndpoint, p.http})
	var oe *oidc.Error
	if errors.As(err, &oe) && oe.ErrorType == oidc.InvalidGrant {
		return RefreshOutcome{Inactive: true}, nil
	}
	if err != nil {
		return RefreshOutcome{}, err
	}
	if tok.AccessToken == "" {
		return RefreshOutcome{}, errors.New("refresh response has no access_token")
	}
	idToken, _ := tok.Extra("id_token").(string)
	return RefreshOutcome{Rotated: tok.RefreshToken, IDToken: idToken}, nil
}
