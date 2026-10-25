package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Issuer is one trusted CI OIDC issuer from PM_CI_OIDC_ISSUERS.
type Issuer struct {
	Name, URL, Audience string
}

var issuerName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ParseIssuers reads PM_CI_OIDC_ISSUERS, `<name>=<issuerUrl>,…`, every issuer sharing audience. An issuer
// must be HTTPS unless authDebug is on.
func ParseIssuers(raw, audience string, authDebug bool) ([]Issuer, error) {
	var out []Issuer
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, issuer, _ := strings.Cut(entry, "=")
		name, issuer = strings.TrimSpace(name), strings.TrimSpace(issuer)
		if !strings.Contains(entry, "=") || !issuerName.MatchString(name) || issuer == "" {
			return nil, fmt.Errorf("PM_CI_OIDC_ISSUERS entry '%s' must be '<name>=<issuerUrl>' with name [a-z0-9-]", entry)
		}
		u, err := url.Parse(issuer)
		if err != nil || (u.Scheme != "https" && !(authDebug && u.Scheme == "http")) || u.Host == "" || u.User != nil ||
			strings.ContainsAny(issuer, "?#") {
			return nil, errors.New("PM_CI_OIDC_ISSUERS issuer must be an HTTPS issuer URI")
		}
		if slices.ContainsFunc(out, func(i Issuer) bool { return i.Name == name }) {
			return nil, errors.New("PM_CI_OIDC_ISSUERS names must be unique")
		}
		out = append(out, Issuer{Name: name, URL: issuer, Audience: audience})
	}
	return out, nil
}

// Nimbus's defaults, which the Kotlin verifier ran with; its JWKS timeout is 500 ms to connect plus 500 ms to read.
const (
	clockSkew       = 60 * time.Second
	jwksTTL         = 5 * time.Minute
	jwksMinRefresh  = 30 * time.Second
	jwksSizeLimit   = 50 * 1024
	jwksTimeout     = time.Second
	discoverTimeout = 30 * time.Second
)

// Verifier checks CI OIDC JWTs against the trusted issuers, discovering each issuer's JWKS on first use.
type Verifier struct {
	issuers []Issuer
	http    *http.Client

	mu   sync.Mutex
	keys map[string]*keySource
}

func NewVerifier(issuers []Issuer, client *http.Client) *Verifier {
	return &Verifier{issuers: issuers, http: client, keys: map[string]*keySource{}}
}

func (v *Verifier) configured() bool { return v != nil && len(v.issuers) > 0 }

// untrusted is a token whose iss names no configured issuer; iss is "" when the token has none.
type untrusted struct{ iss string }

func (untrusted) Error() string { return "untrusted issuer" }

// invalid is a token rejected for reason, in Nimbus's wording where Kotlin surfaced it.
type invalid struct{ reason string }

func (e invalid) Error() string { return e.reason }

// token is a parsed compact JWS, before its signature is checked.
type token struct {
	signingInput string
	signature    []byte
	alg, kid     string
	typ          *string
	crit         bool
	claims       map[string]any
}

func parse(jwt string) (*token, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, invalid{"malformed"}
	}
	var header struct {
		Alg  *string         `json:"alg"`
		Kid  *string         `json:"kid"`
		Typ  *string         `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if !decodeJSON(parts[0], &header) || header.Alg == nil || *header.Alg == "" || strings.EqualFold(*header.Alg, "none") {
		return nil, invalid{"malformed"}
	}
	var claims map[string]any
	if !decodeJSON(parts[1], &claims) || claims == nil || !standardClaimsParse(claims) {
		return nil, invalid{"malformed"}
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, invalid{"malformed"}
	}
	t := &token{signingInput: parts[0] + "." + parts[1], signature: sig, alg: *header.Alg, typ: header.Typ, crit: header.Crit != nil, claims: claims}
	if header.Kid != nil {
		t.kid = *header.Kid
	}
	return t, nil
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func decodeJSON(part string, v any) bool {
	raw, err := b64(part)
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v) == nil && !dec.More()
}

// standardClaimsParse is whether Nimbus's JWTClaimsSet.parse accepts the registered claims' types.
func standardClaimsParse(c map[string]any) bool {
	for _, k := range []string{"iss", "sub", "jti"} {
		if v, ok := c[k]; ok && v != nil {
			if _, ok := v.(string); !ok {
				return false
			}
		}
	}
	for _, k := range []string{"exp", "nbf", "iat"} {
		if v, ok := c[k]; ok && v != nil {
			if _, ok := v.(json.Number); !ok {
				return false
			}
		}
	}
	switch aud := c["aud"].(type) {
	case nil, string:
	case []any:
		for _, a := range aud {
			if _, ok := a.(string); !ok {
				return false
			}
		}
	default:
		return false
	}
	return true
}

// Verify checks jwt and returns its issuer and claims. An untrusted error is a token from an issuer not
// configured; an invalid one is any other rejection. Anything else is the issuer's discovery failing.
func (v *Verifier) Verify(ctx context.Context, jwt string) (Issuer, map[string]any, error) {
	t, err := parse(jwt)
	if err != nil {
		return Issuer{}, nil, err
	}
	iss, _ := t.claims["iss"].(string)
	i := slices.IndexFunc(v.issuers, func(c Issuer) bool { return c.URL == iss })
	if iss == "" || i < 0 {
		return Issuer{}, nil, untrusted{iss}
	}
	cfg := v.issuers[i]
	keys, err := v.keySource(ctx, cfg)
	if err != nil {
		return Issuer{}, nil, err
	}
	if t.typ != nil && !strings.EqualFold(*t.typ, "JWT") {
		return cfg, nil, invalid{"JOSE header typ (type) " + *t.typ + " not allowed"}
	}
	if err := v.checkSignature(ctx, t, keys); err != nil {
		return cfg, nil, err
	}
	if err := v.checkClaims(t.claims, cfg); err != nil {
		return cfg, nil, err
	}
	return cfg, t.claims, nil
}

func (v *Verifier) checkSignature(ctx context.Context, t *token, keys *keySource) error {
	if t.alg != "RS256" {
		return invalid{"Signed JWT rejected: Another algorithm expected, or no matching key(s) found"}
	}
	candidates, err := keys.matching(ctx, v, t.kid)
	if err != nil {
		return invalid{err.Error()}
	}
	if len(candidates) == 0 {
		return invalid{"Signed JWT rejected: Another algorithm expected, or no matching key(s) found"}
	}
	// Nimbus understands no critical header parameter, so any crit fails as a bad signature.
	if t.crit {
		return invalid{"Signed JWT rejected: Invalid signature"}
	}
	digest := sha256.Sum256([]byte(t.signingInput))
	for _, k := range candidates {
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], t.signature) == nil {
			return nil
		}
	}
	return invalid{"Signed JWT rejected: Invalid signature"}
}

// checkClaims is Nimbus's DefaultJWTClaimsVerifier in its order, then Kotlin's future-iat check.
func (v *Verifier) checkClaims(c map[string]any, cfg Issuer) error {
	var aud []string
	switch a := c["aud"].(type) {
	case string:
		aud = []string{a}
	case []any:
		for _, s := range a {
			aud = append(aud, s.(string))
		}
	}
	if len(aud) == 0 {
		return invalid{"JWT missing required aud claim"}
	}
	if !slices.Contains(aud, cfg.Audience) {
		return invalid{"JWT aud claim rejected"}
	}
	var missing []string
	for _, k := range []string{"aud", "exp", "iat", "iss", "sub"} {
		if c[k] == nil {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return invalid{"JWT missing required claims: [" + strings.Join(missing, ", ") + "]"}
	}
	now := time.Now()
	if !seconds(c["exp"]).Add(clockSkew).After(now) {
		return invalid{"Expired JWT"}
	}
	if c["nbf"] != nil && !seconds(c["nbf"]).Add(-clockSkew).Before(now) {
		return invalid{"JWT before use time"}
	}
	if seconds(c["iat"]).After(now.Add(clockSkew)) {
		return invalid{"iat in the future"}
	}
	return nil
}

// seconds is a NumericDate claim, truncated to whole seconds as Nimbus reads it.
func seconds(v any) time.Time {
	f, _ := v.(json.Number).Float64()
	return time.Unix(int64(math.Trunc(f)), 0)
}

// keySource is an issuer's JWKS, refetched when stale or when no cached key matches.
type keySource struct {
	jwksURI string

	mu        sync.Mutex
	set       []jose.JSONWebKey
	fetchedAt time.Time
}

// keySource discovers cfg's jwks_uri on first use; a failed discovery is retried on the next token.
func (v *Verifier) keySource(ctx context.Context, cfg Issuer) (*keySource, error) {
	v.mu.Lock()
	ks := v.keys[cfg.URL]
	v.mu.Unlock()
	if ks != nil {
		return ks, nil
	}
	var doc struct {
		Issuer  *string `json:"issuer"`
		JwksURI *string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, strings.TrimRight(cfg.URL, "/")+"/.well-known/openid-configuration", discoverTimeout, &doc); err != nil {
		return nil, fmt.Errorf("CI OIDC discovery: %w", err)
	}
	if doc.Issuer == nil || doc.JwksURI == nil {
		return nil, errors.New("CI OIDC discovery document lacks issuer or jwks_uri")
	}
	if strings.TrimRight(*doc.Issuer, "/") != strings.TrimRight(cfg.URL, "/") {
		return nil, errors.New("CI OIDC discovery issuer mismatch")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys[cfg.URL] == nil {
		v.keys[cfg.URL] = &keySource{jwksURI: *doc.JwksURI}
	}
	return v.keys[cfg.URL], nil
}

// matching is the RSA signing keys under kid (any kid when kid is empty).
func (ks *keySource) matching(ctx context.Context, v *Verifier, kid string) ([]*rsa.PublicKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	now := time.Now()
	if ks.set == nil || now.Sub(ks.fetchedAt) >= jwksTTL {
		if err := ks.fetch(ctx, v); err != nil {
			return nil, err
		}
	}
	keys := match(ks.set, kid)
	if len(keys) == 0 && now.Sub(ks.fetchedAt) >= jwksMinRefresh {
		if err := ks.fetch(ctx, v); err != nil {
			return nil, err
		}
		keys = match(ks.set, kid)
	}
	return keys, nil
}

func (ks *keySource) fetch(ctx context.Context, v *Verifier) error {
	var set jose.JSONWebKeySet
	if err := v.getJSON(ctx, ks.jwksURI, jwksTimeout, &set); err != nil {
		return fmt.Errorf("Couldn't retrieve JWK set from URL: %w", err)
	}
	ks.set, ks.fetchedAt = set.Keys, time.Now()
	return nil
}

func match(set []jose.JSONWebKey, kid string) []*rsa.PublicKey {
	var out []*rsa.PublicKey
	for _, k := range set {
		pub, ok := k.Key.(*rsa.PublicKey)
		if !ok || (kid != "" && k.KeyID != kid) || (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != "RS256") {
			continue
		}
		out = append(out, pub)
	}
	return out
}

func (v *Verifier) getJSON(ctx context.Context, u string, timeout time.Duration, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksSizeLimit+1))
	if err != nil {
		return err
	}
	if len(body) > jwksSizeLimit {
		return fmt.Errorf("%s answered more than %d bytes", u, jwksSizeLimit)
	}
	return json.Unmarshal(body, out)
}
