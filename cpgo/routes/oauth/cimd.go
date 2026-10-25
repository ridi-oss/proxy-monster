package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Client is a client ID metadata document, with Kotlin's defaults for the fields it may omit.
type Client struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// Resolver fetches the metadata document a client_id names.
type Resolver interface {
	Resolve(ctx context.Context, clientID string) (*Client, error)
}

const maxDocumentBytes = 5 * 1024

// HTTPResolver fetches the document over HTTPS, pinned to the addresses it checked.
type HTTPResolver struct {
	// AllowSpecialUse lets a client_id resolve to loopback and private addresses, as under PM_AUTH_DEBUG.
	AllowSpecialUse bool
	// RootCAs replaces the system roots when set.
	RootCAs *x509.CertPool
}

func (h HTTPResolver) Resolve(ctx context.Context, clientID string) (*Client, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path == "" || u.User != nil ||
		strings.Contains(clientID, "#") || slices.ContainsFunc(strings.Split(u.Path, "/"), func(s string) bool { return s == "." || s == ".." }) {
		return nil, errors.New("client_id must be an HTTPS metadata-document URL with a path and no userinfo, dot segments, or fragment")
	}
	addrs, err := lookup(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	if !h.AllowSpecialUse && slices.ContainsFunc(addrs, specialUse) {
		return nil, errors.New("client metadata resolves to a special-use address")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	// Dial only the addresses that passed the check, so a rebinding answer cannot reach localhost.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: h.RootCAs},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var last error
				for _, a := range addrs {
					c, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
					if err == nil {
						return c, nil
					}
					last = err
				}
				return nil, last
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("client metadata answered %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil ||
		!(mt == "application/json" || strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json")) {
		return nil, errors.New("client metadata must be JSON")
	}
	if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil && n > maxDocumentBytes {
		return nil, errors.New("client metadata is too large")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDocumentBytes {
		return nil, errors.New("client metadata is too large")
	}
	c := Client{GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none"}
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, err
	}
	switch {
	case c.ClientID != clientID:
		return nil, errors.New("client metadata client_id mismatch")
	case strings.TrimSpace(c.ClientName) == "":
		return nil, errors.New("client metadata client_name is required")
	case len(c.RedirectURIs) == 0 || slices.ContainsFunc(c.RedirectURIs, func(s string) bool { return strings.TrimSpace(s) == "" }):
		return nil, errors.New("client metadata redirect_uris is required")
	}
	for _, r := range c.RedirectURIs {
		if _, err := redirectURI(r); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("client metadata host did not resolve")
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	return ips, nil
}

var specialUseRanges = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
		// Java's isSiteLocalAddress also covers the deprecated IPv6 site-local range.
		"fec0::/10",
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

func specialUse(a netip.Addr) bool {
	return slices.ContainsFunc(specialUseRanges, func(p netip.Prefix) bool { return p.Contains(a) })
}

// redirectURI accepts an absolute HTTPS URI, or HTTP to a loopback host (OAuth 2.1 native clients).
func redirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("redirect_uri is invalid")
	}
	if u.Scheme == "" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") {
		return nil, errors.New("redirect_uri must be an absolute URI with a host and no userinfo or fragment")
	}
	https := strings.EqualFold(u.Scheme, "https")
	loopbackHTTP := strings.EqualFold(u.Scheme, "http") && loopbackHost(u.Hostname())
	if !https && !loopbackHTTP {
		return nil, errors.New("redirect_uri must use HTTPS unless it targets localhost")
	}
	return u, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || host == "::1" {
		return true
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 || octets[0] != "127" {
		return false
	}
	for _, o := range octets {
		if n, err := strconv.Atoi(o); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// validate checks an authorization request against the client's metadata.
func (c *Client) validate(redirect string, scopes []string) error {
	if !slices.ContainsFunc(c.RedirectURIs, func(d string) bool { return redirectMatches(redirect, d) }) {
		return errors.New("redirect_uri is not registered")
	}
	if _, err := redirectURI(redirect); err != nil {
		return err
	}
	switch {
	case !slices.Contains(c.ResponseTypes, "code"):
		return errors.New("client does not support response_type=code")
	case !slices.Contains(c.GrantTypes, "authorization_code"):
		return errors.New("client does not support authorization_code")
	case c.TokenEndpointAuthMethod != "none":
		return errors.New("only public clients are supported")
	}
	if declared := strings.Fields(c.Scope); len(declared) > 0 {
		for _, s := range scopes {
			if !slices.Contains(declared, s) {
				return errors.New("requested scope is not declared by client metadata")
			}
		}
	}
	return nil
}

// redirectMatches is exact, except that a portless loopback HTTP redirect matches any port (RFC 8252 §7.3):
// a native client binds its listener to a port chosen at launch, so its metadata can only declare none.
func redirectMatches(requested, declared string) bool {
	if requested == declared {
		return true
	}
	r, err1 := url.Parse(requested)
	d, err2 := url.Parse(declared)
	if err1 != nil || err2 != nil || !strings.EqualFold(d.Scheme, "http") || d.Hostname() == "" || d.Port() != "" ||
		!loopbackHost(d.Hostname()) {
		return false
	}
	return strings.EqualFold(r.Scheme, "http") && strings.EqualFold(r.Hostname(), d.Hostname()) &&
		r.Path == d.Path && r.RawQuery == d.RawQuery && r.ForceQuery == d.ForceQuery
}
