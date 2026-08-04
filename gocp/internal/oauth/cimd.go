package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------------
// A11 §7 — Client ID Metadata Documents, SSRF-hardened
// ---------------------------------------------------------------------------------------------

// CimdClientMetadata is `@Serializable data class CimdClientMetadata` (Cimd.kt:18-27).
//
// Three fields are required and four carry Kotlin defaults; [CimdClientMetadata.UnmarshalJSON]
// reproduces both halves, because encoding/json would zero-fill the required ones (turning a document
// with no `client_id` into one whose client_id is "", which then fails the equality check with a
// confusing message) and would leave the defaulted ones EMPTY (turning an omitted `response_types`
// into a client that supports nothing, so every real CIMD document would be rejected).
type CimdClientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// UnmarshalJSON applies Cimd.kt:23-26's four default arguments and enforces the three required
// fields. `ignoreUnknownKeys = true` (Cimd.kt:104) is encoding/json's default, so nothing is needed
// for it.
func (m *CimdClientMetadata) UnmarshalJSON(b []byte) error {
	var raw struct {
		ClientID                *string  `json:"client_id"`
		ClientName              *string  `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method"`
		Scope                   *string  `json:"scope"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.ClientID == nil {
		return errors.New("client metadata is missing required field client_id")
	}
	if raw.ClientName == nil {
		return errors.New("client metadata is missing required field client_name")
	}
	if raw.RedirectURIs == nil {
		return errors.New("client metadata is missing required field redirect_uris")
	}
	m.ClientID, m.ClientName, m.RedirectURIs = *raw.ClientID, *raw.ClientName, raw.RedirectURIs
	m.GrantTypes = raw.GrantTypes
	if m.GrantTypes == nil {
		m.GrantTypes = []string{"authorization_code"}
	}
	m.ResponseTypes = raw.ResponseTypes
	if m.ResponseTypes == nil {
		m.ResponseTypes = []string{"code"}
	}
	m.TokenEndpointAuthMethod = "none"
	if raw.TokenEndpointAuthMethod != nil {
		m.TokenEndpointAuthMethod = *raw.TokenEndpointAuthMethod
	}
	m.Scope = ""
	if raw.Scope != nil {
		m.Scope = *raw.Scope
	}
	return nil
}

// CimdResolver is `fun interface CimdResolver` (Cimd.kt:29-31). One method, so a test can pass a
// literal function.
type CimdResolver interface {
	Resolve(ctx context.Context, clientID string) (*CimdClientMetadata, error)
}

// CimdResolverFunc adapts a plain function to [CimdResolver] — Kotlin's SAM conversion.
type CimdResolverFunc func(ctx context.Context, clientID string) (*CimdClientMetadata, error)

// Resolve implements CimdResolver.
func (f CimdResolverFunc) Resolve(ctx context.Context, clientID string) (*CimdClientMetadata, error) {
	return f(ctx, clientID)
}

// The three timeouts (Cimd.kt:80-82) and the document cap (Cimd.kt:103).
const (
	cimdConnectTimeout   = 2 * time.Second
	cimdRequestTimeout   = 5 * time.Second
	cimdSocketTimeout    = 5 * time.Second
	cimdMaxDocumentBytes = 5 * 1024
)

// HTTPCimdResolver is `class HttpCimdResolver(productionChecks, clientFactory)` (Cimd.kt:33-114).
//
// 🔒 The eight defences, in the order Cimd.kt applies them:
//
//  1. `client_id` must be HTTPS, have a host, a non-blank path, no userinfo, no fragment and NO
//     `.`/`..` path segments.
//  2. The host must resolve to at least one address.
//  3. Under [HTTPCimdResolver.ProductionChecks], NO address may be special-use — see [isSpecialUse].
//  4. 🔒 THE HTTP CLIENT IS DNS-PINNED TO THE ADDRESSES THAT PASSED STEP 3.
//  5. Redirects disabled.
//  6. Timeouts: connect 2s, request 5s, socket 5s.
//  7. Content-Type must be `application/json` or `application/*+json`.
//  8. 5 KiB cap, enforced on Content-Length AND by reading MAX+1 bytes.
//
// 🔒 INV-A11-25 — STEPS 3 AND 4 ARE ONE DEFENCE, NOT TWO. Verbatim from Cimd.kt:50-51: "Leaving DNS
// resolution to the HTTP engine would create a check/use gap in which a rebinding answer could reach
// localhost." A Go port MUST dial the vetted IPs through a custom DialContext; pre-checking and then
// calling http.Get leaves the gap wide open. [HTTPCimdResolver.pinnedClient] is that dialer and
// TestTheHTTPClientIsPinnedToTheVettedAddresses is the pin.
//
// 🔒 INV-A11-26 — redirects are disabled because a followed redirect would re-resolve and escape the
// pin. The Kotlin disables them at BOTH layers (Ktor `followRedirects = false` plus OkHttp's
// `followRedirects(false)` / `followSslRedirects(false)`); Go has one layer, so the CheckRedirect hook
// below is joined by the explicit 2xx status check that reproduces Ktor's `expectSuccess = true`.
//
// INV-A11-27 — the size cap is enforced TWICE because `Content-Length` is advisory; the read-MAX+1
// check is the real bound.
type HTTPCimdResolver struct {
	// ProductionChecks is `productionChecks = !config.authDebug` (OAuthRoutes.kt:109), so a dev box
	// can point at localhost metadata. It gates step 3 ONLY — the DNS pin, the redirect ban, the
	// timeouts and the size cap apply in every mode.
	ProductionChecks bool

	// LookupIP is `InetAddress.getAllByName(host)`, as a seam so a suite can vet an address set
	// without owning DNS. Nil uses the system resolver.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)

	// ClientFactory is Cimd.kt:35's `clientFactory: ((String, List<InetAddress>) -> HttpClient)?`.
	// Nil uses [HTTPCimdResolver.pinnedClient].
	ClientFactory func(host string, addrs []net.IP) *http.Client

	// TLSConfig is handed to the DEFAULT pinned client, so a suite can trust an httptest certificate
	// while still exercising the real DNS-pinned DialContext. Overriding ClientFactory instead would
	// test the fake dialer, which is the one thing INV-A11-25 is about.
	TLSConfig *tls.Config
}

// NewHTTPCimdResolver is `HttpCimdResolver(productionChecks = !config.authDebug)`.
func NewHTTPCimdResolver(productionChecks bool) *HTTPCimdResolver {
	return &HTTPCimdResolver{ProductionChecks: productionChecks}
}

// Resolve is `HttpCimdResolver.resolve(clientId)` (Cimd.kt:37-74).
//
// Every failure is an error; A11's routes turn any error from here into `400 invalid_client` and
// never surface the message, so the messages are the Kotlin's `require` messages verbatim only for
// log and test legibility.
func (r *HTTPCimdResolver) Resolve(ctx context.Context, clientID string) (*CimdClientMetadata, error) {
	// ---- 1. the client_id shape --------------------------------------------------------------
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("client_id is not a valid URI: %w", err)
	}
	if !isSafeCimdURL(clientID, u) {
		return nil, errors.New(
			"client_id must be an HTTPS metadata-document URL with a path and no userinfo, dot segments, or fragment")
	}
	host := u.Hostname()

	// ---- 2. the host must resolve ------------------------------------------------------------
	addrs, err := r.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("client metadata host did not resolve: %w", err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("client metadata host did not resolve")
	}

	// ---- 3. no special-use address -----------------------------------------------------------
	if r.ProductionChecks {
		for _, ip := range addrs {
			if isSpecialUse(ip) {
				return nil, errors.New("client metadata resolves to a special-use address")
			}
		}
	}

	// ---- 4-6. the pinned, redirect-free, timeout-bounded client ------------------------------
	client := r.pinnedClient(host, addrs)
	if r.ClientFactory != nil {
		client = r.ClientFactory(host, addrs)
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
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10)); _ = resp.Body.Close() }()

	// Ktor's `expectSuccess = true`: a 3xx (the redirect this client refused to follow), a 4xx or a
	// 5xx all raise. This is the second half of INV-A11-26 — without it a 302 would fall through to
	// the content-type check and report the wrong reason.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("client metadata request failed with status %d", resp.StatusCode)
	}

	// ---- 7. JSON content type ----------------------------------------------------------------
	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil, errors.New("client metadata must be JSON")
	}

	// ---- 8. the size cap, twice --------------------------------------------------------------
	if raw := resp.Header.Get("Content-Length"); raw != "" {
		// `?.toLongOrNull()?.let { require(it <= MAX) }` — an unparseable header is IGNORED, not an
		// error, exactly as the Kotlin's null-safe chain is.
		if n, convErr := strconv.ParseInt(raw, 10, 64); convErr == nil && n > cimdMaxDocumentBytes {
			return nil, errors.New("client metadata is too large")
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > cimdMaxDocumentBytes {
		return nil, errors.New("client metadata is too large")
	}

	var metadata CimdClientMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, err
	}
	if metadata.ClientID != clientID {
		return nil, errors.New("client metadata client_id mismatch")
	}
	if isBlankKotlin(metadata.ClientName) {
		return nil, errors.New("client metadata client_name is required")
	}
	if len(metadata.RedirectURIs) == 0 {
		return nil, errors.New("client metadata redirect_uris is required")
	}
	for _, uri := range metadata.RedirectURIs {
		if isBlankKotlin(uri) {
			return nil, errors.New("client metadata redirect_uris is required")
		}
	}
	for _, uri := range metadata.RedirectURIs {
		if _, err := ValidatedRedirectURI(uri); err != nil {
			return nil, err
		}
	}
	return &metadata, nil
}

func (r *HTTPCimdResolver) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if r.LookupIP != nil {
		return r.LookupIP(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// pinnedClient is `private fun pinnedClient(host, addresses)` (Cimd.kt:76-96).
//
// 🔒 INV-A11-25 lives in the DialContext: a connection to `host` (at whatever port the URL names) is
// dialled against the VETTED addresses and never re-resolved. Any other host — which cannot happen,
// since redirects are refused — falls through to the system resolver, matching the Kotlin's
// `if (hostname.equals(host, ignoreCase = true)) addresses else Dns.SYSTEM.lookup(hostname)`.
//
// TLS still verifies the CERTIFICATE against the hostname: Go's transport takes the ServerName from
// the request URL, not from the dialled address, so pinning the address does not weaken the name
// check.
//
// ⚠️ DEVIATION — `Proxy` is nil rather than [http.ProxyFromEnvironment]. OkHttp's default honours a
// system proxy, and a proxied request would be dialled to the PROXY, defeating the pin entirely. The
// Kotlin inherits that hole from its engine default; reproducing it here would knowingly reintroduce
// the check/use gap INV-A11-25 exists to close, so the port refuses the proxy instead. Recorded as a
// deliberate divergence, not an oversight.
func (r *HTTPCimdResolver) pinnedClient(host string, addrs []net.IP) *http.Client {
	dialer := &net.Dialer{Timeout: cimdConnectTimeout}
	pinned := append([]net.IP(nil), addrs...)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, port, err := net.SplitHostPort(addr)
			if err != nil || !strings.EqualFold(h, host) {
				return dialer.DialContext(ctx, network, addr)
			}
			var lastErr error = errors.New("client metadata host has no vetted address")
			for _, ip := range pinned {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
		TLSClientConfig:       r.TLSConfig,
		TLSHandshakeTimeout:   cimdConnectTimeout,
		ResponseHeaderTimeout: cimdSocketTimeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cimdRequestTimeout,
		// INV-A11-26. ErrUseLastResponse hands the 3xx back rather than following it; the 2xx check in
		// Resolve then rejects it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// isSafeCimdURL is Cimd.kt:39-42's single `require`.
//
// ⚠️ The scheme comparison is `uri.scheme == "https"`, CASE-SENSITIVE — `java.net.URI.getScheme()`
// preserves the case it was given, so `HTTPS://…` is rejected. Go's url.Parse LOWERCASES the scheme,
// which would silently accept it, so the check is made against the raw string. (Contrast
// [ValidatedRedirectURI], whose scheme comparisons ARE case-insensitive. The inconsistency is real and
// is reproduced on both sides.)
//
// The fragment test is `uri.fragment == null`, and `URI("https://x/y#").getFragment()` is `""`, not
// null — so a bare trailing `#` IS a fragment and IS rejected. Go's url.URL cannot express that
// distinction (both give Fragment == ""), so the raw string is searched for the delimiter, which is
// exactly what Java's parser does.
func isSafeCimdURL(raw string, u *url.URL) bool {
	if rawScheme(raw) != "https" {
		return false
	}
	if u.Hostname() == "" {
		return false
	}
	if isBlankKotlin(u.Path) {
		return false
	}
	if u.User != nil {
		return false
	}
	if strings.IndexByte(raw, '#') >= 0 {
		return false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// rawScheme returns the scheme exactly as written, without url.Parse's lowercasing.
func rawScheme(raw string) string {
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		return ""
	}
	return raw[:i]
}

// isJSONContentType is Cimd.kt:56-59: the type must be `application` and the subtype must be `json`
// or end in `+json`. An absent or unparseable header is not JSON.
func isJSONContentType(header string) bool {
	if header == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return false
	}
	kind, subtype, ok := strings.Cut(mediaType, "/")
	if !ok || !strings.EqualFold(kind, "application") {
		return false
	}
	return strings.EqualFold(subtype, "json") || strings.HasSuffix(strings.ToLower(subtype), "+json")
}

// ---------------------------------------------------------------------------------------------
// The special-use address check — Cimd.kt:98-112
// ---------------------------------------------------------------------------------------------

// isSpecialUse is `private fun isSpecialUse(address)` (Cimd.kt:98-100).
//
// The five `InetAddress` predicates are spelled out rather than mapped onto Go's `net.IP` methods,
// because two of them do not correspond: Java's `isSiteLocalAddress` for IPv6 is `fec0::/10` (the
// DEPRECATED site-local range) while Go's `IP.IsPrivate` for IPv6 is `fc00::/7` (ULA). `fc00::/7` is
// in the CIDR blocklist below, but `fec0::/10` is NOT — so delegating to IsPrivate would silently
// UNBLOCK deprecated site-local addresses. The rest agree, and are written out anyway so the whole
// predicate reads against the JDK's definitions in one place.
func isSpecialUse(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return isAnyLocalV4(v4) || isLoopbackV4(v4) || isLinkLocalV4(v4) ||
			isSiteLocalV4(v4) || isMulticastV4(v4) || inSpecialUseCIDRs(v4)
	}
	v6 := ip.To16()
	if v6 == nil {
		// Not an address at all. Fail closed.
		return true
	}
	return isAnyLocalV6(v6) || isLoopbackV6(v6) || isLinkLocalV6(v6) ||
		isSiteLocalV6(v6) || isMulticastV6(v6) || inSpecialUseCIDRs(v6)
}

// The Inet4Address predicates, from the JDK.
func isAnyLocalV4(a net.IP) bool  { return a[0]|a[1]|a[2]|a[3] == 0 }
func isLoopbackV4(a net.IP) bool  { return a[0] == 127 }
func isLinkLocalV4(a net.IP) bool { return a[0] == 169 && a[1] == 254 }
func isSiteLocalV4(a net.IP) bool {
	return a[0] == 10 || (a[0] == 172 && a[1]&0xf0 == 16) || (a[0] == 192 && a[1] == 168)
}
func isMulticastV4(a net.IP) bool { return a[0]&0xf0 == 0xe0 }

// The Inet6Address predicates, from the JDK.
func isAnyLocalV6(a net.IP) bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}

func isLoopbackV6(a net.IP) bool {
	for _, b := range a[:15] {
		if b != 0 {
			return false
		}
	}
	return a[15] == 1
}

func isLinkLocalV6(a net.IP) bool { return a[0] == 0xfe && a[1]&0xc0 == 0x80 }
func isSiteLocalV6(a net.IP) bool { return a[0] == 0xfe && a[1]&0xc0 == 0xc0 }
func isMulticastV6(a net.IP) bool { return a[0] == 0xff }

// specialUseCIDRs is Cimd.kt:105-112's 30-entry blocklist — RFC 1918/6598/5737/6890 plus the IPv6
// ULA/link-local/documentation/6to4/NAT64 ranges — in the Kotlin's order.
var specialUseCIDRs = parseCIDRs(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
	"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)

func inSpecialUseCIDRs(addr net.IP) bool {
	for _, c := range specialUseCIDRs {
		if c.contains(addr) {
			return true
		}
	}
	return false
}

// cidr is `private data class Cidr(network, prefixBits)` (Cimd.kt:116-133): byte compare over the
// whole bytes, then a boundary mask.
//
// ⚠️ F18 — THIS IS THE THIRD HAND-ROLLED CIDR IMPLEMENTATION IN THE CODEBASE, alongside A12's
// `cidrContains` (ported as httpapi's unexported `cidrContains`) and… itself. 11-mcp-oauth-management.md
// is explicit: "REPRODUCE all three (F18). Duplication is explicitly not grounds for OMIT, 'identical
// logic' is a claim about today that a single shared implementation would silently freeze, and
// collapsing three gates onto one code path is a refactor — which during a port is a fix during a
// port. Unify after cutover, as its own reviewable change."
//
// The two are also not interchangeable as written: httpapi's takes an UNPARSED `entry string` and is
// unexported, while this one is a PRE-PARSED value matched thirty times per resolve. Exporting the
// other would mean editing a package this area does not own, mid-port.
//
// 🔒 The width check is the security-relevant half: `address.size != network.size` refuses a
// cross-family match, so `::ffff:10.0.0.1/104` can never match a v4 address. Callers must therefore
// pass addresses in their NATIVE width — 4 bytes for IPv4 — which is what [isSpecialUse]'s `To4()`
// does.
type cidr struct {
	network    net.IP
	prefixBits int
}

func (c cidr) contains(address net.IP) bool {
	if len(address) != len(c.network) {
		return false
	}
	wholeBytes := c.prefixBits / 8
	remainingBits := c.prefixBits % 8
	for i := 0; i < wholeBytes; i++ {
		if address[i] != c.network[i] {
			return false
		}
	}
	if remainingBits == 0 {
		return true
	}
	mask := byte(0xff << (8 - remainingBits))
	return address[wholeBytes]&mask == c.network[wholeBytes]&mask
}

// parseCIDRs is `Cidr.parse` over the literal list. A malformed entry is a programming error in a
// compile-time constant list, so it panics at init exactly as `InetAddress.getByName` /
// `toInt()` would throw during class initialization.
func parseCIDRs(values ...string) []cidr {
	out := make([]cidr, 0, len(values))
	for _, v := range values {
		addr, bits, ok := strings.Cut(v, "/")
		if !ok {
			panic("oauth: malformed special-use CIDR " + v)
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			panic("oauth: malformed special-use CIDR address " + v)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		prefix, err := strconv.Atoi(bits)
		if err != nil {
			panic("oauth: malformed special-use CIDR prefix " + v)
		}
		out = append(out, cidr{network: ip, prefixBits: prefix})
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// validateRequest / redirect-URI matching — Cimd.kt:135-191
// ---------------------------------------------------------------------------------------------

// ValidateRequest is `fun CimdClientMetadata.validateRequest(redirectUri, requestedScopes)`
// (Cimd.kt:135-145). Nil means the request is acceptable for this client.
//
// 🔒 `token_endpoint_auth_method == "none"` — PUBLIC CLIENTS ONLY. This is the counterpart of the
// discovery document's `token_endpoint_auth_methods_supported = ["none"]`: there is no client secret
// in this design, so a client asserting any other method is asserting a capability the server does
// not have.
//
// The scope rule is conditional: a client that declares NO scopes accepts any of them, and only a
// client that declares some is held to its list. `OAuthRoutesDbTest` case 3's first line pins that
// ("accepts omitted scope").
func (m *CimdClientMetadata) ValidateRequest(redirectURI string, requestedScopes []string) error {
	matched := false
	for _, declared := range m.RedirectURIs {
		if loopbackAwareRedirectURIMatch(redirectURI, declared) {
			matched = true
			break
		}
	}
	if !matched {
		return errors.New("redirect_uri is not registered")
	}
	if _, err := ValidatedRedirectURI(redirectURI); err != nil {
		return err
	}
	if !contains(m.ResponseTypes, "code") {
		return errors.New("client does not support response_type=code")
	}
	if !contains(m.GrantTypes, "authorization_code") {
		return errors.New("client does not support authorization_code")
	}
	if m.TokenEndpointAuthMethod != "none" {
		return errors.New("only public clients are supported")
	}
	declaredScopes := splitScopesNotBlank(m.Scope)
	if len(declaredScopes) == 0 {
		return nil
	}
	for _, s := range requestedScopes {
		if !contains(declaredScopes, s) {
			return errors.New("requested scope is not declared by client metadata")
		}
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// ValidatedRedirectURI is `internal fun validatedRedirectUri(value)` (Cimd.kt:148-157). Its KDoc:
// "OAuth 2.1 permits HTTPS redirects plus HTTP loopback redirects for native/local clients."
//
// Absolute, has a host, no userinfo, no fragment, and HTTPS unless it targets loopback. The scheme
// comparisons here ARE case-insensitive, unlike [isSafeCimdURL]'s.
func ValidatedRedirectURI(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("redirect_uri is invalid: %w", err)
	}
	const shapeMsg = "redirect_uri must be an absolute URI with a host and no userinfo or fragment"
	if !u.IsAbs() || u.Hostname() == "" || u.User != nil || strings.IndexByte(value, '#') >= 0 {
		return nil, errors.New(shapeMsg)
	}
	https := strings.EqualFold(u.Scheme, "https")
	loopbackHTTP := strings.EqualFold(u.Scheme, "http") && IsLoopbackRedirectHost(u.Hostname())
	if !https && !loopbackHTTP {
		return nil, errors.New("redirect_uri must use HTTPS unless it targets localhost")
	}
	return u, nil
}

// IsLoopbackRedirectHost is `internal fun isLoopbackRedirectHost(host)` (Cimd.kt:159-163).
//
// `[::1]` is accepted alongside `::1` because Java's `URI.getHost()` returns the BRACKETED form for an
// IPv6 literal. Go's `URL.Hostname()` strips the brackets, so only the bare form can arrive here in
// practice — the bracketed arm is kept anyway, both to match the Kotlin and because this function is
// exported and a caller may hand it a raw authority.
//
// ⚠️ The dotted-quad test only checks that the FIRST octet is `127`; `127.0.0.1.evil.example` fails
// on the octet count, but `127.999.0.1` passes the range test only because `toIntOrNull() in 0..255`
// rejects it — reproduced exactly, including that a 4-part all-numeric host with a leading 127 is
// loopback regardless of whether the OS agrees.
func IsLoopbackRedirectHost(host string) bool {
	if strings.EqualFold(host, "localhost") || host == "::1" || host == "[::1]" {
		return true
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return octets[0] == "127"
}

// loopbackAwareRedirectURIMatch is `private fun loopbackAwareRedirectUriMatch(requested, declared)`
// (Cimd.kt:178-191). Its KDoc is worth carrying verbatim, because the rule looks like a relaxation
// and is in fact the only thing that makes a real CLI login possible:
//
//	"RFC 8252 section 7.3: a native/CLI client binds its loopback redirect listener to a port chosen
//	 at launch, so a CIMD document that wants to support this can only ever declare a **portless**
//	 loopback redirect_uri — an authorization server MUST then match it against the actual request
//	 while ignoring the port. Claude Code's own published metadata declares exactly
//	 `http://localhost/callback` / `http://127.0.0.1/callback` for this reason; a plain
//	 `requested == declared` string check rejects every real login (`claude mcp login`), since the
//	 request always carries an explicit ephemeral port. A declared loopback redirect_uri that DOES
//	 specify a port is left exact-match — nothing forces a client to omit it, and relaxing a
//	 deliberately fixed port would let a request substitute an arbitrary one. Every non-loopback
//	 redirect_uri (HTTPS, per validatedRedirectUri) is likewise always exact-match — a fixed HTTPS
//	 endpoint has no ephemeral-port excuse to relax against."
//
// 🔒 The relaxation is gated FOUR ways on the DECLARED side (http, has a host, has NO port, is
// loopback) and then still compares scheme, host, path AND query. Dropping any one of the four turns
// it into an open redirect for that client.
func loopbackAwareRedirectURIMatch(requested, declared string) bool {
	if requested == declared {
		return true
	}
	requestedURI, err := url.Parse(requested)
	if err != nil {
		return false
	}
	declaredURI, err := url.Parse(declared)
	if err != nil {
		return false
	}
	if !strings.EqualFold(declaredURI.Scheme, "http") || declaredURI.Hostname() == "" ||
		declaredURI.Port() != "" || !IsLoopbackRedirectHost(declaredURI.Hostname()) {
		return false
	}
	return strings.EqualFold(requestedURI.Scheme, "http") &&
		strings.EqualFold(requestedURI.Hostname(), declaredURI.Hostname()) &&
		requestedURI.Path == declaredURI.Path &&
		requestedURI.RawQuery == declaredURI.RawQuery
}
