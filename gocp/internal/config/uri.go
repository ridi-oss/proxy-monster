package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// This file reproduces the three java.net.URI-backed guards in Config.kt: canonicalMcpResource (V10),
// mcpOrigin (the mcpIssuer derived value) and requireSecureOidcUri (V8).
//
// 🔴 The hard part is that java.net.URI is STRICTER than Go's net/url, and V10 is a security rule. Two
// places where "just use net/url" silently widens what boots:
//
//   - java.net.URI.getHost() returns null unless the authority is server-based per RFC 2396 — so an
//     underscore in the host, or a top label starting with a digit, makes the URI fail V10. Go's
//     url.Parse accepts both. javaURIHost below reproduces the RFC 2396 grammar.
//   - java.net.URI distinguishes "no query" (null) from "empty query" (`?` with nothing after it), and
//     the same for the fragment. Go's url.URL collapses both to "". Since the Kotlin tests `query ==
//     null`, `http://h/mcp?` must be REJECTED — reproduced by looking for the delimiter in the raw
//     string, which is sound because normalize() only ever rewrites the path.
//
// A third, subtler one: Go's url.Parse LOWERCASES the scheme, java.net.URI does not. V10 compares the
// scheme against {http, https} case-sensitively, so `HTTPS://h/mcp` boots on a naive port and is
// refused by the Kotlin. rawScheme below takes the scheme from the input text for that reason.
type javaURI struct {
	scheme      string
	host        string // "" ⇒ java.net.URI.getHost() would be null
	port        int    // -1 ⇒ absent, matching java.net.URI.getPort()
	path        string
	hasUserInfo bool
	hasQuery    bool
	hasFragment bool
	absolute    bool // java.net.URI.isAbsolute() — i.e. a scheme is present
}

// parseJavaURI parses `raw` the way `java.net.URI(raw)` does, as far as the four guards care.
//
// DEVIATION: java.net.URI's constructor throws URISyntaxException, which is NOT an
// IllegalArgumentException — so a truly unparseable PM_MCP_RESOURCE escapes Config.fromEnv as a
// different exception class than every other config failure. Go has one error channel, so both arrive
// as an error. No test distinguishes them (01-bootstrap.md §4 case 11 only covers scheme + case).
func parseJavaURI(raw string) (javaURI, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return javaURI{}, fmt.Errorf("invalid URI: %s", raw)
	}
	scheme := rawScheme(raw)
	out := javaURI{
		scheme:      scheme,
		port:        -1,
		path:        u.Path,
		hasUserInfo: u.User != nil,
		absolute:    scheme != "",
	}
	// Java's null-vs-empty distinction, recovered from the raw text. Only the part after the
	// authority can carry these delimiters, and a '#' always precedes any '?' it might contain.
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		out.hasFragment = true
		raw = raw[:i]
	}
	if strings.IndexByte(raw, '?') >= 0 {
		out.hasQuery = true
	}

	if u.Opaque == "" {
		host, port, ok := javaURIHost(u.Host)
		if ok {
			out.host = host
			out.port = port
		}
	}
	return out, nil
}

// rawScheme returns the scheme EXACTLY as written, or "" when the URI is relative. RFC 3986's
// production is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` terminated by ':'.
func rawScheme(raw string) string {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case isAlpha(c):
			// legal anywhere
		case c >= '0' && c <= '9', c == '+', c == '-', c == '.':
			if i == 0 {
				return "" // a scheme must start with a letter
			}
		case c == ':':
			if i == 0 {
				return ""
			}
			return raw[:i]
		default:
			return "" // hit a delimiter before any ':' — the reference is relative
		}
	}
	return ""
}

// javaURIHost applies java.net.URI's server-based-authority grammar (RFC 2396) to the authority
// component. It returns ok=false where java.net.URI.getHost() would return null.
//
//	hostname    = domainlabel [ "." ] | 1*( domainlabel "." ) toplabel [ "." ]
//	domainlabel = alphanum | alphanum *( alphanum | "-" ) alphanum
//	toplabel    = alpha | alpha *( alphanum | "-" ) alphanum
//
// i.e. the LAST label must start with a letter — unless the whole host is an IPv4 literal, which Java
// tries first. IPv6 literals are bracketed and validated as addresses.
func javaURIHost(authority string) (host string, port int, ok bool) {
	if authority == "" {
		return "", -1, false
	}
	port = -1
	rest := authority
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:] // userInfo is reported separately
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", -1, false
		}
		host = rest[:end+1]
		if net.ParseIP(strings.Trim(host, "[]")) == nil {
			return "", -1, false
		}
		rest = rest[end+1:]
		if rest != "" && rest[0] != ':' {
			return "", -1, false
		}
		if rest != "" {
			rest = rest[1:]
			if rest != "" {
				p, err := strconv.Atoi(rest)
				if err != nil || p < 0 {
					return "", -1, false
				}
				port = p
			}
		}
		return host, port, true
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		portText := rest[i+1:]
		rest = rest[:i]
		if portText != "" { // "h:" ⇒ java.net.URI reports port -1
			p, err := strconv.Atoi(portText)
			if err != nil || p < 0 {
				return "", -1, false
			}
			port = p
		}
	}
	if rest == "" {
		return "", -1, false
	}
	if isIPv4Literal(rest) {
		return rest, port, true
	}
	if !isRFC2396Hostname(rest) {
		return "", -1, false
	}
	return rest, port, true
}

// isIPv4Literal is java.net.URI's IPv4address production: exactly four dotted decimal octets.
func isIPv4Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || !allASCIIDigits(p) {
			return false
		}
		if v, err := strconv.Atoi(p); err != nil || v > 255 {
			return false
		}
	}
	return true
}

func isRFC2396Hostname(s string) bool {
	s = strings.TrimSuffix(s, ".") // hostname may carry one trailing dot
	if s == "" {
		return false
	}
	labels := strings.Split(s, ".")
	for i, label := range labels {
		if label == "" {
			return false
		}
		if !isAlphanum(label[0]) || !isAlphanum(label[len(label)-1]) {
			return false
		}
		for j := 0; j < len(label); j++ {
			if !isAlphanum(label[j]) && label[j] != '-' {
				return false
			}
		}
		if i == len(labels)-1 && !isAlpha(label[0]) {
			return false // toplabel must start with a letter
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlphanum(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9')
}

// normalizePath is java.net.URI.normalize()'s effect on the path: RFC 3986 remove_dot_segments.
//
// It is NOT path.Clean. Clean("/mcp/") == "/mcp", while normalize("/mcp/") == "/mcp/" — and since V10
// demands the path be EXACTLY "/mcp", using Clean here would let `https://h/mcp/` boot as a canonical
// resource that the Kotlin rejects.
func normalizePath(in string) string {
	var out strings.Builder
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = "/" + in[3:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = "/" + in[4:]
			trimLastSegment(&out)
		case in == "/..":
			in = "/"
			trimLastSegment(&out)
		case in == "." || in == "..":
			in = ""
		default:
			start := 0
			if in[0] == '/' {
				start = 1
			}
			end := strings.IndexByte(in[start:], '/')
			if end < 0 {
				out.WriteString(in)
				in = ""
			} else {
				out.WriteString(in[:start+end])
				in = in[start+end:]
			}
		}
	}
	return out.String()
}

func trimLastSegment(b *strings.Builder) {
	s := b.String()
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[:i]
	} else {
		s = ""
	}
	b.Reset()
	b.WriteString(s)
}

// canonicalMCPResource is Config.kt:256-264 — validation rule V10.
//
// 🔒 V10: PM_MCP_RESOURCE must be absolute, have a host, carry no userInfo/query/fragment, have the
// path EXACTLY "/mcp", use http or https, and be https unless PM_AUTH_DEBUG is on. The accepted value
// is canonicalised to a lowercase scheme and host.
//
// Note the scheme membership test is CASE-SENSITIVE in the Kotlin (java.net.URI does not fold the
// scheme on parse, and `uri.scheme in setOf("http", "https")` compares raw), so "HTTPS://h/mcp" is
// rejected — which makes the .lowercase() applied to the scheme afterwards unreachable. REPRODUCE
// both: the rejection is observable, the dead lowercase is not, and removing it would be a refactor.
func canonicalMCPResource(raw string, requireHTTPS bool) (string, error) {
	fail := func() (string, error) {
		https := ""
		if requireHTTPS {
			https = "HTTPS "
		}
		return "", fmt.Errorf("PM_MCP_RESOURCE must be a canonical %sURI with exact /mcp path", https)
	}
	uri, err := parseJavaURI(raw)
	if err != nil {
		return "", err
	}
	uri.path = normalizePath(uri.path)

	okScheme := uri.scheme == "http" || uri.scheme == "https"
	if !uri.absolute || uri.host == "" || uri.hasUserInfo || uri.hasFragment || uri.hasQuery ||
		uri.path != "/mcp" || !okScheme || (requireHTTPS && uri.scheme != "https") {
		return fail()
	}
	return buildOrigin(strings.ToLower(uri.scheme), strings.ToLower(uri.host), uri.port) + "/mcp", nil
}

// mcpOrigin is Config.kt:266-270 — the scheme + host + port of a resource URI, with any trailing "/"
// stripped. It backs the mcpIssuer derived value, which is NEVER inferred from request headers.
func mcpOrigin(resource string) (string, error) {
	uri, err := parseJavaURI(resource)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(buildOrigin(uri.scheme, uri.host, uri.port), "/"), nil
}

// buildOrigin is `URI(scheme, null, host, port, …).toASCIIString()` for the authority part: the port is
// omitted when java.net.URI would report -1, and an IPv6 host keeps its brackets.
func buildOrigin(scheme, host string, port int) string {
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	if port >= 0 {
		b.WriteString(":")
		b.WriteString(strconv.Itoa(port))
	}
	return b.String()
}

// requireSecureOIDCURI is Config.kt:272-278 — validation rule V8.
//
// 🔒 V8: with PM_AUTH_DEBUG off the OIDC issuer must be HTTPS with a host and no
// userInfo/query/fragment. Note there is deliberately NO path constraint here (unlike V10) — an issuer
// legitimately lives at a sub-path on many IdPs. It also does NOT normalize() first, unlike V10.
func requireSecureOIDCURI(raw, name string) error {
	uri, err := parseJavaURI(raw)
	if err != nil {
		return fmt.Errorf("%s must be an HTTPS issuer URI", name)
	}
	if uri.scheme != "https" || uri.host == "" || uri.hasUserInfo || uri.hasQuery || uri.hasFragment {
		return fmt.Errorf("%s must be an HTTPS issuer URI", name)
	}
	return nil
}
