package front

import (
	"net/http"
	"net/netip"
	"strings"
)

// RequesterIP is Kotlin's resolveHttpRequesterIp: the socket peer, or, when the peer is a trusted edge,
// the rightmost X-Forwarded-For entry. An edge's own address is never the requester, so a trusted peer
// with no usable entry resolves to "".
func RequesterIP(r *http.Request, edges TrustedEdges) string {
	peer, ok := remoteAddr(r)
	if !ok {
		return ""
	}
	if !edges.Contains(peer) {
		return peer.String()
	}
	lines := r.Header.Values("X-Forwarded-For")
	if len(lines) == 0 {
		return ""
	}
	last := lines[len(lines)-1]
	entry := strings.TrimSpace(last[strings.LastIndexByte(last, ',')+1:])
	return bareIP(entry)
}

// bareIP accepts an address with an optional port ("1.2.3.4:5", "[::1]:5") and returns the address, or ""
// when it is not one Cedar's ip() accepts.
func bareIP(s string) string {
	s = strings.TrimPrefix(s, "/")
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return ""
		}
		if rest := s[end+1:]; rest != "" && !(strings.HasPrefix(rest, ":") && isPort(rest[1:])) {
			return ""
		}
		s = s[1:end]
	case strings.Count(s, ":") == 1:
		host, port, _ := strings.Cut(s, ":")
		if !isPort(port) {
			return ""
		}
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return ""
	}
	return a.String()
}

func isPort(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
