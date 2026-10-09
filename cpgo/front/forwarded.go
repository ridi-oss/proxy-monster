// Package front is the control plane's network edge: it owns the public HTTP and gRPC ports and
// forwards what Go does not serve yet to the Kotlin control plane on loopback.
package front

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedEdges is PM_TRUSTED_PROXIES: the peers whose X-Forwarded-* headers are honored. It matches
// the Kotlin isTrustedEdge rules, so moving the edge to Go does not change who may speak for a client.
type TrustedEdges struct {
	addrs    map[netip.Addr]bool
	prefixes []netip.Prefix
}

// ParseTrustedEdges reads comma-separated IPs and CIDR blocks. A malformed entry trusts nothing and is
// logged, matching the Kotlin side's fail-closed handling of a typo.
func ParseTrustedEdges(entries []string) TrustedEdges {
	t := TrustedEdges{addrs: map[netip.Addr]bool{}}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				slog.Warn("PM_TRUSTED_PROXIES: ignoring unusable entry", "entry", e)
				continue
			}
			t.prefixes = append(t.prefixes, p.Masked())
			continue
		}
		if strings.HasPrefix(e, "[") && strings.HasSuffix(e, "]") {
			e = e[1 : len(e)-1]
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			slog.Warn("PM_TRUSTED_PROXIES: ignoring unusable entry", "entry", e)
			continue
		}
		t.addrs[a.WithZone("")] = true
	}
	return t
}

// Contains reports whether peer is a trusted edge. An IPv4 peer never matches an IPv6 entry.
func (t TrustedEdges) Contains(peer netip.Addr) bool {
	peer = peer.WithZone("")
	if t.addrs[peer] {
		return true
	}
	for _, p := range t.prefixes {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// forwardedHeaders are the X-Forwarded-* headers the Kotlin control plane reads.
var forwardedHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}

// setForwarded makes the Kotlin side, which trusts only cp-go, resolve the same client as it would
// have with the original peer: a trusted edge's headers pass through untouched, and any other peer is
// named in X-Forwarded-For with its own headers dropped.
func setForwarded(in, out *http.Request, edges TrustedEdges) {
	for _, h := range forwardedHeaders {
		out.Header.Del(h)
	}
	out.Header.Del("Forwarded")
	peer, ok := remoteAddr(in)
	if ok && edges.Contains(peer) {
		for _, h := range forwardedHeaders {
			if v := in.Header.Values(h); len(v) > 0 {
				out.Header[h] = append([]string(nil), v...)
			}
		}
		return
	}
	if ok {
		out.Header.Set("X-Forwarded-For", peer.String())
	}
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}
