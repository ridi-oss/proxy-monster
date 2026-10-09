package front

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestSetForwarded(t *testing.T) {
	edges := ParseTrustedEdges([]string{"10.0.0.5", "172.16.0.0/12", "2001:db8::/32", "not-an-ip", "10.1.0.0/99"})
	cases := []struct {
		name   string
		peer   string
		in     http.Header
		expect http.Header
	}{
		{
			name:   "direct client: its forged headers are replaced by its own address",
			peer:   "203.0.113.7:51000",
			in:     http.Header{"X-Forwarded-For": {"1.2.3.4"}, "X-Forwarded-Host": {"evil.example"}, "X-Forwarded-Proto": {"https"}},
			expect: http.Header{"X-Forwarded-For": {"203.0.113.7"}},
		},
		{
			name: "trusted literal edge: every header line passes through",
			peer: "10.0.0.5:443",
			in: http.Header{
				"X-Forwarded-For":   {"1.1.1.1", "198.51.100.9"},
				"X-Forwarded-Host":  {"pm.example"},
				"X-Forwarded-Proto": {"https"},
			},
			expect: http.Header{
				"X-Forwarded-For":   {"1.1.1.1", "198.51.100.9"},
				"X-Forwarded-Host":  {"pm.example"},
				"X-Forwarded-Proto": {"https"},
			},
		},
		{
			name:   "trusted CIDR edge without headers: nothing is invented",
			peer:   "172.20.3.4:443",
			in:     http.Header{},
			expect: http.Header{},
		},
		{
			name:   "trusted IPv6 block",
			peer:   "[2001:db8::1]:443",
			in:     http.Header{"X-Forwarded-For": {"198.51.100.9"}},
			expect: http.Header{"X-Forwarded-For": {"198.51.100.9"}},
		},
		{
			name:   "IPv4-mapped peer matches its IPv4 entry",
			peer:   "[::ffff:10.0.0.5]:443",
			in:     http.Header{"X-Forwarded-For": {"198.51.100.9"}},
			expect: http.Header{"X-Forwarded-For": {"198.51.100.9"}},
		},
		{
			name:   "IPv6 peer outside every block",
			peer:   "[2001:db9::1]:443",
			in:     http.Header{"X-Forwarded-For": {"198.51.100.9"}},
			expect: http.Header{"X-Forwarded-For": {"2001:db9::1"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := httptest.NewRequest(http.MethodGet, "/", nil)
			in.RemoteAddr = tc.peer
			in.Header = tc.in.Clone()
			out := in.Clone(in.Context())
			out.Header.Set("Forwarded", "for=1.2.3.4")
			setForwarded(in, out, edges)
			if !reflect.DeepEqual(out.Header, tc.expect) {
				t.Fatalf("headers = %v, want %v", out.Header, tc.expect)
			}
		})
	}
}

func TestMalformedEntriesTrustNothing(t *testing.T) {
	edges := ParseTrustedEdges([]string{"10.0.0.0/33", "garbage", " ", "[203.0.113.7", "203.0.113.7]"})
	if len(edges.addrs) != 0 || len(edges.prefixes) != 0 {
		t.Fatalf("parsed %v / %v from malformed entries", edges.addrs, edges.prefixes)
	}
}
