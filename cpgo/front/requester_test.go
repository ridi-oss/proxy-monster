package front

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequesterIP(t *testing.T) {
	edges := ParseTrustedEdges([]string{"10.0.0.5"})
	for _, tc := range []struct {
		name, peer string
		xff        []string
		want       string
	}{
		{"direct peer; its header is ignored", "203.0.113.7:5000", []string{"1.2.3.4"}, "203.0.113.7"},
		{"edge: rightmost entry of the last line", "10.0.0.5:443", []string{"9.9.9.9", "1.1.1.1, 198.51.100.4"}, "198.51.100.4"},
		{"edge: entry with a port", "10.0.0.5:443", []string{"198.51.100.4:8080"}, "198.51.100.4"},
		{"edge: bracketed IPv6 with a port", "10.0.0.5:443", []string{"[2001:db8::1]:8080"}, "2001:db8::1"},
		{"edge: bare IPv6", "10.0.0.5:443", []string{"2001:db8::1"}, "2001:db8::1"},
		{"edge: no header is never the edge's own address", "10.0.0.5:443", nil, ""},
		{"edge: garbage", "10.0.0.5:443", []string{"not-an-ip"}, ""},
		{"edge: bracket without a colon before the port", "10.0.0.5:443", []string{"[2001:db8::1]80"}, ""},
		{"edge: zoned address", "10.0.0.5:443", []string{"fe80::1%eth0"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := RequesterIP(r, edges); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestInternalPathsAreNeverForwarded(t *testing.T) {
	forwarded := 0
	h := Route(http.NewServeMux(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded++ }))
	for _, p := range []string{"/internal/authorize", "//internal/authorize", "/x/../internal/authorize", "/%69nternal/authorize", "/internal"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "http://cp"+p, nil)
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	if forwarded != 0 {
		t.Fatalf("forwarded %d internal requests", forwarded)
	}
}
