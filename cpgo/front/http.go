package front

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"
)

// Route serves a request with the Go handler registered for it in mux, and forwards every other request
// to the Kotlin control plane: non-canonical paths ServeMux would redirect, and HEAD, which ServeMux
// would hand to a GET handler.
func Route(mux *http.ServeMux, forward http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// cp-go's own calls into the Kotlin child; never reachable from outside.
		if strings.HasPrefix(path.Clean("/"+r.URL.Path), "/internal/") || path.Clean("/"+r.URL.Path) == "/internal" {
			http.NotFound(w, r)
			return
		}
		if _, pattern := mux.Handler(r); pattern != "" && r.Method != http.MethodHead && path.Clean(r.URL.Path) == r.URL.Path {
			mux.ServeHTTP(w, r)
			return
		}
		forward.ServeHTTP(w, r)
	})
}

// NewHTTP forwards every request to the Kotlin control plane at upstream (e.g. http://127.0.0.1:18090).
func NewHTTP(upstream *url.URL, edges TrustedEdges) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
			setForwarded(pr.In, pr.Out, edges)
		},
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 256,
			IdleConnTimeout:     90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Warn("http: upstream request failed", "method", r.Method, "path", r.URL.Path, "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}
