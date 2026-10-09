package front

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

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
