package aiapps

import (
	"context"
	"net/url"
	"strings"

	"github.com/ridi-oss/proxy-monster/pmon/internal/instance"
)

// Lookup is the server at controlPlane with the MCP URL it advertises (GET /api/instance), or
// <controlPlane>/mcp for a server too old to say. An MCP URL on another origin is ignored: https entries
// matching it are replaced, so the response must not be able to name some other service's.
func Lookup(ctx context.Context, name, controlPlane string) Server {
	base := strings.TrimRight(controlPlane, "/")
	srv := Server{Name: name, MCPURL: base + "/mcp"}
	if info, err := instance.Fetch(ctx, base); err == nil && sameOrigin(info.MCPURL, base) {
		srv.MCPURL = info.MCPURL
	}
	return srv
}

// sameOrigin reports whether a and b have the same scheme, host and port.
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return ua.Scheme != "" && ua.Host != "" && sameEndpoint(ua.Scheme+"://"+ua.Host, ub.Scheme+"://"+ub.Host)
}
