package session

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// Settings are the web-session rules, shared with the Kotlin control plane.
type Settings struct {
	Secret string
	// AuthDebug enables POST /auth/debug and a session's simulated requester IP.
	AuthDebug bool
	// Secure marks cookies Secure; on when PM_MCP_RESOURCE is https.
	Secure bool
	// OIDCEnabled is whether all four PM_OIDC_* settings are present.
	OIDCEnabled bool
	// ResultKey is whether editor results are stored; ending a session deletes them only then.
	ResultKey bool
	// WebOrigin prefixes redirects into the console when it is served from another origin.
	WebOrigin string

	// MCPResource is PM_MCP_RESOURCE in its canonical form, the resource every MCP token is bound to.
	MCPResource string
	// SessionWindowSeconds caps how long a pmon login renews its wire token before logging in again.
	SessionWindowSeconds int64
	// ElevatedScopeTTL is how long a pmon login's scopes beyond mcp:read and mcp:query last.
	ElevatedScopeTTL int64
	// MCPAccessTTL is an MCP access token's lifetime.
	MCPAccessTTL int64
	// MCPRefreshTTL is an MCP OAuth refresh token's lifetime.
	MCPRefreshTTL int64
	// OAuthDebugAutoConsent skips the consent page under PM_AUTH_DEBUG.
	OAuthDebugAutoConsent bool

	AbsoluteSeconds, IdleSeconds, SlideSeconds   int64
	IdleWarnLeadSeconds, AbsoluteWarnLeadSeconds int64
	HeartbeatSeconds                             int64
}

// ParseDuration is Kotlin's parseDuration: plain digits are seconds, else whole-string h/m/s segments
// ("1h30m"); the result must be positive and fit in an int64.
func ParseDuration(raw string) (int64, error) {
	if raw == "" {
		return 0, fmt.Errorf("duration must not be empty")
	}
	if strings.Trim(raw, "0123456789") == "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid duration: %q", raw)
		}
		return n, nil
	}
	var total int64
	for rest := raw; rest != ""; {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 0 || i == len(rest) {
			return 0, fmt.Errorf("invalid duration: %q", raw)
		}
		var unit int64
		switch rest[i] {
		case 'h':
			unit = 3600
		case 'm':
			unit = 60
		case 's':
			unit = 1
		default:
			return 0, fmt.Errorf("invalid duration: %q", raw)
		}
		n, err := strconv.ParseInt(rest[:i], 10, 64)
		if err != nil || n > math.MaxInt64/unit || total > math.MaxInt64-n*unit {
			return 0, fmt.Errorf("duration is too large: %q", raw)
		}
		total += n * unit
		rest = rest[i+1:]
	}
	if total <= 0 {
		return 0, fmt.Errorf("invalid duration: %q", raw)
	}
	return total, nil
}

// MCPScopes is every scope an MCP tool requires (McpCapabilityRegistry.supportedScopes), sorted.
func MCPScopes() []string {
	return []string{
		"mcp:approvals:write", "mcp:datasources:write", "mcp:identity:write", "mcp:policies:write",
		"mcp:query", "mcp:read", "mcp:tokens",
	}
}

// Issuer is this server's origin, the MCP resource without its /mcp path.
func (s Settings) Issuer() string { return strings.TrimSuffix(s.MCPResource, "/mcp") }

// WebRedirect is a console path, under PM_WEB_ORIGIN when that is set.
func (s Settings) WebRedirect(path string) string {
	if strings.TrimSpace(s.WebOrigin) == "" {
		return path
	}
	return strings.TrimRight(strings.TrimSpace(s.WebOrigin), "/") + path
}

// WebBase is the console's origin for links it hands out: PM_WEB_ORIGIN, else this server's own origin.
func (s Settings) WebBase() string {
	if origin := strings.TrimRight(strings.TrimSpace(s.WebOrigin), "/"); origin != "" {
		return origin
	}
	return s.Issuer()
}

// CanonicalResource is Kotlin's canonicalMcpResource for a URI it accepted: lowercase scheme and host, path /mcp.
func CanonicalResource(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + "/mcp"
}

// ClampSeconds is a token lifetime: def when raw is not an integer, then clamped to [60s, 24h].
func ClampSeconds(raw string, def int64) int64 {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		v = def
	}
	return min(max(v, 60), 24*3600)
}
