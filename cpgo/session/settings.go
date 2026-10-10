package session

import (
	"fmt"
	"math"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Settings are the web-session rules, read from the same environment as the Kotlin control plane.
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

	AbsoluteSeconds, IdleSeconds, SlideSeconds   int64
	IdleWarnLeadSeconds, AbsoluteWarnLeadSeconds int64
	HeartbeatSeconds                             int64
}

// SettingsFromEnv reads Settings the way Kotlin's Config does, refusing a duration Kotlin would refuse.
func SettingsFromEnv() (Settings, error) {
	s := Settings{
		Secret:           envOr("PM_SESSION_SECRET", "dev-insecure-session-secret-change-me"),
		AuthDebug:        strictBool(os.Getenv("PM_AUTH_DEBUG"), true),
		Secure:           strings.HasPrefix(envOr("PM_MCP_RESOURCE", "http://127.0.0.1:8080/mcp"), "https://"),
		ResultKey:        os.Getenv("PM_RESULT_KEY") != "",
		WebOrigin:        os.Getenv("PM_WEB_ORIGIN"),
		OIDCEnabled:      true,
		MCPResource:      canonicalResource(envOr("PM_MCP_RESOURCE", "http://127.0.0.1:8080/mcp")),
		ElevatedScopeTTL: clampedSeconds(os.Getenv("PM_ELEVATED_SCOPE_TTL"), 3600),
		MCPAccessTTL:     clampedSeconds(os.Getenv("PM_OAUTH_ACCESS_TTL"), 600),
	}
	for _, k := range []string{"PM_OIDC_ISSUER", "PM_OIDC_CLIENT_ID", "PM_OIDC_CLIENT_SECRET", "PM_OIDC_REDIRECT_URI"} {
		if os.Getenv(k) == "" {
			s.OIDCEnabled = false
		}
	}
	for _, d := range []struct {
		env string
		def int64
		dst *int64
	}{
		{"PM_WEB_SESSION_ABSOLUTE", 7200, &s.AbsoluteSeconds},
		{"PM_WEB_SESSION_IDLE", 900, &s.IdleSeconds},
		{"PM_WEB_SESSION_SLIDE", 120, &s.SlideSeconds},
		{"PM_WEB_SESSION_IDLE_WARN_LEAD", 60, &s.IdleWarnLeadSeconds},
		{"PM_WEB_SESSION_ABSOLUTE_WARN_LEAD", 300, &s.AbsoluteWarnLeadSeconds},
		{"PM_WEB_SESSION_HEARTBEAT", 90, &s.HeartbeatSeconds},
		{"PM_SESSION_WINDOW", 7200, &s.SessionWindowSeconds},
	} {
		*d.dst = d.def
		if raw := os.Getenv(d.env); raw != "" {
			v, err := ParseDuration(raw)
			if err != nil {
				return s, fmt.Errorf("%s: %w", d.env, err)
			}
			*d.dst = v
		}
	}
	return s, nil
}

var durationSegment = regexp.MustCompile(`(\d+)([hms])`)

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
	end := 0
	for _, m := range durationSegment.FindAllStringSubmatchIndex(raw, -1) {
		if m[0] != end {
			return 0, fmt.Errorf("invalid duration: %q", raw)
		}
		n, err := strconv.ParseInt(raw[m[2]:m[3]], 10, 64)
		unit := map[string]int64{"h": 3600, "m": 60, "s": 1}[raw[m[4]:m[5]]]
		if err != nil || n > math.MaxInt64/unit || total > math.MaxInt64-n*unit {
			return 0, fmt.Errorf("duration is too large: %q", raw)
		}
		total += n * unit
		end = m[1]
	}
	if end != len(raw) || total <= 0 {
		return 0, fmt.Errorf("invalid duration: %q", raw)
	}
	return total, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// strictBool is Kotlin's toBooleanStrictOrNull with a default: only "true" and "false" count.
func strictBool(raw string, def bool) bool {
	switch raw {
	case "true":
		return true
	case "false":
		return false
	}
	return def
}

// WebRedirect is a console path, under PM_WEB_ORIGIN when that is set.
func (s Settings) WebRedirect(path string) string {
	if strings.TrimSpace(s.WebOrigin) == "" {
		return path
	}
	return strings.TrimRight(strings.TrimSpace(s.WebOrigin), "/") + path
}

// canonicalResource is Kotlin's canonicalMcpResource for a URI it accepted: lowercase scheme and host, path /mcp.
func canonicalResource(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + "/mcp"
}

// clampedSeconds is a token lifetime: def when raw is not an integer, then clamped to [60s, 24h].
func clampedSeconds(raw string, def int64) int64 {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		v = def
	}
	return min(max(v, 60), 24*3600)
}

// WebBase is the console's origin for links pmon prints: PM_WEB_ORIGIN, else this server's own origin.
func (s Settings) WebBase() string {
	if origin := strings.TrimRight(strings.TrimSpace(s.WebOrigin), "/"); origin != "" {
		return origin
	}
	return strings.TrimSuffix(s.MCPResource, "/mcp")
}
