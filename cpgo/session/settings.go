package session

import (
	"fmt"
	"math"
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
