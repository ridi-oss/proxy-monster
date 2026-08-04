package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Lookup is the injected environment reader — the Go form of Kotlin's `env: (String) -> String?`
// parameter to Config.fromEnv (Config.kt:151).
//
// 🔴 PRESERVE THIS SEAM. It is the single reason ConfigGuardTest can drive all 25 cases without
// touching the real process environment (01-bootstrap.md §1). Nothing in this package may call
// os.Getenv directly; OSEnv below is the one adapter, and only FromEnv's caller uses it.
type Lookup func(key string) (value string, present bool)

// OSEnv is the production Lookup — Kotlin's `System::getenv` default argument.
func OSEnv(key string) (string, bool) { return os.LookupEnv(key) }

// EnvOf builds a Lookup over a fixed table. This is ConfigGuardTest's `envOf(vararg pairs)` helper
// (ConfigGuardTest.kt:17-20), exported because ~40 Kotlin test files build a Config this way.
func EnvOf(pairs map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := pairs[key]
		return v, ok
	}
}

const (
	// devSessionSecret is the dev-only signing secret. PM_SESSION_SECRET must be set in any real
	// deployment; V5 and V6 both key on this exact string (Config.kt:129).
	devSessionSecret = "dev-insecure-session-secret-change-me"

	// DefaultGRPCPort is the port the control-plane listens on for the proxy (Config.kt:132).
	DefaultGRPCPort = 9090

	// MaxQueryTimeoutSeconds matches the proxy's duration-safe ceiling in goproxy/config/config.go:
	// (MaxInt64ns - 30s)/1s. Bounding the control-plane to the identical value keeps the "one shared
	// PM_QUERY_TIMEOUT" lockstep contract exact and every downstream millisecond conversion in range
	// (Config.kt:138). Validation rule V4.
	MaxQueryTimeoutSeconds int64 = 9_223_372_006

	// QueryExchangeGraceMS is the headroom the control-plane's per-statement exchange budget adds over
	// the proxy's own PM_QUERY_TIMEOUT watchdog, so the watchdog fires FIRST and cancels the statement
	// in-band (Config.kt:149).
	//
	// It has to absorb everything the proxy does around the guarded execution: the watchdog wraps only
	// the backend statement, while authorization and the catalog probes before it run outside that
	// guard and have been measured in the tens of seconds against a large remote catalog. Shrinking it
	// makes the control-plane blame a query for time spent before it started.
	QueryExchangeGraceMS int64 = 150_000
)

// OIDCConfig is Kotlin's OidcConfig (Config.kt:15-22). Provider-agnostic: endpoints are resolved from
// discovery at ${issuer}/.well-known/openid-configuration, never hardcoded per provider. Parsed only
// when ALL FOUR required values are present. Used by both the web authorization-code flow and the
// CLI/daemon device-authorization flow — device-auth reuses this same confidential client.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       string
	GroupMapping OIDCGroupMapping
}

// Config is the immutable, fully-validated configuration snapshot (Config.kt:28-98).
//
// The Kotlin data class is constructed BY NAME in ~40 test files, so most of its fields carry
// defaults. Defaults() is the Go equivalent of that ergonomic: start from it and set only the fields
// the test cares about. The fields Kotlin leaves without a default (httpPort, dbUrl, dbUser,
// dbPassword, authDebug, secretToken, sessionSecret, oidc, resultKey, scimToken, sessionWindowSeconds,
// idpRecheckIntervalSeconds, devMarker) are deliberately left zero by Defaults() — naming them is
// required in Kotlin too.
type Config struct {
	HTTPPort int
	// GRPCPort is the port the proxy connects to (docs/datasource-registration.md). Separate from
	// HTTPPort: the web UI keeps talking HTTP/JSON; only the proxy↔control-plane wire protocol is gRPC.
	GRPCPort int
	// DBURL is a JDBC URL — `jdbc:postgresql://host:port/db`. DEFERRED (00-INDEX.md's disposition
	// table, A1 Q1): keeping the prefix and translating internally vs changing the contract touches
	// deploy/, docker-compose.yml, mise.toml and every deployed environment. FromEnv reproduces the
	// Kotlin exactly — it stores whatever the operator set, unparsed.
	DBURL      string
	DBUser     string
	DBPassword string
	// AuthDebug defaults to TRUE and is a full authentication bypass. V5 is what stops it reaching
	// production; see the comment there.
	AuthDebug bool
	// SecretToken is the ONE shared secret gating every proxy↔control-plane surface: the gRPC
	// transport (all RPCs) plus the HTTP ingest routes. When set, calls must present it; when nil the
	// gate is OPEN (dev only, logged). nil is meaningful — do not collapse it to "".
	SecretToken *string
	// SessionSecret is the cookie MAC key.
	SessionSecret string
	// OIDC is nil unless all four of PM_OIDC_ISSUER/_CLIENT_ID/_CLIENT_SECRET/_REDIRECT_URI are set.
	OIDC *OIDCConfig
	// ResultKey is the AES-256 key (exactly 32 bytes) for at-rest encryption of APPROVER_EXEC query
	// results. nil when PM_RESULT_KEY is unset ⇒ approver-exec execution is refused fail-closed, so no
	// plaintext PII lands at rest.
	//
	// Note 01-bootstrap.md §2: Kotlin's data-class equals on a ByteArray is REFERENCE identity, so two
	// Configs with equal keys compare unequal there. Go's == on a struct containing a slice does not
	// compile at all, which removes the trap rather than reproducing it. No test relies on Config
	// equality.
	ResultKey []byte
	// ScimToken is the SCIM 2.0 bearer token — a standing secret, constant-time compared, TLS-only.
	// nil disables the SCIM endpoints fail-closed (no unauthenticated provisioning surface).
	ScimToken *string
	// SessionWindowSeconds is the daemon/CLI session window: within it, silent wire-token renewal;
	// after it, device-auth re-prompts.
	SessionWindowSeconds      int64
	WebSessionAbsoluteSeconds int64
	// WebSessionIdleSeconds is the sliding inactivity window for web sessions.
	WebSessionIdleSeconds int64
	// WebSessionSlideSeconds is the minimum interval between web idle-deadline extensions. V1 requires
	// it to be strictly less than the idle window.
	WebSessionSlideSeconds int64
	// The two warn leads may EXCEED their session windows; the client clamps them rather than the
	// config rejecting them.
	WebSessionIdleWarnLeadSeconds     int64
	WebSessionAbsoluteWarnLeadSeconds int64
	WebSessionHeartbeatSeconds        int64
	// IdpRecheckIntervalSeconds is the timer-driven IdP identity/group revalidation interval for both
	// web and daemon sessions. V2 requires it to be positive.
	IdpRecheckIntervalSeconds int64
	// DevMarker is the explicit non-production marker required alongside PM_AUTH_DEBUG (V5).
	DevMarker bool
	// TrustedProxies holds the SOCKET-PEER addresses (literal addresses or CIDR blocks) of edges the
	// control-plane trusts to assert forwarded headers. THREE headers are trusted from such a peer:
	// X-Forwarded-For for requester_ip, X-Forwarded-Proto for the SCIM TLS gate, and X-Forwarded-Host
	// for the host the client addressed.
	//
	// Empty (the default) means NO edge is trusted: every one of those headers is ignored, so
	// requester_ip is the raw socket peer, a plaintext request can never pass the SCIM TLS gate, and
	// the /mcp check sees the socket authority — the fail-closed posture, since an untrusted client can
	// set any of them to anything.
	//
	// DEPLOYMENT REQUIREMENT for any address listed here: the edge must OVERWRITE the forwarded headers
	// it asserts, from its own view of the connection — never pass an inbound client-supplied value
	// through. An edge that forwards a client's `X-Forwarded-Proto: https` verbatim lets a PLAINTEXT
	// request satisfy the SCIM TLS gate, and the standing SCIM bearer then travels in the clear. Every
	// resolver reads the RIGHTMOST value, so an appending edge is also safe; a relaying one is not.
	TrustedProxies map[string]struct{}
	// MCPResource is the canonical MCP resource identifier. The co-hosted OAuth issuer is always this
	// URI's origin; it is never independently configured and never inferred from Host/X-Forwarded-*.
	MCPResource string
	// WebOrigin is the origin of the WEB console, used to build the browser URL `pmon login` prints
	// (the /device verification page is a web route, not a control-plane one). Blank means "same
	// origin as the control plane" — correct for the normal single-edge deployment.
	WebOrigin            string
	MCPAccessTTLSeconds  int64
	MCPRefreshTTLSeconds int64
	MCPDebugAutoConsent  bool
	QueryTimeoutSeconds  int64
}

// Defaults returns a Config carrying exactly the defaults the Kotlin data class declares inline
// (Config.kt:33, 52-60, 84-97). See the Config doc comment for why the rest are left zero.
func Defaults() Config {
	return Config{
		GRPCPort:                          DefaultGRPCPort,
		WebSessionAbsoluteSeconds:         2 * 3600,
		WebSessionIdleSeconds:             15 * 60,
		WebSessionSlideSeconds:            2 * 60,
		WebSessionIdleWarnLeadSeconds:     60,
		WebSessionAbsoluteWarnLeadSeconds: 5 * 60,
		WebSessionHeartbeatSeconds:        90,
		TrustedProxies:                    map[string]struct{}{},
		MCPResource:                       "http://127.0.0.1:8080/mcp",
		WebOrigin:                         "",
		MCPAccessTTLSeconds:               600,
		MCPRefreshTTLSeconds:              21_600,
		MCPDebugAutoConsent:               true,
		QueryTimeoutSeconds:               600,
	}
}

// Validate is the Kotlin data class's `init` block (Config.kt:99-109) — the two rules that fire on
// EVERY construction, including `copy()`, not just on fromEnv. FromEnv calls it last, mirroring the
// fact that Kotlin runs `init` after every constructor argument has been evaluated.
//
// Go has no constructor hook, so a Config assembled field-by-field is unvalidated until this is
// called. ConfigGuardTest case 25's final assertion (`fromEnv(envOf()).copy(slide = 900, idle = 900)`
// throws) is ported against it.
func (c Config) Validate() error {
	// V1
	if !(c.WebSessionSlideSeconds < c.WebSessionIdleSeconds) {
		return fmt.Errorf("PM_WEB_SESSION_SLIDE must be less than PM_WEB_SESSION_IDLE")
	}
	// V2 — the liveness sweep loops on delay(idpRecheckIntervalSeconds). A zero or negative value
	// would either busy-loop the sweep (exhausting single-use refresh tokens and hammering the IdP) or
	// make delay() throw and permanently kill the SOLE revalidator. Refuse to start instead.
	if c.IdpRecheckIntervalSeconds <= 0 {
		return fmt.Errorf("PM_IDP_RECHECK_INTERVAL must be a positive number of seconds")
	}
	return nil
}

// MCPIssuer is the `mcpIssuer` derived value (Config.kt:111-115): the origin of MCPResource — scheme,
// host and port — with any trailing "/" stripped. NEVER inferred from request headers.
//
// DEVIATION: the Kotlin getter throws if MCPResource is unparseable. A Go getter has no error channel,
// so this returns "" in that case. Unreachable via FromEnv, which validates MCPResource under V10
// before it is ever stored; reachable only from a hand-built Config.
func (c Config) MCPIssuer() string {
	origin, err := mcpOrigin(c.MCPResource)
	if err != nil {
		return ""
	}
	return origin
}

// WebBaseURL is the `webBaseUrl` derived value (Config.kt:117-119): WebOrigin trimmed of surrounding
// whitespace and trailing slashes, falling back to MCPIssuer when that leaves nothing.
func (c Config) WebBaseURL() string {
	trimmed := strings.TrimRight(strings.TrimSpace(c.WebOrigin), "/")
	if strings.TrimSpace(trimmed) == "" {
		return c.MCPIssuer()
	}
	return trimmed
}

// QueryExchangeTimeoutMS is the `queryExchangeTimeoutMs` derived value (Config.kt:124-125): the outer
// per-statement exchange budget the run paths wait on. Overflow-safe because QueryTimeoutSeconds is
// bounded by V4.
func (c Config) QueryExchangeTimeoutMS() int64 {
	return c.QueryTimeoutSeconds*1000 + QueryExchangeGraceMS
}

// FromEnv reads the whole PM_* contract through the injected Lookup and returns a validated Config
// (Config.kt:151-254).
//
// 🔴 THE ORDER BELOW IS CONTRACTUAL, not cosmetic. Which rule fires first is observable whenever an
// environment violates more than one, and ConfigGuardTest relies on it — e.g. case 12 sets
// PM_AUTH_DEBUG=false with neither a session secret nor OIDC, and expects V6's message rather than
// V7's. The sequence mirrors Kotlin exactly: the OIDC block, then authDebug/sessionSecret/devMarker,
// then V10, then the query-timeout parse and V3/V4, then V5/V6/V7, then V8/V9, then the constructor
// arguments left-to-right (V11 among them), and finally the init block's V1/V2.
func FromEnv(env Lookup) (Config, error) {
	var zero Config

	// --- OIDC block (Config.kt:152-171). All four or nothing.
	var oidc *OIDCConfig
	issuer, hasIssuer := env("PM_OIDC_ISSUER")
	clientID, hasClientID := env("PM_OIDC_CLIENT_ID")
	clientSecret, hasClientSecret := env("PM_OIDC_CLIENT_SECRET")
	redirectURI, hasRedirectURI := env("PM_OIDC_REDIRECT_URI")
	if hasIssuer && hasClientID && hasClientSecret && hasRedirectURI {
		// offline_access → a refresh token, needed for the daemon's silent renewal and the
		// refresh-grant IdP liveness check (docs/auth-model.md). It is load-bearing, not decoration.
		scopes := envOr(env, "PM_OIDC_SCOPES", "openid profile email groups offline_access")
		oidc = &OIDCConfig{
			Issuer:       issuer,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
			Scopes:       scopes,
			GroupMapping: ParseOIDCGroupMapping(envPtr(env, "PM_OIDC_GROUP_MAP"), envPtr(env, "PM_OIDC_GROUP_PREFIX")),
		}
	}

	authDebug := envBoolStrict(env, "PM_AUTH_DEBUG", true)
	sessionSecret := envOr(env, "PM_SESSION_SECRET", devSessionSecret)
	devMarker := envBoolStrict(env, "PM_DEV", false)

	// --- V10 (Config.kt:175-178).
	mcpResource, err := canonicalMCPResource(
		envOr(env, "PM_MCP_RESOURCE", "http://127.0.0.1:8080/mcp"),
		!authDebug,
	)
	if err != nil {
		return zero, err
	}
	mcpIssuer, err := mcpOrigin(mcpResource)
	if err != nil {
		return zero, err
	}

	// --- PM_QUERY_TIMEOUT (Config.kt:182-191). A set-but-garbage value fails fast rather than
	// silently falling back to 600 — a misconfigured timeout must surface at boot, not be ignored.
	queryTimeoutSeconds := int64(600)
	if raw, ok := env("PM_QUERY_TIMEOUT"); ok {
		v, perr := parseInt64(raw)
		if perr != nil {
			return zero, fmt.Errorf("PM_QUERY_TIMEOUT must be a positive integer number of seconds; got '%s'", raw)
		}
		queryTimeoutSeconds = v
	}
	// V3
	if queryTimeoutSeconds <= 0 {
		return zero, fmt.Errorf("PM_QUERY_TIMEOUT must be greater than zero")
	}
	// V4 — reject what the proxy would also reject, so a set-but-oversized timeout fails fast at boot
	// instead of silently overflowing the millisecond exchange/run-stream conversions to a negative or
	// tiny cap (and diverging from the proxy's identical bound).
	//
	// ⚠️ F26 — REPRODUCE, do not fix. This overflow guard is the ONLY upper bound on PM_QUERY_TIMEOUT,
	// while the run token minted for a statement is separately clamped to TOKEN_MAX_TTL_SECONDS (24h)
	// inside TokenStore.issue. Above 86,220 s (23h57m) the two stop tracking each other and the token
	// expires MID-STATEMENT, so the query fails UNAUTHENTICATED on the proxy's revalidation. The honest
	// fix is a new V-rule clamping this to TOKEN_MAX_TTL_SECONDS − TOKEN_TTL_GRACE_SECONDS; the port
	// policy says that is a separate decision taken before or after cutover, never as part of it.
	// TestF26TimeoutLadderIsNotTotal pins the defect. See 00-INDEX.md F26 and 01-bootstrap.md §4.
	if queryTimeoutSeconds > MaxQueryTimeoutSeconds {
		return zero, fmt.Errorf("PM_QUERY_TIMEOUT must be at most %d seconds; got '%d'", MaxQueryTimeoutSeconds, queryTimeoutSeconds)
	}

	// --- V5 🔒 (Config.kt:199-202). PM_AUTH_DEBUG is a full authentication bypass (/auth/debug and the
	// dev-resolved device flow set any principal) and defaults ON for local dev. Heuristically detect a
	// production-LOOKING context — real OIDC configured, or a real (non-default) session secret — and
	// refuse to start with debug auth on unless PM_DEV explicitly opts in. The heuristic can't be
	// perfect, but it stops the common "forgot to unset PM_AUTH_DEBUG in prod" mistake.
	if !(!authDebug || devMarker || (oidc == nil && sessionSecret == devSessionSecret)) {
		return zero, fmt.Errorf("PM_AUTH_DEBUG on in a production-looking context (PM_OIDC_* or PM_SESSION_SECRET set) without PM_DEV — refusing to start")
	}
	// --- V6 🔒 (Config.kt:203-205).
	if !(authDebug || (sessionSecret != devSessionSecret && utf16Len(sessionSecret) >= 32)) {
		return zero, fmt.Errorf("PM_SESSION_SECRET must be a non-default secret of at least 32 characters when PM_AUTH_DEBUG is false")
	}
	// --- V7 🔒 (Config.kt:206).
	if !(authDebug || oidc != nil) {
		return zero, fmt.Errorf("PM_OIDC_* must be configured when PM_AUTH_DEBUG is false")
	}
	if !authDebug {
		// --- V8 🔒
		if err := requireSecureOIDCURI(oidc.Issuer, "PM_OIDC_ISSUER"); err != nil {
			return zero, err
		}
		// --- V9 🔒 — the callback is CO-HOSTED, so the redirect URI is fully determined by mcpIssuer.
		if oidc.RedirectURI != mcpIssuer+"/auth/oidc/callback" {
			return zero, fmt.Errorf("PM_OIDC_REDIRECT_URI must equal the co-hosted control-plane callback URI")
		}
	}

	// --- Constructor arguments, evaluated left-to-right exactly as Kotlin does (Config.kt:214-253).
	cfg := Config{
		HTTPPort:      envIntOr(env, "PM_HTTP_PORT", 8080),
		GRPCPort:      envIntOr(env, "PM_GRPC_PORT", DefaultGRPCPort),
		DBURL:         envOr(env, "PM_DB_URL", "jdbc:postgresql://localhost:5432/proxymonster"),
		DBUser:        envOr(env, "PM_DB_USER", "proxymonster"),
		DBPassword:    envOr(env, "PM_DB_PASSWORD", "proxymonster"),
		AuthDebug:     authDebug,
		SecretToken:   envPtr(env, "PM_SECRET_TOKEN"),
		SessionSecret: sessionSecret,
		OIDC:          oidc,
	}
	// --- V11 (Config.kt:224-228).
	if raw, ok := env("PM_RESULT_KEY"); ok {
		key, kerr := decodeBase64Key(strings.TrimSpace(raw))
		if kerr != nil || len(key) != 32 {
			return zero, fmt.Errorf("PM_RESULT_KEY must be a base64-encoded 32-byte (AES-256) key")
		}
		cfg.ResultKey = key
	}
	cfg.ScimToken = envPtr(env, "PM_SCIM_TOKEN")
	if cfg.SessionWindowSeconds, err = envDurationOr(env, "PM_SESSION_WINDOW", 2*3600); err != nil {
		return zero, err
	}
	if cfg.WebSessionAbsoluteSeconds, err = envDurationOr(env, "PM_WEB_SESSION_ABSOLUTE", 2*3600); err != nil {
		return zero, err
	}
	if cfg.WebSessionIdleSeconds, err = envDurationOr(env, "PM_WEB_SESSION_IDLE", 15*60); err != nil {
		return zero, err
	}
	if cfg.WebSessionSlideSeconds, err = envDurationOr(env, "PM_WEB_SESSION_SLIDE", 2*60); err != nil {
		return zero, err
	}
	if cfg.WebSessionIdleWarnLeadSeconds, err = envDurationOr(env, "PM_WEB_SESSION_IDLE_WARN_LEAD", 60); err != nil {
		return zero, err
	}
	if cfg.WebSessionAbsoluteWarnLeadSeconds, err = envDurationOr(env, "PM_WEB_SESSION_ABSOLUTE_WARN_LEAD", 5*60); err != nil {
		return zero, err
	}
	if cfg.WebSessionHeartbeatSeconds, err = envDurationOr(env, "PM_WEB_SESSION_HEARTBEAT", 90); err != nil {
		return zero, err
	}
	// PM_IDP_RECHECK_INTERVAL uses toLong, NOT parseDuration (01-bootstrap.md §1) — so "5m" is a hard
	// failure here while it is legal for every PM_WEB_SESSION_* var. REPRODUCE the inconsistency.
	// Kotlin's toLong throws NumberFormatException (an IllegalArgumentException) on garbage.
	cfg.IdpRecheckIntervalSeconds = 300
	if raw, ok := env("PM_IDP_RECHECK_INTERVAL"); ok {
		v, perr := parseInt64(raw)
		if perr != nil {
			return zero, fmt.Errorf("PM_IDP_RECHECK_INTERVAL is not a number: '%s'", raw)
		}
		cfg.IdpRecheckIntervalSeconds = v
	}
	cfg.DevMarker = devMarker
	// `PM_TRUSTED_PROXIES = 10.0.0.1,10.0.0.2` — comma-separated socket-peer addresses (the same
	// split/trim/filter-blank shape as OidcGroupMapping.parse). Unset or empty ⇒ no trusted edge.
	cfg.TrustedProxies = parseTrustedProxies(envOr(env, "PM_TRUSTED_PROXIES", ""))
	cfg.MCPResource = mcpResource
	cfg.WebOrigin = envOr(env, "PM_WEB_ORIGIN", "")
	// INV-A14-3: this is the FIRST of two deliberate clamps; the token store clamps again at insert.
	// A garbage value falls back to the default and is then clamped — unlike PM_QUERY_TIMEOUT, which
	// throws. REPRODUCE the asymmetry.
	cfg.MCPAccessTTLSeconds = clampTTLSeconds(envInt64Or(env, "PM_OAUTH_ACCESS_TTL", 600))
	cfg.MCPRefreshTTLSeconds = clampTTLSeconds(envInt64Or(env, "PM_OAUTH_REFRESH_TTL", 21_600))
	cfg.MCPDebugAutoConsent = envBoolStrict(env, "PM_OAUTH_DEBUG_AUTO_CONSENT", true)
	cfg.QueryTimeoutSeconds = queryTimeoutSeconds

	// --- init block: V1 then V2.
	if err := cfg.Validate(); err != nil {
		return zero, err
	}
	return cfg, nil
}

func parseTrustedProxies(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, entry := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}

// decodeBase64Key reproduces java.util.Base64.getDecoder().decode.
//
// DEVIATION, narrow and deliberate: Java's BASIC decoder accepts input whose padding is omitted, while
// Go's StdEncoding requires it and RawStdEncoding forbids it. Trying padded first and unpadded second
// covers both, which is what the Java decoder does. Java additionally rejects any character outside
// the standard alphabet, as both Go encodings do.
func decodeBase64Key(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// utf16Len counts UTF-16 code units, which is what Kotlin's String.length returns. V6's "at least 32
// characters" is therefore a code-unit count, not a byte count and not a rune count: a 32-character
// secret of emoji is 64 units long in Kotlin and 128 bytes long in Go. Counting units keeps the
// security check identical on every input.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += len(utf16.Encode([]rune{r}))
	}
	return n
}

// --- Lookup adapters. Each mirrors one Kotlin idiom on the injected `env` lambda.

// envOr is `env("K") ?: default`.
func envOr(env Lookup, key, def string) string {
	if v, ok := env(key); ok {
		return v
	}
	return def
}

// envPtr is `env("K")` kept nullable — for the fields where unset is meaningful (PM_SECRET_TOKEN's
// open gate, PM_SCIM_TOKEN's fail-closed disable).
func envPtr(env Lookup, key string) *string {
	if v, ok := env(key); ok {
		return &v
	}
	return nil
}

// envBoolStrict is `env("K")?.toBooleanStrictOrNull() ?: default`.
//
// ⚠️ Kotlin's toBooleanStrictOrNull is CASE-SENSITIVE: only the exact words "true" and "false" parse;
// everything else, "TRUE" and "True" included, yields null and therefore the default. So PM_DEV=TRUE
// silently means false while PM_AUTH_DEBUG=TRUE silently means true — because their defaults differ,
// not because the parser does. REPRODUCE.
func envBoolStrict(env Lookup, key string, def bool) bool {
	v, ok := env(key)
	if !ok {
		return def
	}
	switch v {
	case "true":
		return true
	case "false":
		return false
	default:
		return def
	}
}

// envIntOr is `env("K")?.toIntOrNull() ?: default` — an invalid value falls back to the default
// silently, which is deliberate for the two ports and NOT what PM_QUERY_TIMEOUT does.
func envIntOr(env Lookup, key string, def int) int {
	v, ok := env(key)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return def
	}
	return int(n)
}

// envInt64Or is `env("K")?.toLongOrNull() ?: default`.
func envInt64Or(env Lookup, key string, def int64) int64 {
	v, ok := env(key)
	if !ok {
		return def
	}
	n, err := parseInt64(v)
	if err != nil {
		return def
	}
	return n
}

// envDurationOr is `env("K")?.let(::parseDuration) ?: default` — present-but-malformed FAILS, it does
// not fall back.
func envDurationOr(env Lookup, key string, def int64) (int64, error) {
	v, ok := env(key)
	if !ok {
		return def, nil
	}
	return ParseDuration(v)
}

// parseInt64 is Kotlin's String.toLong / toLongOrNull: base 10, an optional leading sign, no
// surrounding whitespace and no underscores. Go's ParseInt agrees on all four.
func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
