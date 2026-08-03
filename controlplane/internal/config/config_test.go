package config

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ConfigGuardTest.kt — 356 LOC, 25 cases, pure unit (injected env lambda, no DB).
//
// Ported 1:1 from
// control-plane/src/test/kotlin/com/ridi/oss/proxymonster/controlplane/ConfigGuardTest.kt. Every test
// below carries the Kotlin case name verbatim in a comment plus its number from 01-bootstrap.md §4,
// so the two suites map onto each other by inspection. Assertions, env tables and loop bounds are the
// Kotlin's; nothing was added to or dropped from a case.
//
// Kotlin's file-level doc: "The fail-closed PM_AUTH_DEBUG guard (docs/auth-model.md 'Security
// invariants' — 'PM_AUTH_DEBUG MUST be off in production ... refuse to start with it on unless a
// PM_DEV marker is set') plus the plain OIDC/session-window/SCIM env parsing in Config.fromEnv. Pure —
// no DB, no network."
//
// Two tests below the 25 are marked ADDED and say why.

// envOf is ConfigGuardTest.kt:17-20.
func envOf(pairs ...string) Lookup {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return EnvOf(m)
}

// productionEnv is ConfigGuardTest.kt:22-31 — a complete debug-off deployment, with the caller's pairs
// applied LAST so they override (Kotlin's `pairs.toMap()` keeps the final duplicate).
func productionEnv(pairs ...string) Lookup {
	base := []string{
		"PM_AUTH_DEBUG", "false",
		"PM_MCP_RESOURCE", "https://proxy.example.com/mcp",
		"PM_SESSION_SECRET", strings.Repeat("x", 32),
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		"PM_OIDC_REDIRECT_URI", "https://proxy.example.com/auth/oidc/callback",
	}
	return envOf(append(base, pairs...)...)
}

func mustFromEnv(t *testing.T, env Lookup) Config {
	t.Helper()
	cfg, err := FromEnv(env)
	if err != nil {
		t.Fatalf("FromEnv: unexpected error: %v", err)
	}
	return cfg
}

func mustFailFromEnv(t *testing.T, env Lookup, what string) {
	t.Helper()
	if _, err := FromEnv(env); err == nil {
		t.Fatalf("FromEnv(%s): expected a failure, got none", what)
	}
}

func sortedKeys(set map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(set))
}

func assertSet(t *testing.T, got map[string]struct{}, want []string, msg string) {
	t.Helper()
	if !slices.Equal(sortedKeys(got), want) {
		t.Errorf("%s: got %v, want %v", msg, sortedKeys(got), want)
	}
}

// --- Case 1 · `bare defaults boot fine (local dev, debug on, dev secret, no oidc)`
func TestBareDefaultsBootFine(t *testing.T) {
	config := mustFromEnv(t, envOf())
	if !config.AuthDebug {
		t.Error("authDebug should default to true")
	}
	if config.OIDC != nil {
		t.Error("oidc should be nil with no PM_OIDC_* set")
	}
	assertSet(t, config.TrustedProxies, nil,
		"no PM_TRUSTED_PROXIES -> no trusted edge -> X-Forwarded-For never honored")
}

// --- Case 2 · `debug mode leaves oidc null unless all four required fields are present`
func TestDebugModeLeavesOidcNullUnlessAllFourPresent(t *testing.T) {
	debugEnv := []string{"PM_AUTH_DEBUG", "true", "PM_DEV", "true"}
	if cfg := mustFromEnv(t, envOf(append(slices.Clone(debugEnv),
		"PM_OIDC_ISSUER", "https://idp.example.com")...)); cfg.OIDC != nil {
		t.Error("issuer alone must not produce an OidcConfig")
	}
	if cfg := mustFromEnv(t, envOf(append(slices.Clone(debugEnv),
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		// redirect_uri missing
	)...)); cfg.OIDC != nil {
		t.Error("three of four must not produce an OidcConfig")
	}
}

// --- Case 3 · `oidc scopes default to openid profile email groups offline_access`
func TestOidcScopesDefault(t *testing.T) {
	config := mustFromEnv(t, productionEnv(
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		"PM_OIDC_REDIRECT_URI", "https://proxy.example.com/auth/oidc/callback",
	))
	if got := config.OIDC.Scopes; got != "openid profile email groups offline_access" {
		t.Errorf("scopes: got %q", got)
	}
	if !strings.Contains(config.OIDC.Scopes, "offline_access") {
		t.Error("device-flow session-renewal needs a refresh token")
	}
}

// --- Case 4 · `oidc scopes are overridable via PM_OIDC_SCOPES`
func TestOidcScopesOverridable(t *testing.T) {
	config := mustFromEnv(t, productionEnv(
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		"PM_OIDC_REDIRECT_URI", "https://proxy.example.com/auth/oidc/callback",
		"PM_OIDC_SCOPES", "openid email",
	))
	if got := config.OIDC.Scopes; got != "openid email" {
		t.Errorf("scopes: got %q, want %q", got, "openid email")
	}
}

// --- Case 5 🔒 · `debug on plus real oidc config without PM_DEV refuses to start` (V5)
func TestDebugOnPlusRealOidcWithoutDevMarkerRefuses(t *testing.T) {
	mustFailFromEnv(t, envOf(
		"PM_AUTH_DEBUG", "true",
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		"PM_OIDC_REDIRECT_URI", "https://app.example.com/auth/oidc/callback",
	), "debug on + real oidc, no PM_DEV")
}

// --- Case 6 🔒 · `debug on plus a real session secret without PM_DEV refuses to start` (V5)
func TestDebugOnPlusRealSessionSecretWithoutDevMarkerRefuses(t *testing.T) {
	mustFailFromEnv(t, envOf(
		"PM_AUTH_DEBUG", "true",
		"PM_SESSION_SECRET", "a-real-production-secret",
	), "debug on + real session secret, no PM_DEV")
}

// --- Case 7 🔒 · `debug on plus a production-looking context WITH PM_DEV is allowed` (V5's escape)
func TestDebugOnProductionLookingWithDevMarkerIsAllowed(t *testing.T) {
	config := mustFromEnv(t, envOf(
		"PM_AUTH_DEBUG", "true",
		"PM_DEV", "true",
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		"PM_OIDC_REDIRECT_URI", "https://proxy.example.com/auth/oidc/callback",
		"PM_SESSION_SECRET", strings.Repeat("x", 32),
	))
	if !config.AuthDebug {
		t.Error("authDebug")
	}
	if !config.DevMarker {
		t.Error("devMarker")
	}
	if config.OIDC == nil {
		t.Error("oidc should be populated")
	}
}

// --- Case 8 · `debug off is always allowed, even with real oidc + session secret` (V5)
func TestDebugOffIsAlwaysAllowed(t *testing.T) {
	config := mustFromEnv(t, productionEnv(
		"PM_OIDC_ISSUER", "https://idp.example.com",
		"PM_OIDC_CLIENT_ID", "cid",
		"PM_OIDC_CLIENT_SECRET", "secret",
		"PM_OIDC_REDIRECT_URI", "https://proxy.example.com/auth/oidc/callback",
		"PM_SESSION_SECRET", strings.Repeat("x", 32),
	))
	if config.AuthDebug {
		t.Error("authDebug should be false")
	}
	if config.OIDC == nil {
		t.Error("oidc should be populated")
	}
}

// --- Case 9 🔒 · `debug off rejects the public development session secret` (V6)
func TestDebugOffRejectsDevelopmentSessionSecret(t *testing.T) {
	mustFailFromEnv(t, envOf(
		"PM_AUTH_DEBUG", "false",
		"PM_MCP_RESOURCE", "https://proxy.example.com/mcp",
	), "debug off with the default dev session secret")
}

// --- Case 10 🔒 · `debug off requires complete secure oidc config on the co-hosted callback`
// (V7 missing OIDC · V8 plaintext issuer · V9 foreign redirect URI)
func TestDebugOffRequiresCompleteSecureOidcOnCoHostedCallback(t *testing.T) {
	mustFailFromEnv(t, envOf(
		"PM_AUTH_DEBUG", "false",
		"PM_MCP_RESOURCE", "https://proxy.example.com/mcp",
		"PM_SESSION_SECRET", strings.Repeat("x", 32),
	), "V7: no PM_OIDC_* at all")
	mustFailFromEnv(t, productionEnv("PM_OIDC_ISSUER", "http://idp.example.com"),
		"V8: plaintext issuer")
	mustFailFromEnv(t, productionEnv("PM_OIDC_REDIRECT_URI", "https://other.example.com/auth/oidc/callback"),
		"V9: redirect URI that is not the co-hosted callback")
}

// --- Case 11 🔒 · `debug off requires secure canonical MCP origins` (V10)
func TestDebugOffRequiresSecureCanonicalMcpOrigins(t *testing.T) {
	mustFailFromEnv(t, productionEnv("PM_MCP_RESOURCE", "http://proxy.example.com/mcp"),
		"V10: plaintext MCP resource with debug off")

	config := mustFromEnv(t, productionEnv("PM_MCP_RESOURCE", "https://PROXY.EXAMPLE.COM/mcp"))
	if got := config.MCPResource; got != "https://proxy.example.com/mcp" {
		t.Errorf("mcpResource: got %q, want %q", got, "https://proxy.example.com/mcp")
	}
	if got := config.MCPIssuer(); got != "https://proxy.example.com" {
		t.Errorf("mcpIssuer: got %q, want %q", got, "https://proxy.example.com")
	}
}

// --- Case 12 · `session window, web clocks, idp recheck interval, and scim token default sanely`
func TestSessionWindowWebClocksRecheckAndScimDefaults(t *testing.T) {
	config := mustFromEnv(t, envOf())
	for _, c := range []struct {
		name string
		got  int64
		want int64
	}{
		{"sessionWindowSeconds", config.SessionWindowSeconds, 2 * 3600},
		{"webSessionAbsoluteSeconds", config.WebSessionAbsoluteSeconds, 2 * 3600},
		{"webSessionIdleSeconds", config.WebSessionIdleSeconds, 900},
		{"webSessionSlideSeconds", config.WebSessionSlideSeconds, 120},
		{"webSessionIdleWarnLeadSeconds", config.WebSessionIdleWarnLeadSeconds, 60},
		{"webSessionAbsoluteWarnLeadSeconds", config.WebSessionAbsoluteWarnLeadSeconds, 300},
		{"webSessionHeartbeatSeconds", config.WebSessionHeartbeatSeconds, 90},
		{"idpRecheckIntervalSeconds", config.IdpRecheckIntervalSeconds, 300},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}
	if config.ScimToken != nil {
		t.Error("scimToken should be nil (SCIM disabled fail-closed)")
	}
	if config.DevMarker {
		t.Error("devMarker should default to false")
	}
}

// --- Case 13 · `session window, idp recheck interval, and scim token are overridable`
func TestSessionWindowRecheckAndScimOverridable(t *testing.T) {
	config := mustFromEnv(t, envOf(
		"PM_SESSION_WINDOW", "3600",
		"PM_IDP_RECHECK_INTERVAL", "60",
		"PM_SCIM_TOKEN", "a-standing-scim-secret",
	))
	if config.SessionWindowSeconds != 3600 {
		t.Errorf("sessionWindowSeconds: got %d", config.SessionWindowSeconds)
	}
	if config.IdpRecheckIntervalSeconds != 60 {
		t.Errorf("idpRecheckIntervalSeconds: got %d", config.IdpRecheckIntervalSeconds)
	}
	if config.ScimToken == nil || *config.ScimToken != "a-standing-scim-secret" {
		t.Errorf("scimToken: got %v", config.ScimToken)
	}
}

// --- Case 14 · `web idle and slide durations accept units and plain seconds`
func TestWebIdleAndSlideAcceptUnitsAndPlainSeconds(t *testing.T) {
	config := mustFromEnv(t, envOf(
		"PM_WEB_SESSION_IDLE", "15m",
		"PM_WEB_SESSION_SLIDE", "120",
	))
	if config.WebSessionIdleSeconds != 900 {
		t.Errorf("idle: got %d, want 900", config.WebSessionIdleSeconds)
	}
	if config.WebSessionSlideSeconds != 120 {
		t.Errorf("slide: got %d, want 120", config.WebSessionSlideSeconds)
	}
	both := mustFromEnv(t, envOf("PM_WEB_SESSION_IDLE", "15m", "PM_WEB_SESSION_SLIDE", "2m"))
	if both.WebSessionSlideSeconds != 120 {
		t.Errorf("slide from 2m: got %d, want 120", both.WebSessionSlideSeconds)
	}
}

// --- Case 15 · `web session absolute duration accepts seconds and concatenated units`
func TestWebSessionAbsoluteAcceptsSecondsAndConcatenatedUnits(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int64
	}{{"2h", 7200}, {"1h30m", 5400}, {"900", 900}} {
		got := mustFromEnv(t, envOf("PM_WEB_SESSION_ABSOLUTE", c.raw)).WebSessionAbsoluteSeconds
		if got != c.want {
			t.Errorf("PM_WEB_SESSION_ABSOLUTE=%q: got %d, want %d", c.raw, got, c.want)
		}
	}
	if got, err := ParseDuration("90s"); err != nil || got != 90 {
		t.Errorf(`ParseDuration("90s"): got %d, %v`, got, err)
	}
	if got, err := ParseDuration("15m"); err != nil || got != 900 {
		t.Errorf(`ParseDuration("15m"): got %d, %v`, got, err)
	}
}

// --- Case 16 · `web session UX timings accept duration units`
func TestWebSessionUxTimingsAcceptDurationUnits(t *testing.T) {
	config := mustFromEnv(t, envOf(
		"PM_WEB_SESSION_IDLE_WARN_LEAD", "2m",
		"PM_WEB_SESSION_ABSOLUTE_WARN_LEAD", "10m",
		"PM_WEB_SESSION_HEARTBEAT", "45s",
	))
	if config.WebSessionIdleWarnLeadSeconds != 120 {
		t.Errorf("idleWarnLead: got %d", config.WebSessionIdleWarnLeadSeconds)
	}
	if config.WebSessionAbsoluteWarnLeadSeconds != 600 {
		t.Errorf("absoluteWarnLead: got %d", config.WebSessionAbsoluteWarnLeadSeconds)
	}
	if config.WebSessionHeartbeatSeconds != 45 {
		t.Errorf("heartbeat: got %d", config.WebSessionHeartbeatSeconds)
	}
}

// --- Case 17 · `web session slide must be strictly less than idle` (V1)
func TestWebSessionSlideMustBeStrictlyLessThanIdle(t *testing.T) {
	mustFailFromEnv(t, envOf("PM_WEB_SESSION_IDLE", "2m", "PM_WEB_SESSION_SLIDE", "2m"), "slide == idle")
	mustFailFromEnv(t, envOf("PM_WEB_SESSION_IDLE", "2m", "PM_WEB_SESSION_SLIDE", "3m"), "slide > idle")
	if got := mustFromEnv(t, envOf("PM_WEB_SESSION_IDLE", "2m", "PM_WEB_SESSION_SLIDE", "119")).
		WebSessionSlideSeconds; got != 119 {
		t.Errorf("slide one second under idle: got %d, want 119", got)
	}
	// Kotlin's fourth assertion is `Config.fromEnv(envOf()).copy(slide = 900, idle = 900)` throwing —
	// i.e. the data class's init block re-running on copy(). Go has no constructor hook, so the port
	// mutates a copy and calls Validate(), which IS that init block.
	mutated := mustFromEnv(t, envOf())
	mutated.WebSessionSlideSeconds = 900
	mutated.WebSessionIdleSeconds = 900
	if err := mutated.Validate(); err == nil {
		t.Error("Validate() on slide == idle == 900: expected a failure, got none")
	}
}

// --- Case 18 · `malformed web session durations fail fast`
func TestMalformedWebSessionDurationsFailFast(t *testing.T) {
	for _, name := range []string{
		"PM_WEB_SESSION_ABSOLUTE",
		"PM_WEB_SESSION_IDLE",
		"PM_WEB_SESSION_SLIDE",
		"PM_WEB_SESSION_IDLE_WARN_LEAD",
		"PM_WEB_SESSION_ABSOLUTE_WARN_LEAD",
		"PM_WEB_SESSION_HEARTBEAT",
	} {
		for _, raw := range []string{"2x", "", "-1h"} {
			mustFailFromEnv(t, envOf(name, raw), name+"="+strconv.Quote(raw))
		}
	}
}

// --- Case 19 · `idp recheck interval must be positive` (V2)
func TestIdpRecheckIntervalMustBePositive(t *testing.T) {
	// Zero would busy-loop the liveness sweep; a negative value makes delay() throw and kills it.
	mustFailFromEnv(t, envOf("PM_IDP_RECHECK_INTERVAL", "0"), "recheck interval 0")
	mustFailFromEnv(t, envOf("PM_IDP_RECHECK_INTERVAL", "-1"), "recheck interval -1")
}

// --- Case 20 · `PM_TRUSTED_PROXIES parses comma-separated entries, trimmed, with blanks dropped`
func TestTrustedProxiesParsing(t *testing.T) {
	assertSet(t, mustFromEnv(t, envOf("PM_TRUSTED_PROXIES", " 10.0.0.1 , 10.0.0.2 ,, ")).TrustedProxies,
		[]string{"10.0.0.1", "10.0.0.2"}, "trimmed, blanks dropped")
	assertSet(t, mustFromEnv(t, envOf("PM_TRUSTED_PROXIES", "10.0.0.1")).TrustedProxies,
		[]string{"10.0.0.1"}, "single entry")
	assertSet(t, mustFromEnv(t, envOf("PM_TRUSTED_PROXIES", "")).TrustedProxies, nil, "empty value")
	assertSet(t, mustFromEnv(t, envOf("PM_TRUSTED_PROXIES", "  ,  ")).TrustedProxies, nil, "blanks only")
}

// --- Case 21 · `PM_QUERY_TIMEOUT defaults overrides and rejects invalid values` (V3)
func TestQueryTimeoutDefaultsOverridesAndRejects(t *testing.T) {
	if got := mustFromEnv(t, envOf()).QueryTimeoutSeconds; got != 600 {
		t.Errorf("default: got %d, want 600", got)
	}
	if got := mustFromEnv(t, envOf("PM_QUERY_TIMEOUT", "45")).QueryTimeoutSeconds; got != 45 {
		t.Errorf("override: got %d, want 45", got)
	}
	mustFailFromEnv(t, envOf("PM_QUERY_TIMEOUT", "0"), "zero")
	mustFailFromEnv(t, envOf("PM_QUERY_TIMEOUT", "-1"), "negative")
	// A set-but-non-numeric value fails fast rather than silently defaulting to 600.
	mustFailFromEnv(t, envOf("PM_QUERY_TIMEOUT", "abc"), "non-numeric")
}

// --- Case 22 · `PM_QUERY_TIMEOUT is bounded to the proxy's duration-safe ceiling (no ms overflow)` (V4)
func TestQueryTimeoutBoundedToProxyCeiling(t *testing.T) {
	// The shared CP+proxy maximum: accepted here, rejected one above. Keeps queryExchangeTimeoutMs and
	// the run-stream cap from overflowing int64, and keeps the lockstep contract with goproxy exact.
	maxText := strconv.FormatInt(MaxQueryTimeoutSeconds, 10)
	if got := mustFromEnv(t, envOf("PM_QUERY_TIMEOUT", maxText)).QueryTimeoutSeconds; got != MaxQueryTimeoutSeconds {
		t.Errorf("at the ceiling: got %d, want %d", got, MaxQueryTimeoutSeconds)
	}
	// The accepted maximum still converts to a positive millisecond exchange budget.
	maxCfg := mustFromEnv(t, envOf("PM_QUERY_TIMEOUT", maxText))
	if maxCfg.QueryExchangeTimeoutMS() <= 0 {
		t.Errorf("queryExchangeTimeoutMs at the ceiling: got %d, want > 0", maxCfg.QueryExchangeTimeoutMS())
	}
	mustFailFromEnv(t, envOf("PM_QUERY_TIMEOUT", strconv.FormatInt(MaxQueryTimeoutSeconds+1, 10)), "ceiling + 1")
	mustFailFromEnv(t, envOf("PM_QUERY_TIMEOUT", "9223372036854775807"), "int64 max")
}

// --- Case 23 · `the exchange budget outlives the proxy's own statement watchdog`
func TestExchangeBudgetOutlivesProxyWatchdog(t *testing.T) {
	// The proxy aborts a statement at PM_QUERY_TIMEOUT. This bound sits outside that one, so it has to
	// fire later — otherwise the control plane reports a timeout for a query the proxy goes on to
	// finish, and the two ends disagree about whether it ran.
	for _, timeout := range []int64{1, 600, 3600, MaxQueryTimeoutSeconds} {
		config := mustFromEnv(t, envOf("PM_QUERY_TIMEOUT", strconv.FormatInt(timeout, 10)))
		if !(config.QueryExchangeTimeoutMS() > timeout*1000) {
			t.Errorf("exchange budget must outlast the proxy watchdog for timeout=%d: %d vs %d",
				timeout, config.QueryExchangeTimeoutMS(), timeout*1000)
		}
	}
}

// --- Case 24 · `the run stream outlives the dial and exchange it wraps`
func TestRunStreamOutlivesDialAndExchange(t *testing.T) {
	// The stream opens before the proxy reports ready, so its lifetime spans BOTH the dial and the
	// statement exchange. If it expires first the control plane tears down a statement that is still
	// legitimately running, and the caller sees a stream-closed error instead of a timeout. The margin
	// is arithmetic across three files, so pin it here rather than leave it to inspection.
	for _, timeout := range []int64{1, 600, 840, 3600, MaxQueryTimeoutSeconds} {
		config := mustFromEnv(t, envOf("PM_QUERY_TIMEOUT", strconv.FormatInt(timeout, 10)))
		streamTimeout := RunStreamTimeoutMS(config.QueryExchangeTimeoutMS())
		if !(streamTimeout > DialTimeoutMS+config.QueryExchangeTimeoutMS()) {
			t.Errorf("run stream (%d ms) must outlive dial + exchange (%d ms) for timeout=%d",
				streamTimeout, DialTimeoutMS+config.QueryExchangeTimeoutMS(), timeout)
		}
	}
}

// A7's two pure TTL formulas, from 07-tasks-approvals-results.md:426:
//
//	runTokenTtlSeconds(q)     = max(900, q + TOKEN_TTL_GRACE_SECONDS)
//	editorSessionTtlSeconds(q) = max(8h,  q + TOKEN_TTL_GRACE_SECONDS)
//
// TODO(A7): these live on RunExecService (RunExec.kt) and are reproduced here ONLY so case 25 can be
// ported in this increment. When A7 lands, delete them and rebind case 25 and the F26 pin to the real
// symbols — a test asserting its own local copy of a formula proves nothing about the shipped one.
const tokenTTLGraceSeconds int64 = 180

func a7RunTokenTTLSeconds(queryTimeoutSeconds int64) int64 {
	return max(900, queryTimeoutSeconds+tokenTTLGraceSeconds)
}

func a7EditorSessionTTLSeconds(queryTimeoutSeconds int64) int64 {
	return max(8*3600, queryTimeoutSeconds+tokenTTLGraceSeconds)
}

// --- Case 25 ⚠️ · `run token TTL always outlives the configured query window`
//
// 🔴 The Kotlin case name's "always" is FALSE — index finding F26. This test asserts the PURE
// FUNCTIONS, exactly as ConfigGuardTest.kt:65-79 does, and it passes at every PM_QUERY_TIMEOUT
// including the ceiling. What it never touches is the value actually persisted to
// proxy_token.expires_at, which TokenStore.issue clamps. TestF26TimeoutLadderIsNotTotal below pins
// the gap the "always" hides. Ported as-is: reproducing a weak test is part of reproducing the
// system, and strengthening it here would hide the finding instead of recording it.
func TestRunTokenTTLOutlivesConfiguredQueryWindow(t *testing.T) {
	// The one-shot run token and the editor-session token must both stay valid for at least the full
	// PM_QUERY_TIMEOUT window a single statement may run for, else a long query fails UNAUTHENTICATED
	// mid-run when the proxy revalidates the token.
	for _, timeout := range []int64{1, 600, 3600, 36_000, MaxQueryTimeoutSeconds} {
		if !(a7RunTokenTTLSeconds(timeout) > timeout) {
			t.Errorf("run token TTL must exceed the query window for timeout=%d", timeout)
		}
		if !(a7EditorSessionTTLSeconds(timeout) > timeout) {
			t.Errorf("editor session TTL must exceed the query window for timeout=%d", timeout)
		}
	}
}

// --- ADDED (not one of the 25) · F26 PIN, per 00-INDEX.md's REPRODUCE + PIN disposition.
//
// 🔒 F26: the timeout ladder is NOT total. runTokenTtlSeconds reaches TokenStore.issue, which clamps
// it through clampTtlSeconds to TOKEN_MAX_TTL_SECONDS (24h), while PM_QUERY_TIMEOUT is bounded only by
// V4's overflow guard (9,223,372,006). Above 86,220 s (23h57m) the STORED token expiry stops tracking
// the query window and the token expires mid-statement — the query then fails UNAUTHENTICATED on the
// proxy's mid-run revalidation.
//
// This test asserts the BUGGY behaviour on purpose. A later fix — clamping PM_QUERY_TIMEOUT to
// TOKEN_MAX_TTL_SECONDS − TOKEN_TTL_GRACE_SECONDS at parse time, which is the honest one — has to
// change this test deliberately and visibly instead of silently passing. See 00-INDEX.md F26,
// 01-bootstrap.md §4 case 25 and 99-reconciliation-report.md §F26.
func TestF26TimeoutLadderIsNotTotal(t *testing.T) {
	// FromEnv accepts every one of these: V4's ceiling is the only upper bound, and no V-rule ties
	// PM_QUERY_TIMEOUT to the token cap.
	for _, c := range []struct {
		queryTimeout int64
		storedTTL    int64
		outlives     bool // does the STORED expiry still outlive the query window?
	}{
		{600, 900, true},
		{86_220, 86_400, true},  // 23h57m — the last point the full grace holds
		{86_300, 86_400, true},  // grace silently eroded to +100s
		{86_400, 86_400, false}, // the token dies exactly at the timeout
		{86_401, 86_400, false}, // and past it, mid-statement
		{MaxQueryTimeoutSeconds, 86_400, false},
	} {
		cfg, err := FromEnv(envOf("PM_QUERY_TIMEOUT", strconv.FormatInt(c.queryTimeout, 10)))
		if err != nil {
			t.Fatalf("PM_QUERY_TIMEOUT=%d must be ACCEPTED (no V-rule bounds it to the token cap): %v",
				c.queryTimeout, err)
		}
		stored := clampTTLSeconds(a7RunTokenTTLSeconds(cfg.QueryTimeoutSeconds))
		if stored != c.storedTTL {
			t.Errorf("stored TTL for PM_QUERY_TIMEOUT=%d: got %d, want %d", c.queryTimeout, stored, c.storedTTL)
		}
		if got := stored > cfg.QueryTimeoutSeconds; got != c.outlives {
			t.Errorf("PM_QUERY_TIMEOUT=%d: stored TTL outlives the window = %v, want %v (F26)",
				c.queryTimeout, got, c.outlives)
		}
		// The pure function the Kotlin case 25 asserts stays true throughout — which is exactly why
		// case 25 passes while the deployment breaks.
		if !(a7RunTokenTTLSeconds(cfg.QueryTimeoutSeconds) > cfg.QueryTimeoutSeconds) {
			t.Errorf("the PURE function should still outlive the window for %d", c.queryTimeout)
		}
	}
}

// --- ADDED (not one of the 25) · the four derived values of 01-bootstrap.md §1.
//
// ConfigGuardTest touches mcpIssuer once (case 11) and queryExchangeTimeoutMs / runStreamTimeoutMs
// only through the ladder cases; webBaseUrl has NO Kotlin coverage at all. The derived values are in
// this increment's scope, and webBaseUrl's trim-then-fallback is exactly the shape a port gets subtly
// wrong, so pin all four here.
func TestDerivedValues(t *testing.T) {
	base := mustFromEnv(t, envOf())
	if got := base.MCPResource; got != "http://127.0.0.1:8080/mcp" {
		t.Errorf("default mcpResource: got %q", got)
	}
	if got := base.MCPIssuer(); got != "http://127.0.0.1:8080" {
		t.Errorf("default mcpIssuer: got %q", got)
	}
	// webBaseUrl: blank PM_WEB_ORIGIN means same-origin as the control plane.
	if got := base.WebBaseURL(); got != base.MCPIssuer() {
		t.Errorf("webBaseUrl with no PM_WEB_ORIGIN: got %q, want the issuer %q", got, base.MCPIssuer())
	}
	for _, c := range []struct{ origin, want string }{
		{"https://console.example.com", "https://console.example.com"},
		{" https://console.example.com/ ", "https://console.example.com"},
		{"https://console.example.com///", "https://console.example.com"},
		{"   ", "http://127.0.0.1:8080"}, // whitespace is blank ⇒ fall back
		{"///", "http://127.0.0.1:8080"}, // and so is a value that trims away entirely
	} {
		if got := mustFromEnv(t, envOf("PM_WEB_ORIGIN", c.origin)).WebBaseURL(); got != c.want {
			t.Errorf("webBaseUrl for PM_WEB_ORIGIN=%q: got %q, want %q", c.origin, got, c.want)
		}
	}
	// queryExchangeTimeoutMs = seconds*1000 + QUERY_EXCHANGE_GRACE_MS.
	if got := base.QueryExchangeTimeoutMS(); got != 600*1000+150_000 {
		t.Errorf("queryExchangeTimeoutMs: got %d", got)
	}
	// runStreamTimeoutMs floors at 15 minutes, then tracks dial + exchange + 30s.
	if got := RunStreamTimeoutMS(151_000); got != 900_000 {
		t.Errorf("runStreamTimeoutMs floor: got %d, want 900000", got)
	}
	if got := RunStreamTimeoutMS(base.QueryExchangeTimeoutMS()); got != 900_000 {
		t.Errorf("runStreamTimeoutMs at the default: got %d, want 900000", got)
	}
	if got := RunStreamTimeoutMS(1_000_000); got != DialTimeoutMS+1_000_000+30_000 {
		t.Errorf("runStreamTimeoutMs above the floor: got %d", got)
	}
}

// --- ADDED (not one of the 25) · V10's canonicalisation, which ConfigGuardTest case 11 covers only
// for the scheme and the host case-fold.
//
// 🔒 V10 is a security rule and the place where java.net.URI is STRICTER than Go's net/url. Each row
// below is a divergence a naive port would boot on. The accept rows run with PM_AUTH_DEBUG at its
// default (on), so requireHttps is off and no OIDC rule interferes.
func TestCanonicalMcpResourceStrictness(t *testing.T) {
	for _, raw := range []string{
		"https://h.example.com/mcp/",     // path is "/mcp/", not "/mcp" — normalize() keeps trailing slashes
		"https://h.example.com/mcp?x=1",  // query present
		"https://h.example.com/mcp?",     // EMPTY query is still non-null to java.net.URI
		"https://h.example.com/mcp#f",    // fragment present
		"https://h.example.com/mcp#",     // empty fragment, likewise
		"https://u:p@h.example.com/mcp",  // userInfo present
		"ftp://h.example.com/mcp",        // scheme outside {http, https}
		"HTTPS://h.example.com/mcp",      // java.net.URI does NOT fold the scheme; the check is case-sensitive
		"https://h.example.com/other",    // path is not /mcp
		"https://h.example.com/mcp/more", // ...nor a prefix of it
		"https://h.example.com",          // no path at all
		"/mcp",                           // relative — isAbsolute is false
	} {
		mustFailFromEnv(t, envOf("PM_MCP_RESOURCE", raw), "PM_MCP_RESOURCE="+strconv.Quote(raw))
	}
	for _, c := range []struct{ raw, resource, issuer string }{
		{"http://127.0.0.1:8080/mcp", "http://127.0.0.1:8080/mcp", "http://127.0.0.1:8080"},
		{"https://h.example.com/mcp", "https://h.example.com/mcp", "https://h.example.com"},
		{"https://H.Example.COM/mcp", "https://h.example.com/mcp", "https://h.example.com"},
		{"https://h.example.com:8443/mcp", "https://h.example.com:8443/mcp", "https://h.example.com:8443"},
		// normalize() runs BEFORE the path check, so dot segments that resolve to /mcp are accepted.
		{"https://h.example.com/a/../mcp", "https://h.example.com/mcp", "https://h.example.com"},
		{"https://h.example.com/./mcp", "https://h.example.com/mcp", "https://h.example.com"},
	} {
		cfg := mustFromEnv(t, envOf("PM_MCP_RESOURCE", c.raw))
		if cfg.MCPResource != c.resource {
			t.Errorf("PM_MCP_RESOURCE=%q: mcpResource got %q, want %q", c.raw, cfg.MCPResource, c.resource)
		}
		if cfg.MCPIssuer() != c.issuer {
			t.Errorf("PM_MCP_RESOURCE=%q: mcpIssuer got %q, want %q", c.raw, cfg.MCPIssuer(), c.issuer)
		}
	}
}

// --- ADDED (not one of the 25) · parseDuration's accept/reject boundary against Go's stdlib.
//
// 01-bootstrap.md §2 states the requirement as a contrast: parseDuration must REJECT what
// time.ParseDuration accepts (1.5h, 300ms, -5m, unit-less) and ACCEPT the bare-integer-seconds form it
// rejects, with segments contiguous from offset 0. ConfigGuardTest only exercises "2x", "" and "-1h",
// so the contrast itself is unpinned in the Kotlin suite — and it is the whole reason this function is
// hand-written rather than delegated (D19).
func TestParseDurationAcceptRejectBoundary(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int64
	}{
		{"1", 1},
		{"900", 900},
		{"0900", 900}, // leading zeros are digits, so the all-digits branch takes it
		{"90s", 90},
		{"15m", 900},
		{"2h", 7200},
		{"1h30m", 5400},
		{"1h30m30s", 5430},
		{"1h0m", 3600}, // a zero SEGMENT is fine as long as the total is positive
	} {
		got, err := ParseDuration(c.raw)
		if err != nil || got != c.want {
			t.Errorf("ParseDuration(%q): got (%d, %v), want (%d, nil)", c.raw, got, err, c.want)
		}
	}
	for _, raw := range []string{
		"",       // empty
		"0",      // all-digits but not positive
		"0s",     // segments parse, total is zero
		"-1",     // no bare negatives
		"-1h",    // the match starts at offset 1, not 0
		"1.5h",   // time.ParseDuration ACCEPTS this
		"300ms",  // ...and this: "300m" consumes, then a bare "s" is left over
		"-5m",    // ...and this
		"1h 30m", // a gap between segments
		"1h x 30m",
		"1hx",  // trailing junk after a valid segment
		"1h5",  // trailing digits with no unit
		"h",    // a unit with no digits
		"abc",  // no digits at all
		" 900", // no surrounding whitespace is tolerated
		"900 ",
		"1d",   // days are not a unit
		"1H",   // units are lower-case only
		"+900", // Kotlin's isDigit branch rejects the sign, and the regex branch finds no match at 0
	} {
		if got, err := ParseDuration(raw); err == nil {
			t.Errorf("ParseDuration(%q): expected a failure, got %d", raw, got)
		}
	}
	// Overflow surfaces as "duration is too large", not as a wrapped arithmetic error.
	if _, err := ParseDuration("9223372036854775807m"); err == nil ||
		!strings.Contains(err.Error(), "duration is too large") {
		t.Errorf("overflow: got %v, want a 'duration is too large' error", err)
	}
}
