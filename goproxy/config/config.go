// Package config is the proxy's environment-sourced configuration. MySQL and Postgres are enforcing
// native-wire brokers, each proxy fronts a registered datasource, and boot must fail closed on an
// invalid configuration rather than start with ambiguous behavior.
package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// rawFlags is the kong grammar: every field is bound to its PM_* environment variable. This struct is
// intentionally unexported — Load() normalizes it into the public Config the rest of the proxy consumes.
//
// The port fields are strings (not ints) on purpose: Load() parses them with parsePort so a blank or
// non-numeric value falls back to the engine default. Binding them as kong ints would instead hard-fail
// on a blank/garbage value.
type rawFlags struct {
	Engine                 string `env:"PM_ENGINE" default:"mysql"`
	ProxyPort              string `env:"PM_PROXY_PORT"`
	TargetHost             string `env:"PM_TARGET_HOST" default:"localhost"`
	TargetPort             string `env:"PM_TARGET_PORT"`
	TargetDb               string `env:"PM_TARGET_DB" default:"acme"`
	TargetUser             string `env:"PM_TARGET_USER" default:"acme"`
	TargetPassword         string `env:"PM_TARGET_PASSWORD" default:"acme"`
	ControlPlaneGrpcTarget string `env:"PM_CONTROL_PLANE_GRPC" default:"localhost:9090"`
	DatasourceName         string `env:"PM_DATASOURCE_NAME"`
	DatasourceTags         string `env:"PM_DATASOURCE_TAGS"`
	AdvertiseAddr          string `env:"PM_ADVERTISE_ADDR"`
	SecretToken            string `env:"PM_SECRET_TOKEN"`
	TLSCertPath            string `env:"PM_TLS_CERT"`
	TLSKeyPath             string `env:"PM_TLS_KEY"`
	TLSNoAdvertise         string `env:"PM_TLS_NO_ADVERTISE"`
	QueryTimeout           string `env:"PM_QUERY_TIMEOUT"`
	ResultCaps             string `env:"PM_RESULT_CAPS"`
}

// parsePort turns a blank, non-numeric, or out-of-range value into 0, which Load() then replaces with the
// engine-dependent default. A deploy that leaves an optional port var explicitly blank must still boot,
// not crash on a parse error.
//
// The bound is 32-bit on purpose: strconv.Atoi would accept a 64-bit value like 4294967297 on this
// platform, which cp.Register would then silently truncate to int32(1) — registering the control plane
// with a bogus but valid-looking target port. ParseInt(_, 10, 32) treats such a value as "absent" and
// falls back to the engine default rather than corrupting the registered metadata.
func parsePort(raw string) int {
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0
	}
	return int(n)
}

// blankToAbsent treats an empty or all-whitespace value as absent ("") so boot fails fast instead of
// proceeding with a whitespace-only datasource name or TLS path. A value carrying any non-whitespace is
// kept verbatim (not trimmed).
func blankToAbsent(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return s
}

// Config is the proxy's normalized configuration. A blank string field means "absent"; there is no
// separate presence flag.
type Config struct {
	// Engine is the raw, lowercased PM_ENGINE value — the genuine string source kept for error messages
	// and the boot log. Dialect is the typed form every downstream consumer uses; the string is parsed to
	// it exactly once, here at the config boundary.
	Engine                 string
	Dialect                engine.Dialect
	Provider               spi.Provider
	ProxyPort              int
	TargetHost             string
	TargetPort             int
	TargetDb               string
	TargetUser             string
	TargetPassword         string
	ControlPlaneGrpcTarget string
	DatasourceName         string
	DatasourceTags         []string
	// AdvertiseAddr is the client-facing host:port a wire client (pmon) dials to reach THIS proxy — distinct
	// from Target* (the upstream db). Registered with the control plane so GET /api/datasources can hand a
	// client the per-datasource connect address. NO default: empty unless PM_ADVERTISE_ADDR is set (the proxy
	// can't guess a client-reachable address; a local/demo run sets 127.0.0.1:<port>, a real deployment the
	// node's MagicDNS name). Empty => the datasource is not brokerable by pmon until an address is configured.
	AdvertiseAddr string
	SecretToken   string
	TLSCertPath   string
	TLSKeyPath    string
	// Serve TLS but advertise NO chain to the control plane, so clients verify purely against their own trust
	// store. Set this when the wire cert comes from a CA the clients already trust (public, or a private root
	// already distributed by your fleet management) and you would rather not publish the certificate through
	// the console at all. Advertising is otherwise harmless — a leaf and its issuers are public material — so
	// this exists for deployments that prefer the control plane hold nothing it does not need.
	TLSNoAdvertise bool
	QueryTimeout   time.Duration
	// ResultCaps is the parsed PM_RESULT_CAPS table (docs/result-caps.md).
	ResultCaps engine.ResultCaps
}

// Load reads the proxy configuration from the environment, applying the engine-dependent port defaults
// and normalization. It parses no command-line arguments (this is a daemon; kong is used purely for its
// env-tag binding), so it is safe to call repeatedly (e.g. from tests using t.Setenv) without touching
// os.Args.
func Load(registry spi.Registry) (*Config, error) {
	if registry == nil {
		return nil, fmt.Errorf("config: provider registry is required")
	}
	var raw rawFlags
	parser, err := kong.New(&raw)
	if err != nil {
		return nil, fmt.Errorf("config: building parser: %w", err)
	}
	if _, err := parser.Parse(nil); err != nil {
		return nil, fmt.Errorf("config: parsing environment: %w", err)
	}

	engineName := strings.ToLower(raw.Engine)
	dialect, parseErr := engine.ParseDialect(engineName)
	var provider spi.Provider
	if parseErr == nil {
		provider, _ = registry.For(dialect)
	}

	proxyPort := parsePort(raw.ProxyPort)
	if proxyPort == 0 && provider != nil {
		proxyPort = dialect.DefaultProxyPort()
	}

	targetPort := parsePort(raw.TargetPort)
	if targetPort == 0 && provider != nil {
		targetPort = dialect.DefaultTargetPort()
	}

	queryTimeout := 600 * time.Second
	if timeoutRaw := strings.TrimSpace(raw.QueryTimeout); timeoutRaw != "" {
		seconds, err := strconv.ParseInt(timeoutRaw, 10, 64)
		maxSeconds := int64((time.Duration(1<<63-1) - 30*time.Second) / time.Second)
		if err != nil || seconds <= 0 {
			return nil, fmt.Errorf("PM_QUERY_TIMEOUT must be a positive integer number of seconds, got %q", raw.QueryTimeout)
		}
		if seconds > maxSeconds {
			return nil, fmt.Errorf("PM_QUERY_TIMEOUT is too large, got %q", raw.QueryTimeout)
		}
		queryTimeout = time.Duration(seconds) * time.Second
	}

	capsSpec := strings.TrimSpace(raw.ResultCaps)
	if capsSpec == "" {
		capsSpec = engine.DefaultResultCaps
	}
	resultCaps, err := engine.ParseResultCaps(capsSpec)
	if err != nil {
		return nil, fmt.Errorf("PM_RESULT_CAPS: %w", err)
	}

	var tags []string
	for _, tag := range strings.Split(raw.DatasourceTags, ",") {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			tags = append(tags, tag)
		}
	}

	// No default on purpose: advertise_addr is the reachable host:port a client (pmon) dials, which the proxy
	// cannot guess — a 127.0.0.1:<port> default is wrong for any non-co-located client (they would dial their
	// OWN loopback) and would clobber a previously-correct advertised address on a restart that forgot the
	// env. Unset => empty => this datasource is simply not brokerable by pmon until an address is configured;
	// a local/demo run sets PM_ADVERTISE_ADDR=127.0.0.1:<port> explicitly.
	advertiseAddr := strings.TrimSpace(raw.AdvertiseAddr)

	return &Config{
		Engine:                 engineName,
		Dialect:                dialect,
		Provider:               provider,
		ProxyPort:              proxyPort,
		TargetHost:             raw.TargetHost,
		TargetPort:             targetPort,
		TargetDb:               raw.TargetDb,
		TargetUser:             raw.TargetUser,
		TargetPassword:         raw.TargetPassword,
		ControlPlaneGrpcTarget: raw.ControlPlaneGrpcTarget,
		// A whitespace-only value is absent, so Validate()/TLSEnabled() treat it as unset rather than a
		// usable name/path.
		DatasourceName: blankToAbsent(raw.DatasourceName),
		DatasourceTags: tags,
		AdvertiseAddr:  advertiseAddr,
		SecretToken:    raw.SecretToken,
		TLSCertPath:    blankToAbsent(raw.TLSCertPath),
		TLSKeyPath:     blankToAbsent(raw.TLSKeyPath),
		TLSNoAdvertise: parseBoolEnv(raw.TLSNoAdvertise),
		QueryTimeout:   queryTimeout,
		ResultCaps:     resultCaps,
	}, nil
}

// parseBoolEnv treats the usual truthy spellings as true and anything else — including blank — as false, so
// an unset or garbled value means "advertise", the behavior that needs no configuration.
func parseBoolEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// TLSEnabled reports whether client-facing TLS is configured: both the cert and key path must be set —
// there is no self-signed/auto-generated fallback.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertPath != "" && c.TLSKeyPath != ""
}

// Validate runs the three fail-closed boot checks IN ORDER, so a typo'd PM_ENGINE can never clobber a
// live datasource's stored dialect via a stray register call.
func (c *Config) Validate() error {
	// (1) The datasource identity is required — otherwise boot would start and NOT_FOUND every query
	// instead of failing fast.
	if c.DatasourceName == "" {
		return fmt.Errorf("PM_DATASOURCE_NAME is required for the %s proxy (which datasource it fronts)", c.Engine)
	}

	// (2) Fail closed on a partial TLS config — a typo'd/empty env var must not silently boot plaintext.
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		return fmt.Errorf("PM_TLS_CERT and PM_TLS_KEY must both be set (or both unset); refusing to start with a partial TLS config")
	}

	// (3) Validate the engine BEFORE any register. The injected registry is the supported-engine authority;
	// adding a provider changes only its wiring row, not config or the engine core.
	if !c.Dialect.Valid() || c.Provider == nil {
		return fmt.Errorf("unsupported PM_ENGINE=%s", c.Engine)
	}

	// (4) A configured advertise address must be a real host:port (port 1-65535) — a typo would register a
	// dead address that a client (pmon) then dials. Empty is fine: the datasource is just not brokerable.
	if c.AdvertiseAddr != "" {
		host, port, err := net.SplitHostPort(c.AdvertiseAddr)
		if err != nil || host == "" {
			return fmt.Errorf("PM_ADVERTISE_ADDR=%q must be host:port", c.AdvertiseAddr)
		}
		if p, perr := strconv.Atoi(port); perr != nil || p < 1 || p > 65535 {
			return fmt.Errorf("PM_ADVERTISE_ADDR=%q has an invalid port (want 1-65535)", c.AdvertiseAddr)
		}
	}

	return nil
}
