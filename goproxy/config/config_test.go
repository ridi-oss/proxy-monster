package config

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"crypto/tls"
	"database/sql"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// clearPMEnv resets every PM_* var this package reads, so a developer's ambient environment can never
// leak into a test's expectations.
//
// Vars with a kong `default:` tag (Engine, TargetHost, TargetDb, TargetUser, TargetPassword,
// ControlPlaneGrpcTarget) must be genuinely UNSET, not set-to-"": kong only applies the default when the
// var is absent — a var explicitly set to "" is treated as present with an empty value. Vars with no
// default (blank == absent either way, including the string-typed ports which Load(testRegistry()) parses
// via parsePort) are set to "" via t.Setenv.
type configTestProvider struct {
	dialect engine.Dialect
}

func (p configTestProvider) Dialect() engine.Dialect                     { return p.dialect }
func (configTestProvider) NewDb() engine.Db                              { return nil }
func (configTestProvider) OpenTarget(spi.BackendTarget) (*sql.DB, error) { return nil, nil }
func (configTestProvider) ProbeNamespace(*sql.Conn, string) ([]string, *int32, error) {
	return nil, nil, nil
}
func (configTestProvider) ReadTableDetail(*sql.Conn, string, string) (*spi.TableDetail, error) {
	return nil, nil
}
func (configTestProvider) NewWireServer(int, spi.BackendTarget, spi.EnforcementClient, engine.Db, func() (*tls.Config, error)) spi.WireServer {
	return nil
}
func (configTestProvider) NewRunSession(context.Context, spi.BackendTarget, engine.Db, spi.SessionClient, string, []byte, engine.ExecGuard, time.Duration) (spi.BackendSession, error) {
	return nil, nil
}

func testRegistry() spi.Registry {
	return spi.MustRegistry(
		configTestProvider{dialect: engine.MySQL},
		configTestProvider{dialect: engine.Postgres},
	)
}

func clearPMEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"PM_PROXY_PORT", "PM_TARGET_PORT",
		"PM_DATASOURCE_NAME", "PM_DATASOURCE_TAGS", "PM_SECRET_TOKEN",
		"PM_TLS_CERT", "PM_TLS_KEY", "PM_ADVERTISE_ADDR", "PM_QUERY_TIMEOUT",
	} {
		t.Setenv(v, "")
	}
	for _, v := range []string{
		"PM_ENGINE", "PM_TARGET_HOST",
		"PM_TARGET_DB", "PM_TARGET_USER", "PM_TARGET_PASSWORD", "PM_CONTROL_PLANE_GRPC",
	} {
		unsetEnv(t, v)
	}
}

// unsetEnv genuinely removes an env var for the duration of the test, restoring its prior state
// (present-with-value, or absent) afterward.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestLoadDefaults(t *testing.T) {
	clearPMEnv(t)

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Engine != "mysql" {
		t.Errorf("Engine = %q, want mysql", cfg.Engine)
	}
	if cfg.ProxyPort != 6033 {
		t.Errorf("ProxyPort = %d, want 6033 (mysql default)", cfg.ProxyPort)
	}
	if cfg.TargetPort != 3307 {
		t.Errorf("TargetPort = %d, want 3307 (mysql default)", cfg.TargetPort)
	}
	if cfg.TargetHost != "localhost" {
		t.Errorf("TargetHost = %q, want localhost", cfg.TargetHost)
	}
	if cfg.TargetDb != "acme" || cfg.TargetUser != "acme" || cfg.TargetPassword != "acme" {
		t.Errorf("target creds = %q/%q/%q, want acme/acme/acme", cfg.TargetDb, cfg.TargetUser, cfg.TargetPassword)
	}
	if cfg.ControlPlaneGrpcTarget != "localhost:9090" {
		t.Errorf("ControlPlaneGrpcTarget = %q, want localhost:9090", cfg.ControlPlaneGrpcTarget)
	}
	if cfg.DatasourceName != "" {
		t.Errorf("DatasourceName = %q, want empty (absent)", cfg.DatasourceName)
	}
	if len(cfg.DatasourceTags) != 0 {
		t.Errorf("DatasourceTags = %v, want empty", cfg.DatasourceTags)
	}
	if cfg.SecretToken != "" {
		t.Errorf("SecretToken = %q, want empty", cfg.SecretToken)
	}
	if cfg.QueryTimeout != 600*time.Second {
		t.Errorf("QueryTimeout = %s, want 600s", cfg.QueryTimeout)
	}
	if cfg.TLSEnabled() {
		t.Errorf("TLSEnabled() = true, want false when both paths are unset")
	}
}

func TestLoadAdvertiseAddr(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_DATASOURCE_NAME", "ds") // required so Validate() only exercises the advertise check

	// Unset => empty (NO loopback guess), and an empty advertise validates fine.
	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdvertiseAddr != "" {
		t.Errorf("unset PM_ADVERTISE_ADDR: AdvertiseAddr = %q, want empty (no loopback default)", cfg.AdvertiseAddr)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty advertise should validate: %v", err)
	}

	// An explicit value is carried verbatim and validates.
	t.Setenv("PM_ADVERTISE_ADDR", "proxy.example.ts.net:6033")
	cfg, _ = Load(testRegistry())
	if cfg.AdvertiseAddr != "proxy.example.ts.net:6033" {
		t.Errorf("AdvertiseAddr = %q, want the explicit value", cfg.AdvertiseAddr)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid host:port advertise should validate: %v", err)
	}

	// Malformed (no port) and out-of-range ports fail Validate rather than register a dead address.
	for _, bad := range []string{"not-a-host-port", "host:99999", "host:0"} {
		t.Setenv("PM_ADVERTISE_ADDR", bad)
		cfg, _ = Load(testRegistry())
		if err := cfg.Validate(); err == nil {
			t.Errorf("PM_ADVERTISE_ADDR=%q should fail Validate", bad)
		}
	}
}

func TestLoadQueryTimeoutOverride(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_QUERY_TIMEOUT", "42")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QueryTimeout != 42*time.Second {
		t.Errorf("QueryTimeout = %s, want 42s", cfg.QueryTimeout)
	}
}

func TestLoadRejectsInvalidQueryTimeout(t *testing.T) {
	// "9223372007" parses as an int64 but exceeds the duration-safe ceiling; it must be rejected the
	// same as garbage, matching the control-plane's identical bound (Config.MAX_QUERY_TIMEOUT_SECONDS).
	for _, value := range []string{"0", "-1", "1.5", "not-a-number", "999999999999999999999", "9223372007"} {
		t.Run(value, func(t *testing.T) {
			clearPMEnv(t)
			t.Setenv("PM_QUERY_TIMEOUT", value)
			if _, err := Load(testRegistry()); err == nil || !strings.Contains(err.Error(), "PM_QUERY_TIMEOUT") {
				t.Fatalf("Load with PM_QUERY_TIMEOUT=%q error = %v, want PM_QUERY_TIMEOUT error", value, err)
			}
		})
	}
}

// The largest whole-second value that still fits a time.Duration with the +30s socket grace is
// accepted; this is the shared CP/proxy boundary asserted rejected one above in the CP suite.
func TestLoadAcceptsMaxQueryTimeout(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_QUERY_TIMEOUT", "9223372006")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QueryTimeout != 9223372006*time.Second {
		t.Errorf("QueryTimeout = %s, want 9223372006s", cfg.QueryTimeout)
	}
}

func TestLoadPostgresDefaults(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_ENGINE", "POSTGRES") // exercise the lowercase normalization

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Engine != "postgres" {
		t.Errorf("Engine = %q, want postgres (lowercased)", cfg.Engine)
	}
	if cfg.ProxyPort != 6432 {
		t.Errorf("ProxyPort = %d, want 6432 (postgres default)", cfg.ProxyPort)
	}
	if cfg.TargetPort != 5433 {
		t.Errorf("TargetPort = %d, want 5433 (postgres default)", cfg.TargetPort)
	}
}

func TestLoadExplicitPortsAreNotOverridden(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_PROXY_PORT", "1234")
	t.Setenv("PM_TARGET_PORT", "5678")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProxyPort != 1234 {
		t.Errorf("ProxyPort = %d, want 1234", cfg.ProxyPort)
	}
	if cfg.TargetPort != 5678 {
		t.Errorf("TargetPort = %d, want 5678", cfg.TargetPort)
	}
}

func TestLoadBlankPortsFallBackToEngineDefaults(t *testing.T) {
	// A deploy that leaves an optional port var explicitly blank must still boot on the engine default,
	// not crash on a parse error.
	clearPMEnv(t)
	t.Setenv("PM_PROXY_PORT", "")
	t.Setenv("PM_TARGET_PORT", "   ")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load with blank ports: %v", err)
	}
	if cfg.ProxyPort != 6033 {
		t.Errorf("ProxyPort = %d, want 6033 (mysql default for a blank var)", cfg.ProxyPort)
	}
	if cfg.TargetPort != 3307 {
		t.Errorf("TargetPort = %d, want 3307 (mysql default for a whitespace-only var)", cfg.TargetPort)
	}
}

func TestLoadNonNumericPortsFallBackToEngineDefaults(t *testing.T) {
	// A non-numeric value is absent, not an error.
	clearPMEnv(t)
	t.Setenv("PM_ENGINE", "postgres")
	t.Setenv("PM_PROXY_PORT", "not-a-port")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load with non-numeric port: %v", err)
	}
	if cfg.ProxyPort != 6432 {
		t.Errorf("ProxyPort = %d, want 6432 (postgres default for a non-numeric var)", cfg.ProxyPort)
	}
}

func TestLoadOutOfInt32PortFallsBackToEngineDefault(t *testing.T) {
	// The port bound is 32-bit: a value outside int32 is "absent" and falls back to the engine default. A
	// 64-bit parse would instead accept 4294967297 and let cp.Register silently truncate it to int32(1) —
	// registering the control plane with a bogus but valid-looking target port. Assert the 32-bit bound: an
	// over-range value is absent, not truncated.
	clearPMEnv(t)
	t.Setenv("PM_TARGET_PORT", "4294967297") // 2^32 + 1: truncates to 1 under a naive int32 cast
	t.Setenv("PM_PROXY_PORT", "2147483648")  // int32 max + 1

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load with out-of-int32 ports: %v", err)
	}
	if cfg.TargetPort != 3307 {
		t.Errorf("TargetPort = %d, want 3307 (out-of-int32 value must fall back to the mysql default, not truncate)", cfg.TargetPort)
	}
	if cfg.ProxyPort != 6033 {
		t.Errorf("ProxyPort = %d, want 6033 (out-of-int32 value must fall back to the mysql default)", cfg.ProxyPort)
	}
}

func TestLoadWhitespaceOnlyDatasourceNameIsAbsent(t *testing.T) {
	// A whitespace-only name is absent, so Validate() fails fast at boot instead of proceeding into
	// registration with an unusable name.
	clearPMEnv(t)
	t.Setenv("PM_DATASOURCE_NAME", "   ")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatasourceName != "" {
		t.Errorf("DatasourceName = %q, want empty (whitespace-only is absent)", cfg.DatasourceName)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil for a whitespace-only datasource name, want error")
	}
}

func TestLoadWhitespaceOnlyTLSPathsAreAbsent(t *testing.T) {
	// Whitespace-only TLS paths are absent, so the proxy boots plaintext (both unset) rather than treating
	// "   " as a filename or as a partial TLS config.
	clearPMEnv(t)
	t.Setenv("PM_TLS_CERT", "   ")
	t.Setenv("PM_TLS_KEY", "\t")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLSCertPath != "" || cfg.TLSKeyPath != "" {
		t.Errorf("TLS paths = %q/%q, want both empty (whitespace-only is absent)", cfg.TLSCertPath, cfg.TLSKeyPath)
	}
	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true for whitespace-only paths, want false")
	}
	cfg.DatasourceName = "ds"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil (whitespace-only paths are both-absent, not a partial config)", err)
	}
}

func TestLoadDatasourceTagsSplitTrimAndDropEmpty(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_DATASOURCE_TAGS", " preset:production , , preset:pii ,")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"preset:production", "preset:pii"}
	if len(cfg.DatasourceTags) != len(want) {
		t.Fatalf("DatasourceTags = %v, want %v", cfg.DatasourceTags, want)
	}
	for i, tag := range want {
		if cfg.DatasourceTags[i] != tag {
			t.Errorf("DatasourceTags[%d] = %q, want %q", i, cfg.DatasourceTags[i], tag)
		}
	}
}

func TestLoadSecretToken(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_SECRET_TOKEN", "the-secret")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SecretToken != "the-secret" {
		t.Errorf("SecretToken = %q, want the-secret", cfg.SecretToken)
	}
}

func TestTLSEnabled(t *testing.T) {
	clearPMEnv(t)
	t.Setenv("PM_TLS_CERT", "/cert.pem")
	t.Setenv("PM_TLS_KEY", "/key.pem")

	cfg, err := Load(testRegistry())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.TLSEnabled() {
		t.Errorf("TLSEnabled() = false, want true when both paths are set")
	}
}

func TestValidateRequiresDatasourceName(t *testing.T) {
	cfg := &Config{Engine: "mysql"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for missing DatasourceName")
	}
}

func TestValidateRejectsPartialTLSConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{"cert only", &Config{Engine: "mysql", DatasourceName: "ds", TLSCertPath: "/cert.pem"}},
		{"key only", &Config{Engine: "mysql", DatasourceName: "ds", TLSKeyPath: "/key.pem"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); err == nil {
				t.Fatal("Validate() = nil, want error for a partial TLS config")
			}
		})
	}
}

func TestValidateAllowsCompleteOrAbsentTLSConfig(t *testing.T) {
	provider, _ := testRegistry().For(engine.MySQL)
	both := &Config{Engine: "mysql", Dialect: engine.MySQL, Provider: provider, DatasourceName: "ds", TLSCertPath: "/cert.pem", TLSKeyPath: "/key.pem"}
	if err := both.Validate(); err != nil {
		t.Errorf("Validate() with both TLS paths set = %v, want nil", err)
	}
	neither := &Config{Engine: "mysql", Dialect: engine.MySQL, Provider: provider, DatasourceName: "ds"}
	if err := neither.Validate(); err != nil {
		t.Errorf("Validate() with no TLS paths set = %v, want nil", err)
	}
}

func TestValidateRejectsUnsupportedEngine(t *testing.T) {
	// Load parses PM_ENGINE to Dialect once; an unrecognized value yields the fail-closed sentinel, which
	// Validate must reject.
	badDialect, _ := engine.ParseDialect("oracle")
	cfg := &Config{Engine: "oracle", Dialect: badDialect, DatasourceName: "ds"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for an unsupported engine")
	}
}

func TestValidateAcceptsMySQLAndPostgres(t *testing.T) {
	for _, name := range []string{"mysql", "postgres"} {
		dialect, _ := engine.ParseDialect(name)
		provider, _ := testRegistry().For(dialect)
		cfg := &Config{Engine: name, Dialect: dialect, Provider: provider, DatasourceName: "ds"}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() for engine %q = %v, want nil", name, err)
		}
	}
}

func TestValidateOrderDatasourceNameCheckedBeforeEngine(t *testing.T) {
	// Both the datasource name AND the engine are invalid; the datasource-name error must win (it is
	// checked first), so a caller logging only the first error still gets the actionable one.
	badDialect, _ := engine.ParseDialect("oracle")
	cfg := &Config{Engine: "oracle", Dialect: badDialect}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error")
	}
	if got := err.Error(); got == "" {
		t.Fatal("expected non-empty error message")
	}
	// Cheap signal that it's the datasource-name error, not the engine error: only the engine error
	// starts with "unsupported".
	if strings.HasPrefix(err.Error(), "unsupported") {
		t.Errorf("Validate() returned the engine error first, want the datasource-name error first: %v", err)
	}
}
