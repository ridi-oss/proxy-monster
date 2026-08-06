// Package config loads the monitor's own configuration from a YAML file with an environment overlay, and
// validates it fail-closed on load. The file is monitor-owned and NOT DB-backed on purpose: config in the
// DB would let a compromised control plane raise every threshold or repoint a sink to silence the watcher.
// Secrets are referenced only by env-var name (never inlined), so the file stays secret-free.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config is the whole monitor configuration: the poll/sign loop, the anomaly-rule thresholds, and the alert
// sinks. It lives in a monitor-owned file (never the DB) so a compromised control plane cannot raise a
// threshold to infinity or repoint a sink to silence the watcher.
type Config struct {
	Monitor MonitorConfig `koanf:"monitor"`
	Rules   RulesConfig   `koanf:"rules"`
	Alerts  AlertsConfig  `koanf:"alerts"`
}

// Canonical anomaly-rule names. Detection fires alerts tagged with these, alert sinks route on them, and a
// sink's rules list matches against them, so they are defined once here as the shared vocabulary.
const (
	RuleMassExport   = "mass_export"
	RuleBulkPII      = "bulk_pii"
	RuleOffHours     = "off_hours"
	RuleRepeatedDeny = "repeated_deny"
	RuleIntegrity    = "integrity"
)

// Alert severities, least to most urgent. A sink routes an alert only when its severity is at least the
// sink's min_severity (see SeverityRank).
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

// SeverityRank orders the severities for min_severity routing. An unknown string ranks as warn so a typo
// never silently drops below the floor.
func SeverityRank(s string) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityCritical:
		return 2
	default: // warn and anything unrecognized
		return 1
	}
}

// RulesConfig holds the thresholds/windows for the four anomaly rules. A rule with a zero window (or, for
// off_hours, an empty business_hours) is disabled; the detector skips it and Validate leaves it alone.
type RulesConfig struct {
	MassExport   MassExportRule   `koanf:"mass_export"`
	BulkPII      BulkPIIRule      `koanf:"bulk_pii"`
	OffHours     OffHoursRule     `koanf:"off_hours"`
	RepeatedDeny RepeatedDenyRule `koanf:"repeated_deny"`
}

// VolumeThreshold is a per-datasource rows/bytes ceiling for mass_export. A zero field means "no ceiling on
// this dimension" — rows catches many records, bytes catches few wide rows / big blobs.
type VolumeThreshold struct {
	Rows  int64 `koanf:"rows"`
	Bytes int64 `koanf:"bytes"`
}

// MassExportRule flags a principal exporting more than a per-datasource volume of result data in a window.
// The primary signal is completion-event volume; when a window carries no completion event yet (the proxy's
// post-execution completion has not shipped in this deployment), it degrades to counting broad-read
// statements against HeuristicMaxBroadReads.
type MassExportRule struct {
	Window                 time.Duration              `koanf:"window"`
	PerDatasource          map[string]VolumeThreshold `koanf:"per_datasource"`
	Default                VolumeThreshold            `koanf:"default"`
	HeuristicMaxBroadReads int                        `koanf:"heuristic_max_broad_reads"`
}

// Threshold returns the volume ceiling for a datasource: its per-datasource entry if present, else the
// default.
func (r MassExportRule) Threshold(datasource string) VolumeThreshold {
	if th, ok := r.PerDatasource[datasource]; ok {
		return th
	}
	return r.Default
}

// BulkPIIRule flags a principal touching PII across more than MaxPIIDecisions decisions or more than
// MaxDistinctPIIColumns distinct PII columns in a window. A zero max disables that dimension.
type BulkPIIRule struct {
	Window                time.Duration `koanf:"window"`
	MaxPIIDecisions       int           `koanf:"max_pii_decisions"`
	MaxDistinctPIIColumns int           `koanf:"max_distinct_pii_columns"`
}

// OffHoursRule flags a PII read or any write whose timestamp falls outside business hours (weekends always
// count as off-hours). BusinessHours is "HH:MM-HH:MM" with an optional trailing IANA zone
// ("09:00-19:00 Asia/Seoul"); Timezone overrides that zone when set. AppliesTo selects which access kinds
// are watched ("pii_read", "write").
type OffHoursRule struct {
	BusinessHours string   `koanf:"business_hours"`
	Timezone      string   `koanf:"timezone"`
	AppliesTo     []string `koanf:"applies_to"`
}

// BusinessWindow is the parsed form of an OffHoursRule: the daily [StartMinute, EndMinute) span and the zone
// it is expressed in.
type BusinessWindow struct {
	StartMinute int
	EndMinute   int
	Location    *time.Location
}

// Parse resolves BusinessHours (+ Timezone) into a BusinessWindow, failing closed on any malformed field.
func (r OffHoursRule) Parse() (BusinessWindow, error) {
	fields := strings.Fields(r.BusinessHours)
	if len(fields) == 0 {
		return BusinessWindow{}, fmt.Errorf("config: off_hours.business_hours is empty")
	}
	start, end, err := parseHourRange(fields[0])
	if err != nil {
		return BusinessWindow{}, err
	}
	zone := "UTC"
	if len(fields) > 1 {
		zone = fields[1]
	}
	if r.Timezone != "" {
		zone = r.Timezone
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return BusinessWindow{}, fmt.Errorf("config: off_hours timezone %q: %w", zone, err)
	}
	return BusinessWindow{StartMinute: start, EndMinute: end, Location: loc}, nil
}

// AppliesToPIIRead reports whether the pii_read access kind is watched.
func (r OffHoursRule) AppliesToPIIRead() bool { return containsFold(r.AppliesTo, "pii_read") }

// AppliesToWrite reports whether the write access kind is watched.
func (r OffHoursRule) AppliesToWrite() bool { return containsFold(r.AppliesTo, "write") }

// RepeatedDenyRule flags a principal accumulating more than MaxDeny DENY/ERROR decisions in a window
// (a probing / brute-force signal).
type RepeatedDenyRule struct {
	Window  time.Duration `koanf:"window"`
	MaxDeny int           `koanf:"max_deny"`
}

// AlertsConfig is the alert delivery configuration: how long to suppress duplicate subjects and where to
// POST. Every alert is always written to the WORM store regardless of sinks; sinks are the out-of-band
// notification on top.
type AlertsConfig struct {
	DedupWindow time.Duration `koanf:"dedup_window"`
	Sinks       []SinkConfig  `koanf:"sinks"`
	// ConsoleURL is the web console's base URL (e.g. https://proxy-monster.dev.ridi.io). When set, the Slack
	// message links each decision id to consoleURL/audit/<id>; empty leaves the bare ids.
	ConsoleURL string `koanf:"console_url"`
}

// SinkConfig is one webhook destination. The URL is never inlined — URLEnv names the environment variable
// (from a mounted secret) that holds it, so the config file stays secret-free and gitops-reviewable.
type SinkConfig struct {
	Type        string        `koanf:"type"`         // webhook
	URLEnv      string        `koanf:"url_env"`      // env var name holding the URL
	MinSeverity string        `koanf:"min_severity"` // info | warn | critical
	Rules       []string      `koanf:"rules"`        // "*" or specific rule names
	Format      string        `koanf:"format"`       // "" (canonical JSON) | slack
	Timeout     time.Duration `koanf:"timeout"`
	MaxRetries  int           `koanf:"max_retries"`
}

// MonitorConfig is the poll/sign loop and its off-box store + signer.
type MonitorConfig struct {
	PollInterval       time.Duration `koanf:"poll_interval"`
	SignInterval       time.Duration `koanf:"sign_interval"`
	FullVerifyInterval time.Duration `koanf:"full_verify_interval"`
	Bucket             string        `koanf:"bucket"`
	Endpoint           string        `koanf:"endpoint"`
	KMSKeyID           string        `koanf:"kms_key_id"`
	DBDSNEnv           string        `koanf:"db_dsn_env"`
	Signer             SignerConfig  `koanf:"signer"`
}

// SignerConfig selects and configures the anchor signer. AllowedKeyIDs are prior key ids still trusted for
// verifying older anchors during rotation; the active KeyID is always trusted. Verification never trusts an
// anchor's self-declared key_id — only these configured ids.
type SignerConfig struct {
	Type          string   `koanf:"type"` // filekey | kms
	KeyPath       string   `koanf:"key_path"`
	KeyID         string   `koanf:"key_id"`
	AllowedKeyIDs []string `koanf:"allowed_key_ids"`
}

// envKeyMap maps AUDITMON_ environment variables onto koanf paths. The mapping is explicit so a leaf key
// that itself contains underscores (poll_interval, key_path) is never mis-split into extra nesting levels.
var envKeyMap = map[string]string{
	"AUDITMON_MONITOR_POLL_INTERVAL":        "monitor.poll_interval",
	"AUDITMON_MONITOR_SIGN_INTERVAL":        "monitor.sign_interval",
	"AUDITMON_MONITOR_FULL_VERIFY_INTERVAL": "monitor.full_verify_interval",
	"AUDITMON_MONITOR_BUCKET":               "monitor.bucket",
	"AUDITMON_MONITOR_ENDPOINT":             "monitor.endpoint",
	"AUDITMON_MONITOR_KMS_KEY_ID":           "monitor.kms_key_id",
	"AUDITMON_MONITOR_DB_DSN_ENV":           "monitor.db_dsn_env",
	"AUDITMON_MONITOR_SIGNER_TYPE":          "monitor.signer.type",
	"AUDITMON_MONITOR_SIGNER_KEY_PATH":      "monitor.signer.key_path",
	"AUDITMON_MONITOR_SIGNER_KEY_ID":        "monitor.signer.key_id",
}

const (
	defaultDedupWindow        = 15 * time.Minute
	defaultFullVerifyInterval = time.Hour
	// The cadences INSTALL.md and the README already document. Defaulted rather than required so a
	// deployment that configures only what is install-specific — the store, the bucket, the signing key —
	// boots and monitors. A monitor that refuses to start is worth strictly less than one polling at a
	// sensible cadence, and every value here is overridable.
	defaultPollInterval = 90 * time.Second
	defaultSignInterval = time.Hour
	// filekey is the dev signer; a real deployment sets signer.type: kms and a key id. Choosing filekey as
	// the default keeps the fallback the one that cannot silently sign with someone else's key.
	defaultSignerType    = "filekey"
	defaultSignerKeyPath = "/var/lib/auditmon/signer.key"
)

// Load reads the YAML file, overlays AUDITMON_ environment variables, applies defaults, and validates.
// Hot-reload on file change is a documented future addition; it is not needed for a correct first load.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	// A MISSING file is not an error: the image ships no config on purpose (it varies per install), so a
	// deployment that supplies everything through AUDITMON_* has no file to mount. Any other failure —
	// unreadable, malformed YAML — still fails closed, because that is a config the operator meant to
	// provide and got wrong. Validate below rejects whatever the overlay leaves incomplete, so an absent
	// file cannot silently boot a half-configured monitor.
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("config: load %s: %w", path, err)
	}

	if err := k.Load(env.Provider("AUDITMON_", ".", func(s string) string {
		return envKeyMap[s]
	}), nil); err != nil {
		return nil, fmt.Errorf("config: load env overlay: %w", err)
	}

	var cfg Config
	// koanf's default decoder parses duration strings ("90s") and weakly-typed env values into the struct.
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if cfg.Monitor.FullVerifyInterval == 0 {
		cfg.Monitor.FullVerifyInterval = defaultFullVerifyInterval
	}
	if cfg.Alerts.DedupWindow == 0 {
		cfg.Alerts.DedupWindow = defaultDedupWindow
	}
	if cfg.Monitor.PollInterval == 0 {
		cfg.Monitor.PollInterval = defaultPollInterval
	}
	if cfg.Monitor.SignInterval == 0 {
		cfg.Monitor.SignInterval = defaultSignInterval
	}
	if cfg.Monitor.Signer.Type == "" {
		cfg.Monitor.Signer.Type = defaultSignerType
	}
	if cfg.Monitor.Signer.Type == defaultSignerType && cfg.Monitor.Signer.KeyPath == "" {
		cfg.Monitor.Signer.KeyPath = defaultSignerKeyPath
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Discrete connection parameters, used when db_dsn_env's variable is unset. A deployment that already
// holds the host, port, user and password separately — an ECS task definition, a Kubernetes Secret —
// composes nothing and parses nothing: it passes the parts. Only the password is a secret, so only the
// password needs secret plumbing.
const (
	dbHostEnv     = "AUDITMON_DB_HOST"
	dbPortEnv     = "AUDITMON_DB_PORT"
	dbNameEnv     = "AUDITMON_DB_NAME"
	dbUserEnv     = "AUDITMON_DB_USER"
	dbPasswordEnv = "AUDITMON_DB_PASSWORD"
	dbSSLModeEnv  = "AUDITMON_DB_SSLMODE"
)

// DBDSN resolves how to reach the store. Two forms, in order:
//
// A whole DSN in the env var named by db_dsn_env, for a local run or anything that already has one.
//
// Otherwise the discrete AUDITMON_DB_* parameters, which is what a real deployment has: passing host,
// port, user and password separately means no connection string is ever assembled by hand, so there is
// no second format to keep in step with the control plane's and nothing to parse. sslmode defaults to
// `require` — a monitor reading an audit trail across a network should not have to be told to encrypt.
//
// Either way the secret stays out of the config file; it arrives only through the environment.
func (c *Config) DBDSN() (string, error) {
	if c.Monitor.DBDSNEnv != "" {
		if dsn := strings.TrimSpace(os.Getenv(c.Monitor.DBDSNEnv)); dsn != "" {
			return dsn, nil
		}
	}
	host := strings.TrimSpace(os.Getenv(dbHostEnv))
	if host == "" {
		if c.Monitor.DBDSNEnv == "" {
			return "", fmt.Errorf("config: monitor.db_dsn_env is not set and %s is empty", dbHostEnv)
		}
		return "", fmt.Errorf(
			"config: neither %s (monitor.db_dsn_env) nor %s is set", c.Monitor.DBDSNEnv, dbHostEnv,
		)
	}
	name := strings.TrimSpace(os.Getenv(dbNameEnv))
	if name == "" {
		return "", fmt.Errorf("config: %s is set but %s is empty", dbHostEnv, dbNameEnv)
	}
	user := strings.TrimSpace(os.Getenv(dbUserEnv))
	if user == "" {
		return "", fmt.Errorf("config: %s is set but %s is empty", dbHostEnv, dbUserEnv)
	}
	port := strings.TrimSpace(os.Getenv(dbPortEnv))
	if port == "" {
		port = "5432"
	} else if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", fmt.Errorf("config: %s = %q is not a port number", dbPortEnv, port)
	}
	sslMode := strings.TrimSpace(os.Getenv(dbSSLModeEnv))
	if sslMode == "" {
		sslMode = "require"
	}
	// url.UserPassword percent-encodes both, so a password containing @ / : or / cannot break out of the
	// userinfo and silently repoint the connection at another host.
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, os.Getenv(dbPasswordEnv)),
		Host:     net.JoinHostPort(host, port),
		Path:     "/" + name,
		RawQuery: url.Values{"sslmode": []string{sslMode}}.Encode(),
	}
	return u.String(), nil
}

// Validate fails closed on any missing or contradictory setting.
func (c *Config) Validate() error {
	m := c.Monitor
	if m.PollInterval <= 0 {
		return fmt.Errorf("config: monitor.poll_interval must be > 0")
	}
	if m.SignInterval <= 0 {
		return fmt.Errorf("config: monitor.sign_interval must be > 0")
	}
	if m.FullVerifyInterval < 0 {
		return fmt.Errorf("config: monitor.full_verify_interval must be >= 0")
	}
	if m.Bucket == "" {
		return fmt.Errorf("config: monitor.bucket is required")
	}
	// db_dsn_env is optional: a deployment may supply the discrete AUDITMON_DB_* parameters instead. Which
	// of the two is present is only knowable at connect time, so DBDSN reports a missing store rather than
	// Validate — requiring the key here would reject a perfectly configured deployment for naming nothing.

	switch m.Signer.Type {
	case "filekey":
		if m.Signer.KeyPath == "" {
			return fmt.Errorf("config: monitor.signer.key_path is required for the filekey signer")
		}
	case "kms":
		if m.Signer.KeyID == "" {
			return fmt.Errorf("config: monitor.signer.key_id is required for the kms signer")
		}
	default:
		return fmt.Errorf("config: monitor.signer.type must be filekey or kms, got %q", m.Signer.Type)
	}
	if err := c.Rules.validate(); err != nil {
		return err
	}
	return c.Alerts.validate()
}

// validate checks only the rules that are enabled; a disabled rule (zero window / empty business_hours) is
// left untouched so an operator can turn one off simply by omitting it.
func (r RulesConfig) validate() error {
	if r.MassExport.Window > 0 {
		me := r.MassExport
		hasCeiling := me.Default.Rows > 0 || me.Default.Bytes > 0 || me.HeuristicMaxBroadReads > 0
		for ds, th := range me.PerDatasource {
			// A per-datasource entry that sets neither ceiling would leave exactly that datasource
			// unprotected (its entry overrides the default), so reject it rather than silently pass its
			// volume. The detector fails closed to the broad-read heuristic at runtime; this catches the
			// misconfiguration at load.
			if th.Rows <= 0 && th.Bytes <= 0 {
				return fmt.Errorf("config: rules.mass_export.per_datasource[%q] sets no rows or bytes ceiling", ds)
			}
			hasCeiling = true
		}
		if !hasCeiling {
			return fmt.Errorf("config: rules.mass_export has a window but no rows/bytes ceiling or heuristic threshold")
		}
	}
	if r.BulkPII.Window > 0 && r.BulkPII.MaxPIIDecisions <= 0 && r.BulkPII.MaxDistinctPIIColumns <= 0 {
		return fmt.Errorf("config: rules.bulk_pii has a window but neither max_pii_decisions nor max_distinct_pii_columns")
	}
	if r.OffHours.BusinessHours != "" {
		if _, err := r.OffHours.Parse(); err != nil {
			return err
		}
		if !r.OffHours.AppliesToPIIRead() && !r.OffHours.AppliesToWrite() {
			return fmt.Errorf("config: rules.off_hours.applies_to must include pii_read and/or write")
		}
	}
	if r.RepeatedDeny.Window > 0 && r.RepeatedDeny.MaxDeny <= 0 {
		return fmt.Errorf("config: rules.repeated_deny has a window but max_deny <= 0")
	}
	return nil
}

// validate checks every configured sink. dedup_window may be zero (dedup disabled); a webhook sink must name
// the env var that holds its URL, and its severity/format must be recognized.
func (a AlertsConfig) validate() error {
	if a.DedupWindow < 0 {
		return fmt.Errorf("config: alerts.dedup_window must be >= 0")
	}
	for i, s := range a.Sinks {
		if s.Type != "webhook" {
			return fmt.Errorf("config: alerts.sinks[%d].type must be webhook, got %q", i, s.Type)
		}
		if s.URLEnv == "" {
			return fmt.Errorf("config: alerts.sinks[%d].url_env is required", i)
		}
		switch s.MinSeverity {
		case "", SeverityInfo, SeverityWarn, SeverityCritical:
		default:
			return fmt.Errorf("config: alerts.sinks[%d].min_severity %q is not info/warn/critical", i, s.MinSeverity)
		}
		switch s.Format {
		case "", "slack":
		default:
			return fmt.Errorf("config: alerts.sinks[%d].format %q is not \"\" or slack", i, s.Format)
		}
	}
	return nil
}

// parseHourRange parses "HH:MM-HH:MM" into start/end minutes-of-day, requiring start < end (no overnight
// spans — business hours are same-day).
func parseHourRange(s string) (start, end int, err error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("config: business_hours %q must be HH:MM-HH:MM", s)
	}
	if start, err = parseHourMinute(lo); err != nil {
		return 0, 0, err
	}
	if end, err = parseHourMinute(hi); err != nil {
		return 0, 0, err
	}
	if start >= end {
		return 0, 0, fmt.Errorf("config: business_hours %q must have start before end", s)
	}
	return start, end, nil
}

// parseHourMinute parses "HH:MM" into minutes-of-day in [0, 1440).
func parseHourMinute(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("config: time %q must be HH:MM: %w", s, err)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// containsFold reports whether values contains target, case-insensitively.
func containsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}
