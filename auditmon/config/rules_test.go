package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadParsesRulesAndAlerts(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	me := cfg.Rules.MassExport
	if me.Window != 10*time.Minute {
		t.Errorf("mass_export.window = %v, want 10m", me.Window)
	}
	if me.HeuristicMaxBroadReads != 50 {
		t.Errorf("mass_export.heuristic_max_broad_reads = %d, want 50", me.HeuristicMaxBroadReads)
	}
	if got := me.Threshold("example-mysql"); got.Rows != 50000 || got.Bytes != 1073741824 {
		t.Errorf("mass_export threshold example-mysql = %+v, want rows 50000 bytes 1073741824", got)
	}
	if got := me.Threshold("unknown-ds"); got.Rows != 100000 {
		t.Errorf("mass_export threshold fallback = %+v, want default rows 100000", got)
	}

	if cfg.Rules.BulkPII.Window != 5*time.Minute || cfg.Rules.BulkPII.MaxPIIDecisions != 200 || cfg.Rules.BulkPII.MaxDistinctPIIColumns != 20 {
		t.Errorf("bulk_pii = %+v", cfg.Rules.BulkPII)
	}
	if cfg.Rules.RepeatedDeny.Window != 5*time.Minute || cfg.Rules.RepeatedDeny.MaxDeny != 20 {
		t.Errorf("repeated_deny = %+v", cfg.Rules.RepeatedDeny)
	}
	if cfg.Rules.AuthFailureBurst.Window != 5*time.Minute || cfg.Rules.AuthFailureBurst.MaxFailures != 10 {
		t.Errorf("auth_failure_burst = %+v", cfg.Rules.AuthFailureBurst)
	}
	if !cfg.Rules.OffHoursAdmin.Enabled {
		t.Errorf("off_hours_admin.enabled = %v, want true", cfg.Rules.OffHoursAdmin.Enabled)
	}

	oh := cfg.Rules.OffHours
	if !oh.AppliesToPIIRead() || !oh.AppliesToWrite() {
		t.Errorf("off_hours applies_to = %v, want pii_read and write", oh.AppliesTo)
	}
	bw, err := oh.Parse()
	if err != nil {
		t.Fatalf("parse off_hours: %v", err)
	}
	if bw.StartMinute != 9*60 || bw.EndMinute != 19*60 {
		t.Errorf("business window = [%d,%d), want [540,1140)", bw.StartMinute, bw.EndMinute)
	}
	if bw.Location.String() != "Asia/Seoul" {
		t.Errorf("business window location = %q, want Asia/Seoul", bw.Location)
	}

	if cfg.Alerts.DedupWindow != 15*time.Minute {
		t.Errorf("dedup_window = %v, want 15m", cfg.Alerts.DedupWindow)
	}
	if len(cfg.Alerts.Sinks) != 2 {
		t.Fatalf("sinks = %d, want 2", len(cfg.Alerts.Sinks))
	}
	if cfg.Alerts.Sinks[0].URLEnv != "SECOPS_WEBHOOK_URL" || cfg.Alerts.Sinks[0].MinSeverity != "warn" || cfg.Alerts.Sinks[0].MaxRetries != 3 {
		t.Errorf("sink[0] = %+v", cfg.Alerts.Sinks[0])
	}
	if cfg.Alerts.Sinks[1].Format != "slack" || cfg.Alerts.Sinks[1].MinSeverity != "critical" {
		t.Errorf("sink[1] = %+v", cfg.Alerts.Sinks[1])
	}
}

func TestDedupWindowDefaultsWhenAbsent(t *testing.T) {
	t.Setenv("AUDITMON_MONITOR_DB_DSN", "unused") // keep other paths inert
	cfg := baseValidConfig()
	cfg.Alerts.DedupWindow = 0
	// Validate tolerates a zero dedup window (dedup disabled); the 15m default is only applied by Load.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("zero dedup window should validate: %v", err)
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank(SeverityInfo) >= SeverityRank(SeverityWarn) {
		t.Error("info must rank below warn")
	}
	if SeverityRank(SeverityWarn) >= SeverityRank(SeverityCritical) {
		t.Error("warn must rank below critical")
	}
	if SeverityRank("bogus") != SeverityRank(SeverityWarn) {
		t.Error("an unknown severity must rank as warn")
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	cases := map[string]func(*Config){
		"mass_export window without ceiling": func(c *Config) {
			c.Rules.MassExport = MassExportRule{Window: time.Minute}
		},
		"bulk_pii window without any max": func(c *Config) {
			c.Rules.BulkPII = BulkPIIRule{Window: time.Minute}
		},
		"repeated_deny window without max": func(c *Config) {
			c.Rules.RepeatedDeny = RepeatedDenyRule{Window: time.Minute}
		},
		"auth_failure_burst window without max": func(c *Config) {
			c.Rules.AuthFailureBurst = AuthFailureBurstRule{Window: time.Minute}
		},
		"off_hours_admin enabled without a window": func(c *Config) {
			c.Rules.OffHoursAdmin = OffHoursAdminRule{Enabled: true}
		},
		"off_hours bad business_hours": func(c *Config) {
			c.Rules.OffHours = OffHoursRule{BusinessHours: "nope", AppliesTo: []string{"write"}}
		},
		"off_hours empty applies_to": func(c *Config) {
			c.Rules.OffHours = OffHoursRule{BusinessHours: "09:00-19:00"}
		},
		"off_hours reversed hours": func(c *Config) {
			c.Rules.OffHours = OffHoursRule{BusinessHours: "19:00-09:00", AppliesTo: []string{"write"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseValidConfig()
			mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %q", name)
			}
		})
	}
}

func TestValidateRejectsBadSinks(t *testing.T) {
	cases := map[string]func(*Config){
		"non-webhook type": func(c *Config) {
			c.Alerts.Sinks = []SinkConfig{{Type: "kafka", URLEnv: "X"}}
		},
		"missing url_env": func(c *Config) {
			c.Alerts.Sinks = []SinkConfig{{Type: "webhook"}}
		},
		"bad severity": func(c *Config) {
			c.Alerts.Sinks = []SinkConfig{{Type: "webhook", URLEnv: "X", MinSeverity: "loud"}}
		},
		"bad format": func(c *Config) {
			c.Alerts.Sinks = []SinkConfig{{Type: "webhook", URLEnv: "X", Format: "xml"}}
		},
		"negative dedup window": func(c *Config) {
			c.Alerts.DedupWindow = -time.Second
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseValidConfig()
			mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %q", name)
			}
		})
	}

	// A well-formed webhook sink and a well-formed rule set both validate.
	ok := baseValidConfig()
	ok.Alerts.Sinks = []SinkConfig{{Type: "webhook", URLEnv: "SECOPS_WEBHOOK_URL", MinSeverity: "warn", Rules: []string{"*"}}}
	ok.Rules.OffHours = OffHoursRule{BusinessHours: "09:00-19:00 UTC", AppliesTo: []string{"pii_read", "write"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("well-formed rules/sinks should validate: %v", err)
	}
}
