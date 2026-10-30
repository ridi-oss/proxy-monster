package sqldb_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/config"
	"github.com/ridi-oss/proxy-monster/goproxy/sqldb"
)

// settingsFromEnv parses the PM_TARGET_* vars through the same kong pass the proxy boots with.
func settingsFromEnv(t *testing.T, e *engines.Engine, env map[string]string) (sqldb.Settings, error) {
	t.Helper()
	for _, key := range []string{"PM_TARGET_HOST", "PM_TARGET_PORT", "PM_TARGET_DB", "PM_TARGET_USER", "PM_TARGET_PASSWORD", "PM_TARGET_TLS", "PM_TARGET_CA"} {
		old, had := os.LookupEnv(key)
		os.Unsetenv(key)
		t.Cleanup(func() {
			if had {
				os.Setenv(key, old)
			} else {
				os.Unsetenv(key)
			}
		})
	}
	for key, value := range env {
		t.Setenv(key, value)
	}
	var flags sqldb.Flags
	if _, err := config.Parse(&flags); err != nil {
		t.Fatal(err)
	}
	return sqldb.NewSettings(flags, e)
}

func TestSettingsDefaults(t *testing.T) {
	settings, err := settingsFromEnv(t, engines.MySQL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := (sqldb.Settings{Host: "localhost", Port: 3307, Db: "acme", User: "acme", Password: "acme"}); settings != want {
		t.Errorf("settings = %+v, want %+v", settings, want)
	}
	settings, err = settingsFromEnv(t, engines.Postgres, nil)
	if err != nil || settings.Port != 5433 {
		t.Errorf("Port = %d, %v; want 5433 (postgres default)", settings.Port, err)
	}
}

func TestSettingsPort(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"5678", 5678},
		{"   ", 3307},
		{"not-a-port", 3307},
		// 2^32 + 1 would register as port 1 under a truncating cast; out of int32 it is absent instead.
		{"4294967297", 3307},
	} {
		settings, err := settingsFromEnv(t, engines.MySQL, map[string]string{"PM_TARGET_PORT": tc.raw})
		if err != nil || settings.Port != tc.want {
			t.Errorf("PM_TARGET_PORT=%q: Port = %d, %v; want %d", tc.raw, settings.Port, err, tc.want)
		}
	}
}

func TestSettingsTLS(t *testing.T) {
	settings, err := settingsFromEnv(t, engines.MySQL, nil)
	if err != nil || settings.TLS != nil {
		t.Fatalf("unset PM_TARGET_TLS = %v, %v; want plaintext", settings.TLS, err)
	}
	settings, err = settingsFromEnv(t, engines.MySQL, map[string]string{"PM_TARGET_HOST": "db.cluster.example", "PM_TARGET_TLS": "verify-full"})
	if err != nil || settings.TLS == nil || settings.TLS.ServerName != "db.cluster.example" || settings.TLS.InsecureSkipVerify {
		t.Fatalf("verify-full = %+v, %v; want a verifying config for PM_TARGET_HOST", settings.TLS, err)
	}
	if _, err := settingsFromEnv(t, engines.MySQL, map[string]string{"PM_TARGET_TLS": "prefer"}); err == nil || !strings.Contains(err.Error(), "PM_TARGET_TLS") {
		t.Fatalf("PM_TARGET_TLS=prefer = %v, want a rejection", err)
	}
}
