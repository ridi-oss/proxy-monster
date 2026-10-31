package edge

import (
	"net/netip"
	"strings"
	"testing"
)

func setEdgeEnv(t *testing.T, listen, routes, trusted, health string) {
	t.Helper()
	t.Setenv("PM_EDGE_LISTEN", listen)
	t.Setenv("PM_WIRE_ROUTES", routes)
	t.Setenv("PM_TRUSTED_PROXIES", trusted)
	t.Setenv("PM_EDGE_HEALTH_PORT", health)
}

func TestLoadParsesListenersRoutesAndTrustedProxies(t *testing.T) {
	setEdgeEnv(t,
		"mysql:3306, postgres:5432,HTTPS:443",
		"DB1.Example.com=10.0.1.5:16033, db2.example.com=db2.internal:16432",
		"100.64.0.0/10, 10.0.0.7",
		"8080",
	)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	wantListeners := []Listener{{KindMySQL, 3306}, {KindPostgres, 5432}, {KindHTTPS, 443}}
	if len(cfg.Listeners) != len(wantListeners) {
		t.Fatalf("listeners = %v, want %v", cfg.Listeners, wantListeners)
	}
	for i, l := range wantListeners {
		if cfg.Listeners[i] != l {
			t.Fatalf("listener %d = %v, want %v", i, cfg.Listeners[i], l)
		}
	}
	if got := cfg.Routes["db1.example.com"]; got != "10.0.1.5:16033" {
		t.Fatalf("db1 route = %q", got)
	}
	if got := cfg.Routes["db2.example.com"]; got != "db2.internal:16432" {
		t.Fatalf("db2 route = %q", got)
	}
	wantTrusted := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("10.0.0.7/32")}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != wantTrusted[0] || cfg.TrustedProxies[1] != wantTrusted[1] {
		t.Fatalf("trusted = %v, want %v", cfg.TrustedProxies, wantTrusted)
	}
	if cfg.HealthPort != 8080 {
		t.Fatalf("health port = %d", cfg.HealthPort)
	}
}

func TestLoadLeavesHealthPortOffWhenUnset(t *testing.T) {
	setEdgeEnv(t, "mysql:3306", "db1.example.com=10.0.1.5:16033", "10.0.0.0/8", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HealthPort != 0 {
		t.Fatalf("health port = %d, want 0", cfg.HealthPort)
	}
}

func TestLoadRefusesInvalidConfiguration(t *testing.T) {
	const (
		listen  = "mysql:3306"
		routes  = "db1.example.com=10.0.1.5:16033"
		trusted = "10.0.0.0/8"
	)
	cases := []struct {
		name                            string
		listen, routes, trusted, health string
		wantErr                         string
	}{
		{"duplicate host", listen, "db1.example.com=10.0.1.5:16033,DB1.example.com=10.0.1.6:16033", trusted, "", "more than once"},
		{"bad kind", "oracle:1521", routes, trusted, "", "unknown kind"},
		{"empty trusted proxies", listen, routes, "", "", "PM_TRUSTED_PROXIES is required"},
		{"blank trusted proxies", listen, routes, " , ", "", "PM_TRUSTED_PROXIES is required"},
		{"bad trusted proxy", listen, routes, "not-an-ip", "", "neither an IP address nor a CIDR block"},
		{"missing listen", "", routes, trusted, "", "PM_EDGE_LISTEN is required"},
		{"listen without port", "mysql", routes, trusted, "", "must be kind:port"},
		{"listen port out of range", "mysql:70000", routes, trusted, "", "1-65535"},
		{"duplicate listen port", "mysql:3306,postgres:3306", routes, trusted, "", "more than once"},
		{"missing routes", listen, "", trusted, "", "PM_WIRE_ROUTES is required"},
		{"route without backend", listen, "db1.example.com", trusted, "", "host=backend-host:port"},
		{"route backend without port", listen, "db1.example.com=10.0.1.5", trusted, "", "must be host:port"},
		{"route wildcard host", listen, "*.example.com=10.0.1.5:16033", trusted, "", "invalid host name"},
		{"health port collides", listen, routes, trusted, "3306", "also a PM_EDGE_LISTEN port"},
		{"health port garbage", listen, routes, trusted, "abc", "PM_EDGE_HEALTH_PORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEdgeEnv(t, tc.listen, tc.routes, tc.trusted, tc.health)
			_, err := Load()
			if err == nil {
				t.Fatalf("Load succeeded, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
