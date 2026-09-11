package providers_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/providers"
)

func TestBuiltinsPreserveBrokerSupport(t *testing.T) {
	registry := providers.Builtins()
	mysql, ok := registry.Lookup("mysql")
	if !ok || mysql.Broker == nil || mysql.Renderer == nil {
		t.Fatal("MySQL must provide both brokering and rendering")
	}
	postgres, ok := registry.Lookup("postgres")
	if !ok || postgres.Broker != nil || postgres.Renderer == nil {
		t.Fatal("PostgreSQL must provide rendering only")
	}
	for _, test := range []struct {
		engine  string
		address string
		reason  string
	}{
		{"mysql", "proxy:3306", ""},
		{"mysql", "", "no advertised proxy address"},
		{"postgres", "proxy:5432", "postgres brokering not yet supported"},
		{"postgres", "", "postgres brokering not yet supported"},
		{"other", "proxy:9999", `engine "other" not brokered`},
		{"other", "", "no advertised proxy address"},
	} {
		t.Run(test.engine+"/"+test.address, func(t *testing.T) {
			got := registry.UnavailableReason(driver.Endpoint{Engine: test.engine, AdvertiseAddr: test.address})
			if got != test.reason {
				t.Fatalf("reason = %q, want %q", got, test.reason)
			}
		})
	}
}
