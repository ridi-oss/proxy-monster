package providers_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/driver"
	"github.com/ridi-oss/proxy-monster/pmon/internal/providers"
)

func TestBuiltinsPreserveBrokerSupport(t *testing.T) {
	registry := providers.Builtins()
	for _, engine := range []string{"mysql", "postgres"} {
		if provider, ok := registry.Lookup(engine); !ok || provider.Engine() != engine {
			t.Fatalf("%s is not registered", engine)
		}
	}
	for _, test := range []struct {
		engine  string
		address string
		reason  string
	}{
		{"mysql", "proxy:3306", ""},
		{"mysql", "", "no advertised proxy address"},
		{"postgres", "proxy:5432", ""},
		{"postgres", "", "no advertised proxy address"},
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
