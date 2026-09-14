package sqltarget

import "testing"

func TestConfigureDefaultsAndPresence(t *testing.T) {
	lookup := func(mapValues map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) { value, ok := mapValues[name]; return value, ok }
	}
	if got := Configure(lookup(nil), 3307); got != (Config{Host: "localhost", Port: 3307, Db: "acme", User: "acme", Password: "acme"}) {
		t.Fatalf("defaults = %+v", got)
	}
	if got := Configure(lookup(map[string]string{"PM_TARGET_HOST": "", "PM_TARGET_DB": "", "PM_TARGET_USER": "", "PM_TARGET_PASSWORD": ""}), 5433); got != (Config{Port: 5433}) {
		t.Fatalf("explicit empty settings = %+v", got)
	}
	values := map[string]string{"PM_TARGET_HOST": "target", "PM_TARGET_PORT": "5678", "PM_TARGET_DB": "app", "PM_TARGET_USER": "svc:reader", "PM_TARGET_PASSWORD": "p@s:s/w@rd"}
	if got := Configure(lookup(values), 3307); got != (Config{Host: "target", Port: 5678, Db: "app", User: "svc:reader", Password: "p@s:s/w@rd"}) {
		t.Fatal("explicit SQL target settings were changed")
	}
}

func TestConfigurePortFallback(t *testing.T) {
	for _, value := range []string{"", "   ", "not-a-port", "0", "4294967297"} {
		t.Run(value, func(t *testing.T) {
			config := Configure(func(name string) (string, bool) { return value, name == "PM_TARGET_PORT" }, 5433)
			if config.Port != 5433 {
				t.Fatalf("port %q = %d, want 5433", value, config.Port)
			}
		})
	}
}
