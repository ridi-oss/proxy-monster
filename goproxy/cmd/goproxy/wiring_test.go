package main

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	"github.com/ridi-oss/proxy-monster/goproxy/config"
)

func TestRegistryOpensTargetsFromTheEnvironment(t *testing.T) {
	t.Setenv("PM_TARGET_HOST", "db.internal")
	t.Setenv("PM_TARGET_PORT", "4000")
	t.Setenv("PM_TARGET_DB", "shop")
	t.Setenv("PM_ADVERTISE_ADDR", "proxy.example:6033")
	var perEngine engineFlags
	flags, err := config.Parse(&perEngine)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*engines.Engine{engines.MySQL, engines.Postgres} {
		provider, err := perEngine.registry(flags.AdvertiseAddr).For(e)
		if err != nil {
			t.Fatal(err)
		}
		target, err := provider.OpenTarget()
		if err != nil {
			t.Fatalf("%s OpenTarget: %v", e.WireName, err)
		}
		if db := target.ConnectionInfo().GetProperties()["database"]; db != "shop" || target.TargetInfo() != "db.internal:4000" {
			t.Errorf("%s database, TargetInfo() = %q, %q; want shop, db.internal:4000", e.WireName, db, target.TargetInfo())
		}
		if endpoint := target.ConnectionInfo().GetEndpoint(); endpoint != "proxy.example:6033" {
			t.Errorf("%s endpoint = %q, want the advertise address", e.WireName, endpoint)
		}
		_ = target.Close()
	}
}
