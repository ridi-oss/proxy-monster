package main

import (
	"context"
	"testing"
)

func TestUpdateRows(t *testing.T) {
	langOverride = "en"
	defer func() { langOverride = "" }()
	if e := find(buildMenu(twoServers(), view{now: now}), "update-check"); e != nil {
		t.Errorf("a build without an updater offers %q", e.title)
	}
	m := buildMenu(twoServers(), view{now: now, updates: true})
	if e := find(m, "update-check"); e == nil || e.act.op != opCheckUpdates {
		t.Fatalf("no Check for Updates row: %+v", e)
	}
	m = buildMenu(nil, view{now: now, updates: true, pendingUpdate: "0.1.9"})
	e := find(m, "update-install")
	if e == nil || e.title != "Install Update 0.1.9" || e.act.op != opInstallUpdate {
		t.Fatalf("a held update is not offered: %+v", e)
	}
	if find(m, "update-check") != nil {
		t.Error("Check for Updates shows beside a held update")
	}
}

func TestAHeldUpdateInstallsOnlyWhenIdle(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir()) // no daemon, so no connections
	installs := 0
	installUpdate = func() { installs++ }
	auto := true
	autoInstall = func() bool { return auto }
	defer func() {
		installUpdate, autoInstall = installHeldUpdate, func() bool { on, _ := autoUpdates(); return on }
	}()

	for _, tc := range []struct {
		name    string
		setup   func(a *app)
		install bool
	}{
		{"idle", func(*app) {}, true},
		{"no update held", func(a *app) { a.pendingUpdate = "" }, false},
		{"a browser sign-in", func(a *app) { a.signingIn["acme"] = true }, false},
		{"the Settings window open", func(a *app) { a.prefsPid = 1 }, false},
		{"automatic updates off", func(*app) { auto = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installs, auto = 0, true
			a := newApp(context.Background())
			a.pendingUpdate = "0.1.9"
			tc.setup(a)
			a.installWhenIdle()
			if got := installs == 1; got != tc.install {
				t.Errorf("installed = %v, want %v", got, tc.install)
			}
		})
	}
}
