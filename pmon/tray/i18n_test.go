package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/aiapps"
)

func TestMain(m *testing.M) {
	langOverride = "en"
	os.Exit(m.Run())
}

// Every message exists in every language, so no screen falls back to English in the middle.
func TestCatalogsHaveTheSameKeys(t *testing.T) {
	for _, l := range languages[1:] {
		for k := range catalogs["en"] {
			if _, ok := catalogs[l][k]; !ok {
				t.Errorf("%s is missing %q", l, k)
			}
		}
		for k := range catalogs[l] {
			if _, ok := catalogs["en"][k]; !ok {
				t.Errorf("%s has %q, which English does not", l, k)
			}
		}
	}
}

// A key the code asks for but no catalog defines would show the raw key to the user.
func TestEveryKeyTheCodeUsesExists(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	html, _ := os.ReadFile("prefs.html")
	key := regexp.MustCompile(`\bTn?\("([a-z][\w.-]*)"`)
	pageKey := regexp.MustCompile(`\bt\('([a-z][\w.-]*)'`)
	var used []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		for _, m := range key.FindAllStringSubmatch(string(src), -1) {
			used = append(used, m[1])
		}
	}
	for _, m := range pageKey.FindAllStringSubmatch(string(html), -1) {
		used = append(used, m[1])
	}
	if len(used) < 40 {
		t.Fatalf("found only %d keys in use; the scan is broken", len(used))
	}
	for _, k := range slices.Compact(slices.Sorted(slices.Values(used))) {
		_, one := catalogs["en"][k+".one"]
		if _, ok := catalogs["en"][k]; !ok && !one && !strings.HasSuffix(k, ".") {
			t.Errorf("no message for %q", k)
		}
	}
}

func TestT(t *testing.T) {
	if got := T("n.signedInBody", "server", "acme", "principal", "dana"); got != "Signed in to acme as dana." {
		t.Errorf("T = %q", got)
	}
	if got := Tn("confirm.conns", 1); got != "1 open database connection will be closed." {
		t.Errorf("Tn(1) = %q", got)
	}
	langOverride = "ko"
	defer func() { langOverride = "en" }()
	if got := Tn("confirm.conns", 3); got != "열린 데이터베이스 연결 3개가 닫힙니다." {
		t.Errorf("Tn(3) in Korean = %q", got)
	}
}

// Keys the code builds at run time, which the literal scan cannot see.
func TestDynamicKeysExist(t *testing.T) {
	var keys []string
	for _, kind := range []string{"signOut", "restart", "quit", "update", "remove"} {
		keys = append(keys, "confirm."+kind, "confirm."+kind+"Button")
	}
	for _, app := range aiapps.Apps() {
		keys = append(keys, "ai.after."+app.ID)
	}
	for _, p := range []string{"servers", "ai", "general", "about"} {
		keys = append(keys, "s.nav."+p)
	}
	for _, v := range []string{"system", "light", "dark"} {
		keys = append(keys, "s.general."+v)
	}
	for _, f := range []string{"url", "jdbc", "go-dsn", "cli", "python", "node", "aws-config"} {
		keys = append(keys, "format."+f)
	}
	for _, l := range languages {
		for _, k := range keys {
			if _, ok := catalogs[l][k]; !ok {
				t.Errorf("%s has no %q", l, k)
			}
		}
	}
}

func TestClockLabel(t *testing.T) {
	now := time.Date(2026, 3, 7, 23, 30, 0, 0, time.Local)
	for _, tc := range []struct {
		lang string
		at   time.Time
		want string
	}{
		{"en", now.Add(10 * time.Minute), "Today 23:40"},
		{"en", time.Date(2026, 3, 8, 9, 5, 0, 0, time.Local), "Tomorrow 09:05"},
		{"en", time.Date(2026, 3, 10, 9, 5, 0, 0, time.Local), "Mar 10 09:05"},
		{"ko", time.Date(2026, 3, 10, 9, 5, 0, 0, time.Local), "3월 10일 09:05"},
	} {
		langOverride = tc.lang
		if got := clockLabel(tc.at, now); got != tc.want {
			t.Errorf("%s %v: %q, want %q", tc.lang, tc.at, got, tc.want)
		}
	}
	langOverride = "en"
}

// One ended sign-in is announced once, however many renders and reauth events see it.
func TestAnEndedSignInIsAnnouncedOnce(t *testing.T) {
	var posted int
	postNotice = func(id, title, body, key string) { posted++ }
	t.Cleanup(func() { postNotice = notifyAction })
	a := newApp(t.Context())
	now := time.Now()
	s := &control.Status{LoggedIn: true, Servers: []control.ServerInfo{{Name: "ridi", LoggedIn: true,
		SessionExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)}}}
	for range 3 {
		a.noticeEndings(s, view{now: now})
	}
	s.Servers[0].ReauthRequired = true
	a.noticeEndings(s, view{now: now})
	if posted != 1 {
		t.Errorf("posted %d notices, want 1", posted)
	}
}
