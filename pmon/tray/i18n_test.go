package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
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
