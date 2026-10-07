package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenBrowserSuppressed: the harness runs a real pmon binary, so a test run would otherwise open
// tabs on whoever is running it.
func TestOpenBrowserSuppressed(t *testing.T) {
	dir := t.TempDir()
	got := filepath.Join(dir, "should-not-exist")
	script := filepath.Join(dir, "fake-browser")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+got+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BROWSER", script)
	t.Setenv("PMON_NO_BROWSER", "1")

	if err := openBrowser("https://idp.example/activate"); !errors.Is(err, errNoBrowser) {
		t.Fatalf("openBrowser err = %v, want errNoBrowser", err)
	}
	if _, err := os.Stat(got); err == nil {
		t.Fatal("the browser ran although PMON_NO_BROWSER was set")
	}
}
