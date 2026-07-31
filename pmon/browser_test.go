package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOpenBrowserHonorsBROWSER: $BROWSER takes precedence over the platform launcher. It points at a
// script writing to a temp file, so nothing reaches a real desktop.
func TestOpenBrowserHonorsBROWSER(t *testing.T) {
	dir := t.TempDir()
	got := filepath.Join(dir, "got.txt")

	for _, test := range []struct {
		name    string
		browser string
		want    string
	}{
		// A bare launcher gets the URL appended, which is what a $BROWSER script expects.
		{"appended", "", "https://idp.example/activate?code=ABCD"},
		// %s is the placeholder the convention defines.
		{"placeholder", "%s", "https://idp.example/activate?code=ABCD"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_ = os.Remove(got)
			script := filepath.Join(dir, "fake-browser")
			body := "#!/bin/sh\nprintf '%s' \"$1\" > " + got + "\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			b := script
			if test.browser == "%s" {
				b = script + " %s"
			}
			t.Setenv("BROWSER", b)
			t.Setenv("PMON_NO_BROWSER", "")

			if err := openBrowser("https://idp.example/activate?code=ABCD"); err != nil {
				t.Fatalf("openBrowser: %v", err)
			}
			// Start() does not wait for the process, so poll until the script writes.
			var data []byte
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if data, _ = os.ReadFile(got); len(data) > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if strings.TrimSpace(string(data)) != test.want {
				t.Fatalf("$BROWSER received %q, want %q", strings.TrimSpace(string(data)), test.want)
			}
		})
	}
}

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
