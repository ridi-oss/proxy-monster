package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// errNoBrowser reports that opening was suppressed rather than attempted and failed.
var errNoBrowser = errors.New("browser opening disabled")

// openBrowser opens url, preferring $BROWSER over the platform launcher. PMON_NO_BROWSER disables it.
//
// The launcher opens a page on the machine running this process, which is the wrong one over SSH;
// $BROWSER can name a script that forwards the URL to the desktop.
//
// An error means nothing could open it; the caller prints the URL regardless.
func openBrowser(url string) error {
	// An automated context has no user to show a page to; opening one is at best noise.
	if os.Getenv("PMON_NO_BROWSER") != "" {
		return errNoBrowser
	}
	if b := strings.TrimSpace(os.Getenv("BROWSER")); b != "" {
		// %s is the placeholder the convention defines; without one the URL is appended.
		if strings.Contains(b, "%s") {
			expanded := strings.ReplaceAll(b, "%s", url)
			fields := strings.Fields(expanded)
			if len(fields) > 0 {
				return exec.Command(fields[0], fields[1:]...).Start()
			}
		} else {
			fields := strings.Fields(b)
			if len(fields) > 0 {
				return exec.Command(fields[0], append(fields[1:], url)...).Start()
			}
		}
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("no known browser launcher for platform %q", runtime.GOOS)
	}
	return cmd.Start()
}
