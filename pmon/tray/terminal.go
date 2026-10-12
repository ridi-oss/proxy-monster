package main

import (
	"path/filepath"
	"strings"
)

// profileMarker ends the line this app adds to a shell profile, so forget removes that line and no other.
const profileMarker = "# added by Proxy Monster Desktop"

const profileLine = `export PATH="$HOME/.local/bin:$PATH" ` + profileMarker

// terminalStatus is the Settings window's "pmon in Terminal" card. Shown is false where the app does not
// manage it (Windows puts its own folder on PATH).
type terminalStatus struct {
	Shown    bool   `json:"shown"`
	AllUsers bool   `json:"allUsers"` // other accounts can run this copy, so "all users" is offered
	Mode     string `json:"mode"`     // "all" or "me": this app's link to this copy; "" for none
	Link     string `json:"link"`     // that link
	Found    string `json:"found"`    // the pmon a new terminal runs, if any
}

// withProfileLine is a shell profile that puts ~/.local/bin on PATH. A profile that already names
// ~/.local/bin is left alone, whatever it does with it.
func withProfileLine(content string) (string, bool) {
	if strings.Contains(content, ".local/bin") {
		return content, false
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + profileLine + "\n", true
}

// withoutProfileLine is a shell profile without the line this app added.
func withoutProfileLine(content string) (string, bool) {
	lines := strings.SplitAfter(content, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if strings.HasSuffix(strings.TrimRight(l, "\n"), profileMarker) {
			continue
		}
		kept = append(kept, l)
	}
	out := strings.Join(kept, "")
	return out, out != content
}

// ownLink reports whether a link target is the pmon inside a copy of this app, so a link that went stale
// when the app moved is still this app's to replace or remove.
func ownLink(target string) bool {
	return strings.HasSuffix(target, ".app/Contents/MacOS/pmon") && strings.Contains(filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(target)))), "Proxy Monster Desktop")
}

// lastLine is the last line of a shell's output, which follows anything its profile printed.
func lastLine(out string) string {
	out = strings.TrimRight(out, "\n")
	if i := strings.LastIndex(out, "\n"); i >= 0 {
		return out[i+1:]
	}
	return out
}

func onPath(dirs []string, dir string) bool {
	for _, d := range dirs {
		if filepath.Clean(d) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}
