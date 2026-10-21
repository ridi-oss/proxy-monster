package main

/*
#include <stdlib.h>
#include "native_darwin.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"fyne.io/systray"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// canUninstall shows Settings' Uninstall button: Windows uninstalls through the MSI.
const canUninstall = true

const (
	// terminalChoicePref records that the first-launch question was settled: "all", "me", "none", or "found"
	// (a terminal already had a pmon).
	terminalChoicePref = "TerminalChoice"
	// terminalLinkPref is the pmon link this app made, so switching or uninstalling removes it.
	terminalLinkPref = "TerminalLink"
	systemLink       = "/usr/local/bin/pmon"
)

var errCanceled = errors.New("canceled")

func userLink() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "pmon")
}

// loginShell is the user's shell from the directory service: an app started by launchd has no SHELL.
func loginShell() string {
	if u, err := user.Current(); err == nil {
		if out, err := exec.Command("/usr/bin/dscl", ".", "-read", "/Users/"+u.Username, "UserShell").Output(); err == nil {
			if f := strings.Fields(string(out)); len(f) == 2 {
				return f[1]
			}
		}
	}
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/zsh"
}

// shellPath is PATH as a new terminal sees it, which ok reports it could read; the app's own PATH is
// launchd's minimal default.
func shellPath() (dirs []string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, loginShell(), "-ilc", `printf '\n%s' "$PATH"`).Output()
	if p := lastLine(string(out)); err == nil && p != "" {
		return filepath.SplitList(p), true
	}
	return filepath.SplitList(os.Getenv("PATH")), false
}

func terminalDirs() []string {
	dirs, _ := shellPath()
	return dirs
}

func findPmon(dirs []string) string {
	for _, d := range dirs {
		p := filepath.Join(d, "pmon")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// offerTerminal asks, on the app's first launch, how to put pmon on PATH, unless a terminal already finds one.
func offerTerminal() {
	if prefString(terminalChoicePref) != "" {
		return
	}
	if _, err := os.Stat(bundledPmon()); err != nil {
		return
	}
	dirs, ok := shellPath()
	if !ok {
		return
	}
	if findPmon(dirs) != "" {
		// Recorded so later launches skip the shell; Settings can still link this copy.
		setPrefString(terminalChoicePref, "found")
		return
	}
	mode := askTerminal()
	switch mode {
	case "":
		return
	case "none":
		setPrefString(terminalChoicePref, "none")
		return
	}
	if err := linkTerminal(mode); err != nil {
		if !errors.Is(err, errCanceled) {
			notify(T("n.terminalFailed"), err.Error())
		}
		return
	}
	notify(T("n.terminalDone"), T("n.terminalDoneBody", "path", displayPath(prefString(terminalLinkPref))))
}

// askTerminal is "all", "me", "none", or "" when the dialog was dismissed or timed out.
func askTerminal() string {
	all, me, none := T("terminal.forAll"), T("terminal.forMe"), T("terminal.notNow")
	body, buttons := T("terminal.askBody"), osaQuote(none)+", "+osaQuote(me)+", "+osaQuote(all)
	if !allUsersCanRun() {
		body, buttons = T("terminal.askBodyMe"), osaQuote(none)+", "+osaQuote(me)
	}
	script := fmt.Sprintf(`display dialog %s with title %s buttons {%s} default button %s giving up after 600`,
		osaQuote(body), osaQuote(T("terminal.ask")), buttons, osaQuote(me))
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return ""
	}
	switch {
	case confirmedIn(string(out), all):
		return "all"
	case confirmedIn(string(out), me):
		return "me"
	case confirmedIn(string(out), none):
		return "none"
	}
	return ""
}

// linkTerminal links pmon for all users ("all", which asks for an administrator's password) or for this user
// ("me", adding ~/.local/bin to the shell profile when a terminal does not have it), replacing the link it
// made before.
func linkTerminal(mode string) error {
	link := userLink()
	if mode == "all" {
		if !allUsersCanRun() {
			return errors.New(T("terminal.allNeedsSystemApp"))
		}
		link = systemLink
	}
	for _, prev := range ownLinks() {
		if prev != link {
			if err := removeLink(prev); err != nil {
				return err
			}
		}
	}
	setPrefString(terminalLinkPref, "")
	if err := placeLink(link, mode == "all"); err != nil {
		return err
	}
	setPrefString(terminalLinkPref, link)
	if mode == "me" && !onPath(terminalDirs(), filepath.Dir(link)) {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		if err := addToProfiles(home, loginShell()); err != nil {
			return err
		}
	}
	setPrefString(terminalChoicePref, mode)
	return nil
}

// ownLinks are the places this app may have linked pmon: the one it recorded, and the two it offers, where an
// earlier pkg also put one without recording it.
func ownLinks() []string {
	links := []string{systemLink, userLink()}
	if l := prefString(terminalLinkPref); l != "" && l != links[0] && l != links[1] {
		links = append(links, l)
	}
	return links
}

// allUsersCanRun reports whether other accounts can reach this copy of the app: one in a home folder is private.
func allUsersCanRun() bool {
	home, err := os.UserHomeDir()
	return err != nil || !strings.HasPrefix(bundledPmon(), home+"/")
}

// placeLink links link to the bundled pmon, refusing to replace a file that is not a copy of this app's.
func placeLink(link string, admin bool) error {
	if target, err := os.Readlink(link); err == nil {
		if !ownLink(target) {
			return errors.New(T("terminal.taken", "path", link, "target", target))
		}
	} else if _, err := os.Lstat(link); err == nil {
		return errors.New(T("terminal.taken", "path", link, "target", link))
	}
	if admin {
		return asAdmin(fmt.Sprintf(`"mkdir -p " & quoted form of %s & " && ln -sfn " & quoted form of %s & " " & quoted form of %s`,
			osaQuote(filepath.Dir(link)), osaQuote(bundledPmon()), osaQuote(link)))
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	_ = os.Remove(link)
	return os.Symlink(bundledPmon(), link)
}

// removeLink removes a link this app made, asking for an administrator's password where the folder needs one.
func removeLink(link string) error {
	target, err := os.Readlink(link)
	if err != nil || !ownLink(target) {
		return nil
	}
	if err := os.Remove(link); err == nil || !errors.Is(err, os.ErrPermission) {
		return err
	}
	return asAdmin(`"rm -f " & quoted form of ` + osaQuote(link))
}

// asAdmin runs an AppleScript-built shell command through the system's administrator prompt.
func asAdmin(command string) error {
	script := fmt.Sprintf(`do shell script %s with administrator privileges with prompt %s`, command, osaQuote(T("terminal.adminPrompt")))
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "-128") {
			return errCanceled
		}
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// profiles are the shell profiles that get the PATH line when they exist.
var profiles = []string{".zshrc", ".bash_profile", ".bash_login", ".profile", ".bashrc"}

// ownProfile is the profile the login shell reads in a new terminal. Bash reads the first of its login profiles
// that exists, so creating .bash_profile beside a .profile would stop it reading .profile.
func ownProfile(home, shell string) string {
	switch filepath.Base(shell) {
	case "zsh":
		return ".zshrc"
	case "bash":
		for _, name := range []string{".bash_profile", ".bash_login", ".profile"} {
			if _, err := os.Stat(filepath.Join(home, name)); err == nil {
				return name
			}
		}
		return ".bash_profile"
	}
	return ""
}

// addToProfiles puts ~/.local/bin on PATH in the login shell's profile, creating it if needed, and in the other
// existing profiles.
func addToProfiles(home, shell string) error {
	own := ownProfile(home, shell)
	seen := map[string]bool{}
	for _, name := range append([]string{own}, profiles...) {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		p := filepath.Join(home, name)
		b, err := os.ReadFile(p)
		if err != nil && !(name == own && errors.Is(err, os.ErrNotExist)) {
			continue
		}
		if s, changed := withProfileLine(string(b)); changed {
			if err := writeKeepingMode(p, s); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeFromProfiles() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for _, name := range profiles {
		p := filepath.Join(home, name)
		if b, err := os.ReadFile(p); err == nil {
			if s, changed := withoutProfileLine(string(b)); changed {
				_ = writeKeepingMode(p, s)
			}
		}
	}
}

func writeKeepingMode(path, content string) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return os.WriteFile(path, []byte(content), mode)
}

func displayPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home+"/") {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

func terminalInfo() terminalStatus {
	st := terminalStatus{Shown: true, AllUsers: allUsersCanRun(), Found: displayPath(findPmon(terminalDirs()))}
	if link := prefString(terminalLinkPref); link != "" {
		if target, err := os.Readlink(link); err == nil && target == bundledPmon() {
			st.Link = displayPath(link)
			st.Mode = prefString(terminalChoicePref)
		}
	}
	return st
}

// forget undoes what the app set up for itself: Open at Login, the pmon link, the PATH line and its settings.
// Saved servers and sign-ins stay: they are pmon's, which the CLI shares. A link it could not remove stops it
// with the settings kept, so a second try still knows the link.
func forget() error {
	for _, link := range ownLinks() {
		if err := removeLink(link); err != nil {
			return err
		}
	}
	_ = setLoginItem(false)
	removeFromProfiles()
	C.pm_forget_prefs()
	return nil
}

// uninstall stops the daemon, forgets the app's setup, moves the app to the Trash and quits.
func (a *app) uninstall() {
	if !a.tryLockAction() {
		return
	}
	body := T("confirm.uninstallBody")
	if n := liveConns(a.ctx, ""); n > 0 {
		body += " " + Tn("confirm.conns", n)
	}
	if !confirm(T("confirm.uninstall"), body, T("confirm.uninstallButton")) {
		a.unlockAction()
		return
	}
	a.mu.Lock()
	a.tellPrefs("quit")
	a.mu.Unlock()
	if err := control.StopDaemon(a.ctx); err != nil && !errors.Is(err, control.ErrDaemonNotRunning) {
		notify(T("n.uninstallFailed"), err.Error())
		a.unlockAction()
		return
	}
	if err := forget(); err != nil {
		if !errors.Is(err, errCanceled) {
			notify(T("n.uninstallFailed"), err.Error())
		}
		a.unlockAction()
		return
	}
	if err := trashApp(); err != nil {
		notify(T("n.uninstallFailed"), err.Error())
		a.unlockAction()
		return
	}
	systray.Quit()
}

func trashApp() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bundle := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	if filepath.Ext(bundle) != ".app" {
		return fmt.Errorf("%s is not an app bundle", bundle)
	}
	p := C.CString(bundle)
	defer C.free(unsafe.Pointer(p))
	if e := C.pm_trash(p); e != nil {
		defer C.free(unsafe.Pointer(e))
		return errors.New(C.GoString(e))
	}
	return nil
}
