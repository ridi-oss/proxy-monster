package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// confirmDialogTimeout bounds how long a confirmation waits for an answer. Its caller holds the action lock, so
// an indefinitely-open dialog would wedge every other lifecycle action.
const confirmDialogTimeout = 60 * time.Second

// macOS integration, done by shelling out to the system tools rather than binding AppKit: pmontray already
// pays for cgo via the systray, and adding Objective-C for three small affordances would buy nothing. Each
// call is best-effort — a failed notification must never break an action.

// notify posts a user notification. Failures are ignored: this is a courtesy channel, and the menu itself is
// the authoritative display.
func notify(title, message string) {
	script := fmt.Sprintf("display notification %s with title %s", osaQuote(message), osaQuote(title))
	_ = exec.Command("osascript", "-e", script).Run()
}

// confirmDialog asks a modal yes/no question and reports whether the user confirmed.
//
// It fails CLOSED — a dialog that cannot be shown returns false, so an unattended or broken-UI state can never
// silently drop someone's live database connections. This mirrors the CLI, where a missing terminal also
// refuses rather than assuming yes.
func confirmDialog(title, message, confirmLabel string) bool {
	// `giving up after` bounds the modal: a dialog left open would otherwise block its caller forever, and the
	// caller holds the action lock — so an unanswered prompt would wedge every other lifecycle action. A
	// give-up returns `gave up:true` with an empty `button returned:`, which fails the check below, so walking
	// away means the destructive action does NOT happen.
	script := fmt.Sprintf(
		`display dialog %s with title %s buttons {"Cancel", %s} default button "Cancel" with icon caution giving up after %d`,
		osaQuote(message), osaQuote(title), osaQuote(confirmLabel), int(confirmDialogTimeout.Seconds()),
	)
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return false // includes the user pressing Cancel, which osascript reports as an error
	}
	return confirmedIn(string(out), confirmLabel)
}

// confirmedIn reports whether osascript's result record says the confirm button was pressed. Split out so the
// parse is testable against the shapes macOS really returns — notably `button returned:, gave up:true` on a
// timeout, which must NOT read as confirmation.
func confirmedIn(out, confirmLabel string) bool {
	if confirmLabel == "" {
		return false
	}
	return strings.Contains(out, "button returned:"+confirmLabel)
}

// copyToClipboard puts s on the system clipboard via pbcopy.
func copyToClipboard(s string) error {
	cmd := exec.Command("pbcopy")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(s)); err != nil {
		stdin.Close()
		_ = cmd.Wait()
		return err
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Wait()
		return err
	}
	return cmd.Wait()
}

// osaQuote renders s as an AppleScript string literal. Required, not cosmetic: a principal, datasource name, or
// error message reaches these scripts as data, and an unescaped quote or backslash would otherwise let it
// terminate the literal and run as AppleScript.
func osaQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
