//go:build !windows

package main

import (
	"strings"
	"testing"
	"time"
)

// TestOsaQuoteNeutralizesInjection is the security-relevant one: a principal, datasource name, or error message
// reaches osascript as DATA, and an unescaped quote or backslash would let it close the string literal and run
// as AppleScript — arbitrary code from a control-plane-supplied value.
func TestOsaQuoteNeutralizesInjection(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// The quoted form must not contain a bare quote that would terminate the literal early.
		mustNotContain []string
	}{
		{
			name:           "closing quote plus a command",
			input:          `x" & (do shell script "touch /tmp/pwned") & "`,
			mustNotContain: []string{`x" &`},
		},
		{
			name:           "trailing backslash could escape the closing quote",
			input:          `abc\`,
			mustNotContain: []string{`abc\"`},
		},
		{
			name:           "newline could start a new statement",
			input:          "a\ndo shell script \"id\"",
			mustNotContain: []string{"\n"},
		},
	}
	for _, tc := range tests {
		got := osaQuote(tc.input)
		if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
			t.Errorf("%s: %q is not a quoted literal", tc.name, got)
		}
		for _, bad := range tc.mustNotContain {
			if strings.Contains(got, bad) {
				t.Errorf("%s: osaQuote(%q) = %q still contains %q", tc.name, tc.input, got, bad)
			}
		}
		// The interior must have no unescaped quote: strip escaped pairs, then look for a stray one.
		interior := got[1 : len(got)-1]
		stripped := strings.ReplaceAll(strings.ReplaceAll(interior, `\\`, ""), `\"`, "")
		if strings.Contains(stripped, `"`) {
			t.Errorf("%s: osaQuote(%q) leaves an unescaped quote: %q", tc.name, tc.input, got)
		}
	}
}

func TestOsaQuotePreservesOrdinaryText(t *testing.T) {
	if got, want := osaQuote("signed in as you@example.com"), `"signed in as you@example.com"`; got != want {
		t.Errorf("osaQuote = %q, want %q", got, want)
	}
}

// TestConfirmParsingIsFailClosed locks the parse of osascript's result record against the shapes macOS actually
// returns. The give-up case is the important one: the dialog is bounded so an unanswered prompt cannot wedge the
// action lock, and a timeout must read as "do NOT proceed" — walking away from the machine must never drop
// someone's live database connections.
func TestConfirmParsingIsFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		out   string
		label string
		want  bool
	}{
		// Verified against a real osascript run.
		{"confirmed", "button returned:Stop, gave up:false\n", "Stop", true},
		{"canceled", "button returned:Cancel, gave up:false\n", "Stop", false},
		{"gave up (timeout)", "button returned:, gave up:true\n", "Stop", false},
		{"empty output", "", "Stop", false},
		{"unrelated", "something else\n", "Stop", false},
	}
	for _, tc := range tests {
		if got := confirmedIn(tc.out, tc.label); got != tc.want {
			t.Errorf("%s: confirmedIn(%q, %q) = %v, want %v", tc.name, tc.out, tc.label, got, tc.want)
		}
	}
}

func TestTimeLeft(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Minute, "ended"},
		{0, "ended"},
		{20 * time.Second, "1 min left"},
		{24 * time.Minute, "24 min left"},
		{90 * time.Minute, "1h 30m left"},
	} {
		if got := timeLeft(tc.d); got != tc.want {
			t.Errorf("timeLeft(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
