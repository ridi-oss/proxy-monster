package driver

import "strings"

// ShellQuote protects a field from POSIX shell expansion, including $() and backticks.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
