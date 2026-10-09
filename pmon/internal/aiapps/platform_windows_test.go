package aiapps

import "golang.org/x/sys/windows"

// The tests edit a config under a temporary profile; a Claude Desktop running on the test machine is not theirs.
func init() { runningClaudeDesktop = func() []windows.Handle { return nil } }
