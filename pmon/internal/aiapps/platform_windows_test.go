package aiapps

import (
	"testing"

	"golang.org/x/sys/windows"
)

var claudeDesktopChecks int

// The tests edit a config under a temporary profile; a Claude Desktop running on the test machine is not theirs.
func init() {
	runningClaudeDesktop = func() []windows.Handle { claudeDesktopChecks++; return nil }
}

// A batch of changes closes Claude Desktop once, not once per change.
func TestBatchClosesClaudeDesktopOnce(t *testing.T) {
	setHome(t, t.TempDir())
	app := claudeDesktop()
	claudeDesktopChecks = 0
	err := app.Batch(Setup{Pmon: `C:\p\pmon.exe`}, func(s Setup) error {
		for _, name := range []string{"a", "b", "c"} {
			if _, _, err := app.Add(s, Server{Name: name}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || claudeDesktopChecks != 1 {
		t.Errorf("err %v, Claude Desktop checked %d times, want once", err, claudeDesktopChecks)
	}
}
