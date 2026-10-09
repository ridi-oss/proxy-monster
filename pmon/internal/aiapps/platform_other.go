//go:build !darwin && !windows

package aiapps

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Claude Desktop has no Linux build; this is where it would keep its config, so the package builds and tests.
func claudeDesktopConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
}

func claudeDesktopInstalled() bool { return false }

func withClaudeDesktopClosed(_ func() bool, edit func() error) error { return edit() }

func toolDirs() []string {
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".local", "bin"), "/usr/local/bin", filepath.Join(home, ".npm-global", "bin")}
}

func toolNames(name string) []string { return []string{name} }

func isRunnable(fi os.FileInfo) bool { return fi.Mode()&0o111 != 0 }

func noConsole(cmd *exec.Cmd) *exec.Cmd { return cmd }
