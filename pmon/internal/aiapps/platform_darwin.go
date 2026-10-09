package aiapps

import (
	"os"
	"os/exec"
	"path/filepath"
)

func claudeDesktopConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
}

func claudeDesktopInstalled() bool {
	_, err := os.Stat("/Applications/Claude.app")
	return err == nil
}

// withClaudeDesktopClosed just makes the edit: Claude Desktop for macOS keeps an edit made while it runs.
func withClaudeDesktopClosed(_ func() bool, edit func() error) error { return edit() }

// toolDirs are where installers put a CLI. An app opened from Finder gets a minimal PATH without ~/.local/bin or
// Homebrew, so PATH alone would miss both.
func toolDirs() []string {
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".npm-global", "bin")}
}

func toolNames(name string) []string { return []string{name} }

func isRunnable(fi os.FileInfo) bool { return fi.Mode()&0o111 != 0 }

func noConsole(cmd *exec.Cmd) *exec.Cmd { return cmd }
