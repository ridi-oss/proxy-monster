package aiapps

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// claudePackage is the folder of Claude Desktop's MSIX package, or "" when it is not installed that way.
func claudePackage() string {
	matches, _ := filepath.Glob(filepath.Join(os.Getenv("LOCALAPPDATA"), "Packages", "Claude_*"))
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// claudeDesktopConfig is where Claude Desktop reads its MCP servers. The MSIX package keeps %APPDATA% writes in
// its own LocalCache, so that is where its config lives; the older installer used %APPDATA% itself.
func claudeDesktopConfig() string {
	if pkg := claudePackage(); pkg != "" {
		return filepath.Join(pkg, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json")
	}
	return filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json")
}

func claudeDesktopInstalled() bool {
	if claudePackage() != "" {
		return true
	}
	_, err := os.Stat(filepath.Join(os.Getenv("LOCALAPPDATA"), "AnthropicClaude"))
	return err == nil
}

// toolDirs are where the Claude Code and Codex installers put their commands: Claude's native installer's
// ~/.local/bin, Codex's installer's %LOCALAPPDATA%\Programs\OpenAI\Codex\bin, and npm's global directory.
func toolDirs() []string {
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".local", "bin"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "OpenAI", "Codex", "bin"),
		filepath.Join(os.Getenv("APPDATA"), "npm")}
}

// toolNames are the file names a command can have: npm installs a .cmd shim.
func toolNames(name string) []string { return []string{name + ".exe", name + ".cmd"} }

func isRunnable(os.FileInfo) bool { return true }

// noConsole keeps an AI app's CLI from opening a console window when a windowless app runs it.
func noConsole(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

// withClaudeDesktopClosed makes a change to Claude Desktop's config while it is not running, restarting it after
// once confirm agrees. Claude for Windows writes its config back from memory, so an edit made while it runs is
// lost the next time it saves.
func withClaudeDesktopClosed(confirm func() bool, edit func() error) error {
	running := runningClaudeDesktop()
	if len(running) == 0 {
		return edit()
	}
	if confirm == nil || !confirm() {
		for _, h := range running {
			windows.CloseHandle(h)
		}
		return ErrDeclined
	}
	exited := true
	for _, h := range running {
		_ = windows.TerminateProcess(h, 0)
		if ev, err := windows.WaitForSingleObject(h, 10_000); err != nil || ev != windows.WAIT_OBJECT_0 {
			exited = false
		}
		windows.CloseHandle(h)
	}
	for _, h := range runningClaudeDesktop() {
		exited = false
		windows.CloseHandle(h)
	}
	// A Claude Desktop still running would write its old config back over the edit.
	if !exited {
		return ErrStillRunning
	}
	err := edit()
	startClaudeDesktop()
	return err
}

var runningClaudeDesktop = claudeDesktopProcesses

// claudeDesktopProcesses opens every running claude.exe of Claude Desktop: its MSIX package, or the older
// per-user install. A process of another app named claude.exe is left alone.
func claudeDesktopProcesses() []windows.Handle {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var handles []windows.Handle
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "claude.exe") {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil || !isClaudeDesktop(windows.UTF16ToString(buf[:n])) {
			windows.CloseHandle(h)
			continue
		}
		handles = append(handles, h)
	}
	return handles
}

func isClaudeDesktop(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, `\windowsapps\claude_`) || strings.Contains(p, `\anthropicclaude\`)
}

// startClaudeDesktop opens Claude Desktop again: the package through its AppUserModelID, the older install
// through its launcher.
func startClaudeDesktop() {
	if pkg := claudePackage(); pkg != "" {
		_ = noConsole(exec.Command("explorer.exe", `shell:AppsFolder\`+filepath.Base(pkg)+"!Claude")).Start()
		return
	}
	_ = exec.Command(filepath.Join(os.Getenv("LOCALAPPDATA"), "AnthropicClaude", "claude.exe")).Start()
}
