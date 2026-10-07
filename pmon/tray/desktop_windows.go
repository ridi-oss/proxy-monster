package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// confirmDialogTimeout bounds how long a confirmation waits for an answer. Its caller holds the action lock, so
// an indefinitely-open dialog would wedge every other lifecycle action.
const confirmDialogTimeout = 60 * time.Second

var confirm = confirmDialog

var notify = func(title, message string) { notifyAction("", title, message, "") }

const pmonName = "pmon.exe"

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	messageBoxTimeout = user32.NewProc("MessageBoxTimeoutW")
	openClipboard     = user32.NewProc("OpenClipboard")
	closeClipboard    = user32.NewProc("CloseClipboard")
	emptyClipboard    = user32.NewProc("EmptyClipboard")
	setClipboardData  = user32.NewProc("SetClipboardData")
	globalAlloc       = kernel32.NewProc("GlobalAlloc")
	globalLock        = kernel32.NewProc("GlobalLock")
	globalUnlock      = kernel32.NewProc("GlobalUnlock")
	globalFree        = kernel32.NewProc("GlobalFree")
	moveMemory        = kernel32.NewProc("RtlMoveMemory")
)

const (
	mbOKCancel     = 0x1
	mbIconWarning  = 0x30
	mbDefButton2   = 0x100
	mbTopmost      = 0x40000
	mbSetForegound = 0x10000
	idOK           = 1
	cfUnicodeText  = 13
	gmemMoveable   = 0x2
)

// notifyAction posts a notification. Windows toasts arrive with the installer, which registers the app's
// identity; until then this is a no-op and the menu is the display.
func notifyAction(id, title, message, key string) { postNative(id, title, message, key) }

// openURL opens an http(s) link in the default browser.
func openURL(u string) error {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return errors.New("not a web link: " + u)
	}
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(u), nil, nil, windows.SW_SHOWNORMAL)
}

// confirmDialog asks an OK/Cancel question with Cancel as the default, and fails CLOSED: a dialog that cannot be
// shown, or is left unanswered until the timeout, is a no. Windows names the buttons; confirmLabel is unused.
func confirmDialog(title, message, _ string) bool {
	r, _, _ := messageBoxTimeout.Call(0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(message))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))),
		mbOKCancel|mbIconWarning|mbDefButton2|mbTopmost|mbSetForegound, 0, uintptr(confirmDialogTimeout.Milliseconds()))
	return r == idOK
}

// copyToClipboard puts s on the clipboard as Unicode text.
func copyToClipboard(s string) error {
	text := utf16.Encode([]rune(s + "\x00"))
	if r, _, err := openClipboard.Call(0); r == 0 {
		return err
	}
	defer closeClipboard.Call()
	if r, _, err := emptyClipboard.Call(); r == 0 {
		return err
	}
	h, _, err := globalAlloc.Call(gmemMoveable, uintptr(len(text)*2))
	if h == 0 {
		return err
	}
	p, _, err := globalLock.Call(h)
	if p == 0 {
		globalFree.Call(h)
		return err
	}
	moveMemory.Call(p, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)*2))
	globalUnlock.Call(h)
	// The clipboard owns the memory once this succeeds.
	if r, _, err := setClipboardData.Call(cfUnicodeText, h); r == 0 {
		globalFree.Call(h)
		return err
	}
	return nil
}

// platformKeySuffix picks the Windows wording of a message (i18n.go).
const platformKeySuffix = "windows"

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

// noConsole keeps a console program this app runs (pmon.exe, an AI app's CLI) from opening a console window.
func noConsole(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

// withClaudeDesktopClosed makes a change to Claude Desktop's config while it is not running, restarting it after
// with the user's OK. Claude for Windows writes its config back from memory, so an edit made while it runs is
// lost the next time it saves.
func withClaudeDesktopClosed(edit func() error) error {
	running := claudeDesktopProcesses()
	if len(running) == 0 {
		return edit()
	}
	if !confirm(T("confirm.claudeRestart"), T("confirm.claudeRestartBody"), T("confirm.restartButton")) {
		for _, h := range running {
			windows.CloseHandle(h)
		}
		return errDeclined
	}
	for _, h := range running {
		_ = windows.TerminateProcess(h, 0)
		_, _ = windows.WaitForSingleObject(h, 10_000)
		windows.CloseHandle(h)
	}
	err := edit()
	startClaudeDesktop()
	return err
}

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
