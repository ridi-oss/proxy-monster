package control

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedPathComponent requires that path be owned by this user or the system, and that nobody else may write
// to it. `what` names it in the error, so a refusal says whether the binary or its directory was the problem.
func trustedPathComponent(path, what string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot verify %s ownership: %w", what, err)
	}
	trusted, err := trustedSIDs()
	if err != nil {
		return err
	}
	isTrusted := func(sid *windows.SID) bool {
		for _, t := range trusted {
			if sid.Equals(t) {
				return true
			}
		}
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("cannot verify %s ownership: %w", what, err)
	}
	if !isTrusted(owner) {
		return fmt.Errorf("%s is owned by %s, not this user or the system", what, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("cannot read %s permissions: %w", what, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s has no access list, so anyone may write to it", what)
	}
	const write = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.DELETE | windows.GENERIC_WRITE | windows.GENERIC_ALL | fileDeleteChild
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("cannot read %s permissions: %w", what, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Object and conditional allow ACEs lay out their SID differently; one that cannot be read is refused.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("%s has an access rule of a kind pmon cannot check (type %d)", what, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&write != 0 && !isTrusted(sid) {
			return fmt.Errorf("%s is writable by %s", what, sid)
		}
	}
	return nil
}

// fileDeleteChild is FILE_DELETE_CHILD, which x/sys/windows does not name.
const fileDeleteChild = 0x40

// trustedSIDs are this user and the accounts that already control the machine.
func trustedSIDs() ([]*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	out := []*windows.SID{u.User.Sid}
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(k)
		if err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	installer, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return nil, err
	}
	return append(out, installer), nil
}

const exeSuffix = ".exe"

// runnable goes by the extension: Windows file modes carry no execute bit.
func runnable(path string, _ os.FileInfo) bool { return strings.EqualFold(filepath.Ext(path), ".exe") }

// detach starts the daemon outside the peer's console and process group, so closing a terminal or pressing
// Ctrl-C in it does not stop the daemon.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
}

// terminate ends the daemon outright: Windows has no SIGTERM for a process without a console.
func terminate(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer p.Release()
	return p.Kill()
}
