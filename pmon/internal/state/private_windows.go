package state

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The control socket lives under the user's own temp directory, which only that user can write.
func socketRoot() string { return os.TempDir() }

func socketDirName() string { return "pmon" }

func currentUser() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

// ownedBy requires this user as the owner, who alone may then change the DACL; or the Administrators group,
// which owns what an elevated process creates, when this user is an administrator. uid is unused: Windows has
// no uids.
func ownedBy(path string, _ os.FileInfo, _ int) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot verify its ownership: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("cannot verify its ownership: %w", err)
	}
	me, err := currentUser()
	if err != nil {
		return err
	}
	if owner.Equals(me) {
		return nil
	}
	if admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err == nil && owner.Equals(admins) &&
		inGroup(admins) {
		// This user's elevated process made it. Taking ownership back keeps an unelevated process from refusing
		// it next time; the DACL already lets this user.
		_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, me, nil, nil, nil)
		return nil
	}
	return fmt.Errorf("owned by %s, not %s", owner, me)
}

// inGroup reports whether this user belongs to group, including as UAC's deny-only membership, which is how an
// administrator's unelevated token lists Administrators.
func inGroup(group *windows.SID) bool {
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(group) {
			return true
		}
	}
	return false
}

// makePrivate gives a directory this user owns a protected DACL granting only this user and SYSTEM, inherited
// by everything in it. Owner first: an owner can always rewrite the DACL. The control socket's only access
// control is this directory's DACL.
func makePrivate(path string, info os.FileInfo, _ bool) error {
	if err := ownedBy(path, info, 0); err != nil {
		return fmt.Errorf("%s is %w; refusing to use it", path, err)
	}
	me, err := currentUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	// Rewriting a directory's DACL also rewrites everything in it, which can fail a concurrent rename there,
	// so it is rewritten only when it is not already exactly this.
	if isPrivate(path, me, system) {
		return nil
	}
	// TrusteeValueFromSID hides the SID from the garbage collector.
	var pin runtime.Pinner
	pin.Pin(me)
	pin.Pin(system)
	defer pin.Unpin()
	grant := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid)},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{grant(me), grant(system)}, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("could not make %s private to this user: %w", path, err)
	}
	return nil
}

// isPrivate reports whether path's DACL is protected, holds only allow entries for me and system, and gives me
// full access to it and, by inheritance, to what it contains. Any other entry, of any kind, means no.
func isPrivate(path string, me, system *windows.SID) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	const inherits = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	var full, inherited bool
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(me) && !sid.Equals(system) {
			return false
		}
		if sid.Equals(me) {
			all := ace.Mask&fileAllAccess == fileAllAccess || ace.Mask&windows.GENERIC_ALL != 0
			full = full || (all && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0)
			inherited = inherited || (all && ace.Header.AceFlags&inherits == inherits)
		}
	}
	return full && inherited
}

// fileAllAccess is FILE_ALL_ACCESS, which x/sys/windows does not name.
const fileAllAccess = 0x1f01ff
