package state

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestEnsureDirIsPrivateToThisUser(t *testing.T) {
	t.Setenv(dirEnv, filepath.Join(t.TempDir(), "state"))
	d, err := EnsureDir()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, _ := sd.Control(); control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the DACL inherits from the parent")
	}
	me, _ := currentUser()
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no DACL: %v", err)
	}
	if dacl.AceCount == 0 {
		t.Error("an empty DACL grants nobody access")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(me) && !sid.Equals(system) {
			t.Errorf("ACE %d grants %s", i, sid)
		}
	}
}

func TestThePidStaysReadableWhileLocked(t *testing.T) {
	t.Setenv(dirEnv, filepath.Join(t.TempDir(), "state"))
	held, err := AcquirePidLock()
	if err != nil || !held {
		t.Fatalf("AcquirePidLock = %v, %v", held, err)
	}
	defer ReleasePidLock()
	if !DaemonRunning() {
		t.Error("DaemonRunning = false while the lock is held")
	}
	if got := DaemonPid(); got != os.Getpid() {
		t.Errorf("DaemonPid = %d, want %d", got, os.Getpid())
	}
	if again, err := AcquirePidLock(); err != nil || again {
		t.Errorf("a second AcquirePidLock = %v, %v; want false, nil", again, err)
	}
}

func TestEnsureDirLeavesAPrivateDACLAlone(t *testing.T) {
	t.Setenv(dirEnv, filepath.Join(t.TempDir(), "state"))
	d, err := EnsureDir()
	if err != nil {
		t.Fatal(err)
	}
	me, _ := currentUser()
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if !isPrivate(d, me, system) {
		t.Fatal("EnsureDir left a DACL isPrivate rejects, so every call would rewrite it")
	}
}
