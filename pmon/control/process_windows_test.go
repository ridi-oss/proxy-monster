package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTrustRefusesAnEveryoneWritableBinary(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pmon.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := trustedPathComponent(exe, "it"); err != nil {
		t.Fatalf("a fresh file of this user's was refused: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(exe, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_WRITE_DATA,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone)},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(exe, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	err = trustedPathComponent(exe, "it")
	if err == nil || !strings.Contains(err.Error(), "writable by") {
		t.Errorf("an Everyone-writable binary: %v, want a refusal", err)
	}
}

func TestOnlyAnExeIsRunnable(t *testing.T) {
	dir := t.TempDir()
	for name, want := range map[string]bool{"pmon.exe": true, "pmon.EXE": true, "pmon": false, "pmon.cmd": false} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := executable(p) == nil; got != want {
			t.Errorf("%s runnable = %v, want %v", name, got, want)
		}
	}
}
