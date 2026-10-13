package daemon

import (
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

func TestValidTargetRejectsSSHOptions(t *testing.T) {
	for _, ok := range []string{"studio", "dana@devbox.example", "devbox:2222", "sjcho-studio.example.ts.net"} {
		if err := validTarget(ok); err != nil {
			t.Errorf("validTarget(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-oProxyCommand=touch /tmp/x", "-v", "a b", "a'b", `a"b`, "a\\b", "a\nb"} {
		if validTarget(bad) == nil {
			t.Errorf("validTarget(%q) accepted it", bad)
		}
	}
}

func TestRemotePathsFitTheSocketLimit(t *testing.T) {
	t.Setenv("PMON_CONFIG_DIR", t.TempDir())
	ctl, sock, err := state.RemotePaths("a-very-long-user-name@a-rather-long-host-name.with.several.domain.labels.example")
	if err != nil {
		t.Fatal(err)
	}
	// ssh binds the control socket through a temporary name 17 bytes longer.
	if len(ctl)+17 > 104 || len(sock) > 104 {
		t.Errorf("paths too long: %q (%d), %q (%d)", ctl, len(ctl), sock, len(sock))
	}
	other, _, _ := state.RemotePaths("another")
	if !strings.HasSuffix(ctl, ".ctl") || !strings.HasSuffix(sock, ".sock") || other == ctl {
		t.Errorf("paths %q %q %q", ctl, sock, other)
	}
}

func TestRemoteShellRunsTheLoginShell(t *testing.T) {
	if got := remoteShell("pmon socket-path"); got != `exec "$SHELL" -lc 'pmon socket-path'` {
		t.Errorf("remoteShell = %s", got)
	}
}

func TestDaemonSocketSkipsForwardSockets(t *testing.T) {
	for path, want := range map[string]bool{
		"/tmp/pmon-501/pmon-9a631b7f1a34259a.sock":           true,
		"/tmp/pmon-501/pmon-9a631b7f1a34259a-r49960de5.sock": false,
		"/tmp/pmon-501/pmon-9a63.sock":                       false,
	} {
		if got := daemonSocket.MatchString(path); got != want {
			t.Errorf("daemonSocket(%q) = %v", path, got)
		}
	}
}
