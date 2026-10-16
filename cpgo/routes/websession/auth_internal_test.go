package websession

import (
	"strings"
	"testing"
)

func TestStorableIP(t *testing.T) {
	for _, bad := range []string{
		"not-an-ip", "999.1.1.1", "100.100.1.10:5432", "100.100.1.0/24",
		"100.100.1.10\x00", "100.100.1.10\x0012", "100.100.1.10​",
		"fe80::1%lo0", "[::1]", "100.100.001.010", "010.1.1.1",
	} {
		if storableIP(strings.TrimSpace(bad)) {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"100.100.1.10", "  100.100.1.10  ", "::1", "2001:db8::1", "fe80::1"} {
		if !storableIP(strings.TrimSpace(good)) {
			t.Errorf("refused %q", good)
		}
	}
}
