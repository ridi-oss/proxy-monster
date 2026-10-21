package main

import "testing"

func TestWithProfileLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", profileLine + "\n"},
		{"alias ll='ls -l'", "alias ll='ls -l'\n" + profileLine + "\n"},
		{"alias ll='ls -l'\n", "alias ll='ls -l'\n" + profileLine + "\n"},
	} {
		got, changed := withProfileLine(tc.in)
		if !changed || got != tc.want {
			t.Errorf("withProfileLine(%q) = %q, %v; want %q", tc.in, got, changed, tc.want)
		}
	}
	// A profile that already names ~/.local/bin is the user's to manage.
	for _, in := range []string{`export PATH="$HOME/.local/bin:$PATH"` + "\n", "path+=(~/.local/bin)\n"} {
		if got, changed := withProfileLine(in); changed || got != in {
			t.Errorf("withProfileLine(%q) changed it to %q", in, got)
		}
	}
}

func TestWithoutProfileLine(t *testing.T) {
	added, _ := withProfileLine("alias ll='ls -l'\n")
	if got, changed := withoutProfileLine(added); !changed || got != "alias ll='ls -l'\n" {
		t.Errorf("withoutProfileLine = %q, %v", got, changed)
	}
	// The user's own line for the same folder stays.
	own := `export PATH="$HOME/.local/bin:$PATH"` + "\n"
	if got, changed := withoutProfileLine(own); changed || got != own {
		t.Errorf("withoutProfileLine removed the user's line: %q", got)
	}
	last := "a\n" + profileLine
	if got, _ := withoutProfileLine(last); got != "a\n" {
		t.Errorf("withoutProfileLine(%q) = %q", last, got)
	}
}

func TestOwnLink(t *testing.T) {
	for target, want := range map[string]bool{
		"/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon":            true,
		"/Users/dana/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmon": true,
		"/Users/dana/Downloads/Proxy Monster Desktop 2.app/Contents/MacOS/pmon":  true,
		"/opt/homebrew/Cellar/pmon/0.1.9/bin/pmon":                               false,
		"/Applications/Other.app/Contents/MacOS/pmon":                            false,
		"/Applications/Proxy Monster Desktop.app/Contents/MacOS/pmontray":        false,
	} {
		if got := ownLink(target); got != want {
			t.Errorf("ownLink(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestLastLine(t *testing.T) {
	if got := lastLine("Welcome!\n\n/usr/bin:/bin"); got != "/usr/bin:/bin" {
		t.Errorf("lastLine = %q", got)
	}
	if got := lastLine("/usr/bin\n"); got != "/usr/bin" {
		t.Errorf("lastLine = %q", got)
	}
}
