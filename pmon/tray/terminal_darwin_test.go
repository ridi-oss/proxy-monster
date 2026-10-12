package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddToProfiles(t *testing.T) {
	write := func(home, name, s string) {
		if err := os.WriteFile(filepath.Join(home, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(home, name string) string {
		b, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			return "<missing>"
		}
		return string(b)
	}
	t.Run("zsh with only a bash profile gets its own .zshrc", func(t *testing.T) {
		home := t.TempDir()
		write(home, ".bashrc", "alias ll='ls -l'\n")
		if err := addToProfiles(home, "/bin/zsh"); err != nil {
			t.Fatal(err)
		}
		if got := read(home, ".zshrc"); got != profileLine+"\n" {
			t.Errorf(".zshrc = %q", got)
		}
		if got := read(home, ".bashrc"); !strings.HasSuffix(got, profileLine+"\n") {
			t.Errorf(".bashrc = %q", got)
		}
	})
	t.Run("bash with only .profile keeps reading it", func(t *testing.T) {
		home := t.TempDir()
		write(home, ".profile", "export EDITOR=vi\n")
		if err := addToProfiles(home, "/bin/bash"); err != nil {
			t.Fatal(err)
		}
		if got := read(home, ".bash_profile"); got != "<missing>" {
			t.Errorf("created .bash_profile, which shadows .profile: %q", got)
		}
		if got := read(home, ".profile"); got != "export EDITOR=vi\n"+profileLine+"\n" {
			t.Errorf(".profile = %q", got)
		}
	})
	t.Run("a profile that names the folder is left alone", func(t *testing.T) {
		home := t.TempDir()
		own := "path+=(~/.local/bin)\n"
		write(home, ".zshrc", own)
		if err := addToProfiles(home, "/bin/zsh"); err != nil {
			t.Fatal(err)
		}
		if got := read(home, ".zshrc"); got != own {
			t.Errorf(".zshrc = %q", got)
		}
	})
	t.Run("an unknown shell edits only existing profiles", func(t *testing.T) {
		home := t.TempDir()
		if err := addToProfiles(home, "/opt/homebrew/bin/fish"); err != nil {
			t.Fatal(err)
		}
		if entries, _ := os.ReadDir(home); len(entries) != 0 {
			t.Errorf("created %v", entries)
		}
	})
}
