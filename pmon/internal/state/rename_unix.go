//go:build !windows

package state

import "os"

func rename(from, to string) error { return os.Rename(from, to) }
