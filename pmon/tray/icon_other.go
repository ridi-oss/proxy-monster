//go:build !windows

package main

// regularIcon is the template icon itself: macOS tints it.
func regularIcon(template []byte) []byte { return template }
