//go:build !darwin

package main

import (
	"errors"
	"unsafe"
)

var onNotificationClick func(key string)

func postNative(id, title, body, key string) bool { return false }

func loginItem() (on, supported bool) { return false, false }

func setLoginItem(bool) error { return errors.New("Open at Login is not supported on this platform") }

func activatePid(int) {}

func listenForLinks() {}

var fakePrefs = map[string]bool{}

var fakeStrings = map[string]string{}

func prefString(key string) string { return fakeStrings[key] }

func setPrefString(key, value string) { fakeStrings[key] = value }

func preferredLanguages() []string { return nil }

func applyTheme(unsafe.Pointer, string) {}

func prefBool(key string) bool { return fakePrefs[key] }

func setPrefBool(key string, v bool) { fakePrefs[key] = v }
