//go:build !darwin

package main

import "errors"

var onNotificationClick func(key string)

func postNative(id, title, body, key string) bool { return false }

func loginItem() (on, supported bool) { return false, false }

func setLoginItem(bool) error { return errors.New("Open at Login is not supported on this platform") }

func activatePid(int) {}

func listenForLinks() {}

var fakePrefs = map[string]bool{}

func prefBool(key string) bool { return fakePrefs[key] }

func setPrefBool(key string, v bool) { fakePrefs[key] = v }
