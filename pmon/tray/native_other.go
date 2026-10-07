//go:build !darwin

package main

import "errors"

var onNotificationClick func(key string)

func postNative(id, title, body, key string) bool { return false }

func loginItem() (on, supported bool) { return false, false }

func setLoginItem(bool) error { return errors.New("Open at Login is not supported on this platform") }

var prefs = map[string]bool{}

func prefBool(key string) bool { return prefs[key] }

func setPrefBool(key string, v bool) { prefs[key] = v }
