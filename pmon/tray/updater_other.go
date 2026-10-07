//go:build !darwin

package main

var onUpdateReady func(version string, interactive bool)

func updatesConfigured() bool { return false }

func autoUpdates() (on, forced bool) { return false, false }

func startUpdater() bool { return false }

func checkForUpdates() {}

func setAutoUpdatesNow(bool) {}

func installHeldUpdate() {}
