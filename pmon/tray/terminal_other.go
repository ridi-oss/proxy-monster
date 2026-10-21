//go:build !darwin

package main

import "errors"

var errCanceled = errors.New("canceled")

const canUninstall = false

// offerTerminal is macOS-only: Windows puts the app's own folder on PATH (putOnPath).
func offerTerminal() {}

func terminalInfo() terminalStatus { return terminalStatus{} }

func linkTerminal(string) error { return errors.New("not supported on this platform") }

// uninstall is macOS-only: Windows uninstalls through the MSI, which runs --forget.
func (a *app) uninstall() {}
