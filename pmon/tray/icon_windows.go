package main

import (
	"crypto/sha256"
	"fmt"
	"image/color"
	"sync"

	"golang.org/x/sys/windows/registry"
)

var (
	iconMu    sync.Mutex
	iconCache = map[string][]byte{}
)

// regularIcon is the state icon for the notification area: white on a dark taskbar, black on a light one.
func regularIcon(template []byte) []byte {
	light := lightTaskbar()
	key := fmt.Sprintf("%t:%x", light, sha256.Sum256(template))
	iconMu.Lock()
	defer iconMu.Unlock()
	if ico, ok := iconCache[key]; ok {
		return ico
	}
	c := color.NRGBA{R: 255, G: 255, B: 255}
	if light {
		c = color.NRGBA{}
	}
	ico := toICO(recolor(template, c))
	iconCache[key] = ico
	return ico
}

func lightTaskbar() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("SystemUsesLightTheme")
	return err == nil && v == 1
}
