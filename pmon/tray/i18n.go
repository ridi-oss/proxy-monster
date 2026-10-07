package main

import (
	"embed"
	"encoding/json"
	"strconv"
	"strings"
)

//go:embed i18n/*.json
var catalogFiles embed.FS

// languages are the UI languages, in the order the language picker lists them.
var languages = []string{"en", "ko"}

var catalogs = loadCatalogs()

func loadCatalogs() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, lang := range languages {
		data, err := catalogFiles.ReadFile("i18n/" + lang + ".json")
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(data, &m); err != nil {
			panic(err)
		}
		out[lang] = m
	}
	return out
}

// Preference keys shared by the menu-bar process and the Settings window.
const (
	prefLanguage = "language" // "system", or one of languages
	prefTheme    = "theme"    // "system", "light" or "dark"
	// prefAutoUpdates is Sparkle's own key, so the updater reads the Settings window's choice directly.
	prefAutoUpdates = "SUEnableAutomaticChecks"
)

// langOverride pins the language, for tests.
var langOverride string

// lang is the UI language: the user's choice, or with "system" the Mac's first preferred language we have.
func lang() string {
	if langOverride != "" {
		return langOverride
	}
	if l := prefString(prefLanguage); l != "" && l != "system" {
		if _, ok := catalogs[l]; ok {
			return l
		}
	}
	for _, l := range preferredLanguages() {
		if base, _, _ := strings.Cut(strings.ToLower(l), "-"); catalogs[base] != nil {
			return base
		}
	}
	return "en"
}

// T is the message for key in the current language, with each {name} replaced by the value after it in kv.
// A key missing from a translation falls back to English, and a missing English key shows the key itself.
func T(key string, kv ...string) string {
	msg, ok := catalogs[lang()][key]
	if !ok {
		if msg, ok = catalogs["en"][key]; !ok {
			msg = key
		}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		msg = strings.ReplaceAll(msg, "{"+kv[i]+"}", kv[i+1])
	}
	return msg
}

// Tn picks key.one or key.other by count, and fills {count}.
func Tn(key string, n int, kv ...string) string {
	form := key + ".other"
	if n == 1 {
		form = key + ".one"
	}
	return T(form, append([]string{"count", strconv.Itoa(n)}, kv...)...)
}

// theme is the chosen appearance: "system", "light" or "dark".
func theme() string {
	switch t := prefString(prefTheme); t {
	case "light", "dark":
		return t
	}
	return "system"
}
