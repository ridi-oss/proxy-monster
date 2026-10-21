package main

import "runtime/debug"

// Version is rewritten by release-please on each pm-ci release, through the marker comment on its line.
const Version = "0.1.1" // x-release-please-version

func fullVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return Version + "+" + s.Value[:12]
			}
		}
	}
	return Version
}
