package main

import "testing"

func TestToastTextCannotBreakTheXML(t *testing.T) {
	if got := xmlEscape(`a"<b>&'`); got != "a&quot;&lt;b&gt;&amp;&apos;" {
		t.Errorf("xmlEscape = %q", got)
	}
}

func TestLinksRouteByKind(t *testing.T) {
	var shown bool
	var key, link string
	onShow = func() { shown = true }
	onNotificationClick = func(k string) { key = k }
	onConnectLink = func(raw string) { link = raw }
	defer func() { onShow, onNotificationClick, onConnectLink = nil, nil, nil }()

	openLink("show")
	openLink("pmon://notification?key=signin%3Aforged")
	openLink("pmon://notification?key=signin%3Aforged&token=0000")
	openLink("pmon://notification-evil?key=signin%3Aforged&token=" + toastToken)
	openLink("pmon://notification?key=signin%3Aacme&token=" + toastToken)
	openLink("pmon://connect?name=acme&url=https%3A%2F%2Fpm.acme.example")
	openLink("https://example.com")
	if !shown || key != "signin:acme" || link != "pmon://connect?name=acme&url=https%3A%2F%2Fpm.acme.example" {
		t.Errorf("shown=%v key=%q link=%q", shown, key, link)
	}
}

func TestPathEntryIsAddedOnceAndMoves(t *testing.T) {
	for _, tc := range []struct{ current, dir, old, want string }{
		{"", `C:\a`, "", `C:\a`},
		{`C:\x;C:\y`, `C:\a`, "", `C:\x;C:\y;C:\a`},
		{`C:\x;c:\A`, `C:\a`, "", `C:\x;c:\A`},
		{`C:\x;C:\old;C:\y`, `C:\a`, `C:\old`, `C:\x;C:\y;C:\a`},
		{`C:\x;;C:\a;C:\a`, `C:\a`, `C:\a`, `C:\x;C:\a`},
		{`C:\x;C:\a\`, `C:\a`, "", `C:\x;C:\a\`},
	} {
		if got := withPathEntry(tc.current, tc.dir, tc.old); got != tc.want {
			t.Errorf("withPathEntry(%q, %q, %q) = %q, want %q", tc.current, tc.dir, tc.old, got, tc.want)
		}
	}
}
