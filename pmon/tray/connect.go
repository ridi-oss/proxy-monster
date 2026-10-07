package main

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// connectLink is a parsed `pmon://connect?name=<server>&url=<address>` link from the console's Connect page.
type connectLink struct {
	name string
	url  string
}

// serverName matches what the daemon accepts as a server name, so a bad link is refused before the dialog.
var serverName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// parseConnectLink accepts only what the console emits. Any web page can open a pmon:// link, so the address
// must be https (http only for this machine, for a local stack), and the user still confirms before anything
// changes.
func parseConnectLink(raw string) (connectLink, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "pmon" || u.Host != "connect" {
		return connectLink{}, errors.New(T("link.invalid"))
	}
	q := u.Query()
	addr, err := url.Parse(q.Get("url"))
	if err != nil || addr.Hostname() == "" || addr.User != nil || addr.RawQuery != "" || addr.Fragment != "" {
		return connectLink{}, errors.New(T("link.noAddress"))
	}
	switch addr.Scheme {
	case "https":
	case "http":
		if host := addr.Hostname(); host != "localhost" && !net.ParseIP(host).IsLoopback() {
			return connectLink{}, errors.New(T("link.https"))
		}
	default:
		return connectLink{}, errors.New(T("link.https"))
	}
	name := strings.ToLower(q.Get("name"))
	if name == "" && net.ParseIP(addr.Hostname()) == nil {
		name, _, _ = strings.Cut(addr.Hostname(), ".")
	}
	if !serverName.MatchString(name) {
		return connectLink{}, errors.New(T("link.noName"))
	}
	return connectLink{name: name, url: strings.TrimSuffix(addr.String(), "/")}, nil
}

// onConnectLink is set before the run loop starts; a link that opens the app arrives as soon as it does.
var onConnectLink func(raw string)

// openConnectLink asks before it changes anything, including starting the daemon: a cancel or an unanswered
// dialog leaves everything as it was.
func (a *app) openConnectLink(raw string) {
	link, err := parseConnectLink(raw)
	if err != nil {
		notify(T("n.connectFailed"), err.Error())
		return
	}
	var existing *control.ServerInfo
	running := false
	if client, err := control.Connect(a.ctx); err == nil {
		if s, err := client.Status(a.ctx); err == nil {
			running = true
			existing = s.Server(link.name)
		}
	}
	same := existing != nil && sameAddress(existing.ControlPlane, link.url)
	if same && existing.LoggedIn && !signInEnded(*existing, time.Now()) {
		notify(T("n.alreadyConnected"), T("n.alreadyConnectedBody", "name", link.name))
		return
	}

	title, verb := T("confirm.connect", "name", link.name), T("confirm.connectButton")
	msg := T("confirm.connectBody", "url", link.url)
	switch {
	case same:
		title, verb = T("confirm.signInTo", "name", link.name), T("confirm.signInButton")
		msg = T("confirm.signInToBody", "url", link.url)
	case existing != nil:
		msg = T("confirm.replaceBody", "name", link.name, "old", existing.ControlPlane, "url", link.url)
	}
	if !running {
		msg += T("confirm.startsApp")
	}
	if !confirm(title, msg, verb) {
		return
	}

	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		notify(T("n.startFailed"), err.Error())
		return
	}
	if !running {
		// Only now can the saved servers be read; a replacement the first dialog could not mention asks again.
		st, err := client.Status(a.ctx)
		if err != nil {
			notify(T("n.connectFailed"), err.Error())
			return
		}
		if ex := st.Server(link.name); ex != nil {
			same = sameAddress(ex.ControlPlane, link.url)
			replace := T("confirm.replaceBody", "name", link.name, "old", ex.ControlPlane, "url", link.url)
			if !same && !confirm(T("confirm.replace", "name", link.name), replace, T("confirm.replaceButton")) {
				return
			}
		}
	}
	if !same {
		res, err := client.SetServer(a.ctx, control.SetServerRequest{Name: link.name, ControlPlane: link.url})
		if err != nil {
			notify(T("n.connectFailed"), err.Error())
			return
		}
		if res.NotEndedOnServer {
			notify(T("n.signedOutLocal"), T("n.signedOutLocalBody", "server", link.name))
		}
	}
	a.doSignIn(link.name)
}

func sameAddress(a, b string) bool {
	return strings.TrimSuffix(strings.ToLower(a), "/") == strings.TrimSuffix(strings.ToLower(b), "/")
}
