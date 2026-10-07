package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

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
		return connectLink{}, errors.New("not a Proxy Monster connect link")
	}
	q := u.Query()
	addr, err := url.Parse(q.Get("url"))
	if err != nil || addr.Hostname() == "" || addr.User != nil || addr.RawQuery != "" || addr.Fragment != "" {
		return connectLink{}, errors.New("the link has no valid server address")
	}
	switch addr.Scheme {
	case "https":
	case "http":
		if host := addr.Hostname(); host != "localhost" && !net.ParseIP(host).IsLoopback() {
			return connectLink{}, errors.New("the server address must start with https://")
		}
	default:
		return connectLink{}, errors.New("the server address must start with https://")
	}
	name := strings.ToLower(q.Get("name"))
	if name == "" && net.ParseIP(addr.Hostname()) == nil {
		name, _, _ = strings.Cut(addr.Hostname(), ".")
	}
	if !serverName.MatchString(name) {
		return connectLink{}, errors.New("the link has no valid server name")
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
		notify("Couldn't connect", err.Error())
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
	if same && existing.LoggedIn && !existing.ReauthRequired {
		notify("Already connected", fmt.Sprintf("You are signed in to %s.", link.name))
		return
	}

	title, verb := fmt.Sprintf("Connect to %s?", link.name), "Connect"
	msg := fmt.Sprintf("Server address: %s\nYou'll sign in with your company account.", link.url)
	switch {
	case same:
		title, verb = fmt.Sprintf("Sign in to %s?", link.name), "Sign In"
		msg = fmt.Sprintf("Server address: %s", link.url)
	case existing != nil:
		msg = fmt.Sprintf("This replaces %s's current address, %s, and signs you out of it.\nNew address: %s", link.name, existing.ControlPlane, link.url)
	}
	if !running {
		msg += "\nThis starts Proxy Monster."
	}
	if !confirm(title, msg, verb) {
		return
	}

	client, err := control.EnsureDaemon(a.ctx)
	if err != nil {
		notify("Couldn't start Proxy Monster", err.Error())
		return
	}
	if !running {
		// Only now can the saved servers be read; a replacement the first dialog could not mention asks again.
		st, err := client.Status(a.ctx)
		if err != nil {
			notify("Couldn't connect", err.Error())
			return
		}
		if ex := st.Server(link.name); ex != nil {
			same = sameAddress(ex.ControlPlane, link.url)
			replace := fmt.Sprintf("This replaces %s's current address, %s, and signs you out of it.\nNew address: %s", link.name, ex.ControlPlane, link.url)
			if !same && !confirm(fmt.Sprintf("Replace %s's address?", link.name), replace, "Replace") {
				return
			}
		}
	}
	if !same {
		if _, err := client.SetServer(a.ctx, control.SetServerRequest{Name: link.name, ControlPlane: link.url}); err != nil {
			notify("Couldn't connect", err.Error())
			return
		}
	}
	a.doSignIn(link.name)
}

func sameAddress(a, b string) bool {
	return strings.TrimSuffix(strings.ToLower(a), "/") == strings.TrimSuffix(strings.ToLower(b), "/")
}
