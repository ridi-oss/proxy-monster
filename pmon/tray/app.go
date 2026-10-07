package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/control"
)

// reconnectDelay is how long to wait before re-subscribing after the event stream drops. The stream ending is
// the normal signal that the daemon stopped, so this is a poll for "did it come back", not an error path.
const reconnectDelay = 2 * time.Second

// tick refreshes the "time left" titles and the ending-soon notices between daemon events.
const tick = time.Minute

// openAtLoginDecided records that Open at Login was set once, by the first sign-in or by the user, so the
// app never turns it back on after the user turned it off.
const openAtLoginDecided = "openAtLoginDecided"

// app is the tray's whole runtime. It mirrors daemon state into the menu; it never holds state the daemon does
// not have, apart from which notices it already showed.
type app struct {
	ctx    context.Context
	cancel context.CancelFunc

	// renderMu serializes renders, so a menu is always built from one status start to finish.
	renderMu  sync.Mutex
	onScreen  bool
	shape     string
	nodes     []*node
	children  map[*node][]*node
	genCancel context.CancelFunc

	// actionBusy serializes the lifecycle actions, so a double-click cannot run two conflicting changes at once.
	// A try-lock rather than a blocking mutex: an action that cannot run should say so and return, never queue
	// behind a long one (a device-auth flow runs for minutes) and leave the menu unresponsive.
	actionBusy sync.Mutex
	actionHeld bool

	mu        sync.Mutex
	status    *control.Status // nil means "no daemon reachable"
	signingIn map[string]bool
	// warned is the sign-in end each server was last warned about, so each ending is announced once.
	warned map[string]time.Time
	// ended is the sign-in end each server's "ended" notice was posted for.
	ended map[string]time.Time
	// ai is the last read of each AI app's settings; reading runs the apps' CLIs, so it is cached.
	ai        []aiState
	aiServers string
	aiMu      sync.Mutex // one AI-settings read at a time
	prefsPid  int        // the Preferences window's process, while open

	errMu  sync.Mutex
	err    error
	exited bool
}

func newApp(ctx context.Context) *app {
	ctx, cancel := context.WithCancel(ctx)
	return &app{ctx: ctx, cancel: cancel, children: map[*node][]*node{}, warned: map[string]time.Time{}, ended: map[string]time.Time{}, signingIn: map[string]bool{}}
}

// tryLockAction claims the lifecycle lock without blocking, reporting whether it was free.
func (a *app) tryLockAction() bool {
	a.actionBusy.Lock()
	defer a.actionBusy.Unlock()
	if a.actionHeld {
		return false
	}
	a.actionHeld = true
	return true
}

func (a *app) unlockAction() {
	a.actionBusy.Lock()
	a.actionHeld = false
	a.actionBusy.Unlock()
}

func (a *app) setErr(err error) {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	if a.err == nil {
		a.err = err
	}
}

func (a *app) exitErr() error {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return a.err
}

func (a *app) view() view {
	a.mu.Lock()
	signingIn := make(map[string]bool, len(a.signingIn))
	for k, v := range a.signingIn {
		signingIn[k] = v
	}
	a.mu.Unlock()
	on, supported := loginItem()
	a.mu.Lock()
	ai := a.ai
	a.mu.Unlock()
	return view{now: time.Now(), signingIn: signingIn, loginItemOn: on, loginItemShow: supported, ai: ai}
}

func (a *app) setSigningIn(server string, on bool) {
	a.mu.Lock()
	if on {
		a.signingIn[server] = true
	} else {
		delete(a.signingIn, server)
	}
	a.mu.Unlock()
	a.renderMu.Lock()
	a.redraw()
	a.renderMu.Unlock()
}

// onReady draws the first menu and starts the watchers.
func (a *app) onReady() {
	a.renderMu.Lock()
	a.onScreen = true
	a.redraw()
	a.renderMu.Unlock()
	go a.watchDaemon()
	go a.ticker()
}

func (a *app) onExit() {
	a.errMu.Lock()
	a.exited = true
	a.errMu.Unlock()
	a.cancel()
}

func (a *app) ticker() {
	t := time.NewTicker(tick)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
			if n++; n%5 == 0 {
				go a.refreshAI(true)
			}
			a.renderMu.Lock()
			a.redraw()
			a.renderMu.Unlock()
		}
	}
}

// noticeEndings posts one notification per server when its sign-in is about to end. Clicking it signs in.
func (a *app) noticeEndings(s *control.Status, v view) {
	if s == nil {
		return
	}
	for _, srv := range s.Servers {
		end, ok := signInEnd(srv)
		if !srv.LoggedIn || srv.ReauthRequired || !ok {
			continue
		}
		left := end.Sub(v.now)
		if left <= 0 {
			a.noticeEnded(srv.Name, end)
			continue
		}
		if left >= endingSoon {
			continue
		}
		a.mu.Lock()
		seen := a.warned[srv.Name].Equal(end)
		a.warned[srv.Name] = end
		a.mu.Unlock()
		if !seen {
			notifyAction("ending:"+srv.Name, fmt.Sprintf("%s sign-in ends in %s", srv.Name, strings.TrimSuffix(timeLeft(left), " left")),
				"Click to sign in again.", "signin:"+srv.Name)
		}
	}
}

// noticeEnded announces once that a server's sign-in window has closed. It shares its id with the daemon's
// reauth notice, so the two never show twice.
func (a *app) noticeEnded(server string, end time.Time) {
	a.mu.Lock()
	seen := a.ended[server].Equal(end)
	a.ended[server] = end
	a.mu.Unlock()
	if !seen {
		notifyAction("ended:"+server, server+" sign-in ended", "AI apps can't reach it until you sign in again. Click to sign in.", "signin:"+server)
	}
}

func (a *app) notificationClicked(key string) {
	if server, ok := strings.CutPrefix(key, "signin:"); ok {
		a.run(action{op: opSignIn, server: server})
	}
}

// watchDaemon keeps the menu in sync with the daemon, and is also how the tray learns the daemon is gone: the
// event stream ending means no daemon, which renders as the stopped state rather than a stale last-known one.
//
// It deliberately does NOT start a daemon. A tray launching at login must not force one up — that is an
// explicit action (Start or Sign In), symmetric with the CLI.
func (a *app) watchDaemon() {
	for {
		if err := a.ctx.Err(); err != nil {
			return
		}
		client, err := control.Connect(a.ctx)
		if err != nil {
			a.render(nil)
			if !a.sleep(reconnectDelay) {
				return
			}
			continue
		}
		// The stream's first event is the current status, so the menu is correct as soon as it opens.
		streamErr := client.Events(a.ctx, func(ev control.Event) {
			switch ev.Kind {
			case "status":
				if ev.Status != nil {
					a.render(ev.Status)
				}
			case "reauth":
				a.refresh(client)
				a.noticeReauth()
			case "shutdown":
				a.render(nil)
			default:
				a.refresh(client)
			}
		})
		if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
			a.render(nil)
		} else {
			a.render(nil) // the stream ended: the daemon is gone until proven otherwise
		}
		if !a.sleep(reconnectDelay) {
			return
		}
	}
}

func (a *app) noticeReauth() {
	a.mu.Lock()
	s := a.status
	a.mu.Unlock()
	if s == nil {
		return
	}
	for _, srv := range s.Servers {
		if srv.ReauthRequired {
			notifyAction("ended:"+srv.Name, srv.Name+" sign-in ended", "Click to sign in again.", "signin:"+srv.Name)
		}
	}
}

// refresh re-reads /status, for an event whose payload does not carry it.
func (a *app) refresh(client *control.Client) {
	s, err := client.Status(a.ctx)
	if err != nil {
		a.render(nil)
		return
	}
	a.render(s)
}

// sleep waits d, returning false if the app is shutting down.
func (a *app) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-a.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// openAtLoginOnce turns Open at Login on after the first sign-in, unless it was already decided.
func openAtLoginOnce() {
	if prefBool(openAtLoginDecided) {
		return
	}
	if _, supported := loginItem(); !supported {
		return
	}
	if err := setLoginItem(true); err == nil {
		setPrefBool(openAtLoginDecided, true)
	}
}
