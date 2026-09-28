# pmontray — proxy-monster in the macOS menu bar

A menu-bar front end for the [`pmon`](../pmon) daemon. It is a **peer of the
CLI, not its owner**: both drive the same control socket, both can start and
stop the daemon, and both work when it is down. Anything the menu does is
equally doable with `pmon`, and vice versa.

```sh
./build-app.sh            # -> ./dist/pmontray.app
open ./dist/pmontray.app
```

To start it at login: System Settings › General › Login Items › add
`pmontray.app`. There is no launchd plist to install — the app is the login
item, and the daemon's lifetime is an explicit choice, never an init system's.

## The menu

```
● you@example.com — 11h23m left
  3 active connection(s)
  ─────────
  acme-mysql    ·  127.0.0.1:6100        ← click to copy the connection string
  acme-orders   ·  127.0.0.1:6101  (2)   ← (2) = live connections
  acme-target   ·  127.0.0.1:6102
  ─────────
  Re-authenticate…
  Log out
  Restart daemon
  Stop daemon
  ─────────
  Quit
```

With no daemon running it shows `daemon not running` and offers **Start daemon**
/ **Log in…**. The menu never displays a stale last-known state: if the daemon
goes away, the event stream ends and the menu says so.

- **Clicking a datasource** copies its `--url` connection string (the same
  string `pmon show <ds>` prints).
- **Log in…** asks the _daemon_ to run the device-auth flow, so the browser
  opens and the user code arrives as a notification. Starts the daemon first if
  none is running.
- **Quit** stops the daemon, then exits — it is the peer of `pmon stop`. Merely
  closing the menu does nothing, matching a CLI command simply returning.
- **Stop / Restart / Log out / Quit** confirm first when connections are open,
  because the daemon is shared: the CLI may have started it and another window
  may be mid-query. The dialog fails **closed** — if it cannot be shown, the
  action is refused rather than silently dropping someone's session.

## Design

It holds **no state**. Every fact shown comes from the daemon's `/status`, and
every action is a call on the same control API the CLI uses, so the two front
ends cannot drift.

It also **never starts a daemon on its own** — launching at login must not force
brokers up. That is an explicit action (Start, or Log in).

Menu items are created once and then updated or hidden, because a systray cannot
remove an item; a menu rebuilt per update would accumulate rows forever.
Datasource rows are a fixed pool (`maxDatasourceItems`).

### Its own module

A systray needs **cgo** and must own the main thread. Keeping it out of `pmon`
leaves that a pure-Go static binary, which is what lets `pmon` be dropped on any
machine and cross-compiled freely.

`build-app.sh` bundles `pmon` inside the `.app` (`Contents/MacOS/pmon`): the
tray spawns the daemon by exec'ing a `pmon` binary, so shipping the pair
together is what keeps the daemon and the front end from skewing.

### macOS integration

Notifications, the confirm dialog, and the clipboard go through
`osascript`/`pbcopy` rather than AppKit bindings — cgo is already paid for by
the systray, and Objective-C for three small affordances would buy nothing. Any
value interpolated into an AppleScript is escaped (`osaQuote`): a principal or
datasource name reaches those scripts as data, and an unescaped quote would
otherwise run as code.

The `.app` bundle is required, not cosmetic: `LSUIElement` (no Dock icon) is an
`Info.plist` property, and the bundle identity is what macOS attaches
notification permission and the Login Item to.

## Environment

Inherits `pmon`'s: `PMON_CONFIG_DIR` (state directory) and `PMON_PORT_BASE`
(loopback port range). Set both to run a tray against an isolated daemon without
disturbing one already running.

`PMON_BINARY` overrides which `pmon` runs the daemon. Normally the tray finds
the `pmon` bundled beside it (`Contents/MacOS/pmon`), falling back to `PATH` —
set this when running an unbundled dev build from `go run`.
