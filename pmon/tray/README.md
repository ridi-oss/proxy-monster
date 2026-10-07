# pmontray — proxy-monster in the macOS menu bar

Shipped as the app **Proxy Monster Desktop**; `pmontray` is its executable.

A menu-bar front end for the [`pmon`](..) daemon. It is a **peer of the CLI, not
its owner**: both drive the same control socket, both can start and stop the
daemon, and both work when it is down. Anything the menu does is equally doable
with `pmon`, and vice versa.

```sh
./build-app.sh            # -> "./dist/Proxy Monster Desktop.app"
open "./dist/Proxy Monster Desktop.app"
```

To start it at login: System Settings › General › Login Items › add
`Proxy Monster Desktop`. There is no launchd plist to install — the app is the
login item, and the daemon's lifetime is an explicit choice, never an init
system's.

## Releases

Each `pmon-v*` release attaches a universal (arm64 + x86_64) build, signed with
RIDI's Developer ID and notarized:

- `ProxyMonsterDesktop_<version>.pkg` installs
  `/Applications/Proxy Monster Desktop.app` and links `/usr/local/bin/pmon` to
  the `pmon` inside it.
- `ProxyMonsterDesktop_<version>_darwin_universal.zip` is the app alone.

The release job runs `signing-keychain.sh`, `build-app.sh` and
`package-macos.sh`; each script lists the environment it reads. Unset, the
signing and notarization inputs fall back to an ad-hoc, unnotarized build.

## The menu

```
acme — dana@acme.example · 9h 12m left  ›  Sign In Again…
                                            Sign Out
                                            ─────────
                                            orders     ›  Copy URL
                                            analytics  ›  Copy JDBC URL
                                                          Copy Go DSN
                                                          Copy Command Line
staging — signed out                    ›  Sign In…
─────────
Connect AI Apps                         ›  ✓ Claude Desktop
                                             Claude Code
                                             Codex
2 open connections
─────────
✓ Open at Login
Settings…
Quit Proxy Monster
```

One submenu per server; each datasource offers every connection-string format
its engine supports (the same strings `pmon show --format` prints). With no
daemon running the menu says so and offers **Start**; it never shows a stale
last-known state.

The menu-bar icon is a monochrome template image; its state is a shape on the
shield: plain when signed in, a clock when a sign-in ends within 30 minutes, a
slash when a server is signed out, dots while a browser sign-in is open, faded
when nothing is running.

- **Sign In…** opens the server's sign-in page in the browser with the code
  filled in, starting the daemon first if none is running. A notification 30
  minutes before a sign-in ends, and one when it has ended, sign in again when
  clicked.
- **Settings…** opens a window with Servers (add, change an address, remove,
  sign in and out), AI Apps (a switch per app and server), General (Open at
  Login) and About (versions). It runs as a second process
  (`pmontray --preferences`) because the systray owns the menu-bar process's
  main thread. The page (`prefs.html`) runs in a system web view and uses the
  console's look: its tokens and the Geist fonts, embedded in the app (`fonts/`,
  SIL Open Font License). It calls Go through one asynchronous `pmCall`, since
  several calls take seconds. Opened in a browser on its own, the page runs on
  demo data, for design review. With no servers, the menu offers **Connect to a
  Server…**, which opens it at Add.
- **`pmon://connect?name=<server>&url=<address>`** links, from the console's
  Connect page, add a server and start its sign-in. Any web page can open such a
  link, so the address must be `https` (`http` only for this machine), the user
  confirms first, and replacing an existing server's address says so. A cancel
  or an unanswered dialog changes nothing.
- **Connect AI Apps** adds or removes `pmon mcp <server>` in Claude Desktop (its
  `claude_desktop_config.json`, other settings untouched), Claude Code
  (`claude mcp add --scope user`) and Codex (`codex mcp add`), listing only the
  apps installed. The entry runs the `pmon` inside the app bundle. The app is
  not restarted; the notification says what to do. Codex's own command rewrites
  the formatting of `~/.codex/config.toml`.
- **Open at Login** turns on after the first sign-in; once the user changes it,
  the app leaves it alone. Needs macOS 13.
- **Quit** stops the daemon, then exits — it is the peer of `pmon stop`. Merely
  closing the menu does nothing, matching a CLI command simply returning.
- **Sign Out / Quit** confirm first when connections are open, because the
  daemon is shared: the CLI may have started it and another window may be
  mid-query. The dialog fails **closed** — if it cannot be shown, the action is
  refused rather than silently dropping someone's session.

## Design

It holds **no state**. Every fact shown comes from the daemon's `/status`, and
every action is a call on the same control API the CLI uses, so the two front
ends cannot drift.

It also **never starts a daemon on its own** — launching at login must not force
brokers up. That is an explicit action: Start, Sign In, or a confirmed
`pmon://connect` link.

The menu is built as a tree from each status (`menu.go`). A tree with the same
keys as the one on screen updates the items in place; any other shape resets the
menu, since a systray can only append items. A Copy item's label and payload
come from one datasource in one render, so they cannot pair two datasources.

### Its own module

A systray needs **cgo** and must own the main thread. Keeping it out of `pmon`
leaves that a pure-Go static binary, which is what lets `pmon` be dropped on any
machine and cross-compiled freely.

`build-app.sh` bundles `pmon` inside the `.app` (`Contents/MacOS/pmon`): the
tray spawns the daemon by exec'ing a `pmon` binary, so shipping the pair
together is what keeps the daemon and the front end from skewing.

### macOS integration

Notifications and Open at Login use the system frameworks (`native_darwin.m`): a
notification is attributed to the app and can be clicked. An unbundled `go run`
build has no app identity, so its notifications fall back to `osascript`. The
confirm dialog and the clipboard use `osascript` and `pbcopy`. Any value
interpolated into an AppleScript is escaped (`osaQuote`): a principal or
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
