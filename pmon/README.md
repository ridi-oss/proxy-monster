# pmon — proxy-monster connector

A single static Go binary, run as a local background daemon, that lets you reach
a datasource through the proxy with a **saved password that never changes**. A
background daemon holds a short-lived wire token, runs one loopback listener per
datasource, and injects the token upstream.

```sh
# Homebrew 6 asks you to trust a third-party formula before it will load one.
brew trust --formula ridi-oss/tap/pmon
brew install ridi-oss/tap/pmon   # or: go build -o /usr/local/bin/pmon ./pmon

pmon login                     # device-auth in your browser; starts the daemon + opens the brokers
pmon status                    # principal, token expiry, every brokered datasource
pmon show acme-mysql            # mysql://you@example.com:pmlocal_…@127.0.0.1:6100/my_database
```

Point any SQL client at the address `pmon show` prints. Logging in is the only
step — there is no separate command to start brokering.

## Commands

<!-- prettier-ignore -->
|  |  |
| --- | --- |
| `pmon login` | Device-auth flow; starts the daemon if needed and opens the brokers |
| `pmon logout` | Clear the credentials and close the brokers (the daemon stays up) |
| `pmon show <ds>` | One datasource's local connection string |
| `pmon status` | Daemon state: login, expiry, brokered datasources, live connections |
| `pmon start` / `stop` / `restart` | Daemon lifecycle (`-f` / `--force` on `stop` and `restart` skips the live-connection prompt) |
| `pmon --version` | The release this binary was built from |

### Connection-string formats

`--url` is the default; `--jdbc`, `--go-dsn`, and `--cli` render the same
connection for other clients.

```sh
pmon show acme-mysql --url      # mysql://user:pw@127.0.0.1:6100/my_database
pmon show acme-mysql --jdbc     # jdbc:mysql://127.0.0.1:6100/my_database?user=…&password=…&jdbcCompliantTruncation=false
pmon show acme-mysql --jdbc --jdbc-with-truncation-diagnostics
pmon show acme-mysql --go-dsn   # user:pw@tcp(127.0.0.1:6100)/my_database?parseTime=true&charset=utf8mb4
pmon show acme-mysql --cli      # mysql -h 127.0.0.1 -P 6100 -u 'user' -p'pw' 'my_database'
```

Output is the bare string, so it pipes straight into a client or an env var.
MySQL JDBC URLs include `jdbcCompliantTruncation=false` by default. This
prevents Connector/J from making an automatic `SHOW WARNINGS` diagnostic
read-back after a warning; explicit diagnostics remain subject to their normal
authorization. Use `--jdbc-with-truncation-diagnostics` with `--jdbc` only when
the client needs Connector/J's truncation diagnostics; its output omits that
parameter and may issue `SHOW WARNINGS`.

The daemon checks that password. It answers `mysql_native_password` and
`caching_sha2_password` directly, and switches any other plugin to
`mysql_clear_password` — which the `mysql` CLI only permits with
`--enable-cleartext-plugin`. A saved connection carrying a stale or blank
password fails with access denied; re-copy it from `pmon show`.

`pmon --version` reports the release and the commit it was built from —
`0.1.1+87d3156f2cb7`, or a `.dirty` suffix when the tree had uncommitted
changes. Go records the revision itself except while a `go.work` is active, so
build local binaries with `mise run build-pmon` to keep the stamp. The daemon
reports its own, and a command warns when the two differ: the daemon keeps
running across an upgrade of the binary on disk, so a fix can look applied while
the running process predates it. `pmon restart` picks up the current build.

## Architecture

The daemon owns all state and logic and exposes a **local control socket**. This
CLI and the [menu-bar app](../pmontray) are symmetric peers over that socket:
neither is privileged, both can start and stop the daemon, and both work when it
is down.

```
pmon CLI ──┐                        ┌── menu-bar app
           │  connect → else spawn detached → wait for socket
           ▼                        ▼
      pmon daemon  (detached; survives whichever peer started it)
        ├─ /tmp/pmon-<uid>/pmon-<hash>.sock  control API
        ├─ daemon.pid   flock: single-instance + liveness
        ├─ 127.0.0.1:6100+  one listener per datasource
        └─ config.json  the daemon is the sole writer
```

- **The daemon runs the login.** A peer asks over the socket and the daemon
  streams the flow's steps back, so there is one implementation and two
  concurrent logins cannot race into two device flows.
- **Lifecycle is explicit.** The daemon is always spawned detached, so it
  outlives the peer that started it (a CLI command returns; an app may be quit)
  — stopping is therefore always an explicit request, never process-tree death.
  If a peer crashes, the daemon keeps brokering and the next peer adopts it.
- **Sticky ports + password.** Each datasource keeps its loopback port across
  restarts and the local password never rotates, so a saved client connection
  stays valid.
- **Silent renewal.** The daemon re-mints the wire token before it expires. Once
  the session window closes renewal is refused, and `status` reports that a
  fresh `pmon login` is required.
- **Revocation.** Discovery re-runs every 30s scoped to `?connectable=true`; a
  datasource that drops out has its listener closed, so the daemon stops
  offering an address you can no longer reach. The listener is a convenience
  layer, not the enforcement boundary — the proxy re-validates the token and
  re-decides every statement server-side. So while a discovery outage delays the
  prune (the error shows on `pmon status`), and an in-flight session keeps its
  socket until the client disconnects, neither extends what a connection may
  read.

### Security

- **Unix socket, not a loopback port.** The control API can start a login, and a
  localhost TCP port is reachable from any web page. The socket sits in a `0700`
  directory at mode `0600` — filesystem permissions are the authentication, so
  only the same OS user can connect.
- **Upstream TLS.** When the control plane advertises the proxy's leaf-cert
  SHA-256, the broker pins exactly that fingerprint (no CA, no system trust) and
  refuses a pinned datasource whose proxy offers no TLS rather than sending the
  token in plaintext. The loopback hop stays plaintext by design.
- **Credentials at rest.** `config.json` is written `0600` via an atomic rename,
  so the token and the renewal secret never land in a world-readable inode.

### Environment

<!-- prettier-ignore -->
|  |  |
| --- | --- |
| `PMON_CONFIG_DIR` | State directory (default: the user config dir). Set it to run several independent daemons |
| `PMON_PORT_BASE` | Low end of the loopback port range (default 6100). Needed when two daemons share a machine — a separate state dir isolates state, not ports |
| `PMON_BINARY` | The `pmon` binary that runs the daemon. Resolved automatically (this binary if it is `pmon`, else a sibling `pmon`, else `PATH`); set it for an unbundled dev build |

## Not yet

- **Postgres brokering** — PG datasources are discovered and listed with a
  reason, not fronted.
- **Notarized menu-bar app** — [`pmontray/`](../pmontray) is built and ad-hoc
  signed; distributing it to other machines needs a Developer ID signature +
  notarization.
