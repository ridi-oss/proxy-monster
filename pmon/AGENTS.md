# pmon

The daemon owns login state, discovery, sticky ports, listener binding, and
active connections. Protocol behavior belongs to providers.

## Protocol SPI

- `driver/` defines endpoints, credentials, renderers, listener-level brokers,
  and the immutable registry.
- `providers/` is the composition root. Register a renderer and an optional
  broker for each engine; renderer availability does not imply broker support.
- `providers/mysql/` owns MySQL rendering, handshakes, TLS negotiation, and
  relay. `providers/postgres/` currently supplies rendering only.
- `conn/` preserves the public rendering API. Its unknown-engine MySQL fallback
  is compatibility behavior, not a broker-selection rule.

A broker receives a real `net.Listener` and owns its native serving loop. The
listener tracks accepted connections so logout, revocation, and replacement can
close them without protocol-specific daemon code. Providers close each accepted
connection when finished.

Call `ResolveSession` when a connection or request needs credentials; do not
capture a token or endpoint in the server constructor. A false result means the
listener's session is no longer available. `RouteKey` controls whether changed
endpoint metadata replaces the listener and established connections while
retaining the sticky port. Keep support checks and route-key computation free of
network I/O.

Do not add engine switches to the daemon or use a fake single-connection
listener to adapt an HTTP server. Keep rendering and escaping with the provider.

## Verification

Run from the repository root:

```sh
mise exec -- go test -race -count=1 ./pmon/...
mise run test-e2e-clients
```

Test registry selection, exact rendering, listener replacement, fresh session
resolution, and connection cleanup. The client-interop suite uses real clients
and MySQL with a test token proxy; it is not full control-plane validation.
