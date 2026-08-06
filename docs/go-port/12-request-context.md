# A12 — Request Context (requester IP, forwarded headers, proxy events)

Files: `RequesterIp.kt` (251) · `ProxyEventsHub.kt` (136). Total 387 LOC. Fully
read.

> **Depth note:** the area map classified this LIGHT. Upgraded to MEDIUM after
> reading — it holds the repo's single anti-spoof invariant, carries 39 test
> cases (more than A1+A2's 27 for A1), and three separate security gates depend
> on `isTrustedEdge`. A light treatment would under-specify it.

## Purpose

Resolves what the control-plane is allowed to _believe_ about a request: the end
client's IP, the host the client addressed, and (in `Scim.kt`, A3) whether the
request arrived over TLS. All three read client-settable `X-Forwarded-*`
headers, so all three share one trust gate. Also owns the registry of open
proxy→control-plane `Events` streams.

---

## 1. The anti-spoof invariant

🔒 **INV-A12-1 — one definition of "this hop may speak for the client".**
`isTrustedEdge` is the single test, shared by all three `X-Forwarded-*`
consumers:

| Header              | Consumer                             | Feeds                                         |
| ------------------- | ------------------------------------ | --------------------------------------------- |
| `X-Forwarded-For`   | `resolveHttpRequesterIp`             | Cedar `requester_ip`                          |
| `X-Forwarded-Host`  | `resolveForwardedAuthority`          | the `/mcp` host check (DNS-rebinding defense) |
| `X-Forwarded-Proto` | `resolveScimTls` (`Scim.kt:193`, A3) | the SCIM TLS gate                             |

The source comment states the reason explicitly: _"a second hand-rolled copy of
this test is how a header ends up honored from an untrusted peer."_ A Go port
must keep one function, not three.

🔒 **INV-A12-2 — the socket peer is the only unspoofable fact.** An HTTP
request's socket peer is a property of the TCP connection. Once a load balancer
sits in front, the peer is the _edge_ and the real client only appears in a
header the client can also forge. So a forwarded header is honored **only when
the socket peer is a configured trusted edge** — forging then requires also
controlling the edge's socket address.

🔒 **INV-A12-3 — a trusted edge's own address is NEVER the requester.** When the
peer _is_ a trusted edge, a missing / blank / malformed `X-Forwarded-For`
resolves to `null`, so `requester_ip` goes absent and a policy conditioning on
it fails closed. It must never silently attribute the request to the edge's own
address. (`resolveForwardedAuthority` differs deliberately — see INV-A12-6.)

🔒 **INV-A12-4 — rightmost entry wins.** By `X-Forwarded-For` convention the
rightmost entry is the one the trusted edge itself appended; everything to its
left came from upstream of the edge and is unattested. Applies to
`X-Forwarded-For` and `X-Forwarded-Host` alike.

Deployment requirement recorded in `Config.kt:77-82` and worth restating in the
Go docs: a listed edge must **overwrite** the headers it asserts from its own
view of the connection. An edge that relays a client's
`X-Forwarded-Proto: https` verbatim lets a _plaintext_ request satisfy the SCIM
TLS gate, and the standing SCIM bearer then travels in the clear. Appending
edges are safe (rightmost wins); relaying edges are not.

---

## 2. Symbols — `RequesterIp.kt`

### `isTrustedEdge(peerAddress: String?, trustedProxies: Set<String>): Boolean` · internal

1. `null` peer ⇒ `false`.
2. **Literal set membership first** — the common single-edge case costs one
   lookup and no parsing.
3. Else `parseIp(peerAddress)`; unparseable ⇒ `false`.
4. Else `trustedProxies.any { cidrContains(entry, peer) }`.

CIDR support is required, not a nicety: an autoscaled LB or Kubernetes ingress
presents whichever pod address it has, so enumeration is impossible and the
alternative is losing every forwarded header.

⚠️ **Operational warning to carry over:** a block widens what may speak for a
client, so it must cover only hops you operate. Anything inside a listed subnet
can assert its own `requester_ip`, pass the SCIM TLS gate over plaintext, and
satisfy the `/mcp` host check.

### `parseIp(candidate: String): ByteArray?` · private

1. Trim, strip surrounding `[` `]`.
2. Empty ⇒ null. **Character allowlist**: digits, `.`, `:`, `a-f`, `A-F`, `%` —
   anything else ⇒ null.
3. `InetAddress.getByName(c).address`, `runCatching` ⇒ null.

🔒 **INV-A12-5 — never a DNS lookup.** The allowlist exists so `getByName` only
ever takes its literal path. Without it, a hostname entry in
`PM_TRUSTED_PROXIES` would _resolve at match time_ — an attacker controlling
that DNS record could become a trusted edge. `ForwardedAuthorityTest` case 14
("a hostname entry is never resolved at match time") pins this.

**Go shape:** `net/netip.ParseAddr` never resolves DNS, so the allowlist is
belt-and-braces there — but keep it, because `%` (zone id) handling and the
bracket-stripping order are observable. Note `ParseAddr` accepts a zone
(`fe80::1%eth0`) and returns 4-byte vs 16-byte forms differently from
`InetAddress`; §5 Q1.

### `cidrContains(entry: String, peer: ByteArray): Boolean` · private

1. No `/` ⇒ `false`.
2. Parse the address part; unparseable ⇒ `false`.
3. **`block.size != peer.size` ⇒ `false`** — an IPv4 peer against an IPv6 block
   is not a match. The two address spaces are compared, never coerced.
4. Prefix must parse and be in `0..bits` ⇒ else `false`.
5. Compare `prefix / 8` whole bytes; then if `prefix % 8 != 0`, compare the
   boundary byte under mask `(0xFF shl (8 - remaining)) and 0xFF`.

🔒 **INV-A12-6 — a malformed entry matches nothing, never everything.** Every
failure path returns `false`. A typo must fail closed.

⚠️ **Go trap:** `InetAddress.getByName("::ffff:10.0.0.1").address` returns **4
bytes** (Java unwraps IPv4-mapped IPv6), so such a peer compares against IPv4
blocks. Go's `netip.Addr` distinguishes `Is4In6()` and `Unmap()` explicitly.
Whichever way the port goes, family-matching behaviour changes unless `Unmap()`
is applied. Not covered by any test — see §4.

### `unusableTrustedProxyEntries(trustedProxies): List<String>` · internal

Entries `isTrustedEdge` could never match. With `/`: address unparseable, or
prefix absent/negative/ `> addr.size * 8`. Without `/`: `parseIp` null. Consumed
by `App.kt:316` to log a startup warning — failing closed _silently_ is how a
typo becomes "forwarded headers stopped working" with nothing pointing at the
cause.

### `resolveHttpRequesterIp(peerAddress, xff, trustedProxies): String?` · internal

Local
`validate(bare) = bare?.takeIf { runCatching { IpAddress(it) }.isSuccess }`.

🔒 **INV-A12-7 — one definition of "valid IP" for the whole control-plane.**
`validate` uses the _same_ cedar-java `IpAddress` parse that
`AuthzContext.toCedarMap` uses, so this resolver and the eventual Cedar
marshalling can never disagree. A stripped-but-still-bogus candidate resolves to
`null` here.

1. **Trusted edge:** `xff` null/blank ⇒ `null`; else
   `validate(stripToBareIp(xff.split(',').last().trim()))`.
2. **Direct client:** `validate(stripToBareIp(peerAddress))` — the TCP peer _is_
   the requester, and any `X-Forwarded-For` it sends is client-forgeable and
   ignored entirely.

Never throws.

### `stripToBareIp(candidate: String?): String?` · private

Strict, because an XFF entry is attacker-adjacent — a malformed candidate must
resolve to `null`, never be salvaged into a valid-looking IP.

1. Trim, `removePrefix("/")` (Netty's `SocketAddress.toString()` shape), empty ⇒
   null.
2. Starts `[`: closing `]` **required** (else null). Any suffix after `]` must
   be exactly `:<digits>` (so `[203.0.113.5` and `[203.0.113.5]junk` are
   rejected, not truncated to a valid IP).
3. Exactly one `:`: the port must be non-empty all-digits (so
   `203.0.113.5:not-a-port` is rejected, not accepted as a bare IPv4).
4. Else bare (bare IPv4, or bare IPv6 whose multiple colons are not a port).
5. Empty host ⇒ null.

The result is only a **candidate** — `resolveHttpRequesterIp` still validates
it.

### `resolveForwardedAuthority(directHost, peerAddress, forwardedHost, trustedProxies): String` · internal

1. Not a trusted edge ⇒ `directHost`.
2. Rightmost `X-Forwarded-Host` entry, trimmed, non-empty — else `directHost`.
3. Split a port off the **last** colon, only when it is after the last `]`, is
   not the final character, and is all digits. Then
   `removeSurrounding("[", "]")`.

🔒 **INV-A12-8 — host only, never a port.** Behind a TLS-terminating edge the
backend is reached on its own cleartext port, and a client's `Host` omits the
port when it is the scheme default — so a port comparison rejects every request
in the deployment shape the check exists to serve. It also buys nothing: an
attacker who controls the host names any port. The port of a browser-facing
request is still enforced, by the `Origin` check's scheme+host+port comparison
in `McpServer.kt` (A11).

**INV-A12-9** — unlike `resolveHttpRequesterIp`, this **falls back to
`directHost`** rather than to `null`, which is also the right answer for an edge
that preserves the client `Host` and sends no `X-Forwarded-Host`. The asymmetry
with INV-A12-3 is deliberate.

IPv6 note: only split at the last colon _after_ the closing bracket, or `[::1]`
gets shredded at its first colon.

### `isStorableIpLiteral(candidate, evaluatesInCedar): Boolean` · internal

1. Empty ⇒ false.
2. Character allowlist (digits, `.`, `:`, `a-f`, `A-F` — **no `%`** here, unlike
   `parseIp`).
3. `IpAddress(candidate)` must not throw.
4. **`evaluatesInCedar(candidate)`** — the authoritative gate.

🔒 **INV-A12-10 — cedar-java's `IpAddress` is looser than the Rust engine that
ultimately parses the value.** It accepts a NUL-bearing string (Postgres then
rejects it at INSERT) and non-canonical IPv4 like `100.100.001.010` (the engine
refuses it). An unevaluable context value fails the _whole_ authorization
closed, so the request would deny everywhere with nothing naming the address.
Hence the round-trip probe; the allowlist is only a cheap pre-filter.

**Go shape:** this is the sharpest conformance question in the area. cedar-go
parses IPs directly, so the two-stage regex-then-engine dance may collapse into
one parse — but the _accepted set_ must match or `/auth/debug` starts rejecting
addresses it used to take (or vice versa). Ties to A2's spike question **S5**.

### `ApplicationCall.httpRequesterIp(config): String?` · internal

1. Under `authDebug`, a session's `debugRequesterIp` short-circuits and is
   returned.
2. `peer = request.local.remoteAddress`;
   `xff = request.headers.getAll("X-Forwarded-For")?.lastOrNull()`.
3. `resolveHttpRequesterIp(peer, xff, config.trustedProxies)`.

⚠️ **INV-A12-11 — no `ForwardedHeaders`/`XForwardedHeaders` plugin is
installed** (`App.kt`), so nothing upstream has already substituted a
client-asserted value; the peer really is the TCP fact. **A Go port must not
enable a framework's forwarded-header middleware** — doing so would silently
defeat INV-A12-2 by rewriting the peer before this code sees it. This is the
single easiest way to break the area during the port.

Note step 2 takes `getAll(...).lastOrNull()` — the **last `X-Forwarded-For`
header instance**, then `resolveHttpRequesterIp` takes the rightmost entry
_within_ it. Two levels of "rightmost". Go's `Header.Values("X-Forwarded-For")`
preserves instance order; `Header.Get` returns the **first** and would be wrong.

**Debug-simulation cost, stated precisely in the source and worth preserving:**
`authDebug` already mints any role, so against a role-only policy a simulated
address adds nothing. But against one gated on role **AND** network — the
shipped `-258` PII unmask needs `system:production-pii-accessor` **AND** the
`trusted-network` tag — the peer was a second independent factor, and simulating
it removes that. So this **widens** the bypass rather than riding on it.
Acceptable only because `Config.fromEnv` refuses to start with `authDebug` on in
a production-looking configuration (INV-A1 V5), and because with the bypass off
the stored value is never consulted.

### `ApplicationCall.httpAuthzContext(config): AuthzContext` · internal

`AuthzContext(requesterIp = httpRequesterIp(config))`. `channel` deliberately
unset (see INV-A2-15).

---

## 3. Symbols — `ProxyEventsHub.kt`

Tracks open proxy→control-plane `Events` streams. Two jobs on one channel:
**liveness** (an open stream means a proxy is attached) and **push** (refresh /
open-run / open-table-detail).

🔒 **INV-A12-12 — the direction invariant.** The control-plane never dials
_into_ a proxy; it only ever writes back down a stream the proxy itself opened.

State:
`ConcurrentHashMap<String, CopyOnWriteArrayList<SendChannel<ControlEvent>>>` —
datasource name → one send channel per attached replica.

| Method                                                                  | Behavior                                                                                                                                                                             |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `register(name, channel)`                                               | Add **inside** `compute` so it is atomic with `deregister`'s remove-and-evict. Logs the open count.                                                                                  |
| `deregister(name, channel)`                                             | Remove inside `compute`; **drop the map entry entirely when the last stream closes**, so a churn of distinct names cannot accumulate empty lists forever.                            |
| `requestRefresh(name): Int`                                             | Fan `RefreshCatalog` to every open stream. Returns the count notified — `0` means no proxy attached, reported honestly. A full buffer (wedged proxy) is **skipped, not blocked on**. |
| `requestOpenRun(name, sessionId, ephemeralToken, connectionId, onOpen)` | `dispatch` an `OpenRunChannel` with `onOpen` refetches                                                                                                                               |
| `requestOpenTableDetail(name, sessionId, schema, table)`                | `dispatch` an `OpenTableDetailChannel`                                                                                                                                               |
| `attached(): Set<String>`                                               | names with ≥1 open stream                                                                                                                                                            |

🔒 **INV-A12-13 — atomicity of `register`.** Adding outside the `compute` lock
would let a concurrent `deregister` evict the freshly-created (still empty) list
before the add landed, losing the registration silently.

### `enum Dispatch { SENT, NOT_ATTACHED, WEDGED }` and `dispatch(name, what, event)`

1. No list ⇒ `NOT_ATTACHED`.
2. Iterate; **first successful non-blocking `trySend` wins** and returns `SENT`.
   Broadcasting would make every replica open a backend connection for the same
   request.
3. Every channel that refused is **deregistered** (`deregisterWedged`, logs a
   warning).
4. `refused.isEmpty() ? NOT_ATTACHED : WEDGED`.

🔒 **INV-A12-14 — `NOT_ATTACHED` and `WEDGED` must stay distinguishable.** They
need different answers: the first means no proxy is there; the second means one
is registered but its channel will not take an event (a stream already closed by
a reset the server has not finished tearing down, or a consumer that stopped
draining). Collapsing both to "no proxy attached" sends whoever debugs it
hunting a proxy that is in fact running.

**INV-A12-15 — a refusing channel is dropped, not left in place.** It cannot
serve a later request either, and leaving it registered means `attached()` keeps
reporting a proxy that cannot be reached — the liveness view would lie until the
stream's own close handler eventually ran.

**Go shape:** buffered `chan *pb.ControlEvent` per stream with non-blocking
`select { case ch <- ev: default: }` reproduces `trySend`. ⚠️ Go has no
`trySend`-on-closed distinction — sending on a closed channel **panics** rather
than returning failure, so the port needs either a `done` channel checked in the
same `select` or a per-stream `closed` flag under a mutex. `ProxyEventsHubTest`
case 3 ("a closed stream is WEDGED, not NOT_ATTACHED") is exactly this case and
will panic a naive port. `⟦LIB⟧` none.

---

## 4. Test inventory — 5 files, 798 LOC, **39 cases**

### `RequesterIpParseTest.kt` — 29 LOC, 2 cases · unit

⚠️ Tests `parseRequesterIp`, which lives in **`Query.kt:1230`** (the wire-path
counterpart), not in `RequesterIp.kt`. Listed here because it is the same
concern; port it with A6 or A12, not both.

1. extracts the ip from Netty host-port forms
2. 🔒 null, blank, empty, or slash-only yield null — fail closed

### `HttpRequesterIpResolutionTest.kt` — 175 LOC, 11 cases · unit + test-host

1. 🔒 an untrusted peer's `X-Forwarded-For` is ignored entirely — the peer
   itself is used (INV-A12-2)
2. a trusted peer's rightmost XFF entry is honored (INV-A12-4)
3. multi-hop XFF takes the RIGHTMOST entry — the one the trusted edge itself
   appended
4. whitespace around a multi-hop XFF entry is trimmed
5. 🔒 an invalid rightmost XFF entry from a trusted peer resolves to null —
   never falls back to the edge's own IP (INV-A12-3)
6. 🔒 a malformed rightmost XFF entry is not salvaged into a valid IP — it
   resolves to null
7. 🔒 a blank or absent XFF from a trusted peer resolves to null (INV-A12-3)
8. a null or unparseable peer resolves to null — fail closed, never throws
9. a peer or XFF entry carrying a well-formed port is stripped to the bare
   address
10. 🔒 an untrusted peer that happens to equal an entry after cleaning does not
    match on the raw (uncleaned) form
11. `httpRequesterIp` honors `X-Forwarded-For` only when the test-host peer is
    configured as trusted

### `ForwardedAuthorityTest.kt` — 171 LOC, 15 cases · unit

Covers both `resolveForwardedAuthority` (1–8) **and**
`isTrustedEdge`/`cidrContains` (9–15). Mixed naming: some cases use plain
camelCase identifiers, not backticks.

1. with no trusted edge the direct host is used
2. `forwardedHostFromAnUntrustedPeerIsIgnored`
3. a trusted edge's forwarded host supersedes the proxy's own authority
4. an edge that preserves the client host needs no forwarded header (INV-A12-9)
5. `aPortIsNeverPartOfTheResolvedHost` (INV-A12-8)
6. the rightmost entry of a multi-hop forwarded host is taken
7. a bracketed IPv6 authority is unwrapped without being split at its own colons
8. a blank or non-numeric-port forwarded host falls back rather than resolving a
   partial authority
9. a literal entry still matches exactly and nothing else
10. an address inside a CIDR block is trusted and one outside it is not
11. a prefix that is not byte-aligned masks the boundary byte
12. 🔒 IPv6 blocks work and never match across address families
13. 🔒 a malformed entry matches nothing rather than everything (INV-A12-6)
14. 🔒 a hostname entry is never resolved at match time (INV-A12-5)
15. an empty trusted set trusts nothing

### `DebugRequesterIpDbTest.kt` — 318 LOC, 4 cases · **DB**

1. a debug login's simulated address replaces the observed peer on the decision
   path
2. 🔒 a malformed address is refused rather than silently ignored (INV-A1-7)
3. a simulated address changes a real Cedar decision through the derived tag
4. 🔒 the stored address is inert once the debug bypass is off

Case 3 crosses into A2's two-pass tag derivation; case 4 pins the containment of
INV-A12-11's widened bypass.

### `ProxyEventsHubTest.kt` — 105 LOC, 7 cases · unit

1. a datasource with no stream is not attached
2. an open stream takes the event
3. ⚠️ a closed stream is WEDGED, not NOT_ATTACHED (INV-A12-14 — **the Go panic
   case**)
4. a full buffer is WEDGED too
5. a wedged stream is dropped so liveness stops claiming it (INV-A12-15)
6. a live replica serves the request even when another is wedged
7. a refresh push skips a wedged stream rather than counting it

### Coverage gaps in A12

- **IPv4-mapped IPv6 (`::ffff:10.0.0.1`)** against an IPv4 CIDR block. Java's
  `getByName().address` returns 4 bytes and therefore _matches_; Go's `netip`
  needs an explicit `Unmap()` to agree. Nothing tests it, and it decides whether
  a hop is trusted.
- `unusableTrustedProxyEntries` is only covered indirectly (via
  `ConfigGuardTest` case 20 parsing, not the warning classification itself).
- `isStorableIpLiteral`'s NUL-bearing and non-canonical-IPv4 cases (INV-A12-10)
  are described in the source but not asserted anywhere.
- `register`/`deregister` concurrency (INV-A12-13) — the `compute`-atomicity
  race is untested.
- Zone-id (`%eth0`) handling: `parseIp` allows `%` but `isStorableIpLiteral`
  does not. No test covers the divergence.

Four of five gaps are exactly where Go's IP library differs from Java's. **Add
these as new tests during Step 3 rather than discovering the divergence in
production.**

---

## 5. Open questions

| #   | Question                                                                                                                                                                                                                                                   |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | `InetAddress.getByName` vs `netip.ParseAddr`: byte-length of IPv4-mapped IPv6, zone-id acceptance, and leading-zero IPv4 (`010.1.1.1`) all differ. Pin the intended semantics with new tests **before** porting, since `isTrustedEdge` is a security gate. |
| Q2  | `parseIp` allows `%` (zone id) but `isStorableIpLiteral` does not. Intentional, or drift?                                                                                                                                                                  |
| Q3  | Does any deployment actually rely on `X-Forwarded-Host`? If not, INV-A12-8/9's asymmetry could be simplified — but only with A11's `/mcp` host check in hand.                                                                                              |
| Q4  | `parseRequesterIp` (`Query.kt:1230`) and `stripToBareIp` overlap. Confirm the wire path really can assume well-formed Netty input, or unify them.                                                                                                          |
