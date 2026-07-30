# Authz request context — `channel`, `requester_ip`, and derived `tags`

Cedar policies condition on a request context: server-attested attributes
threaded into every decision. This doc owns the context model. The RBAC/Cedar
spine it plugs into is [`authz-model.md`](./authz-model.md).

## Decision (TL;DR)

Every authorization decision carries a request context — attributes Cedar
policies condition on. It is always resolved server-side and attested, never
client-asserted (the `context` analog of authz-model's "roles resolved
server-side, never from the token"). Two kinds:

Raw attested inputs, set by the control-plane from what the client cannot forge:

- `channel` — which surface/phase the decision is in: `wire` | `editor` |
  `workflow-executor` | `workflow-viewer` | `mcp`. Derived from the entry point
  / ephemeral-token kind, never a client-supplied field.
- `requester_ip` — the end client's source address, a Cedar `ipaddr`. From the
  proxy's `client_addr` on the wire path; from `resolveHttpRequesterIp`
  (`RequesterIp.kt`) on the HTTP paths.

Derived `context.tags` — a `Set<String>` of stable tag names
(`"trusted-network"`, …) the control-plane computes before the real decision by
evaluating admin-authored Cedar tag rules over the raw inputs (the
[two-pass mechanism](#derived-contexttags--the-two-pass-mechanism)). Consuming
policies condition on the tag names, not the raw signal:

```cedar
permit(principal in Role::"pii-reader", action == Action::"result.read.unmasked", resource in Tag::"pii")
  when { context has channel && context.channel == "workflow-viewer"
         && context has tags && context.tags.contains("trusted-network") };
```

So the CIDR range that _means_ "trusted-network" lives in one tagging rule; a
range change is a one-line edit and every consuming policy is untouched. Raw
attrs stay in the schema as the tagging inputs (and a direct escape hatch where
a named tag is not worth defining).

Fail-closed throughout: an absent / unattributable / error input → the tagging
rule does not fire → the tag is absent → `context.tags.contains(...)` is false →
the conditioned grant does not apply → deny. Absence is never "allow."

Authoring rule (Cedar strict validation): every `context` attribute is optional,
and Cedar refuses an unguarded read of an optional attribute (the policy fails
validation, the policy store rejects the write, and `CedarEngine` fails fast at
boot). So a policy touching `channel` / `requester_ip` / `tags` MUST guard
first: `context has tags && context.tags.contains("…")`.

## `channel` — which surface / phase

Closed set (a value outside it is a config error → fail-closed deny):

<!-- prettier-ignore -->
| `channel` | when | set by |
| --- | --- | --- |
| `wire` | a native DB client's query through the proxy | proxy `Decide` (wire-session token) |
| `editor` | the web SQL editor | the editor's ephemeral token kind |
| `workflow-executor` | an approval running as role R to fetch + store the result | the approval-exec ephemeral token kind |
| `workflow-viewer` | viewing a stored approval result as role R | the control-plane view route |
| `mcp` | an access-control change over the MCP admin surface | the MCP request handler (`Channel.MCP`) |

For the proxy-mediated paths the value is derived from the ephemeral-token kind
(the control-plane mints the kind; the proxy cannot assert it); the view route
sets it directly. It is never read from a client-supplied field. The MCP channel
is consumed by [`mcp-access-control.md`](./mcp-access-control.md).

## `requester_ip` — attestation

`requester_ip` is a Cedar `ipaddr`, server-observed, never client-supplied. Two
disjoint resolution cases, never blended (plus a development-only exception,
[below](#the-development-only-simulated-address)):

- Wire path: the proxy's socket peer (`client_addr` on `DecisionRequest`) is the
  requester.
- HTTP path (`resolveHttpRequesterIp`, `RequesterIp.kt`): resolved by the trust
  status of the socket peer. `X-Forwarded-For` is client-settable, so it is
  honored only when the socket peer matches a `PM_TRUSTED_PROXIES` entry (a load
  balancer / edge terminating TLS), and even then only its rightmost entry (the
  one that edge appended). A missing, blank, or malformed rightmost entry
  resolves to `null` (absent, fail-closed) and never falls back to the edge's
  own address. When the peer is a direct / untrusted client, the raw socket peer
  is the requester and any `X-Forwarded-For` it sends is ignored. A malformed
  candidate on either path is rejected, not salvaged, and validated through the
  same `cedar-java` `IpAddress` parse the Cedar marshalling uses.
  `PM_TRUSTED_PROXIES` is empty by default: no configured edge means
  `X-Forwarded-For` is never honored.

`PM_TRUSTED_PROXIES` is not requester-IP-only. The same trusted-edge test gates
`X-Forwarded-Proto` for the SCIM TLS check (`resolveScimTls`, `Scim.kt`), which
accepts a request as TLS when either the connection is directly HTTPS or a
trusted peer asserts `https`. So listing an address there carries a deployment
requirement: that edge must **overwrite** every forwarded header it asserts,
from its own view of the connection, and never relay a client-supplied value. An
edge that passes an inbound `X-Forwarded-Proto: https` straight through would
let a plaintext request satisfy the TLS gate, and the standing `PM_SCIM_TOKEN`
would travel in the clear. Both resolvers read the rightmost value — the one a
correctly appending edge wrote — so appending is safe and relaying is not.

Over the tailnet, `requester_ip` is a Tailscale-assigned `100.x` — you cannot
present another node's `100.x` without being it — so a CIDR match is
meaningfully attested, not a flat-LAN guess. A cryptographically-attested
tailnet capability (resolved via `whois`) is the intended stronger successor to
matching on the raw IP; consuming policies would be unchanged because they read
the derived tag, not the raw signal.

### The development-only simulated address

`PM_AUTH_DEBUG` is the one exception to "never client-supplied", and it exists
because a tag rule keyed on a CIDR can otherwise never fire on a development box
— every browser request there arrives from loopback, so everything the rule
gates is unreachable. Under that bypass, `POST /auth/debug` accepts a
`requesterIp`, stores it on the session row
(`principal_session.debug_requester_ip`), and `httpRequesterIp` substitutes it
for the observed peer.

Scope it honestly:

- It is **inert whenever `PM_AUTH_DEBUG` is off** — the resolver consults the
  column only under the bypass, so a row left by a development run cannot weaken
  a real deployment. `/auth/me` likewise reports it only under the bypass, so
  the console never shows an address the decision path is ignoring.
- It **widens what the bypass already grants**, and is not merely equivalent to
  it. `PM_AUTH_DEBUG` already mints any role, so for a policy gated on role
  alone it adds nothing. But a policy conditioned on role **and** network — the
  shipped `-258` PII unmask, which needs `system:production-pii-accessor` _and_
  the `trusted-network` tag — previously still required a genuinely in-range
  peer. Simulating the address removes that second, independent factor. That is
  acceptable only because it is confined to a bypass a production-looking
  configuration refuses to start with (`Config.fromEnv`), not because the two
  are equivalent.

`requester_ip` reaches every authorize site, query and non-query alike. The
datasource-scoped non-query sites (`requireAdmin` — the single choke point the
admin routes funnel through — plus `computeMePermissions`, the audit-read
routes, and the `task.approve` sites) go through `Authz.authorizeWithContext`,
which resolves the principal's roles once and threads that single snapshot
through both the pass-1 tag derivation and the pass-2 authorization (never a
forked tag-derivation, never a second, disagreeing role resolution). For the
CP-mediated `editor` / approval-executor decide path — where the gRPC `decide`
handler has only the resolved ephemeral token, no HTTP request in hand — the
HTTP requester IP observed when the token was minted is carried via a
token-hash-keyed `RequesterIpRegistry` on `ControlPlaneCore` (entry lifetime ==
token lifetime; an absent entry means `requester_ip` is simply absent,
fail-closed). A persistent editor session's `requester_ip` is refreshed per
query, so a decision always sees the current request's IP.

## Concepts

- Context — request-scoped attributes passed to Cedar (`AuthzContext`,
  `Authz.kt`): `channel`, `requester_ip`, and the derived `tags`, threaded
  end-to-end from the decide path.
- Attested — derived by the control-plane / proxy from something the client
  cannot set: the entry point (for `channel`), the observed connection (for
  `requester_ip`). The client never sends a context field — including `tags`,
  which is _computed_, never accepted as input.
- Tag rule — an admin-authored Cedar policy on a `context.tag::<name>` action
  that decides whether the request earns tag `<name>`, conditioning only on raw
  inputs (never on `context.tags` — no tag-on-tag).

## Derived `context.tags` — the two-pass mechanism

Cedar is single-pass and pure: a policy cannot compute or write a context
attribute. So the tag → raw-signal mapping runs as a control-plane pre-pass
(`resolveContextTags`), but the rules themselves are ordinary Cedar —
gitops-reviewable, schema-validated, formally analyzable:

1. Pass 1 — resolve tags. For each tag name `T` in the vocabulary (derived from
   the enabled tag rules — every `context.tag::<name>` a rule targets _is_ a
   tag), the control-plane evaluates
   `isAuthorized(principal, Action::"context.tag::T", datasource, context = {channel, requester_ip})`.
   Each ALLOW adds `T` to `context.tags`. Because the pass-1 resource is the
   request's datasource and the principal is real, a tag rule can scope by
   resource and/or principal, not just the raw context:
   ```cedar
   // "trusted-network" for any datasource from the tailnet range:
   permit(principal, action == Action::"context.tag::trusted-network", resource)
     when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };
   // …or only when operating on a specific datasource:
   permit(principal, action == Action::"context.tag::trusted-network", resource == Datasource::"acme-prod")
     when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };
   ```
2. Pass 2 — the real decision. `result.read.*` / `sql.*` / … evaluated with
   `context.tags` populated (raw attrs still present). Consuming policies read
   `context.tags.contains("trusted-network")`.

Constraints that keep it safe and simple:

- Tags are not predefined — the control-plane auto-declares the actions from the
  rules. The vocabulary _is_ the set of `context.tag::<name>` actions the
  enabled tag rules target: write a tag rule and the tag exists; delete it and
  it is gone. But Cedar strict validation rejects an undeclared action, so the
  control-plane scans the policy source for `context.tag::<name>` actions and
  augments the validation schema with a generated `action "context.tag::<name>"`
  decl per name (on write and at boot). The generated action's context omits
  `tags`, so a tag-on-tag rule cannot validate. The consuming side is a plain
  string (`context.tags.contains("trusted-network")`) needing no declaration.
- Residual gap: Cedar cannot match a tag _name_ across producer↔consumer, so a
  typo makes a phantom tag or a silently-never-matching consumer (fail-closed,
  but silent). Safety net: a dangling-tag lint in the readiness diagnostics
  (`/health`) walks the enabled set for _produced_ tags (the
  `context.tag::<name>` actions) vs _consumed_ tags (the
  `context.tags.contains("…")` literals) and warns on a consumer with no
  producer, or a producer no consumer uses.
- No recursion / ordering. Tag rules condition on raw inputs only — never on
  `context.tags` (the pass-1 context type omits `tags`). One level,
  order-independent.
- Fail-closed. Deny-by-default in pass 1 too: a tag exists only if a `permit`
  fired; any pass-1 error → tag absent → consuming grant denied. A `forbid` in a
  tag rule can positively exclude a tag.
- Client cannot inject a tag. `tags` is computed, never read from input.
- Granularity and cost. Tags resolve at the datasource level — pass 1 runs once
  per request (resource = the request's single datasource), N extra in-memory
  Cedar evaluations (N = tag vocabulary, tiny). Datasource-, principal-, and
  context-scoped tags all work directly. A tag that must vary per table/column
  within one datasource would need pass 1 to run per-resource — a heavier
  variant, only if a real policy needs sub-datasource tag scoping.

## Security invariants

- Server-attested, never client-asserted — `channel` from the entry point,
  `requester_ip` from the observed connection, `tags` computed by the
  control-plane. A wire / editor client cannot set its channel, spoof its
  source, or assert a tag. The sole exception is the development-only simulated
  address above, which is honored only under `PM_AUTH_DEBUG` and forfeits
  network as an independent factor for as long as that bypass is on.
- Fail-closed at every step (raw resolution, tag pass, real decision).
- Tag rules see only raw context — no tag-on-tag, so the pre-pass is a pure
  one-level function of attested inputs.
- Context is per-connection, never baked into a token — resolved fresh each
  decision.

The decision audit (`audit_event`) records the `channel` and the derived
`context_tags` on every decision — ALLOW, MASK, and DENY alike — so a decision
is traceable to the surface it came from.

## Cedar schema

The context is declared once as a common type referenced by every action's
`context` (the shape `AuthzContext.toCedarMap` builds):

```cedarschema
type RequestContext = {
    network_zones?: Set<String>,
    channel?: String,
    requester_ip?: ipaddr,       // Cedar IP extension
    tags?: Set<String>,          // DERIVED by pass 1; never client-supplied
};

// Pass-1 tag rules: the control-plane GENERATES one such action decl per tag name found in the rules
// (the vocabulary is derived, then auto-declared so Cedar can validate the rule). Its context omits
// `tags` — a tag rule reading context.tags won't validate (no recursion).
action "context.tag::trusted-network" appliesTo {
    principal: [User, Role], resource: [Datasource],
    context: { network_zones?: Set<String>, channel?: String, requester_ip?: ipaddr },
};
```

Every attribute is optional, so a policy that conditions on none is unchanged; a
policy that _does_ condition on one must `has`-guard it or it fails validation.
