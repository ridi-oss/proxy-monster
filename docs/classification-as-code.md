# Column classification as proxy-declared config

Proposed, not built. This replaces where column classification lives and how it
reaches a decision. It does not change masking, lineage, or the Cedar model —
only who owns "which columns carry which tags."

## Decision

Column classification — a column's `tags` and its `mask_fn` — is **declared by
the proxy** from its own config, not stored in the control plane. The proxy
pushes classification alongside the catalog it already introspects; the control
plane uses it for the live decision and keeps **no durable copy**. A saved
workflow result freezes the classification it was decided under, so a view can
re-decide with no live proxy
([stored-result-classification.md](./stored-result-classification.md)).

Three consequences fall out, each its own section below:

- No control-plane classification store, so no runtime admin CRUD and no
  cross-datasource dedup machinery (the parked profile abstraction).
- When a proxy is gone the control plane cannot decide a live query anyway, so
  there is nothing to persist for the live path — fail-closed is automatic.
- The one path that decides without a live proxy — viewing a saved result —
  reads the per-result snapshot, which becomes the only durable classification
  the control plane holds.

## Classification is config, not state

`column_classification` today is a control-plane table mutated by a runtime
admin API. But the data is authored, not discovered:

- It references only `datasource` and `mask_fn`, never `catalog_column`
  (`V2__catalog.sql`). It is keyed by `(schema, table, column)` **name**, and a
  write does not check the column exists — you can classify a column before it
  is introspected.
- The enforcement path reads it independently of the structural catalog
  (`DatasourceStore.classificationsFor` — "keyed independently of
  catalog_column").

So classification is a name-keyed declaration that happens to sit in a table. It
belongs in version control, authored next to the schema it describes — a runtime
CRUD store, plus the profile dedup this supersedes, is machinery for a problem
the file layer already solves.

## The proxy already declares per-datasource config

The proxy declares its datasource `tags` at Register (`controlplane.proto`,
`RegisterRequest.tags`) — the posture (`system:development` /
`system:production`) that every shipped preset keys on, authored in the proxy's
own config block. Column classification is the same shape one level down:
per-column tags plus a mask function, authored in the same block, next to the
`tags` line an operator already writes.

That is the single config surface the settings-file direction wants. The proxy's
config is where per-datasource facts already live; classification joins them
rather than becoming a second, control-plane-side surface an operator has to
keep in sync.

Delivery reuses **PushCatalog**, not Register: classification is per-column and
changes with the schema, not with proxy identity, and PushCatalog already
carries the per-column payload. The `Column` message (or a parallel per-column
message) gains `tags` and a mask-function **name** — not the control plane's
`mask_fn_id`, which the proxy cannot know. Mask-function definitions stay
control-plane config; the declaration references them by name and the control
plane resolves.

## No persistence — fail-closed is automatic

A live query is decided while its proxy is connected, so the control plane has
the freshly-declared classification in hand. When the proxy is gone there is no
connection to decide over — the statement fails closed for want of a backend,
not for want of a tag. So the live path needs no durable classification at all.

The control plane holds the last declaration transiently, per datasource,
refreshed on each PushCatalog. A control-plane restart re-receives it on the
next push; a datasource whose proxy has never attached has none, and any
decision against it fails closed.

This is the point the persisted design missed: it kept a durable
`column_classification` table to answer a question — "what are this datasource's
tags right now?" — that only has a live answer when a proxy is present, and when
one is present the proxy can just say.

## Saved results freeze that point's tags

One path decides with no proxy in the loop: viewing a saved workflow result.
`decideResultView` re-decides already-extracted bytes stored in `query_result`,
and the proxy that produced them may be long gone.

Under a persisted store this "worked" by reading today's classification — which
is the fail-open bug
[stored-result-classification.md](./stored-result-classification.md) describes:
a `pii` tag removed after a cleanup unmasks bytes that still hold the old value.
The fix there is to snapshot the touched columns' tags and the datasource
posture at execution and re-decide the view against that snapshot, strictly — no
union with current tags, no tag history.

Under **this** model the snapshot is not a bug-fix bolted onto a persisted
store. It is the only durable classification the control plane keeps, and it is
exactly the right one: a saved result must be judged by the tags in force when
its bytes were captured, never by tags declared afterward. The two proposals
compose — this one removes the standing store, that one supplies the per-result
record that makes removing it safe.

## The trust boundary does not widen

The obvious objection to sourcing tags from the proxy: the proxy is the
internet-facing component, so letting it declare what is sensitive lets a
compromised proxy declare nothing sensitive and unmask everything.

It does not widen the boundary, because the proxy already holds the datasource's
cleartext. It executes every statement against the backend and applies masks
**inline on the result stream** (`AGENTS.md`: "masks those columns inline on the
result stream") — it necessarily sees the unmasked rows in order to mask them,
and it holds the only credential to the target. A compromised proxy is already
total for that datasource's data; trusting it to declare classification adds no
exposure it did not already have. The control plane, which never dials a target,
is not made more trusting by this — it was already trusting the proxy with the
data itself.

## Presence — a failed read must not read as "nothing sensitive"

Each PushCatalog is a full declaration; there is no "keep what's stored" merge,
because nothing is stored. But the fail-open shape the persisted `tags` upsert
guards against still applies: a proxy that **fails to read** its config file
must not be indistinguishable from one that genuinely declares "no
classification." The wire needs an explicit present-vs-absent signal (as
`advertise_cert_chain` carries `optional` presence today), so a missing or
unreadable config denies rather than silently unmasking. A declaration that is
present and empty is a deliberate "no tags"; an absent one is "I could not tell
you," and the control plane treats the datasource as unclassifiable —
fail-closed — until a real declaration arrives.

## What stays control-plane config

Classification is per-datasource, so it goes with the proxy. The rest of the
config-as-code surface is **global** and has no per-proxy home — Cedar policies,
roles, the `group_role` map, and `mask_fn` definitions are one set shared across
every datasource. Those remain control-plane settings, reconciled separately;
this doc does not cover them. Mask-function definitions in particular stay
control-plane-owned precisely so a per-datasource declaration can reference one
by name.

## Migration and open questions

- **Retire the store.** `column_classification`, its admin CRUD routes and MCP
  tools, and the parked profile abstraction all go. The proxy config becomes the
  source; the control plane's per-datasource in-memory classification and the
  per-result snapshot are the only readers left.
- **The proto change** — extend `Column` with `tags` + a mask-function name, or
  add a parallel per-column classification message — plus the presence signal,
  is the concrete wire work.
- **The compose-preview and approval-discover paths** call `decideQuery` with
  `catalog(ds.id)` server-side. They must read the transient declared
  classification and fail closed when no proxy is attached; confirm neither runs
  in a state where it would otherwise silently see empty classification.
- **Where the proxy's classification config lives** — inline in the proxy's
  existing config block, or a sibling file it loads — is a proxy-config-format
  decision this doc leaves open.
