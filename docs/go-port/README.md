# The Go control-plane port

The specification the Go control-plane (`gocp/`) is written from, plus the
decisions taken along the way. Each area document states what the Kotlin does,
which invariants are load-bearing, and what a port must not "improve".

## How the port lands

As a series of small, independently mergeable PRs rather than one change. Each
one ports a bounded slice, carries its own `KT:` markers and its own slice of
the differential corpus, and merges **inert** — nothing is deployed until the
whole surface is across and the harness agrees on it. The Kotlin plane keeps
serving throughout.

The order is forced by the Go package import graph, not chosen: a package can
only land after everything it imports.

An area document arrives with the slice that ports its area, so this index grows
as the series does. A document is written against the Kotlin **at the time its
slice is cut** — where a document and the Kotlin on `main` disagree, the Kotlin
is right and the document is stale.

## Start here

- **[96-traceability.md](./96-traceability.md)** — the `KT:` marker convention
  and how the case inventory is counted. The checker in `gocp/internal/tracing`
  enforces it, so this document is the contract behind the coverage number.
  Regenerate the inventory with
  `go run ./internal/tracing/geninventory.go`; `-check` fails when it is stale.
- **[99-library-decisions.md](./99-library-decisions.md)** — every third-party
  choice the port makes and what was rejected, including the JSON-encoding
  constraints kotlinx imposes on the wire format.

## The fourteen areas

| | Area | Landed |
| --- | --- | --- |
| [01](./01-bootstrap.md) | Bootstrap, config, the composition root | config, store, migrations |
| 02 | Cedar authorization | — |
| 03 | Identity, groups, SCIM | — |
| 04 | Auth, sessions, tokens | — |
| 05 | Datasources and the catalog | — |
| 06 | The per-statement decision | — |
| 07 | Tasks, approvals, stored results | — |
| 08 | The audit trail and its hash chain | — |
| 09 | Roles, assignments, mask functions | — |
| 10 | The proxy-facing gRPC surface | — |
| 11 | MCP, OAuth, the management services | — |
| 12 | Request context and the trusted edge | — |
| 13 | The shared enforcement engine | — |
| 14 | OIDC login and the MCP authorization server | — |

## The differential harness

`gocp/internal/conformance/differential` replays one request corpus against both
control-planes and diffs the answers, so equivalence is **measured** rather than
transcribed. It is the reason a slice can be trusted without re-reading the
Kotlin by hand.

Its corpus grows with each slice. This slice ports no routes, so the corpus holds
only the liveness probe and the harness cannot yet demonstrate equivalence of
anything — the non-vacuity check in `normalize_test.go`, which proves the
normaliser does not collapse a real difference, is the assertion that ships here.
