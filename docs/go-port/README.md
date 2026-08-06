# The Go control-plane port

The specification the Go control-plane (`gocp/`) was written from, plus the
decisions taken along the way. Written against the Kotlin `control-plane/` as it
stood when the port began, and kept because it is what makes a 154k-line port
reviewable: each area document states what the Kotlin does, which invariants are
load-bearing, and what a port must not "improve".

Start here if you are reviewing the port:

- **[96-traceability.md](./96-traceability.md)** — the `KT:` marker convention,
  how the 929-case inventory is counted, and the shortcuts that were tried and
  found wrong. The checker in `gocp/internal/tracing` enforces this, so this
  document is the contract behind the coverage number.
- **[00-INDEX.md](./00-INDEX.md)** — scope, the case/LOC ledger, the port policy
  (REPRODUCE / REPRODUCE+PIN / OMIT / DEFER), and the findings register.

## The fourteen areas

|                                       | Area                                        |
| ------------------------------------- | ------------------------------------------- |
| [01](./01-bootstrap.md)               | Bootstrap, config, the composition root     |
| [02](./02-authz.md)                   | Cedar authorization                         |
| [03](./03-identity-scim.md)           | Identity, groups, SCIM                      |
| [04](./04-auth-session-tokens.md)     | Auth, sessions, tokens                      |
| [05](./05-datasources-catalog.md)     | Datasources and the catalog                 |
| [06](./06-query-decision.md)          | The per-statement decision                  |
| [07](./07-tasks-approvals-results.md) | Tasks, approvals, stored results            |
| [08](./08-audit.md)                   | The audit trail and its hash chain          |
| [09](./09-policies.md)                | Roles, assignments, mask functions          |
| [10](./10-grpc.md)                    | The proxy-facing gRPC surface               |
| [11](./11-mcp-oauth-management.md)    | MCP, OAuth, the management services         |
| [12](./12-request-context.md)         | Request context and the trusted edge        |
| [13](./13-engine.md)                  | The shared enforcement engine               |
| [14](./14-auth.md)                    | OIDC login and the MCP authorization server |

## Decisions and evidence

- **[98-cedar-spike-report.md](./98-cedar-spike-report.md)** — the cedar-java →
  cedar-go spike. Whether the Go library could carry the authorization model at
  all was the one question that could have stopped the port, so it was answered
  first.
- **[99-library-decisions.md](./99-library-decisions.md)** — every library and
  codegen choice, with what was rejected and why.

## Working artifacts

Kept for provenance rather than as reference material:

- **[99-reconciliation-report.md](./99-reconciliation-report.md)** — how the
  specification was reconciled against the Kotlin after it was written,
  including the counting errors that pass found and corrected.
- **[97-missing-routes.txt](./97-missing-routes.txt)** — the route-coverage
  scratch list from the point where the route table was still incomplete.

## A caveat on reading these

They describe the Kotlin **as of the start of the port**, not as of today.
`main` has moved since — most visibly `#78`, which removed Cedar tag
type-scoping and inverted the reasoning several of these documents give for it.
Where an area document and the current Kotlin disagree, the Kotlin is right and
the document is history. The differential harness
(`gocp/internal/conformance/differential`), not these files, is what holds the
two implementations to each other.
