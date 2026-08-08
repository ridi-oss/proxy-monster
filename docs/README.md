# proxy-monster — documentation index

Index of every design and reference doc. Each doc is the detailed territory;
this page is the map.

For the components, topology, and ports start with
[`../ARCHITECTURE.md`](../ARCHITECTURE.md), and for the design decisions on top
of that shape [`../DESIGN.md`](../DESIGN.md); for accepted caveats and known
gaps see [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md); deferred and open
work lives in [`backlog.md`](./backlog.md). To build, test, and contribute see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md); to report a vulnerability see
[`../SECURITY.md`](../SECURITY.md).

## What's built

proxy-monster runs on `main`: the enforcing wire proxy for MySQL and PostgreSQL,
the Cedar authorization core, the sqlglot-go lineage analyzer, OIDC and session
auth, the query-approval workflow, and the tamper-evident audit trail with its
independent monitor. Two tracks are still moving: the OAuth-2.1-authenticated
MCP admin surface is partial, and a port of the control-plane to Go (the data
plane is already Go) is a proposal under evaluation.

## Documents

### Guides — for people using proxy-monster

Everything else on this page is a design doc, written for people building
proxy-monster. [`guides/`](./guides) is the other direction: onboarding material
meant to be read by an agent, which then walks a human through the system.

<!-- prettier-ignore -->
| Doc | Reader |
| --- | --- |
| [`guides/usage.md`](./guides/usage.md) | A developer querying through it — console, masked results, requesting access, local SQL clients |
| [`guides/admin.md`](./guides/admin.md) | An admin configuring it — tags, roles, policy, MCP |

### Access model and enforcement

The enforcement engine states _facts_ (resources + tags, sql-kind, analyzable?,
maskable?); Cedar sets policy over every tagged resource per datasource, with no
hardcoded allow/deny. Schema-aware enforcement is built over a policy store and
a facts layer.

<!-- prettier-ignore -->
| Doc | Summary |
| --- | --- |
| [`access-model.md`](./access-model.md) | Umbrella: "engine states facts, Cedar sets policy"; generalizes the authz model with the facts half. |
| [`mapping-schema-construction.md`](./mapping-schema-construction.md) | Depth-3 sqlglot MappingSchema for a datasource's full catalog. |
| [`schema-threading-problem.md`](./schema-threading-problem.md) | Fully-qualified static resolver, exact catalog matching, re-introspection. |
| [`connection-model.md`](./connection-model.md) | Per-connection model: live namespace + trusted datasource catalog; makes schema-threading wire-safe. |
| [`per-connection-catalog.md`](./per-connection-catalog.md) | Per-connection enforcement catalog: content-addressed fragments, DB-hash-gated freshness. |
| [`policy-store.md`](./policy-store.md) | One policy table, two id spaces; migration-owned system rows with toggle-only UI; the default policy seed. |
| [`facts-emission.md`](./facts-emission.md) | Statement facts + Cedar marshalling; dangerous-function gating; `analyzable` / `maskability` gates. |
| [`statement-facts-contract.md`](./statement-facts-contract.md) | Go emits a complete `StatementFacts` / `RequiredGrant` contract; the CP is a pure Cedar grant-walk, no lexing. |
| [`system-classification.md`](./system-classification.md) | Immutable per-engine/version manifest; exposed system schemas; curated dangerous set; open-unknown posture. |
| [`diagnostic-redaction.md`](./diagnostic-redaction.md) | Closes the DB error/warning value-leak side-channel; fail-closed field strip; message tables from catalogs. |
| [`derived-masking.md`](./derived-masking.md) | Lets a masked column pass through a provably-total builtin string transform and stay masked. |
| [`relation-model.md`](./relation-model.md) | Whole-row / composite-value resolution: how a relation used in value position never leaks a protected column. |

### Identity and authorization

<!-- prettier-ignore -->
| Doc | Summary |
| --- | --- |
| [`authz-model.md`](./authz-model.md) | The spine: RBAC + Cedar + masking-as-column-config. Also the exemplar design doc for house style. |
| [`authz-context.md`](./authz-context.md) | The `context` Cedar policies condition on (channel + requester IP + two-pass tags); approval + network isolation consume it. |
| [`auth-model.md`](./auth-model.md) | Authentication: OIDC web login + CP-brokered device-auth; roles resolved locally. |
| [`session-lifetime.md`](./session-lifetime.md) | Server-side sessions on a unified `principal_session` table; two clocks; newest-wins / device-bind; ≤5-min IdP revalidation. |
| [`approval-workflow.md`](./approval-workflow.md) | Run a query under role R, once, via an approver: role discovery + execute-under-R + view-as-R. |
| [`task-execution.md`](./task-execution.md) | The execute-under-R task model behind the approval workflow: executor context, masking, viewing. |
| [`mcp-access-control.md`](./mcp-access-control.md) | OAuth-2.1-authenticated MCP access-control tools over the live Cedar/RoleResolver authority; co-hosted authorization server. |

### Infrastructure and operations

<!-- prettier-ignore -->
| Doc | Summary |
| --- | --- |
| [`datasource-registration.md`](./datasource-registration.md) | gRPC self-registration; Decide cutover; Register / PushCatalog + proxy introspection; events. |
| [`web-console.md`](./web-console.md) | The `web/` console: Editor / Workflows / Access / Audit / Admin. |
| [`migrations.md`](./migrations.md) | Flyway, auto-migrate on boot in per-migration transactions, fail-closed; single→multi-instance path. |
| [`l10n.md`](./l10n.md) | Localized user-facing errors (en/ko): the server returns a stable `code` + `params`; the web client resolves it. |
| [`audit-trail-hardening.md`](./audit-trail-hardening.md) | Tamper-evident hash-chained `audit_event` trail + the CP-independent `auditmon/` Go monitor. |

### Reference

<!-- prettier-ignore -->
| Doc | Summary |
| --- | --- |
| [`backlog.md`](./backlog.md) | Roadmap: planned and open work. |
| [`cedar-sim/`](./cedar-sim/) | Runnable Cedar verification behind the approval workflow's assume-role-at-view options. |

## Relationships

- [`access-model.md`](./access-model.md) generalizes
  [`authz-model.md`](./authz-model.md): it adds the _facts_ half on top of
  authz's Cedar _policy_ spine.
