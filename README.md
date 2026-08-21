# proxy-monster

A self-hosted, open-source database access-control proxy for MySQL and
PostgreSQL. Clients connect with their normal tools over the native wire
protocol; proxy-monster enforces column-level access control per role —
deterministic, lineage-aware masking and deny — and records every decision to a
tamper-evident audit trail.

## What it does

- **Transparent proxy.** Speaks the native MySQL and PostgreSQL wire protocols,
  so `psql`, `mysql`, JDBC, and application drivers connect unchanged. It
  authenticates the client to a principal, authorizes each statement, applies
  masking, and brokers to the target DB with a per-datasource service account —
  users never hold database credentials.
- **Column-level access control.** Deterministic, role-based masking and deny,
  driven by [Cedar](https://www.cedarpolicy.com/) policy over per-column tags.
- **Lineage-aware.** It parses each query and follows sensitive values through
  expressions, functions, subqueries, joins, and `SELECT *`, so a masked column
  stays masked wherever it flows. Anything it cannot prove safe is denied by
  default through Cedar (fail-closed) — a policy decision, not a hardcoded
  error.
- **Just-in-time elevation.** Time-boxed, revocable role grants through an
  approval workflow, so access widens only along an audited path.
- **Tamper-evident audit.** Every decision is written to a hash-chained log on
  the decision path, so a statement cannot run unlogged. Verifying that chain,
  anchoring it off-box, detecting anomalies, and exporting to a SIEM are the job
  of `auditmon`, a separate process you deploy and point at the store — it is
  not started by the default local stack.

## How it works

A split control plane (Kotlin/JVM) and data plane (Go), talking over gRPC:

- **`goproxy`** (Go) — the data-plane wire proxy: protocol codecs, token auth, a
  per-statement `Decide` call to the control plane, inline result masking, and
  the target-DB broker.
- **`control-plane`** (Kotlin) — identity and roles (OIDC), Cedar policy, the
  catalog, the per-statement decision, and the admin/console API.
- **`analyzer`** (Go, reached from the JVM through a Foreign Function & Memory
  binding) — the [sqlglot-go](https://github.com/ridi-oss/sqlglot-go) lineage
  probe that emits each statement's required grants.
- **`auditmon`** (Go) — the independent audit-trail monitor.

Two different things are called an engine here, and they are independent:

- **Target databases — what proxy-monster protects.** MySQL and PostgreSQL.
  MySQL is the primary, fully-enforced target; PostgreSQL is experimental.
- **The control-plane store — what proxy-monster runs on.** PostgreSQL only.
  There is no MySQL-store option, and `PM_DB_URL` must be a PostgreSQL JDBC URL.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the components, topology, and
ports.

## Quick start

You need Docker, plus the toolchain pinned in `mise.toml` — JDK, Gradle, Go,
Node, and pnpm. Install it once, then one task brings up the whole local stack —
the PostgreSQL control-plane store, the control plane, a sample MySQL and
PostgreSQL target database with a wire proxy in front of each, and the web
console:

```sh
mise trust     # a freshly cloned mise.toml is untrusted, and every mise command refuses it
mise install
mise run dev
```

Running through `mise` matters: it pins the JDK for you. The build needs JDK 24,
because `build.gradle.kts` pins the Java compiler to `--release 24`, so an older
ambient JDK fails to compile.

The console is at http://localhost:41300. The full walkthrough — component by
component, local and AWS — is in [INSTALL.md](./INSTALL.md).

## Using it

Two guides in [docs/guides/](./docs/guides), written to be read by your agent so
it can walk you through the system:

- [usage.md](./docs/guides/usage.md) — querying through proxy-monster: the
  console, what a masked result looks like, requesting access you do not have,
  and connecting TablePlus or DataGrip through `pmon`.
- [admin.md](./docs/guides/admin.md) — configuring it: tags, roles, policy, and
  the MCP admin surface.

### Let your agent walk you through it

Already running an AI coding agent? Paste this:

```
Help me understand and use proxy-monster. Read
https://raw.githubusercontent.com/ridi-oss/proxy-monster/main/docs/guides/usage.md
first, then walk me through it step by step.
```

Swap in `admin.md` if you are the one configuring it. Each guide is written to
be read cold, so the agent answers from it rather than guessing.

## Documentation

- [docs/guides/](./docs/guides) — onboarding guides for people using
  proxy-monster: [usage.md](./docs/guides/usage.md) (developers) and
  [admin.md](./docs/guides/admin.md) (administrators).
- [ARCHITECTURE.md](./ARCHITECTURE.md) — the components, topology, trust
  boundaries, and ports.
- [INSTALL.md](./INSTALL.md) — install, run locally, and deploy (local + AWS
  ECS).
- [DESIGN.md](./DESIGN.md) — the design decisions and the
  decision-to-enforcement flow.
- [docs/](./docs/README.md) — the design-doc index, plus a summary of what's
  built.
- [KNOWN_LIMITATIONS.md](./KNOWN_LIMITATIONS.md) — accepted caveats and gaps.
- [AGENTS.md](./AGENTS.md) — project entry point: intent, layout, conventions,
  and the control-plane HTTP route map.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — how to build, test, and contribute.
- [SECURITY.md](./SECURITY.md) — how to report a vulnerability.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — the standards we hold each other
  to, and how to report a problem.

## License

Licensed under the [Apache License 2.0](./LICENSE). Attribution that
redistributors must carry forward is in [NOTICE](./NOTICE).
