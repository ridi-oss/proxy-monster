# The connection model — live namespace-aware enforcement

The connection is the unit of enforcement state. A backend query resolves names
against _its connection's_ live session — the current `search_path` / database,
the temp objects it created, and the catalog as it stands right now — never
against "the datasource" in the abstract. So the proxy's decision must resolve
against that same per-connection state, or it authorizes a different table than
the backend binds, which is a cleartext leak.

Three things are therefore per-connection, not per-datasource:

- The connection — each editor session and each wire client holds its own
  persistent backend connection (not a fresh pooled connection per statement),
  exactly as psql/JDBC/TablePlus already behave.
- The namespace — the connection's live effective `search_path` (PG) / current
  database (MySQL), tracked as `SET search_path` / `USE` change it.
- The catalog — the connection's view of the schema, kept transactionally
  current including its own temp objects
  ([per-connection-catalog.md](./per-connection-catalog.md)).

Enforcement resolves each statement against the connection's namespace +
catalog, matching the backend exactly. It stays per-statement: a persistent
connection is a data-plane fact, not an authz relaxation. Every statement still
goes through `decideQuery` → Cedar independently against the connection's
current namespace/catalog. Session continuity is not trust continuity — a
statement touching a masked column still `DENY`s mid-session.

## Per-connection connection (editor + wire, unified)

- Wire clients already hold a persistent backend connection through the proxy.
  The decision path reads _that connection's_ namespace + catalog, not a
  datasource-global snapshot.
- The editor holds one persistent connection per editor session.
  `BEGIN…COMMIT`/`ROLLBACK`, `SET`/`USE`, and temp tables persist across the
  session like a wire client. Selecting N statements runs them in order on that
  session's connection; each is still independently gated by the shared query
  engine. The control plane holds one proxy stream (one backend connection) per
  editor session across many queries (`RunExecService.openSession` /
  `runOnSession` / `closeSession` / `sweepIdleSessions`); the web editor opens,
  reuses, and closes one session per datasource (`useResultTabs`).
- The session-close route is ownership-checked (`closeSessionOwnedBy`), so a
  leaked session id cannot tear down another principal's connection.
- Idle-bounded. The backend connection is held for the session and released on
  disconnect / idle timeout.

## Per-connection namespace (`SET search_path` / `USE`)

The backend resolves a bare name against the connection's live effective path;
the proxy must resolve against the same path or it authorizes the wrong table:

`SET search_path = restricted, public; SELECT ssn FROM users` — a
datasource-global default (`public`) authorizes `public.users` (ALLOW), while
the backend binds `restricted.users` (PII). Same via MySQL `USE otherdb`.

- Track the effective path by probing the backend. `current_schemas(true)` /
  `current_database()` on the connection already reflect every `SET`/`USE`, the
  `pg_catalog`-implicit-first rule, and `$user` expansion — more robust than
  re-parsing every `SET` form. The engine caches the probe and re-runs it when
  the protocol marks the namespace dirty (`MarkNamespaceDirty` /
  `probeNamespace`, goproxy) — never by classifying SQL text.
- Resolve and decide under it. The analyzer resolves each bare table via the
  connection's effective path, stamps the resolved schema, and Cedar decides on
  the fully-qualified key. `pg_catalog`'s position is whatever the live path
  says (implicit-first unless explicitly placed).
- No control-plane decision is stored across Parse/Bind/Execute. PostgreSQL
  re-Decides at Parse and again at every Execute (Execute uses the Bind-time
  namespace/temp snapshot); MySQL freezes the PREPARE-time namespace/`sql_mode`
  and re-authorizes every EXECUTE against that triple. Cedar always decides on
  the fully-qualified keys resolved under that path.
- Fail-closed on an unknown / unresolvable / foreign-catalog name.

The editor channel passthrough-allows `SET`/`USE`/`BEGIN`: admission rejects
multi-statement batches and the proxy re-probes the live namespace per query, so
a lone `SET` changes the path and the next query decides and binds against it.

## Catalog freshness and temp objects

The connection's enforcement catalog is kept transactionally current by
[per-connection-catalog.md](./per-connection-catalog.md): the proxy introspects
each referenced schema on the connection's own held backend connection, so a
decision sees uncommitted in-transaction DDL.

Temp objects need care because a session temp shadowing a real table is
invisible to a datasource-global catalog — the analyzer would resolve the real
table while the backend binds the temp. For PostgreSQL the proxy introspects the
held connection's visible `pg_temp` columns (`probeTempColumns`, goproxy) and
sends them with each decide; the control plane overlays only `pg_temp*` entries
onto the base catalog (`editorTempOverlay`, EDITOR-channel-gated). The temp is
searched first, so the analyzer resolves the same relation the backend binds. A
session temp reads unmasked (the user owns it) and a zero-column temp scan skips
the uncovered-scan gate.

Reading a temp back plain is safe: `CREATE TEMP … AS SELECT` is a write, so the
write-references-masked deny (`Query.kt`) blocks copying a masked/denied source
into a temp at creation — a temp can only ever hold data its creator could read.
MySQL session temps are invisible to `information_schema`, so they remain
fail-closed (see [per-connection-catalog.md](./per-connection-catalog.md) known
limitations).

## Why this makes schema threading safe on the wire

[schema-threading-problem.md](./schema-threading-problem.md) fixes the _static_
keys (names → fully-qualified keys, fail-closed on unresolvable) but resolves
against a _snapshot_ namespace/catalog. On the wire the backend binds against
the _live_ connection session, and every divergence — `search_path`/`USE`,
freshly-created or temp tables — is a leak. This model removes the divergence:
same connection, same live namespace, same fresh catalog on both sides.

## Scope

- In: the per-connection connection (editor + wire); per-connection namespace
  tracking (probe → re-decide under the live or Bind/PREPARE-frozen path); the
  editor `pg_temp` overlay.
- Out: static key construction and resolver correctness
  ([schema-threading-problem.md](./schema-threading-problem.md)); building the
  mapping ([mapping-schema-construction.md](./mapping-schema-construction.md));
  enforcement-catalog freshness
  ([per-connection-catalog.md](./per-connection-catalog.md)); the editor UI that
  consumes the connection ([web-console.md](./web-console.md)); the policy/tag
  model over the resolved key ([access-model.md](./access-model.md)).
