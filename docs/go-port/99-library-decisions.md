# 99 — Library & layout decisions

**Date:** 2026-08-01 · **Decides:** every `⟦LIB⟧` marker the 14 area docs
deferred, plus the module layout and codegen wiring that building Increment 1
forces. **Status:** decisions below are binding for the Go port unless a later
spike overturns one. Anything marked **DEFER** names what would settle it.

Read alongside `00-INDEX.md` § **PORT POLICY**. Several choices here are _worse_
engineering in the abstract and are made anyway, because the policy is
bug-for-bug fidelity: a library that helpfully adds caching, retries, or
normalisation is disqualified precisely for helping.

---

## 0. The marker census

```
$ grep -n '⟦LIB⟧\|(LIB)' docs/go-port/*.md | wc -l
37
```

37 marker lines across 11 area docs plus the index. Three are the index's own
description of the convention (`00-INDEX.md:294,298,299`). Fourteen resolve to
**"none" / "stdlib only"** and need no decision — they are listed here so a
reader does not go looking for a library that was deliberately not chosen:

| Marker                             | Says                                          | Capability                                                                    |
| ---------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------- |
| `01-bootstrap.md:103`              | `⟦LIB⟧ none`                                  | `parseDuration` — hand-written, must reject what `time.ParseDuration` accepts |
| `01-bootstrap.md:109`              | `⟦LIB⟧ none required`                         | `Config` construction ergonomics                                              |
| `03-identity-scim.md:327`          | `⟦LIB⟧ none`                                  | `pg_advisory_xact_lock` — raw SQL, not an in-process mutex                    |
| `03-identity-scim.md:344`          | `⟦LIB⟧ none`                                  | `inTx` begin/commit/rollback wrapper                                          |
| `03-identity-scim.md:635`          | `⟦LIB⟧ none`                                  | lock-ordering in `revokeActiveCredentials`                                    |
| `03-identity-scim.md:1052`         | `⟦LIB⟧ none beyond the JSON decoder`          | SCIM payload decode                                                           |
| `07-tasks-approvals-results.md:87` | `⟦LIB⟧ stdlib only`                           | AES-GCM `iv‖ct+tag` — `crypto/aes` + `cipher.NewGCM`                          |
| `10-grpc.md:915`                   | `(LIB)` … "the Go standard library covers it" | X.509/PEM parse + RSA/ECDSA verify — `crypto/x509`, `encoding/pem`            |
| `12-request-context.md:244`        | `⟦LIB⟧ none`                                  | WEDGED-vs-NOT_ATTACHED stream state                                           |
| `13-engine.md:409`                 | `⟦LIB⟧` UTF-16 code-unit ops                  | JVM-parity string ops — `unicode/utf16`, hand-written                         |
| `13-engine.md:507,721,943,1131`    | `⟦LIB⟧ none`                                  | SHA-256, tag `fromId`, error text, misc                                       |
| `14-auth.md:1473,1474`             | "stdlib — no ⟦LIB⟧"                           | CSPRNG + unpadded base64url; SHA-256 + lowercase hex                          |

That leaves **20 lines naming a real capability**, which collapse to **13
distinct decisions**. Those 13, plus four decisions the spec never marked but
that building forces (module layout, codegen, logging, JSON codec), are below.

---

## 1. Decision table

| #   | Capability                                  | Choice                                                                                                            | Version                                        | Why                                                                                                                                                        | Risk if wrong                                                                                         | Spec ref                                                                       |
| --- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| D1  | Go module + workspace slot                  | `github.com/ridi-oss/proxy-monster/gocp` at `gocp/`, added to `go.work`                                           | —                                              | Matches the four existing single-word module dirs; avoids colliding with the live Kotlin `control-plane/`                                                  | Rename churn across imports + `go.work` + mise tasks                                                  | `00-INDEX.md:86`                                                               |
| D2  | protobuf codegen                            | `buf` v2 config, `protoc-gen-go` + `protoc-gen-go-grpc`, `Mengine.proto=…/analyzer/probe/pb`                      | plugins pinned to **v1.35.2 / v1.5.1**         | Two independent generations of `engine.proto` panic the global registry at `init` the moment `analyzer/probe` and the CP's own pb are in one binary        | `panic: file already registered` at process start — before any log line                               | `goproxy/buf.gen.yaml`, `13-engine.md:690`                                     |
| D3  | Postgres driver                             | **`github.com/jackc/pgx/v5`**, native (`pgxpool`)                                                                 | **v5.7.1** (workspace-pinned)                  | Only driver already in the repo; `*pgconn.PgError.Code` gives SQLSTATE without message-text matching; jsonb param typing reproduces both of F16's idioms   | Fall back to `database/sql` + `pgx/v5/stdlib`; cost is jsonb typing ergonomics, not correctness       | `03-identity-scim.md:878`, `04-auth-session-tokens.md:1003`, `14-auth.md:1472` |
| D4  | Migrations                                  | **Hand-rolled runner over Flyway's own `flyway_schema_history`** — no migration library                           | —                                              | Every Go migration library owns its own history table; the constraint is _reading the table Flyway already wrote_                                          | Boot refuses on a correct database (checksum mismatch), or worse, re-applies `V1`                     | `01-bootstrap.md:124-128`, Q2 `:491`                                           |
| D5  | Cedar                                       | **`github.com/cedar-policy/cedar-go`**, in-process, exact pin, `x/exp` firewalled to one wrapper package          | **v1.8.0** (no range)                          | Settled by the spike: 186/186 corpus records reproduce their oracle; fingerprint identical across five releases                                            | Re-open the Rust-sidecar option; the spike says that costs a second runtime for no measured gain      | `98-cedar-spike-report.md`, `02-authz.md:550`                                  |
| D6  | HTTP router                                 | **stdlib `net/http.ServeMux`**                                                                                    | Go 1.26                                        | All 120 routes are literal segments + single-segment `{name}`; no optional, wildcard or regex params anywhere. Repo precedent: `pmon/control/server.go:69` | Swap to `chi` later — handler signatures are unchanged, so the swap is mechanical                     | `01-bootstrap.md:240`, route census below                                      |
| D7  | Cookie encoding                             | **hand-rolled `crypto/hmac` + `crypto/sha256`** in one `websession` package                                       | stdlib                                         | The only two live options are "byte-compatible with Ktor" or "fresh scheme"; a third-party cookie library can satisfy neither                              | If byte-compat is later required, the format is one function to change                                | `01-bootstrap.md:217`, `04-auth-session-tokens.md:397`                         |
| D8  | Byte-compat with Ktor's cookie MAC          | **DEFER** — see §7                                                                                                | —                                              | Product decision: does cutover log every browser session out?                                                                                              | Cutover surprise in either direction                                                                  | `01-bootstrap.md:494` Q3                                                       |
| D9  | JSON codec                                  | **stdlib `encoding/json`** with hand-written struct tags + a conformance fixture                                  | stdlib                                         | INV-A1-4 wants the exact inverse of Go's defaults on two axes; no library fixes that, only discipline does                                                 | Silent wire-shape drift that breaks `web/` and the MCP TS SDK's Zod schemas                           | `01-bootstrap.md:173-188`, `13-engine.md:1080`                                 |
| D10 | Embedded resources                          | **`embed.FS`**                                                                                                    | stdlib                                         | Classpath → compile-time embed; makes "missing bundle" a build error                                                                                       | none material                                                                                         | `13-engine.md:1080`                                                            |
| D11 | i18n bundles                                | **`embed.FS` + hand-written `.properties` reader + `{name}` interpolation** — keep the 6 files byte-for-byte      | —                                              | Kotlin uses _named_ `{param}` placeholders, not `MessageFormat` `{0}`; no Go i18n library reproduces that, and `mcp_tools` text is wire-visible            | Wire-visible MCP tool descriptions drift from the Kotlin                                              | `11-mcp-oauth-management.md:238`, `:591` Q5                                    |
| D12 | gRPC server                                 | **`google.golang.org/grpc`**                                                                                      | **v1.68.1** (match goproxy)                    | Only implementation exposing all six required knobs; the proxy client already speaks to it                                                                 | none — no alternative meets the keepalive-enforcement requirement                                     | `10-grpc.md:1072`                                                              |
| D13 | Test containers                             | **`testcontainers-go`**, `dbtest`-style shared container, **fail not skip**                                       | **v0.34.0** (match goproxy)                    | `goproxy/internal/dbtest/dbtest.go` already solves this exact problem in this exact repo                                                                   | Version skew bumps goproxy's build (see §3.4)                                                         | `00-INDEX.md:334`, `:342-349`                                                  |
| D14 | JWT / JWKS                                  | **`github.com/go-jose/go-jose/v4`** + hand-written JWKS fetch and claim checks. **`coreos/go-oidc` disqualified** | v4.1.4 · **DEFER wiring to the A14 increment** | go-oidc's `RemoteKeySet` caches keys and retries — F61/F62 are REPRODUCE, i.e. _no_ cache and _no_ TTL are the required behaviour                          | Adopting a caching JWKS client silently changes key-rotation and IdP-outage behaviour on an auth path | `14-auth.md:1055`, `:1471`; `00-INDEX.md:394-395`                              |
| D15 | Outbound HTTP client                        | **stdlib `net/http` + `encoding/json`**                                                                           | stdlib                                         | `expectSuccess` = a status check; `ignoreUnknownKeys` = Go's default; per-request timeout = `context`                                                      | none                                                                                                  | `14-auth.md:1053`, `:1470`                                                     |
| D16 | Signed-JWT builder for the fake IdP (tests) | **`go-jose/v4`** (same dep, test scope)                                                                           | v4.1.4                                         | One JOSE dependency, not two                                                                                                                               | none                                                                                                  | `04-auth-session-tokens.md:1418`                                               |
| D17 | Constant-time compare                       | **`crypto/subtle`**, with the length-oracle divergence documented                                                 | stdlib                                         | Java's `MessageDigest.isEqual` folds length into the accumulator; Go's returns 0 on length mismatch                                                        | A length oracle the Kotlin does not have — §9                                                         | `03-identity-scim.md:950`                                                      |
| D18 | MCP SDK                                     | **DEFER** to the MCP spike — `github.com/modelcontextprotocol/go-sdk` v1.7.0 is the only candidate                | —                                              | Two blocking unknowns (§10) that only a spike answers                                                                                                      | Could force the CP to hand-roll Streamable HTTP + SSE                                                 | `11-mcp-oauth-management.md:591` Q7, `01-bootstrap.md:496` Q4                  |
| D19 | Logging                                     | **stdlib `log/slog`**, text handler, INFO default                                                                 | stdlib                                         | Kotlin uses logback + Ktor `CallLogging(INFO)`; nothing in the spec makes log _format_ a contract                                                          | Log-scraping ops runbooks would need updating                                                         | `01-bootstrap.md:195`                                                          |
| D20 | CLI / flags                                 | **none in Increment 1**                                                                                           | —                                              | `Main.kt` takes no arguments; everything is env. `kong` (used by goproxy/pmon) only becomes relevant if `--migrate-only` lands                             | none                                                                                                  | `01-bootstrap.md:154`                                                          |

### Dependency budget for Increment 1

Exactly **two** direct requires beyond the intra-repo `analyzer`:

```
github.com/cedar-policy/cedar-go v1.8.0
github.com/jackc/pgx/v5          v5.7.1
```

`google.golang.org/protobuf` arrives indirectly via `analyzer/probe/pb`. `grpc`,
`testcontainers-go` and `go-jose` are **not** added yet — they belong to the
increments that use them, and every added require perturbs the workspace build
list (§3.4).

---

## 2. D1 — module layout and name

**Capability:** none stated; forced by building.

**Candidates**

| Option                                             | Verdict                                                                                                                                                  |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gocp/` → `github.com/ridi-oss/proxy-monster/gocp` | **chosen**                                                                                                                                               |
| `control-plane-go/` → `…/control-plane-go`         | rejected — a temporary name that outlives the migration; hyphens are legal in a module path but not in a Go package name, so every import needs an alias |
| Add packages under the existing `goproxy/` module  | rejected — the CP would inherit goproxy's whole require set, and `goproxy/internal/pb` is not the CP's to own                                            |

**Evidence for the convention.** Read this session:

```
$ cat go.work
go 1.26.0
use ( ./analyzer ./auditmon ./goproxy ./mysqlwire ./pmon ./pmontray )

$ head -1 goproxy/go.mod   → module github.com/ridi-oss/proxy-monster/goproxy
$ head -8 analyzer/go.mod  → module github.com/ridi-oss/proxy-monster/analyzer
```

Six modules, six single-word directories, one module path per directory,
`go 1.26.0` in each. Both existing `go.mod` files open with a prose comment
explaining _why the module exists_ — `analyzer`'s is eight lines about probe
ownership. Match that: the CP's `go.mod` should say it is the Go port of
`control-plane/` and that both trees are live during the migration.

**Why `controlplane` and not `control-plane`.** `control-plane/` is the Kotlin
module and is still building and shipping. Two directories differing only by a
hyphen is a footgun in every `cd`, glob and CI path filter. `controlplane` is
also the only form that can be a Go package identifier, and it matches
`goproxy`/`auditmon`/`mysqlwire`/`pmontray`.

**Follow-on that is easy to forget.** Adding to `go.work` is not enough to get
the tests _run_. `mise.toml` enumerates modules explicitly in two places, both
verified this session:

```
mise.toml (verify) : go test ./analyzer/... ./auditmon/... ./goproxy/... ./mysqlwire/... ./pmon/...
mise.toml (test-go): for m in analyzer auditmon goproxy mysqlwire pmon; do …
```

Neither lists `pmontray` today, so the precedent for omission exists — but a
control-plane whose suite never runs in `mise run verify` is not ported. **Add
`controlplane` to both lists in Increment 1.**

**Risk if wrong:** a rename is mechanical (`gofmt -r` cannot do import paths;
`go mod edit` + sed can) but touches `go.work`, `mise.toml`, CI, and every file.
Cheap now, annoying at 18k LOC.

---

## 3. D2 — protobuf codegen, and the registry panic

**Capability quote** — `13-engine.md:690`:

> `⟦LIB⟧` a protobuf runtime + generated Go stubs for
> `analyzer.proto`/`controlplane.proto` — implied by §3.3 (the proto messages
> _are_ this area's data classes, so there is no way to port it without one).

### 3.1 The hard constraint, restated from the source

`goproxy/buf.gen.yaml` documents it (read verbatim this session):

> controlplane.proto imports the shared engine.proto (proxymonster.v1.Engine)
> but this module does NOT generate a second copy of it: goproxy links
> analyzer/probe into the same binary … which already generates engine.proto
> into analyzer/probe/pb — two independently-generated Go types for the same
> logical .proto file panic the protobuf runtime's global file registry at init
> ("file already registered") the instant both packages are imported into one
> process.

The control-plane is in **exactly** the same position, for the same two reasons:

```
$ grep -n '^import' proto/src/main/proto/controlplane.proto
8:import "engine.proto";
9:import "google/protobuf/empty.proto";

$ ls analyzer/probe/pb/
analyzer.pb.go   engine.pb.go
```

The CP links `analyzer/probe` (A13 §3.3 — the analyzer's proto messages _are_
A13's data types) and therefore already has `engine.proto` registered. It must
generate `controlplane.proto` for A10 and must **not** generate `engine.proto`.

### 3.2 Why the CP cannot just import goproxy's stubs

`goproxy/internal/pb` is under `internal/`, so it is importable only from
`github.com/ridi-oss/proxy-monster/goproxy/…`. The CP has to generate its own
`controlplane.pb.go`. That is safe: goproxy and the control-plane are separate
processes, so two registrations of the file path `controlplane.proto` never
meet. Only `engine.proto` collides, and only inside the CP binary.

### 3.3 The config, with a reason per line

`gocp/buf.gen.yaml`:

```yaml
version: v2
managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      value: github.com/ridi-oss/proxy-monster/gocp/internal/pb
plugins:
  - local: protoc-gen-go
    out: internal/pb
    opt: paths=source_relative,Mengine.proto=github.com/ridi-oss/proxy-monster/analyzer/probe/pb
  - local: protoc-gen-go-grpc
    out: internal/pb
    opt: paths=source_relative
```

Regenerate with:

```sh
cd controlplane && buf generate ../proto/src/main/proto \
  --path ../proto/src/main/proto/controlplane.proto
```

| Option                                       | Why it is there                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version: v2`                                | Both existing configs are v2. One config schema in the repo.                                                                                                                                                                                                                                                                                                                                                                                                |
| `managed.enabled: true`                      | `controlplane.proto` declares only `java_package`/`java_multiple_files` (verified: `grep 'option ' controlplane.proto`). `protoc-gen-go` refuses a file with no `go_package`. The `.proto` is **shared with the still-live Kotlin build**, so adding a Go option to it is not available — managed mode injects it at generation time instead.                                                                                                               |
| `go_package_prefix` (not `go_package`)       | Mirrors `goproxy/buf.gen.yaml`, the module with the identical generation set. `analyzer` uses the flat `go_package` because it generates _two_ files into _one_ package; the prefix form keeps a second CP-owned proto in its own directory automatically.                                                                                                                                                                                                  |
| `out: internal/pb` + `paths=source_relative` | Puts the output at `gocp/internal/pb/controlplane.pb.go` — byte-for-byte the same tree shape as goproxy. `internal/` keeps the generated surface module-private, which is right: A10's contract is `GrpcServer`/`ControlPlaneGrpcService`, not raw stubs.                                                                                                                                                                                                   |
| **`Mengine.proto=…/analyzer/probe/pb`**      | **The load-bearing one.** Without it, managed mode gives `engine.proto` the CP prefix too and `protoc-gen-go` emits a second `engine.pb.go`. Both files call `protoimpl.TypeBuilder` on the path `engine.proto` in their `init()`, and the second one panics the process before `main()` runs. With it, `RegisterRequest.Engine` resolves to the **already-registered** `pb.Engine` from `analyzer/probe/pb` — one Go type, shared, not two colliding ones. |
| no `M` for `google/protobuf/empty.proto`     | The well-known types carry their own `go_package` and buf managed mode leaves them alone; the runtime registers them once from `google.golang.org/protobuf/types/known/emptypb`. Proof this works: `goproxy/internal/pb/controlplane.pb.go` exists and builds against the same import.                                                                                                                                                                      |
| `--path` on the command line                 | Restricts the run to `controlplane.proto` so the CP's codegen never picks up `analyzer.proto` — a second generation of _that_ file is the same panic with a different filename. Both existing configs carry the same instruction in a comment; repeat it.                                                                                                                                                                                                   |

**Tool versions.** The committed output names them:

```
$ head -4 goproxy/internal/pb/controlplane.pb.go       → protoc-gen-go v1.35.2
$ head -4 goproxy/internal/pb/controlplane_grpc.pb.go  → protoc-gen-go-grpc v1.5.1
$ head -4 analyzer/probe/pb/engine.pb.go               → protoc-gen-go v1.35.2
```

Pin the CP to the same two, and record them in the `buf.gen.yaml` header comment
(neither existing config does; the generated code is committed, so an unpinned
regeneration produces a spurious diff).

**⚠️ Tooling is not installed on this machine.** Verified this session:

```
$ which buf protoc-gen-go protoc-gen-go-grpc
buf not found
protoc-gen-go not found
protoc-gen-go-grpc not found
```

Increment 1 excludes gRPC, so the practical decision is: **write `buf.gen.yaml`
now, generate in the A10 increment.** Whoever does that installs the three tools
with `go install` at the versions above.

**Risk if wrong:** a missing `M`-option is not a subtle bug — the binary panics
in `init()` with `proto: file "engine.proto" is already registered`, before any
log output, on every start. Easy to diagnose once seen, impossible to miss.

### 3.4 The workspace build-list hazard (applies to every version pin here)

`go.work` resolves **one version per module across the whole workspace**.
Measured:

```
$ go list -m github.com/jackc/pgx/v5                    → v5.7.1
$ go list -m github.com/testcontainers/testcontainers-go → v0.34.0
```

Those are goproxy's requires. If the CP requires pgx v5.10.0 or testcontainers
v0.43.0 (the current latest, checked this session), MVS bumps **goproxy's**
build to that version for every workspace-mode command — which is all of them:
`mise run verify` and `mise run test-go` both run inside the workspace.
`cedar-go` also pulls `github.com/google/go-cmp v0.7.0`, above the `v0.6.0` the
analyzer carries today.

**Decision:** pin shared dependencies to the versions goproxy already requires
(pgx v5.7.1, testcontainers-go v0.34.0, grpc v1.68.1, protobuf v1.35.2). Bump
deliberately, in a separate change that re-runs goproxy's suite. `go-cmp`'s bump
is unavoidable and is a test-only comparison library — accept it, and note it in
the Increment 1 result summary.

---

## 4. D3 — Postgres driver

**Capability quotes.** `14-auth.md:1472`: _"Postgres driver supporting
`ON CONFLICT … WHERE <partial-index-predicate> DO UPDATE … RETURNING`,
`SELECT … FOR UPDATE`, `INSERT … SELECT`, batched statements, and explicit
transactions."_ `03-identity-scim.md:878`: _"the port needs a driver-level 'is
this a unique-violation' predicate on Postgres SQLSTATE `23505` ⟦LIB⟧ … Note
`23503` (foreign-key violation) is **not** matched."_
`04-auth-session-tokens.md:1003`: _"needs SQLSTATE inspection, not string
matching on the driver's message text."_

**Candidates**

| Option                                                 | Verdict                                                                      |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `jackc/pgx/v5`, native API (`pgxpool`)                 | **chosen**                                                                   |
| `jackc/pgx/v5` behind `database/sql` (`pgx/v5/stdlib`) | viable fallback; what `goproxy/introspect` and `goproxy/internal/dbtest` use |
| `lib/pq`                                               | rejected — maintenance mode, and not in this repo                            |

**Why pgx native.** Four reasons, in order of weight:

1. **It is already the repo's Postgres driver.** `goproxy/pgproxy` speaks
   `pgproto3`/`pgconn` directly; `goproxy/introspect/introspect.go:18` and
   `internal/dbtest/dbtest.go:22` register `pgx/v5/stdlib`. Adding a second
   Postgres driver to one repo is a smell with no upside.
2. **SQLSTATE is first-class.** `*pgconn.PgError` carries `.Code`, so
   `errors.As` + `err.Code == "23505"` is a direct port of
   `SQLException.sqlState == "23505"` (`Users.kt:890`). No message parsing. And
   the _narrowness_ the spec insists on — 23505 matched, 23503 **not** — is
   expressible exactly, which a string match would blur.
3. **jsonb typing.** F16 (REPRODUCE, both idioms) needs `PGobject(type="jsonb")`
   and `$1::jsonb` to stay two distinguishable code paths. pgx's type map infers
   the parameter OID from the prepared statement, which is the `PGobject`
   analogue; the cast form stays a literal cast. Under `database/sql` both
   collapse into "pass a string and hope".
4. **Pool cap.** `Db.kt` sets `maximumPoolSize = 10` (read this session).
   `pgxpool.Config.MaxConns = 10` is the one-line equivalent; `database/sql`'s
   `SetMaxOpenConns` also works but pools _on top of_ pgx rather than being
   pgx's pool.

Everything else in the quote is plain SQL that any driver executes:
`ON CONFLICT … WHERE … DO UPDATE … RETURNING`, `FOR UPDATE`,
`pg_advisory_xact_lock` (`03-identity-scim.md:327` — raw SQL, explicitly _not_
an in-process mutex), `INSERT … SELECT`.

**One real porting cost.** JDBC's `?` placeholders become `$1…$n`. That is a
mechanical rewrite of every statement, and it is the single most likely place to
introduce a silent argument-order bug in the whole port. Budget review attention
there, not on the driver choice.

**Risk if wrong:** low and reversible. `pgxpool` → `database/sql` is a change of
handle type and `Query`/`Exec` signatures; the SQL text and the SQLSTATE check
are unchanged.

---

## 5. D4 — migrations, and the live-deployment path

**Capability quote** — `01-bootstrap.md:124-128`:

> a migration runner that keeps Flyway's `flyway_schema_history` table shape and
> versioned-checksum semantics `⟦LIB⟧`. **Migrating an existing deployment means
> the Go runner must read the table Flyway already wrote** — this is a hard
> compatibility constraint, not a greenfield choice.

**Candidates**

| Option                                              | History table                              | Checksums            | Verdict                                                                                         |
| --------------------------------------------------- | ------------------------------------------ | -------------------- | ----------------------------------------------------------------------------------------------- |
| `golang-migrate/migrate` v4.19.1                    | `schema_migrations(version, dirty)`        | none                 | **rejected** — cannot read Flyway's table, and has no concept of "an applied migration changed" |
| `pressly/goose` v3.27.3                             | `goose_db_version(version_id, is_applied)` | none                 | **rejected** — same                                                                             |
| Atlas                                               | `atlas_schema_revisions`                   | yes, its own format  | **rejected** — would need a translation step _and_ a new tool in the toolchain                  |
| **Hand-rolled runner over `flyway_schema_history`** | Flyway's, unchanged                        | Flyway's, recomputed | **chosen**                                                                                      |

Every library owns its own table. The constraint is the _opposite_: adopt
someone else's. A hand-rolled runner is ~200 lines and is the only option that
can satisfy it.

### What the runner must do

Reproducing `Db.migrate()` (read this session at
`control-plane/src/main/kotlin/…/gocp/Db.kt`) plus `docs/migrations.md`:

1. Read `flyway_schema_history`; the applied set is the `version` column where
   `success = true`.
2. For each shipped `V{n}__desc.sql` under `embed.FS`, apply only those above
   the recorded version, **in its own transaction**, aborting startup on failure
   (`docs/migrations.md:5-7`).
3. Honour `-- flyway:executeInTransaction=false` at the top of a file
   (`docs/migrations.md:74-77`). No shipped migration uses it today — `V1..V10`,
   verified by `ls` — but the guard is part of the contract.
4. Recompute the checksum of every already-applied migration and refuse to boot
   on a mismatch (Flyway's `validateOnMigrate`). This is the behaviour
   `.github/workflows/ci.yml:91-96` exists to protect and
   `docs/migrations.md:81-83` states as a rule.
5. `PM_DB_REPAIR_CHECKSUMS=true` rewrites the stored checksums _before_
   migrating, touching no schema or data. ⚠️ This is the **only env var read
   outside `Config.fromEnv`** (`01-bootstrap.md:50`) — REPRODUCE the seam, do
   not tidy it into `Config`.
6. Append new rows in Flyway's exact column shape so a rollback to the Kotlin
   binary still works.

### The one open technical risk: the checksum algorithm

Flyway computes a CRC32 over the migration file's _lines_, not over its bytes.
**Unverified** — I have neither a Flyway jar nor a populated history table on
this machine, and reimplementing it from recall is exactly the kind of claim
that should not be trusted.

Note also a doc/build divergence found this session:
`control-plane/build.gradle.kts:12` pins `flywayVersion = "13.0.0"`, while
`docs/migrations.md:11` says _"pins Flyway 11.1.0"_. The doc is stale, and the
checksum reimplementation must target **13.0.0**, the version that actually
wrote the rows in any recent deployment.

**Mandatory gate before this decision is considered settled:** stand up the
Kotlin stack via `docker-compose.yml`, let Flyway migrate a clean database, dump
`flyway_schema_history`, and assert the Go runner recomputes an identical
`checksum` for all ten shipped migrations. Until that test is green, the Go
runner must not be pointed at a real deployment.

**Fallback if parity cannot be reached:** a one-time translation step — a
guarded statement that rewrites the `checksum` column to Go-computed values on
first Go boot, recorded as its own decision. That preserves rule 4 going forward
while giving up the ability to roll back to the Kotlin binary without a second
rewrite. Prefer parity; keep this in reserve.

### Migration path for a live deployment

1. **Before cutover** — run the Go runner in a verify-only mode against a
   _restored copy_ of production, confirming zero pending migrations and zero
   checksum mismatches. This is the whole test.
2. **At cutover** — do **not** rely on migrate-on-boot with both binaries in the
   fleet. Flyway serialises concurrent migrators with a Postgres advisory lock
   on the history table (`docs/migrations.md:96-99`); whether the Go runner
   takes the _same_ lock key is **Unverified**, and a mismatch means two
   migrators that do not see each other. Sidestep it: add the `--migrate-only`
   entry point `docs/migrations.md:102` already notes does not exist, run
   migrations as one discrete step, then start the fleet. This also removes the
   DDL privilege from the app role.
3. **After cutover** — the table is unchanged, so a rollback to the Kotlin
   binary is a deploy, not a restore. That property is the entire reason for
   adopting Flyway's table rather than translating.

**Risk if wrong:** boot-time fail-closed in both directions. A checksum
reimplementation that is too strict refuses to start a healthy control-plane;
one that is too lax lets an edited migration through silently, which is the
guarantee `PM_DB_REPAIR_CHECKSUMS` exists to _restore_, not discard.

---

## 6. D5 — Cedar: settled, with two required mappings

**Settled by `98-cedar-spike-report.md`:** `cedar-policy/cedar-go` **v1.8.0**,
in-process, no Rust sidecar. Confirmed available and correctly shaped this
session:

```
$ go list -m -versions github.com/cedar-policy/cedar-go | awk '{print $NF}'
v1.8.0
$ ls $(go env GOMODCACHE)/github.com/cedar-policy/cedar-go@v1.8.0/x/exp/
ast  batch  dot  eval  schema  types
$ ls .../x/exp/schema/
ast  internal  resolved  schema.go  validate  ...
$ head -3 .../cedar-go@v1.8.0/go.mod
module github.com/cedar-policy/cedar-go
go 1.23.0
```

The two mappings below are **correctness constraints established by the spike,
not preferences.** Both are cases where the naive Go code compiles, passes the
ported Kotlin tests, and is wrong.

### Required mapping 1 — errors-first `toAuthzDecision` (W1)

cedar-go's `Diagnostic.Errors` is **per-policy and non-fatal**: it can return
`Allow` _and_ an error in the same response, a state cedar-java's
present-or-absent `success` payload cannot express. The spike's E10 probe,
verbatim:

```
RAW: decision=allow reasons=[policy-ok] errors=[{policy-bad: `User::"alice"` does not have the attribute `dept`}]
  errors-first mapping : Deny("authorization engine error: ...")
  verdict-first mapping: Allow
```

Replayed against the **shipped** policy set with the `Request` entity omitted —
the failure class a port is most likely to introduce — the
`system:no-self-approval` FORBID (`-2`) errors out, cedar-go drops it, and the
`system:admin` PERMIT (`-3`) stands. **A verdict-first mapping lets a
system-admin approve their own request**, which is precisely the hole
`AuthzTest` case 6 exists to keep closed.

> **any `len(Diagnostic.Errors) > 0` ⇒ Deny.** Applied in `toAuthzDecision`, at
> all five batch call sites (`Authz.kt:525,603,672,737,825`), and in
> `resolveContextTags` (INV-A2-13).

No Kotlin test pins this (the spike grepped: zero test hits for
`authorization engine error`, `denied by policy`,
`no policy permits this action`), so it is **REPRODUCE + PIN** — write the
assertion the Kotlin suite never had.

### Required mapping 2 — the two-stage IP check (W3)

`isStorableIpLiteral` is two-stage in Kotlin (character allowlist → engine
probe) and must stay two-stage in Go, even though `types.ParseIPAddr` is
stricter in most respects:

```
FAITHFUL — L1 charset allowlist + '/' range guard, then ParseIPAddr : 16/16 of DebugRequesterIpDbTest.kt:156-195
NAIVE    — delegate wholly to ParseIPAddr                           : 15/16 (accepts 100.100.1.0/24, must be 400)
```

`types.ParseIPAddr` accepts a CIDR _as a value_ (Cedar's `ipaddr` covers
prefixes); Kotlin rejects it at layer 1 because `/` is not in the allowed
character set. The one place Go's parser is **laxer** is exactly where the
allowlist is load-bearing — so "Go is stricter, collapse the layers" is wrong.

Two corollaries the spike settled and the port must carry:

- `evaluatesInCedar` does **not** survive as an authorize round-trip (its probe
  request matches no policy scope, so `len(Errors) == 0` for every parseable
  IP). It collapses to `types.ParseIPAddr`.
- **Never persist `IPAddr.String()`** — it is not round-trip safe for v4-mapped
  v6 (`::ffff:6464:010a` renders as `::ffff:100.100.1.10`, which `ParseIPAddr`
  then rejects).

### Carried from the spike as build constraints

- **Pin exactly, no range** (W6). Firewall every `x/exp` identifier into **one**
  wrapper package — proven achievable at 5 identifiers in 1 file. Note the
  decision path reaches `x/exp/ast` transitively, so the CI fingerprint gate
  must cover decisions, not just validation. Fingerprint to assert:
  `56af35d135a2649d975c9674`.
- **Cache the _resolved_ schema** (`.Resolve()` output), not the parsed AST —
  otherwise the resolve cost is paid on every `validate`.
- **`schemaFor` stays TEXT concatenation** (W4), not the elegant AST merge: the
  AST path removes the malformed-declaration rejection, which is observable
  Kotlin behaviour.
- **Reject multi-statement policy source explicitly** (W2) — `UnmarshalCedar`
  silently keeps statement 1, so `permit(…); forbid(…);` drops a security
  control at load time.

**Risk if wrong:** both mappings fail **open**. That is the whole reason they
are recorded here as constraints rather than left to the implementer.

---

## 7. D6 — HTTP router, and D7/D8 — cookies

### D6 — stdlib `net/http.ServeMux`

**Capability:** 120 routes with `{id}`-style parameters and per-group auth
gates.

**Route census, measured this session** over `control-plane/src/main/kotlin`:

```
$ grep -rhoE '\b(get|post|put|delete|patch|sse)\("/[^"]*"' --include='*.kt' | wc -l
120
   48 get   43 post   17 delete   9 put   2 patch   1 sse

$ grep -rhoE '\{[a-zA-Z]+(\?|\.\.\.)\}' --include='*.kt'
(no output)          # no optional params, no tailcards, no regex constraints
```

Every parameter is a single literal segment: `{id}` (55 uses), `{taskId}`,
`{sessionId}`, `{userId}`, `{roleId}`. The deepest shape is
`delete("/api/groups/{id}/members/{userId}")`. Go 1.22+ `ServeMux` patterns
cover this exactly — verified from the installed stdlib docs:

> A path can include wildcard segments of the form {NAME} or {NAME...} … The
> match for a wildcard can be obtained by calling Request.PathValue with the
> wildcard's name. — `go doc net/http.ServeMux`, go1.26.4

**Candidates:** stdlib `ServeMux`; `go-chi/chi/v5`; `gorilla/mux`.

**Chosen: stdlib.** Repo precedent is unanimous — `pmon/control/server.go:69`
uses `http.NewServeMux()`, and a grep for
`chi|gorilla/mux|gin-gonic|httprouter|echo.New` across
`goproxy auditmon pmon pmontray` returns no dependency hits. Method-aware
patterns give 405 with an `Allow` header for free, and conflicting-pattern
registration **panics at startup**, which turns a 120-route table into a
boot-time consistency check. chi's advantages (`Group`, `Use`, `Mount`) are
replaceable by ordinary wrapper functions — `requireApi(h)`, `requireAdmin(h)`
compose fine, and the Kotlin gates are per-route helpers already (`AGENTS.md`:
_"a route states its requirement by which gate helper it calls"_), not framework
middleware.

**Two conformance divergences to pin with tests, not to design away:**

1. **Trailing slash.** Ktor's `IgnoreTrailingSlash` plugin is **not** installed
   (grepped: no hits in `control-plane/src/main/kotlin`), so `/a` and `/a/` are
   distinct. `ServeMux` registering a pattern _ending_ in `/` creates a subtree
   match **and a 301 redirect** from the bare path. Mitigation: never register a
   trailing-slash pattern; use `{$}` where an exact match is wanted.
2. **Path cleaning and `%2F`.** `ServeMux` unescapes segment-by-segment and
   redirects unclean paths. Ktor's behaviour here is **Unverified**. Add a small
   conformance suite over `//`, `/./`, `%2F` and trailing slashes before
   trusting the route table.

**Risk if wrong:** low. Handler signatures are `http.HandlerFunc` either way, so
adopting chi later is a change to the registration file only.

### D7 — cookie encoding: hand-rolled HMAC

**Capability quote** — `01-bootstrap.md:217`: _"`⟦LIB⟧` HMAC-authenticated,
tamper-evident cookie encoding, byte-compatible with Ktor's
`SessionTransportTransformerMessageAuthentication` **if** existing browser
sessions must survive cutover."_

Five cookies, all with the same transform. Read this session at
`App.kt:476-534`: every one is
`SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray())`.
Note `SESSION_COOKIE` is backed by `webSessionStorage`, so the MAC'd value is a
server-side session **id**, not the payload; the other four carry JSON payloads.

**Candidates:** `gorilla/securecookie` v1.1.2; `crypto/hmac` + `crypto/sha256`
hand-rolled.

**Chosen: hand-rolled**, ~40 lines in one `websession` package. `securecookie`
cannot be made byte-compatible with Ktor (it has its own `value|timestamp|mac`
framing) and brings its own opinions about timestamps and rotation. Since the
only two live options are "match Ktor's bytes" or "a fresh scheme", a library
that can do neither adds a dependency and forecloses the first.

### D8 — byte-compatibility with Ktor: **DEFER**

`01-bootstrap.md:494` Q3 asks it directly, and `00-INDEX.md:38` lists cookie
compatibility as a DEFER, not a defect. What it costs each way:

| Choice              | Cost                                                                                                                                                                                                                                                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Byte-compatible** | Must reproduce Ktor's exact framing and MAC encoding. ⚠️ The exact wire format is **Unverified here** — there is no Ktor jar and no `~/.gradle/caches` on this machine (checked). Settling it means reading `ktor-server-sessions`' source. Also freezes the format forever: a scheme chosen to match a framework the port is deleting. |
| **Fresh scheme**    | Every logged-in browser session is invalidated at cutover — one forced re-login, at a moment when the operator most wants a quiet deploy. The four short-lived cookies (300s/600s TTLs) are harmless; only `SESSION_COOKIE` is user-visible.                                                                                            |

**What would settle it:** ask whether cutover is allowed to log everyone out. If
a maintenance window exists, take the fresh scheme — it is strictly less code
and less frozen surface. Whichever is chosen, the four short-TTL cookies can
always use the fresh scheme regardless.

---

## 8. D9 — JSON codec: stdlib plus discipline

**Capability quote** — `01-bootstrap.md:186`, on
`Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }`:

> For a Go port this reduces to: **omit optional fields entirely, always emit
> empty slices as `[]`.** Naive `encoding/json` gives the opposite of both by
> default (`omitempty` drops empty slices; absent pointers marshal as `null`).
> Every DTO needs deliberate tags, and this needs a conformance fixture.

This is not a library choice — no Go JSON library flips both defaults — it is a
**discipline plus a test**. `encoding/json` it is, with three rules:

1. Optional field ⇒ `*T` with `json:",omitempty"` (a nil pointer is then
   _absent_, not `null`). Required by the MCP TypeScript SDK's Zod schemas,
   which model optional protocol fields as `.optional()`, never `.nullable()` —
   INV-A1-4 records that explicit nulls made every `claude mcp login` fail with
   a bare client-side `invalid_union`.
2. Slice field ⇒ **never** `omitempty`, and initialise to `[]T{}` not `nil`, so
   it marshals `[]` not `null`. The UI relies on
   `effectiveRoles[]`/`rows[]`/`columns[]` being present arrays.
3. Unknown keys on input are ignored — Go's default. No action.

Note the deliberate exception at `04-auth-session-tokens.md:397`: cookie
payloads use the **bare** Kotlin `Json` default, so `explicitNulls` is **true**
inside cookies. INV-A1-4 does not apply there. REPRODUCE the asymmetry.

**Risk if wrong:** silent and wide. A single `omitempty` on a slice breaks a UI
table; a single non-pointer optional emits `null` where the MCP client expects
absence. The conformance fixture the spec asks for is not optional — build it in
Increment 1 alongside the shared DTOs.

---

## 9. D11 / D10 / D17 — i18n, embedded resources, constant-time compare

### D11 — i18n bundles

**Capability quote** — `11-mcp-oauth-management.md:238`: _"A Go port needs the
two `.properties` bundles … carried over — **6 resource bundles**, currently JVM
`ResourceBundle`. `⟦LIB⟧` i18n message loading."_ Q5 adds: _"note `mcp_tools`
descriptions are part of the MCP tool contract, so they are wire-visible."_

**Candidates:** `nicksnyder/go-i18n/v2` v2.6.1; `golang.org/x/text/message` +
`gotext`; `embed.FS` + a hand-written reader.

**Chosen: hand-written**, and the deciding fact is the placeholder syntax.
Inspected this session:

```
$ head -3 control-plane/src/main/resources/mcp_errors_en.properties
common.not_found=No such {resource}.
common.field_required={fields} required.
common.already_exists=This {resource} already exists.
$ head -1 control-plane/src/main/resources/mcp_errors_ko.properties
common.not_found={resource} 항목을 찾을 수 없습니다.
```

Those are **named** placeholders, not `java.text.MessageFormat`'s `{0}`.
`go-i18n` wants `{{.Name}}` in TOML/JSON/YAML; `x/text` wants printf verbs.
Either means rewriting all 128 lines into a new syntax — and `mcp_tools` text is
on the MCP wire, so a rewrite is a wire change dressed up as a refactor.

The files are trivially parseable: 6 files, 128 lines total, plain `key=value`,
raw UTF-8 Korean, and verified free of backslash escapes and `\uXXXX` sequences
(`grep -c '\\\\'` → 0 on all six; `grep -l '\\u'` → none). So: `embed.FS` + ~30
lines of `key=value` reader + a `{name}` interpolator. Keeping the six files
byte-for-byte also means they stay diffable against the Kotlin during cutover,
which is worth more than any library feature here.

### D10 — embedded resources

`13-engine.md:1080` asks for _"a compile-time-embedded read-only resource
bundle"_ for the four system-classification manifests. `embed.FS`, stdlib. Two
constraints from the same section:

- **INV-A13-30** — the bundle checksum is over `BUNDLED.sorted()` order and over
  the **raw file text**. Sort the same way or every deployment's logged checksum
  changes.
- Compile-time embedding makes a missing manifest a _build_ error rather than a
  runtime one. That is a strengthening, so **keep the runtime check anyway** for
  the `of`-style path.

### D17 — constant-time compare

`03-identity-scim.md:950` states the divergence precisely: _"Java's
`MessageDigest.isEqual` folds the length difference into the accumulator,
whereas Go's `crypto/subtle.ConstantTimeCompare` returns 0 immediately on a
length mismatch — a length oracle the Kotlin does not have."_

**Chosen: `crypto/subtle`**, over fixed-size SHA-256 digests of both inputs
rather than the raw strings. That removes the length oracle at the cost of one
hash per comparison, and it keeps `ConstantTimeCompare`'s contract intact
(equal-length inputs). This is one of the few places the port does _not_
faithfully reproduce a JVM implementation detail — but the behaviour reproduced
is the _absence of a side channel_, which is what the Kotlin actually has.
Record it as a deliberate divergence in the code comment, not as an improvement.

---

## 10. Deferred, with what settles each

| #                | Decision                          | Why deferred                                                                                                      | What settles it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **D8**           | Ktor cookie byte-compatibility    | Product question, not technical                                                                                   | Answer "may cutover log every browser session out?" If yes → fresh scheme. Also requires reading `ktor-server-sessions`' source, which is not available on this machine.                                                                                                                                                                                                                                                                                                                                             |
| **D14 (wiring)** | JWT/JWKS implementation           | Belongs to the A14 increment; the _library_ is decided, the code is not                                           | Build `IdTokenValidator` against `go-jose/v4`. **Constraint already fixed:** no JWKS cache, no TTL, no retry — F61/F62 are REPRODUCE, so `coreos/go-oidc`'s `RemoteKeySet` is disqualified by its caching, not by its quality.                                                                                                                                                                                                                                                                                       |
| **D18**          | MCP SDK                           | Two blocking unknowns                                                                                             | `11-mcp…:591` Q7 — does `github.com/modelcontextprotocol/go-sdk` v1.7.0's `StreamableHTTPHandler` support **per-request server construction** (the stateless model the Kotlin mount depends on), and does its DNS-rebinding guard have the same HTTP/2 problem as INV-A11-4? Plus `01-bootstrap.md:496` Q4 — **if the Go SDK's handler does not install SSE, the port must supply SSE itself for `/api/tasks/events`.** Ktor's mount installs it unconditionally, which is why `App.kt:464` deliberately does _not_. |
| —                | `PM_DB_URL` shape                 | `01-bootstrap.md:488` Q1 — keep the `jdbc:postgresql://` prefix and translate internally, or change the contract? | Cheap to defer: translation is a five-line rewrite in `Config`. Changing the contract touches `deploy/`, `docker-compose.yml`, `mise.toml:58`, and every deployed environment — so **translate for now**, decide later.                                                                                                                                                                                                                                                                                              |
| —                | `CedarValidateResult.errors` text | Spike W8                                                                                                          | Go's parse-error text differs from cedar-java's on every parse error (semantic text is byte-identical). Zero CI coverage, but `web/`'s policy editor renders it verbatim. **Ask `web/`.**                                                                                                                                                                                                                                                                                                                            |
| —                | Flyway checksum parity            | Cannot be measured on this machine                                                                                | The docker-compose gate in §5. Until it is green, do not point the Go runner at a real deployment.                                                                                                                                                                                                                                                                                                                                                                                                                   |

---

## 11. Verification log

Every command below was run this session, in
`/Users/donggyukim/ClaudeProjects/ridi/proxy-monster/.claude-wt/go-cp-prototype`
unless noted.

| Claim                           | Command                                                                                                                 | Result                                                                                                                                        |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Toolchain                       | `export PATH=…/go/1.26.4/bin:$PATH; go version`                                                                         | `go1.26.4 darwin/arm64`                                                                                                                       |
| Module convention               | `cat go.work; head -1 goproxy/go.mod analyzer/go.mod`                                                                   | 6 modules, single-word dirs, `…/proxy-monster/<name>`                                                                                         |
| Workspace build list is unified | `go list -m github.com/jackc/pgx/v5`                                                                                    | `v5.7.1` (goproxy's require, resolved workspace-wide)                                                                                         |
| ″                               | `go list -m github.com/testcontainers/testcontainers-go`                                                                | `v0.34.0`                                                                                                                                     |
| goproxy's driver                | `grep -rn 'jackc/pgx' goproxy --include='*.go'`                                                                         | 20 hits: `pgx/v5/stdlib`, `pgconn`, `pgproto3`                                                                                                |
| No third-party router in repo   | `grep -rn 'chi\|gorilla/mux\|gin-gonic\|httprouter\|echo.New' goproxy auditmon pmon pmontray --include='*.go'`          | no dependency hits                                                                                                                            |
| stdlib mux precedent            | `grep -rn 'http.NewServeMux' pmon auditmon --include='*.go'`                                                            | `pmon/control/server.go:69`                                                                                                                   |
| Route count                     | `grep -rhoE '\b(get\|post\|put\|delete\|patch\|sse)\("/[^"]*"' control-plane/src/main/kotlin --include='*.kt' \| wc -l` | **120**                                                                                                                                       |
| No exotic route params          | `grep -rhoE '\{[a-zA-Z]+(\?\|\.\.\.)\}' control-plane/src/main/kotlin --include='*.kt'`                                 | no output                                                                                                                                     |
| No `IgnoreTrailingSlash`        | `grep -rn 'IgnoreTrailingSlash' control-plane/src/main/kotlin`                                                          | no output                                                                                                                                     |
| ServeMux pattern support        | `go doc net/http.ServeMux`                                                                                              | documents `METHOD /path/{name}` + `PathValue`                                                                                                 |
| proto imports                   | `grep -n '^import' proto/src/main/proto/controlplane.proto`                                                             | `engine.proto`, `google/protobuf/empty.proto`                                                                                                 |
| engine.proto already generated  | `ls analyzer/probe/pb/`                                                                                                 | `analyzer.pb.go`, `engine.pb.go`                                                                                                              |
| Codegen tool versions           | `head -4` on the three committed `*.pb.go`                                                                              | protoc-gen-go **v1.35.2**, protoc-gen-go-grpc **v1.5.1**                                                                                      |
| buf not installed               | `which buf protoc-gen-go protoc-gen-go-grpc`                                                                            | all three "not found"                                                                                                                         |
| cedar-go version                | `go list -m -versions github.com/cedar-policy/cedar-go`                                                                 | latest is **v1.8.0** — matches the spike exactly                                                                                              |
| cedar-go layout                 | `ls $(go env GOMODCACHE)/…/cedar-go@v1.8.0/x/exp/{,schema/}`                                                            | `schema`, `schema/validate`, `schema/resolved`, `types`, `ast` present; `go 1.23.0`                                                           |
| Flyway version drift            | `grep -n flywayVersion control-plane/build.gradle.kts` vs `docs/migrations.md:11`                                       | build says **13.0.0**, doc says 11.1.0                                                                                                        |
| Migration set                   | `ls control-plane/src/main/resources/db/migration/`                                                                     | `V1__…` … `V10__…`, ten files                                                                                                                 |
| Cookie transform                | `App.kt:476-534`                                                                                                        | five cookies, all `SessionTransportTransformerMessageAuthentication(sessionSecret.toByteArray())`                                             |
| No Ktor jar available           | `ls ~/.gradle/caches`; `find / -name 'ktor-server-sessions*jar'`                                                        | no such directory; no output                                                                                                                  |
| Bundle format                   | `head` + `grep -c '\\\\'` + `grep -l '\\u'` over the six `.properties`                                                  | named `{param}` placeholders, raw UTF-8, **zero** escapes                                                                                     |
| Candidate library versions      | `go list -m -versions` ×10                                                                                              | goose v3.27.3 · golang-migrate v4.19.1 · go-jose/v4 v4.1.4 · go-oidc/v3 v3.20.0 · mcp go-sdk v1.7.0 · go-i18n/v2 v2.6.1 · securecookie v1.1.2 |

**Kotlin read to resolve ambiguity** (per the brief, declared):
`control-plane/.../Db.kt` (whole file — the spec's Flyway description needed the
actual `repair()`/`migrate()` order and the `System.getenv` seam),
`App.kt:466-534` (the five cookie declarations — the spec named the transformer
but not which cookies are storage-backed), and
`control-plane/build.gradle.kts` + `auth/build.gradle.kts` (dependency versions,
to name the capabilities being replaced: nimbus-jose-jwt 9.40, HikariCP 7.1.0,
Flyway 13.0.0, cedar-java 4.3.1, MCP kotlin-sdk 0.10.0).

---

## 12. What Increment 1 should now do

1. `gocp/go.mod` — module path per D1, `go 1.26.0`, a prose header saying why
   the module exists and that `control-plane/` is still live.
2. `go.work` — insert `./controlplane` in alphabetical position (after
   `./auditmon`).
3. `mise.toml` — add `controlplane` to the `verify` `go test` list **and** the
   `test-go` loop.
4. `gocp/buf.gen.yaml` — exactly as §3.3, with the tool versions in the header
   comment. Do not run it yet; A10 owns the generation.
5. Requires: `cedar-go v1.8.0` and `pgx/v5 v5.7.1`, nothing else. Expect
   `go-cmp` to move v0.6.0 → v0.7.0 workspace-wide; call it out in the result
   summary.
6. Firewall `x/exp` behind one wrapper package from the very first Cedar commit
   — retrofitting a firewall after the identifiers have spread is the expensive
   version of W6.

---

## 13. Increment 4 — A4/A14 OIDC + device authorization

**Date:** 2026-08-02 · **Packages:** `internal/oidc`, `internal/device` ·
**Spec:** `04-auth-session-tokens.md` §1.1/§2.1/§3.7/§6, `14-auth.md` §6.

### 13.1 D14 wiring — RESOLVED. `go-jose/v4` v4.1.4, added.

§10 deferred D14's _wiring_ to this increment ("the library is decided, the code
is not"). It is now wired, and the library choice is confirmed rather than
revisited:

```
$ go get github.com/go-jose/go-jose/v4@v4.1.4
go: added github.com/go-jose/go-jose/v4 v4.1.4
```

Three capabilities were needed and `go-jose/v4` covers exactly them, with
nothing extra:

| Capability                   | `go-jose/v4`                                                                                                                                                                                                                | Reproduces                                                                          |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| single-algorithm PINNING     | `jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})` — the permitted set is a **parser argument**, so `alg:none`, an HS256 algorithm-confusion token and ES256/PS256 are all refused **before** a key is selected | `JWSVerificationKeySelector(JWSAlgorithm.RS256, …)` (`auth/Oidc.kt:72`), INV-A14-30 |
| JWKS parse + `kid` selection | `jose.JSONWebKeySet` + `.Key(kid)`                                                                                                                                                                                          | Nimbus's `JWKMatcher`-from-header                                                   |
| remote JWKS fetch            | **NOT used** — hand-written, per D14                                                                                                                                                                                        | `RemoteJWKSet`, F36                                                                 |

🔒 **The fetch is hand-written on purpose, and that is the whole reason
`coreos/go-oidc` stays disqualified.** Its `RemoteKeySet` caches keys and
retries; F36 requires the _opposite_ — a fetch on **every** validation, because
the Kotlin constructs `RemoteJWKSet(URL(...))` per call and throws the cache
away with it. A rotated key therefore takes effect _immediately_ in both, where
a caching port would lag by its TTL.
`internal/oidc.TestValidate_F36_JWKSIsRefetchedEveryCall` asserts exactly three
fetches over three validations, and asserts in the same test that the
**discovery document** is fetched exactly **once** (F35) — the two caching
behaviours are deliberately opposite, and pinning them together is what stops a
later "consistency" refactor from unifying them.

**Claim checks are hand-written too**, and not because go-jose lacks
`jwt.Claims.Validate`: the Kotlin's semantics are not the library-default ones.
See 13.2.

### 13.2 F43 — RESOLVED against the Kotlin source. `aud` is EXACT-MATCH.

14-auth.md carried this as a `Hypothesis` with "Resolve before porting — Q11,
coverage gap 13, F43". Read this session at
`auth/src/main/kotlin/com/ridi/oss/proxymonster/auth/Oidc.kt:73-76`:

```kotlin
jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
    JWTClaimsSet.Builder().issuer(issuer).audience(clientId).build(),
    setOf("exp"),
)
```

That is the **two-argument** `(exactMatchClaims, requiredClaims)` constructor.
The three-argument overload — the one taking an `acceptedAudience` and doing a
_contains_ check — is not used. With `.audience(clientId)` stored as a
one-element `List<String>` and no accepted-audience, `aud` is just another
exact-match claim compared with `equals()`, i.e. `List.equals`.

**Consequence, and it REPRODUCES in Go:** an `id_token` carrying
`aud: ["<clientId>", "<other>"]` — which Okta and Entra _do_ emit when a second
resource is requested — is **REJECTED**. A Go port written with the idiomatic
`slices.Contains(aud, clientID)` would **accept** it: a _widening_ divergence on
an authentication path. `audienceMatches` therefore compares for exact
single-element equality (a bare string `aud` is normalised to a singleton first,
as every JWT parser does), and `TestValidate_F43_MultiAudienceTokenIsRejected`
pins all four sub-cases.

⚠️ **Still `Unverified` in one respect, stated so it is not read as settled:**
nimbus-jose-jwt 9.40's jar is _still_ absent from this machine —
`find / -name 'nimbus-jose-jwt*.jar'` returned nothing this session, the same
result 14-auth.md recorded — so the constructor semantics above are read off the
library's documented contract plus the call site, not off its bytecode. The
Kotlin suite does not decide it either (`IdTokenValidatorTest.kt:83` defaults
`audience = clientId`; case 4 tries only a _wrong single_ audience — coverage
gap 13). **The Go test is now the port's own oracle for this behaviour, and
04/14's Q11 stays open** until someone runs the Kotlin suite with a
multi-audience token. If the product decides multi-audience must be accepted,
that is a deliberate change on **both** sides, not a Go-side fix.

### 13.3 Clock skew — made EXPLICIT rather than inherited.

`MaxClockSkew = 60s`, with a **strict** comparison (`exp > now − skew`). D14's
instruction was "set the Go verifier's leeway explicitly rather than inheriting
a library default", and this is that. The value is not arbitrary:
`IdTokenValidatorTest.kt:146` builds its expired token with
`expiresInSeconds = -60` and requires it to FAIL, which holds only for a skew ≤
60s under a strict comparison — 60s is the single value consistent with the
frozen assertion. Nimbus's own default remains `Unverified` (no jar).

### 13.4 HTTP client — D15 confirmed, with one recorded deviation.

`NewHTTPClient()` is `&http.Client{Timeout: 0}`. The zero timeout is
**load-bearing, not an oversight**: F38 records that `oidcHttpClient()` installs
no `HttpTimeout` plugin, so a hung IdP stalls whatever is fetching. Deadlines
come from `context.Context` at every call site instead.

⚠️ **DEVIATION (not a port):** responses are read through
`io.LimitReader(…, 1 MiB)`. ktor streams without a cap; Go's `io.ReadAll` on an
outbound third-party response is an attacker-controlled memory-exhaustion
primitive. The cap is far above any real discovery document, JWKS or token
response, so no legitimate response is affected — recorded rather than hidden.

### 13.5 Cookies — NO new decision. D7/D8 stand, and this increment adds no second codec.

`internal/session` (A4) owns all six cookies: names, payload DTOs, lifetimes and
the HMAC codec, with D8's "cutover logs every browser session out" decision
recorded there. `internal/oidc` re-exports the three OIDC/device payload types
as **Go type aliases** so its API reads like `control-plane/Oidc.kt` (where
those three are declared) while there remains exactly **one** definition and
**one** wire encoding. A second codec for `pm_oauth_state` would be two
independently-evolving encodings of one browser cookie: a login written by one
and read by the other fails authentication, and the symptom is "SSO stopped
working" with no error anywhere.

### 13.6 Dependency budget after this increment

One new direct require:

```
github.com/go-jose/go-jose/v4 v4.1.4     # D14, D16 (the fake IdP's signer is the same dep, test scope)
```

D16 is satisfied without a second dependency: `internal/oidc`'s fake IdP signs
its test tokens with `jose.NewSigner`. The one exception is the
algorithm-confusion payload, which is hand-rolled — go-jose refuses to _sign_
with a key type that mismatches the algorithm family, which is precisely the
behaviour under test on the _verify_ side.
