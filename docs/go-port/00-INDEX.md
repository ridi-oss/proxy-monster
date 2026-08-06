# proxy-monster control-plane → Go: Specification Index

Step 1 deliverable. A behavioural specification of the Kotlin control-plane,
written so that Step 2 (Go prototype) can be implemented **without reading the
Kotlin source**, and Step 3 (1:1 test migration + TDD hardening) has an
enumerated test-case inventory to work from.

Status: **COMPLETE.** All 14 area docs written, cross-checked, and reconciled.
`01-bootstrap.md` and `02-authz.md` define the format; `12-request-context.md`
is the MEDIUM exemplar.

**Read `99-reconciliation-report.md` alongside this file.** It holds the
verified case/LOC ledger, the cross-area contradictions, and the full
**106-finding** list (F2–F125) — none of which fits here.

**Read `96-traceability.md` before writing or reviewing a ported test.** Step 3
is only auditable if each of the 903 Kotlin cases maps to a named Go test, so a
Go test declares its origin with a `KT:` marker and
`gocp/internal/tracing/coverage_test.go` enforces it inside `go test ./...`.
That doc holds the authoritative counting method, the case-identity format, the
marker rules, the ratchet procedure, and — importantly — the mechanical
shortcuts that were **falsified** and must not be reused.

## PORT POLICY — bug-for-bug fidelity (binding, decided 2026-08-01)

**The Go port reproduces the Kotlin control-plane's observable behaviour
exactly, including its defects. Nothing on the finding list is fixed during the
migration.** Each defect is reproduced, documented, and its fix recorded as a
**separate decision, taken before or after cutover but never as part of it.**

Three reasons this is the right default, not laziness:

1. **It is what makes differential conformance possible.** The harness plan
   compares Kotlin and Go responses on the same input. Every behaviour the Go
   side "improves" turns into a diff you must triage — so a port that fixes 20
   bugs produces 20 false positives indistinguishable from 20 real regressions,
   precisely on the paths that were already fragile.
2. **It decouples two risks that must not be coupled.** "Did we port this
   correctly?" and "is this new behaviour correct?" have different reviewers,
   different tests, and different blast radii. Answer them one at a time.
3. **A fix made during the port is unreviewable.** The diff is an 18,000-line
   rewrite; a behaviour change inside it is invisible. The same change against a
   working Go service is a ten-line reviewable PR.

### Disposition vocabulary — every finding gets exactly one

| Disposition         | Meaning                                                                                                                                                        | Applies to                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **REPRODUCE**       | Port the behaviour as-is, defect included. Add a doc comment saying it is a known defect and pointing at the finding id. _This is the default._                | every behavioural finding                                                       |
| **REPRODUCE + PIN** | Reproduce, **and write a test asserting the buggy behaviour.** A later fix then has to change that test deliberately and visibly, instead of silently passing. | findings on a security or data path — F22, F23, F24, F26, F33, F42              |
| **OMIT**            | Do not port. Legitimate **only** where there is no observable behaviour to preserve.                                                                           | dead code; JVM-implementation artifacts                                         |
| **DEFER**           | Not a defect — a genuine design question the port must not settle unilaterally.                                                                                | cookie compatibility, `PM_DB_URL` shape, Flyway table, discovery channel-parity |

### The OMIT boundary — the only thing that is not ported

**Observable behaviour is reproduced. Non-observable implementation artifacts
are not.** Two categories qualify, and nothing else does:

- **Dead code** — no call path, therefore no observable behaviour. Not porting
  it changes nothing. (`CedarPolicyStore.insertReturningId`, `decideQuery`'s
  unused `accessStore` parameter, `Users.kt`'s `queryOne`/4-arg `deleteUser`, …)
  ⚠️ **Caveat:** several "dead" symbols are live _test_ fixtures
  (`setUserActive` is used by nine suites across five areas; `find…ByExternalId`
  by three). Those need a test-visible equivalent in Go or the suites need
  rewriting — OMIT does **not** mean "delete and move on".
- **JVM artifacts** — `closeConnectionCatalog`'s `runBlocking` wrapper (a JDK
  verifier workaround), the FFM binding, `analyzer/jvm`, Kotlin/Java protobuf
  codegen. These exist because of the runtime, not because of the contract.

⚠️ **Explicitly NOT grounds for OMIT:** inefficiency (F8's O(n) lookup),
duplication (F18's three CIDR implementations, F16's two JSON idioms),
inconsistency (F14's hand-rolled transaction), or ugliness. Those are all
**REPRODUCE** — they are observable or they are refactors, and a refactor during
a port is a fix during a port.

### Docs corrected to match

Roughly fifteen places said "fix in the port" / "unify in the port" /
"inefficiency to fix, not replicate". Those predate this policy and are being
swept to the vocabulary above. Where a doc still says "fix", **this section
wins.**

## Why this document exists

`AGENTS.md:110-116` states the control-plane has **no API reference and no
OpenAPI spec** — "the routes are the surface and the `@Serializable` Kotlin data
classes in each owning file are the request/response reference." The Kotlin
implementation _is_ the specification today. Since the goal includes deleting
it, that specification has to be extracted into a form that survives the
deletion.

## Scope

`:control-plane` cannot be ported alone. `:engine` and `:auth` are consumed
**only** by `:control-plane` (verified:
`grep 'project(":engine")\|project(":auth")'` across all `build.gradle.kts` —
`control-plane/build.gradle.kts:23-24` is the sole consumer of each), so they
migrate with it. `:analyzer:jvm` is deleted rather than ported: it is an FFM
binding to a Go c-shared library, and a Go control-plane imports
`analyzer/probe` directly.

| Module                         | Main LOC   | Test LOC               | Disposition                                                        |
| ------------------------------ | ---------- | ---------------------- | ------------------------------------------------------------------ |
| `control-plane/`               | 16,684     | 26,325 (847 cases)     | **port**                                                           |
| `engine/`                      | 804        | 668 (56 cases)         | **port** (partly already twinned — see below)                      |
| `auth/`                        | 691        | 0                      | **port**                                                           |
| `analyzer/jvm/`                | 342        | (in module)            | **delete** — Go calls `analyzer/probe` natively                    |
| `proto/` (Kotlin/Java codegen) | 24         | 0                      | **delete** — replaced by buf → Go stubs, as `goproxy` already does |
| **Total to port**              | **18,179** | **26,993 (903 cases)** | 121 test files                                                     |

### Already twinned in Go (do not re-derive)

| Kotlin                                     | Existing Go                   | Evidence                                                                                                                                                                                              |
| ------------------------------------------ | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AuditCanonical.kt` (129)                  | `auditmon/canon/canonical.go` | `canonical.go:1-9` — "Go re-implementation … byte-for-byte agreement … frozen by a shared golden-vector suite"; `canon/canonical_test.go:90` reads control-plane's own `atrail/canonical-golden.json` |
| `engine/probe/Masking.kt`, `Masks.kt` (48) | `goproxy/engine/masking.go`   | `docs/backlog.md:374-379` flags these as hand-maintained byte-identical twins                                                                                                                         |
| `engine/probe/Sqlglot.kt` + `analyzer/jvm` | `analyzer/probe` (Go, direct) | `analyzer/go.mod` — already a Go module                                                                                                                                                               |

## Area map

Twelve areas. LOC sums to 16,684 exactly.

| #   | Area                            | Files                                                                                                                                                       | LOC   | Spec                               | Cases     | Risk                   |
| --- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ---------------------------------- | --------- | ---------------------- |
| A1  | Bootstrap, config, shared types | `Main` 69, `App` 785, `Config` 307, `ControlPlaneCore` 54, `Db` 48, `ApiErrors` 58, `Decision` 46                                                           | 1,367 | ✅ `01-bootstrap.md`               | **34**    | med                    |
| A2  | Authz / Cedar                   | `authz/Authz` 915, `authz/CedarEngine` 217, `authz/CedarPolicyStore` 320                                                                                    | 1,452 | ✅ `02-authz.md`                   | 90        | **high**               |
| A3  | Identity, users, SCIM           | `Users` 1031, `Scim` 594, `Deprovision` 106, `RoleResolver` 94                                                                                              | 1,825 | ✅ `03-identity-scim.md`           | **98**    | med                    |
| A4  | Auth, session, tokens           | `DaemonSession` 802, `DeviceAuth` 408, `Tokens` 328, `Oidc` 235, `Auth` 109, `PrincipalSessionStorage` 28, `OidcHttp`/`OidcDiscovery`/`IdTokenValidator` 11 | 1,921 | ✅ `04-auth-session-tokens.md`     | **110**   | **high**               |
| A5  | Datasources, catalog            | `Datasources` 967, `ConnectionCatalog` 532, `Engines` 173, `SystemClassificationService` 160, `TableDetailExec` 158, `ConnectionDecide` 157                 | 2,147 | ✅ `05-datasources-catalog.md`     | **69**    | med                    |
| A6  | Query decision path             | `Query` 1237, `Access` 713                                                                                                                                  | 1,950 | ✅ `06-query-decision.md`          | **183**   | **high**               |
| A7  | Tasks, approvals, results       | `Approvals` 887, `RunExec` 655, `QueryResultStore` 289, `QueryHistory` 76, `TaskCompletionHub` 61, `ResultCrypto` 45                                        | 2,013 | ✅ `07-tasks-approvals-results.md` | 71        | **high**               |
| A8  | Audit                           | `AuditStore` 191, `AuditCanonical` 129, `AuditRoutes` 67                                                                                                    | 387   | ✅ `08-audit.md`                   | 18        | low (twinned)          |
| A9  | Roles, assignments, mask fns    | `Policies` 242                                                                                                                                              | 242   | ✅ `09-policies.md`                | **0** ⚠️  | low code, **no tests** |
| A10 | gRPC surface                    | `grpc/ControlPlaneGrpcService` 594, `grpc/GrpcServer` 77, `grpc/GrpcMappers` 44, `grpc/SecretTokenInterceptor` 42                                           | 757   | ✅ `10-grpc.md`                    | **104**   | med                    |
| A11 | MCP, OAuth AS, management       | `mcp/McpServer` 766, `management/ManagementServices` 732, `oauth/OAuthRoutes` 411, `oauth/Cimd` 191, `management/McpCapabilityRegistry` 136                 | 2,236 | ✅ `11-mcp-oauth-management.md`    | **18** ⚠️ | **high**               |
| A12 | Request context                 | `RequesterIp` 251, `ProxyEventsHub` 136                                                                                                                     | 387   | ✅ `12-request-context.md`         | 39        | med (upgraded)         |

| A13 | `engine/` module | `SystemClassifier` 183, `SystemClassificationStore`
157, `CatalogApi` 118, `TableDetail` 82, `SystemManifest` 68,
`BaselineDangerousFunctions` 59, `Sqlglot` 52, `SqlNormalize` 34, `Masks` 26,
`Masking` 22, `Dialect` 3 | 804 | ✅ `13-engine.md` | **56** | med | | A14 |
`auth/` module | `McpOAuth` 480, `Oidc` 126, `OidcDirectoryProvisioner` 85 | 691
| ✅ `14-auth.md` | **13** | med |

## ✅ Reconciled ledger — Step 1 COMPLETE

**18,179 LOC · 903 cases · 14 docs · 13,940 lines of specification.**

| A1  | A2  | A3  | A4  | A5  | A6  | A7  | A8  | A9  | A10 | A11 | A12 | A13 | A14 | Σ          |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---------- |
| 34  | 90  | 98  | 110 | 69  | 183 | 71  | 18  | 0   | 104 | 18  | 39  | 56  | 13  | **903** ✅ |

Verified this session:
`grep -rhoE '@Test\b' --include='*.kt' control-plane/src/test | wc -l` → 847;
same over `engine/src/test` → 56; total **903**. Main LOC: 16,684 + 804 + 691 =
**18,179**, all 52 control-plane main files assigned exactly once, 0 unassigned,
0 double-assigned.

### How the ledger closed — four corrections, and why they nearly cancelled

The first pass summed to **904**, which looked like a single off-by-one. It was
two errors pulling in opposite directions, worth **21 cases** in total:

|                | Suite                    | Cases | Was            | Now                                                                                                                                                            |
| -------------- | ------------------------ | ----- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| double-counted | `OidcGroupMappingTest`   | 7     | A3 **and** A14 | **A14** — the symbol is `auth/Oidc.kt:103`, reached from the CP only via a typealias at `Config.kt:6`                                                          |
| double-counted | `TokenTtlTest`           | 4     | A4 **and** A14 | **A4** — `TokenTtlTest.kt:14-15` uses `DEFAULT_USER_TTL_SECONDS`/`SESSION_TTL_SECONDS`, declared **only** at `Tokens.kt:77-78`, absent from `auth/McpOAuth.kt` |
| unassigned     | `MePermissionsRouteTest` | 7     | nobody         | **A1** — both symbols under test are in `App.kt` (`:293`, `:255`)                                                                                              |
| unassigned     | `SchemaKeyWiringTest`    | 3     | nobody         | **A6** — drives `Query.kt:213,236,230`; its cases 2–3 are the only direct test of A13's analyzer-key injectivity                                               |

`904 − 11 double-counted + 10 unassigned = 903.` ⚠️ **A near-correct total is
the dangerous case** — it invites rounding away rather than auditing. Always
decompose, never adjust.

Two test-LOC headlines were also wrong and are fixed: A6 claimed 4,833 (actual
**4,730**), A7 claimed 2,432 while its own body summed to **2,489**.

⚠️ **Also note:** A14's 302 test LOC, A3's 51 and A4's 35 are _subsets_ of
control-plane's 26,325 — `auth/src/test` does not exist. Never add them on top.
`support/` (915 LOC, 0 cases) is owned by no area.

**Test density varies 11×** and that is itself a planning input:

| Area                         | LOC/case | Reading                          |
| ---------------------------- | -------- | -------------------------------- |
| A6 query decision            | 11       | exhaustively specified by tests  |
| A2 authz                     | 16       | ditto                            |
| A7 tasks/approvals           | 28       | well covered                     |
| A12 request context          | 10       | well covered                     |
| A1 bootstrap                 | 51       | config covered, plumbing not     |
| **A11 MCP/OAuth/management** | **124**  | ⚠️ thin — 732 LOC of it untested |
| **A9 roles/mask-fns**        | **∞**    | ⚠️ zero tests                    |

Where density is low, Step 3's 1:1 migration provides little signal and new
tests are required. The `tbd` column fills in as each area is specified; the
per-area sums must reconcile to 903, which is the completeness check on this
inventory.

Depth deviations from the risk weighting, with reasons:

- **A12 upgraded LIGHT → MEDIUM.** It holds the repo's only anti-spoof
  invariant, three security gates depend on one function (`isTrustedEdge`), and
  it carries 39 cases. Four of its five coverage gaps sit exactly where Go's IP
  library differs from Java's.
- **A9 stays LIGHT on code but needs new tests, not ported ones** — it has zero.

## Cross-area findings

Things worth acting on independently of the port. Maintained as areas are
specified.

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Where                                          | Kind                   |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ---------------------- |
| F1      | `AuthzResource.Datasource` documented but does not exist                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Authz.kt:756`                                 | stale doc              |
| F2      | `insertReturningId` private and never called                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `CedarPolicyStore.kt:229`                      | dead code              |
| F3      | Purge-loop step order is load-bearing and untested; reversing it makes expired editor result rows linger forever, payload-stripped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `App.kt:413-418`                               | untested invariant     |
| F4      | Marshalling an _unclassified_ utility or function inverts its decision from deny to **allow**; the upstream hard-deny is the only thing preventing it. **Utility half IS covered** (`UtilityGateDbTest` case 2, found while specifying A6); the **function** half — `authorizeFunctions` with an unclassified name — is still untested                                                                                                                                                                                                                                                                                                                                                                                            | `Authz.kt:626,697`                             | 🔒 partly untested     |
| ~~F5~~  | ~~`GET /api/roles` is `requireApi` while every sibling route is admin-gated~~ — **RESOLVED: deliberate and load-bearing.** `web/src/lib/hooks.ts:131` `useRoles()` is consumed by two **non-admin** surfaces: `components/query/request-access-dialog.tsx:58` and `components/workflows/role-request-composer.tsx:51` — where an ordinary user picks the role R to request elevation to. Tightening this to `requireAdmin` would break JIT elevation for every non-admin, i.e. the product. The MCP asymmetry is also correct: `list_roles` is an admin _management_ tool, so `ADMIN_POLICIES` fits there. Two gates because two callers with different legitimate needs. **Preserve both exactly**; add a doc comment saying why | `Policies.kt:155`                              | closed — by design     |
| ~~F6~~  | ~~`isSystemRole` declared but never called in its own file~~ — **RESOLVED, false alarm.** It IS enforced, in A11: `ManagementServices.kt:362,370,382,389` all throw `role.system_immutable`. A9's hypothesis was right — the guard lives in the management layer, not the route file. ⚠️ But it has **no test** (see F19)                                                                                                                                                                                                                                                                                                                                                                                                         | `ManagementServices.kt:362`                    | closed                 |
| F7      | `GET /api/role-assignments` returns `[]` for a malformed `roleId` instead of `400 common.bad_id`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `Policies.kt:190`                              | contract inconsistency |
| F8      | `createAssignment` loads every assignment row to find the one it just inserted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `Policies.kt:98`                               | inefficiency           |
| F9      | `canonical-golden.json` is read by `auditmon` via a `../../control-plane/src/test/...` path that **breaks at cutover**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `canonical_test.go:90`                         | cutover task           |
| F10     | 11 A9 routes and `PolicyStore`'s own CRUD have zero direct tests, while ~36 suites depend on `PolicyStore` as a fixture                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `Policies.kt`                                  | coverage gap           |
| F11     | `AccessStore.reject` UPDATEs with **no status guard**, unlike `decideQueryRequest` which guards on `PENDING`. An already-decided ROLE request looks re-rejectable, overwriting `decided_by`/`decided_at`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Access.kt:476`                                | 🔒 possible bug        |
| F12     | `decideQuery` takes an `accessStore` parameter it never uses                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `Query.kt:278`                                 | dead parameter         |
| F13     | `DecisionContext.denyReason`/`detail` are English prose and reach REST via `QueryResponse.denyReason` — an unlocalized wire surface, contra INV-A1-13                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `Query.kt:98`, `723-732`                       | l10n gap               |
| F14     | `AccessStore.approve` hand-rolls `autoCommit=false`/`commit`/`rollback` while every other write uses the `inTx {}` helper                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `Access.kt:449`                                | inconsistency          |
| F15     | `Query.kt:818-820` states _"the minting path must refuse rows with `failed_stage='admission'`"_, but `validateApprovalSource` never checks `failedStage`, and no other guard in the from-denied branch does either. **DOWNGRADED from "possible live gap"**: at `/execute` the run re-enters `decideQuery`, whose step 4 re-checks `failureClass == INADMISSIBLE` before anything else, so such a task fails closed with `approval.execute_denied`. Real impact = useless approval requests reaching approvers' inboxes, plus a missing defence-in-depth layer — **not** privilege escalation. No test covers it                                                                                                                  | `Approvals.kt:158`, `Query.kt:818`             | queue hygiene          |
| F16     | Two different idioms for binding a JSON column: `PGobject(type="jsonb")` in `QueryResultStore.completeRun` vs `?::jsonb` casts in `AuditStore.insert`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `QueryResultStore.kt:120`, `AuditStore.kt:181` | inconsistency          |
| F17     | `QueryHistoryStore` has no dedicated test file — `DISTINCT ON` dedup, `limit` coercion, and blank-SQL skipping are all unasserted. Second untested store after `PolicyStore` (F10)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `QueryHistory.kt`                              | coverage gap           |
| F18     | **Three** hand-rolled CIDR implementations with identical byte-compare + boundary-mask logic                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `Cimd.kt:116`, `RequesterIp.kt:71`             | duplication            |
| **F19** | `ManagementServices.kt` (732 LOC) has **no dedicated test file** — including `replaceDirectRoles`' advisory-lock concurrency invariant, `isSystemRole` enforcement (F6's guard), and all three SYSTEM-immutability guards. **Largest untested surface in the control-plane, and it contains security guards**                                                                                                                                                                                                                                                                                                                                                                                                                     | `ManagementServices.kt`                        | 🔒 coverage gap        |
| F20     | `McpMutationExecutor`'s advisory-lock key joins segments with the literal 6-character string `\u0000`, not a NUL byte. Part of a hash input, so replicate as-is and fix deliberately                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `McpServer.kt:256`                             | latent bug             |

### F21–F125 — see `99-reconciliation-report.md` §6

The six agent-written areas raised **106 findings** (F2–F125 after renumbering —
six of them originally collided on `F21` because each area began its own
sequence there). The full ranked list with file:line evidence is in the
reconciliation report; only the ones that change what someone should _do_ are
repeated here.

🔴 **Confirmed live gaps — these are bugs in the running Kotlin, not port
concerns.** Unlike the three false alarms below, each of these was verified end
to end:

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                         | Location                                                |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| **F22** | 🔒 `ScimUser.active` defaults to `true` and `PUT /Users/{id}` passes `body.active` verbatim, so a PUT body **omitting** `active` silently **reactivates a deprovisioned user** — and skips the deactivate branch, so no credential teardown re-runs. Untested                                                                                                                                                   | `Scim.kt:54,419`                                        |
| **F24** | 🔒 A `groups` claim of the wrong **shape** (bare string, or comma-joined — both shipped by real IdPs) fails `as? List<*>` → `emptyList()`. Because provisioning _reconciles_ membership to exactly the claim, an IdP claim-shape change **strips every group from every user on next login, including `system:admin`**                                                                                          | `auth/Oidc.kt:86`                                       |
| **F26** | 🔒 **The timeout ladder is not total** — and my own A1/A7 docs asserted it was. `runTokenTtlSeconds` is clamped at `TOKEN_MAX_TTL_SECONDS` (24h) while `PM_QUERY_TIMEOUT` is bounded only by an overflow guard, so above 23h57m the run token expires mid-statement. `ConfigGuardTest.kt:65-79` asserts the **pure function**, never the stored `expires_at`, so it passes regardless                           | `RunExec.kt:280`, `Tokens.kt:126,76`, `Config.kt:138`   |
| **F33** | 🔒 `requireScimAuth` has **no** `PM_AUTH_DEBUG` bypass, while `AGENTS.md` and `docs/authz-model.md:363` both state _"`PM_AUTH_DEBUG` short-circuits all four"_. **The code is right and the docs are wrong** — `ScimAuthTest` runs every case with `authDebug = true` and still expects 501/403/401. ⚠️ **A port that implements the documentation makes a dev-mode control-plane accept unauthenticated SCIM** | `Scim.kt`, `docs/authz-model.md:363`                    |
| **F42** | 🔒 `DELETE /api/scim/v2/Groups/{id}` **hard-deletes**, CASCADE-dropping every `group_role` and `group_member` row — an IdP group delete silently revokes roles from every member, with no audit record and no undo, while users are never hard-deleted                                                                                                                                                          | `Users.kt:296`, `Scim.kt:581-593`                       |
| **F32** | 🔒 SCIM and local-admin identity mutations write **no** audit-trail row — only `log.info`. Provision, deprovision, rename and group delete are invisible to the tamper-evident chain, while a Cedar SYSTEM policy toggle writes a sentinel (INV-A2-22)                                                                                                                                                          | `Scim.kt`, `Users.kt`, `ManagementServices.kt:513-713`  |
| **F23** | 🔒 In `rotateRefresh` the client/resource mismatch check _precedes_ the rotated-replay check, so replaying a stolen rotated token with a **wrong `client_id`** returns `null` **without** `revokeFamily` — the breach-detection alarm is side-steppable                                                                                                                                                         | `auth/McpOAuth.kt:242-246`                              |
| **F34** | 🔒 `V8__seed.sql:48-58` installs **seven** `source=SYSTEM` groups (`system:admin`, `system:developer`, five `system:production-*`). Every immutability guard keys on the **column**, but every test names only the string `system:admin` — a port that special-cases that string leaves six production-capability groups mutable                                                                                | `V8__seed.sql:48-58`                                    |
| F21     | 🔒 Admin `PUT`/`DELETE` on a datasource clear the persisted catalog but never `invalidateDatasource`; only gRPC `Register` does, and only when `priorDbName` changed. Authoritative entries are keyed by **name**, so a replacement inherits the freed name's entries — and on MySQL the next connection _adopts_ them with no fetch                                                                            | `Datasources.kt`, `grpc/ControlPlaneGrpcService.kt:365` |
| F31     | 🔒 `findUserIdByEmail` matches on `app_user.email`, which has **no unique constraint and no index**, with no `ORDER BY` and no `LIMIT` — `if (rs.next())` takes an arbitrary row                                                                                                                                                                                                                                | `Users.kt:839-844`, `V1__identity.sql:21`               |

**F26 is mine.** I asserted the ladder as unconditional in both
`01-bootstrap.md` and `07-tasks-approvals-results.md`; A4's author caught it and
the reconciler confirmed it against source. Both docs are corrected in place
with the full arithmetic.

---

**Earlier live-gap candidates: all three were FALSE ALARMS.** Closed on
investigation:

- ~~F6~~ — the guard exists (A11 `ManagementServices.kt:362`).
- ~~F15~~ — downgraded; execution re-decides and fails closed (A6 step 4).
- ~~F5~~ — deliberate and load-bearing (non-admin elevation picker in `web/`).

Still real but lower-grade: **F11** (`AccessStore.reject`'s unguarded UPDATE —
reads as a bug, small blast radius) and **F19** (a _coverage_ gap over real
guards, not a gap in the guards).

⚠️ **Method note — the single most transferable lesson from Step 1.**

Solo, reading one area at a time, I raised **three** "possible live security
gap" flags. **All three were false positives** — each resolved only by looking
_outside_ the area that raised it. Meanwhile the cross-area pass found **ten
genuine ones** that no single-area reading could have caught, because each
depends on two files that no one area owns.

So the failure mode is not carelessness, it is **scope**: a security property in
this codebase is almost never local. F26 needed `RunExec` + `Tokens` +
`Config` + a test file; F24 needed `auth/Oidc` + `OidcDirectoryProvisioner`'s
reconcile semantics; F33 needed the code _and_ two doc files that contradict it.

The three false alarms:

| Flag | Raised in                             | Closed by                                             |
| ---- | ------------------------------------- | ----------------------------------------------------- |
| F6   | A9 (guard not called in its own file) | A11 — guard lives in the management layer             |
| F15  | A7 (minting path lacks a check)       | A6 — the execute path re-checks and fails closed      |
| F5   | A9 (route gate looks too weak)        | `web/` — the caller is a legitimate non-admin surface |

**Trace the full call path, and check the actual consumer, before calling
anything a live security gap.** Re-check every such claim when an adjacent area
lands. The corollary also holds (F4): a gap that looks _untested_ from inside
one area is often covered by a neighbour's suite.

**Resolved questions.** A6 Q7 ("does the minting path refuse
`failed_stage='admission'`?") — answered by specifying A7: **no**. Became F15.

**Correction log.** F4 was recorded from A2 as fully untested; specifying A6
found `UtilityGateDbTest` case 2 covers the utility half. Only the function half
remains uncovered. Expect more of these — a gap that looks untested from inside
one area is often covered by a neighbouring area's suite, so **re-check gap
claims when the adjacent area is specified.**

## Spec conventions

Each area doc contains:

1. **Purpose** — one paragraph, what the area owns.
2. **Wire contract** — every `@Serializable` DTO with exact JSON field names,
   nullability, and defaults. This is a _contract_, not a suggestion: `web/`
   consumes it.
3. **Routes** (where applicable) — method, path, auth gate, request DTO,
   response DTO, status codes, error codes.
4. **Symbols** — every class, function, method, enum, and top-level constant.
   Format below.
5. **Invariants** — numbered `INV-<area>-<n>`, with the ones that are _security_
   invariants marked 🔒. These become assertions in Step 3.
6. **Test inventory** — every test case, with what it asserts and its fixture
   class.
7. **Open questions** — anything the source did not settle.

### Symbol format

```
### <name>  ·  <kind>
Kotlin: <signature>
Contract:  what it guarantees to callers
Behavior:  numbered rules, including every edge case and error path
Deps:      what it calls / which tables it touches
Go shape:  the shape the Go port needs — NOT a library choice
```

### `⟦LIB⟧` markers

Library decisions are deliberately **deferred until after Step 2** (per the
agreed sequencing). Where the spec needs a capability that implies a dependency,
it states the _capability_ and tags it `⟦LIB⟧`. All markers collect into
`99-library-decisions.md` for that discussion. Example: "needs an
HMAC-authenticated, tamper-evident cookie value `⟦LIB⟧`" — not "use
gorilla/securecookie".

### Fidelity rule

Where the Kotlin does something non-obvious, the spec records **the reason**,
because the reason is what tells the Go implementer whether a deviation is safe.
Almost every such comment in this codebase documents a bug that was already
fixed once; a port that "cleans it up" reintroduces it. Example:
`App.kt:125-137` writes SSE keepalives on the consumer's own coroutine rather
than using Ktor's `heartbeat` helper, because the helper's separate coroutine
turned every closed browser tab into an unhandled exception and a 500.

## Test inventory summary

**121 files · 26,993 LOC · 903 test cases** (control-plane 847 + engine 56;
`auth/` has no tests).

⚠️ **Counting method — use exactly this.** Two independent ways to get it wrong,
and they pull in opposite directions:

```sh
grep -rhoE '@Test\b' --include='*.kt' <dir> | wc -l     # correct
```

- `grep -c '@Test'` **over**-counts — it also matches `@TestInstance` (e.g.
  `AdminGateTest.kt:32`).
- `grep -c '@Test[[:space:]]*$'` **under**-counts — many tests put the
  annotation on the same line, `@Test fun \`group grants a
  role\`()`(e.g. all four in`EffectiveRolesTest.kt`).
- Counting backtick-named functions also under-counts: some tests use plain
  camelCase identifiers (e.g. `ForwardedAuthorityTest`'s
  `forwardedHostFromAnUntrustedPeerIsIgnored`).

The `\b` form is the only one that agrees with a hand count. It gives 90 for A2
and 27 for A1, which match the enumerations in those docs.

Naming convention observed in the tree:

| Suffix         | Count | Meaning                                                                                                                       | Go equivalent needs                                |
| -------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `*DbTest.kt`   | ~55   | Real Postgres (+ MySQL for target-engine tests) via Testcontainers, shared containers (`support/TestDatabases.kt`)            | containerised PG/MySQL, shared per package `⟦LIB⟧` |
| `*Test.kt`     | ~60   | In-process; some drive real routing via `ktor-server-test-host`                                                               | in-process HTTP test server                        |
| `support/*.kt` | 5     | Fixtures: `TestDatabases`, `EnforcementHarness`, `EnforcementFixture`, `PerConnectionCatalogFixture`, `WebSessionTestSupport` | port first — everything else depends on them       |

`support/` is the porting critical path: 5 files gate the other 116.

## Sequencing note

Two facts from the DB-backed suites shape Step 2:

- The DB-backed tests **fail rather than skip** when Docker is absent
  (`mise.toml:191-199`), and `db-support.json` drives a version sweep
  (`mise.toml:229`). The Go suite must keep both properties or the matrix
  silently narrows.
- `control-plane/build.gradle.kts:104-137` carries five separate Testcontainers
  workarounds (Docker socket discovery on macOS, API version pinning, Ryuk
  disabled). Whatever Go containerisation is chosen will hit the same
  environment; budget for it rather than rediscovering it.

## Port dispositions

The sweep promised in **Docs corrected to match** above, carried out. Every
instruction in the 14 area docs that told the port to fix, unify, drop or delete
something has been rewritten in the disposition vocabulary. This table is the
ledger; the reasoning lives at each site. ⚠️ The **old instruction** column
quotes the pre-policy phrasings verbatim, on purpose — so a sweep grep for
`fix in the port` / `unify in the port` / `to fix, not replicate` matches here
and in the policy section above, and nowhere else in the 14 area docs.

`99-reconciliation-report.md` is a **frozen artifact and was not edited** — its
wording predates this policy, and where it says "unify" or "fix", this section
wins.

| Finding                                                   | Old instruction                                                                              | Disposition                                                             | Why                                                                                                                   |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| F1 (`02-authz.md:111`, `:723` Q1)                         | "Documentation defect to resolve, not replicate" / "drop the comment rather than porting it" | **REPRODUCE** behaviour + **OMIT** comment                              | Name-keyed marshalling is observable; a stale KDoc has no call path and no wire effect                                |
| F2 (`02-authz.md:491`, `:727` Q5)                         | "dead code, do not port" / "Confirm and delete"                                              | **OMIT**                                                                | `private` and uncalled — unreachable from main _and_ test, so no fixture depends on it                                |
| `02-authz.md:724` Q2                                      | "`dedupeByEuid` can be dropped in Go (map-keyed entities)"                                   | **REPRODUCE**                                                           | Whether a duplicated EUID authorizes or throws is observable at the Cedar call                                        |
| `05-datasources-catalog.md:611`                           | "Candidate finding, do not port"                                                             | **OMIT** (after a test-tree sweep)                                      | Private helpers, zero call sites; the caveat is to check for fixture uses first                                       |
| `05-datasources-catalog.md:624-626`                       | "A Go port should hoist it somewhere neutral"                                                | **REPRODUCE** (placement only)                                          | Clarified as a file-placement decision; the gate's behaviour is unchanged                                             |
| F14 (`06-query-decision.md:422`, `:750` Q5)               | "Behaviourally equivalent; unify in the port"                                                | **REPRODUCE**                                                           | Inconsistency is not grounds for OMIT; folding into `inTx {}` is a refactor                                           |
| F12 (`06-query-decision.md:747` Q2)                       | "Confirm and drop"                                                                           | **OMIT**                                                                | An unread parameter has no observable behaviour; check no test binds positionally                                     |
| F11 (`06-query-decision.md:746` Q1)                       | "confirm before replicating"                                                                 | **REPRODUCE**                                                           | The unguarded UPDATE is observable; the open part is what to fix afterwards                                           |
| F16 (`07-tasks-approvals-results.md:158-164`, `:779` Q2)  | "Two different idioms…; unify in the port"                                                   | **REPRODUCE** both                                                      | Duplication is explicitly not an OMIT case; unify after cutover                                                       |
| `07-tasks-approvals-results.md:569-572`, `:784` Q7        | "A JVM-specific workaround; drop it in Go"                                                   | **OMIT**                                                                | `runBlocking` is a JDK-verifier artifact — runtime, not contract                                                      |
| F8 (`09-policies.md:79`)                                  | "Inefficiency to fix, not replicate"                                                         | **REPRODUCE**                                                           | Inefficiency is named in the policy as _not_ grounds for OMIT; `.first {}` vs `getAssignment` also differ on a miss   |
| `09-policies.md:95-98`                                    | "a Go port should factor one small shared query helper rather than three copies"             | **REPRODUCE** (three copies)                                            | Duplication; collapsing three call paths is a refactor                                                                |
| F18 (`11-mcp-oauth-management.md:422`, `:575`)            | "Unify in the port"                                                                          | **REPRODUCE** all three                                                 | Duplication; "identical logic" is a claim about today that one shared impl would freeze                               |
| F83 / A13 F23 (`13-engine.md:603-607`)                    | "do not port it as an unordered set if a consumer ever appears"                              | **REPRODUCE** as test-visible, insertion-ordered                        | `AnalyzerTest:46` reads it — fixture-live, so outside the OMIT boundary                                               |
| F82 / A13 F22 (`13-engine.md:699`)                        | "Do not port it … delete the entry point"                                                    | **OMIT**                                                                | No caller in main _or_ test; rendering rule survives in `validateUniqueness`                                          |
| F37 / A13 F32 (`13-engine.md:777`, `:1385`, `:1404` Q9)   | "Fix in the port" / "fix in the port"                                                        | **REPRODUCE + PIN**                                                     | Last-pair-wins is observable at boot and can silently downgrade a credential surface — a security path                |
| F38 / A13 F29 (`13-engine.md:1401` Q6)                    | "Recommendation: **fix**"                                                                    | **REPRODUCE**                                                           | Validation hole is observable; "behaviour-neutral for four manifests" expires at the fifth                            |
| F72 / A13 F26 (`13-engine.md:1089`)                       | "the port should not copy the asymmetry"                                                     | **REPRODUCE**                                                           | The missing guards are observable — a duplicate silently overwrites where the disk path aborts boot                   |
| F79 / A13 F21 (`13-engine.md:507`, `:1399` Q4)            | "delete the file and its suite" / "delete … the 24-case suite"                               | **DEFER** (REPRODUCE meanwhile)                                         | Product question (is the one-time query grant planned?); production-dead but a 24-case suite + `EnginesTest` are live |
| F104 (`03-identity-scim.md:730`)                          | "Do not port the first"                                                                      | **OMIT** comment, **REPRODUCE** behaviour                               | A contradictory KDoc is non-observable; reconcile-and-remove is the contract                                          |
| F80 / A3 F27 (`03-identity-scim.md:899`, `:611`, `:1474`) | "do not port"                                                                                | **OMIT** call-path-free symbols; **REPRODUCE as test helpers** the rest | `setUserActive` (nine suites, five areas), `find…ByExternalId` (three), 4-arg `deleteUser` are fixture-live           |
| F81 / A10 F21 (`10-grpc.md:1449`)                         | "Dropping it in Go silently kills `GrpcServerTest` cases 1 and 4"                            | **REPRODUCE** as test-visible                                           | Production-dead, fixture-live; the stale doc claim is the OMIT half                                                   |
| F53 / A4 F33 (`04-auth-session-tokens.md:1042-1048`)      | "either drop the parameter or add the missing warn-level lines"                              | **OMIT** parameter, **REPRODUCE** the silence                           | Unused parameter is non-observable; adding logs to a security surface is a behaviour change                           |
| `14-auth.md:307-315`                                      | "should collapse all three into one function — the one duplication it is _safe_ to remove"   | **REPRODUCE**                                                           | Duplication; the safety argument is "they agree today", which is about the present, not the contract                  |
| F65 / A14 F31 (`14-auth.md:645`)                          | "A port should fold it into step 1"                                                          | **REPRODUCE**                                                           | Inefficiency; the extra statement is inside the same `FOR UPDATE` transaction and is observable                       |
| F28 / A14 F32 (`14-auth.md:691`)                          | "a Go port should use one clock"                                                             | **REPRODUCE + PIN**                                                     | Token-expiry path: unifying the clock changes who is refused under skew                                               |
| F67 / A14 F34 (`14-auth.md:772`)                          | "add `, id DESC` in the port and note the change"                                            | **REPRODUCE**                                                           | Result order is wire-observable; an "improvement" here becomes harness noise                                          |
| F93 / A14 F21 (`14-auth.md:1400` Q3)                      | "Should the two copies be unified in Go?"                                                    | **REPRODUCE** both                                                      | Duplication; separate-tunability question decides a _later_ unification                                               |
| A14 Q1 (`14-auth.md:1398`)                                | "decide whether the Go port should reject non-ASCII outright"                                | **REPRODUCE + PIN**                                                     | `pkceS256` is a security path; rejecting non-ASCII is a narrowing, hence its own decision                             |
| F61 / A14 F35 (`14-auth.md:1402` Q5)                      | "should the port add a TTL?"                                                                 | **REPRODUCE**                                                           | Adding a TTL changes failure behaviour under IdP maintenance                                                          |
| F62 / A14 F36 (`14-auth.md:1403` Q6)                      | "Caching it in the port is strictly better for load"                                         | **REPRODUCE**                                                           | Caching delays key-rotation pickup — a behaviour change on an auth path                                               |
| F49 / A14 F30 (`14-auth.md:1404` Q7)                      | "Should the port return a typed error…?"                                                     | **REPRODUCE**                                                           | The 500 is observable; the typed error is the right fix, taken separately                                             |

**Pattern worth naming.** Of the 31 retagged instructions, only five are genuine
OMITs, and four of those five are one of two shapes: a `private`/unreferenced
symbol, or a JVM artifact. Every other "just drop it" turned out to be either
observable (inefficiency, duplication, ordering, an error class) or fixture-live
— a symbol production stopped calling but nine test suites still do. **"Dead"
was wrong more often than it was right**, which is the practical form of the
OMIT boundary: the burden of proof is on OMIT, and the first check is always the
test tree, not the main tree.
