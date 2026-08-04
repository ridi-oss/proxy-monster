# A7 — Tasks, Approvals, Result Storage

Files: `Approvals.kt` (887) · `RunExec.kt` (655) · `QueryResultStore.kt` (289) ·
`QueryHistory.kt` (76) · `TaskCompletionHub.kt` (61) · `ResultCrypto.kt` (45).
Total 2,013 LOC. Fully read. Tables: `query_result`, `query_history` (+
`access_request` via A6's `AccessStore`).

FULL depth. The only place the control-plane **persists PII-bearing rows**, and
the only place it mints ephemeral tokens that carry an assume-role set.

## Purpose

The human query-approval workflow (`docs/approval-workflow.md`) and the
machinery under it: **execute-under-R**, encrypted short-retention result
storage, live view re-decision, the CP-driven run transport over a proxy-dialed
stream, and in-process task-completion push.

---

## 1. The execute-under-R model

The whole area turns on one sentence from `Approvals.kt:144-152`:

> Execute-under-R runs on the proxy via `RunExecService.run(assumeRoles = {R})`
> — **R alone** — at the workflow-executor channel. The stored rows are R's
> execution-enforced output: masked per {R} in the executor's context, encrypted
> before persistence. `GET /result` then re-decides at workflow-viewer under
> exactly {R} and applies the viewer-context masks, narrowing further where that
> context requires — **never revealing more than the stored bytes**.

🔒 **INV-A7-1 — `assumeRoles` is R alone, never a union with the executor's own
roles.** The CP mints it onto the ephemeral token (CP authority, never
proxy-asserted); the gRPC Decide handler forwards it as `decideQuery`'s
`providedRoles`, which **replaces** server role resolution (A6 step 6).

🔒 **INV-A7-2 — a row with an empty {R} fails closed at both ends.** No role to
re-decide under ⇒ `decideResultView` denies, and `/execute` rejects with
`approval.no_execute_role`. **There is no raw-snapshot side channel.** Without
the execute-side guard the run would fall through to the proxy Decide under the
_requester's own roles_, silently reinterpreting the authorization.

🔒 **INV-A7-3 — the view can only narrow, never widen.** The stored bytes are
already R-enforced; the view re-decides and applies further masks. A viewer
whose context is _broader_ than the executor's still sees only the stored
(already-masked) bytes.

---

## 2. Wire contract

| DTO                       | Fields                                                                                                                                                                                             |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CreateApprovalInput`     | `sourceDecisionId: Long? = null`, `datasourceId: Long? = null`, `sql: String? = null`, `title: String? = null`, `reason: String = ""`, `roleId: Long? = null`, `requestedDurationSec: Long = 3600` |
| `CreateApprovalResponse`  | `request: AccessRequest`, `wouldAllow: Boolean`                                                                                                                                                    |
| `DiscoverRolesRequest`    | `datasourceId: Long`, `sql: String`                                                                                                                                                                |
| `DiscoverRolesResponse`   | `baselineAllowed: Boolean`, `options: List<RoleOption>`                                                                                                                                            |
| `RoleOption`              | `roleId: Long`, `roleName: String`, `unmasksColumns: List<String>`                                                                                                                                 |
| `ApprovalDetail`          | `request: AccessRequest`, `canDecide: Boolean`, `result: QueryResultMeta? = null`, `canExecute: Boolean = false`, `canCancel: Boolean = false`                                                     |
| `QueryResultView`         | `meta`, `columns: List<String>`, `rows: List<List<String?>>`, `decision: Decision = ALLOW`, `maskedColumns: List<String> = []`                                                                     |
| `ExecuteApprovalResponse` | `decision: String` (only ever `"EXECUTING"`)                                                                                                                                                       |
| `QueryResultMeta`         | `taskId`, `executedBy?`, `executedAt?`, `rowCount: Int?`, `expiresAt?`, `status?`, `errorCode?`, `columns: List<String> = []`                                                                      |
| `DecryptedResult`         | `columns: List<String>`, `rows: List<List<String?>>`                                                                                                                                               |
| `TaskEvent`               | `taskId: Long`, `status: String` (EXECUTED / FAILED / CANCELLED)                                                                                                                                   |
| `QueryHistoryEntry`       | `sql: String`, `datasourceId: Long? = null`, `ranAt: String`                                                                                                                                       |

🔒 **INV-A7-4 — `QueryResultView.decision`/`maskedColumns` describe the LIVE
view re-decision, not the execution that stored the bytes.** The viewer's own
context can narrow an execution's ALLOW to a MASK. Without them the caller
cannot tell a masked cell from a value that genuinely looks like one, and a
console showing rows has nothing to label them with but a guess.

`AccessRequest.isWorkflowApproval` (private ext val) =
`kind == "QUERY" && creatorKind == "WORKFLOW"`.

🔒 **INV-A7-5 — every id-addressed approval route guards on
`isWorkflowApproval`.** EDITOR and WIRE tasks share `access_request` but are
internal lifecycle records with null SQL and no approver, so they must never be
listed, fetched, decided, executed, or viewed through `/api/approvals`.
`ApprovalSurfaceCreatorKindDbTest`'s 3 cases pin all three surfaces.

---

## 3. `ResultCrypto`

`class ResultCrypto(keyBytes: ByteArray)` — `require(keyBytes.size == 32)`.

AES-256-GCM. `encrypt`: random 12-byte IV from `SecureRandom`, returns
**`iv || ciphertext+tag`**. `decrypt`: `require(blob.size > IV_LEN)`, split,
decrypt. `TRANSFORM = "AES/GCM/NoPadding"`, `TAG_BITS = 128`.

🔒 **INV-A7-6 — GCM gives confidentiality _and_ integrity**; a tampered blob
fails to decrypt rather than yielding garbage. A per-result random IV keeps
identical results from producing identical blobs.

**Go shape:** `crypto/aes` + `cipher.NewGCM`, `gcm.Seal(nonce, nonce, pt, nil)`
reproduces the `iv || ct+tag` layout exactly (Go's `Seal` appends the tag, same
as JCE). `NonceSize()` is 12 and the tag is 16 bytes by default — matching.
`⟦LIB⟧` stdlib only.

---

## 4. `QueryResultStore` — the child state machine

Parent (`access_request`) statuses are A6's; the **child** (`query_result`) has
its own: `NULL → RUNNING → DONE | FAILED | CANCELLED`.

| Method                                              | Transition                                                                    | Notes                                                                                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `startRun(taskId, executedBy)`                      | `NULL → RUNNING`                                                              | standalone; guard `status IS NULL`                                                                                             |
| `claimAndStartRun(taskId, executedBy, claimParent)` | parent `APPROVED→EXECUTING` **+** child `NULL→RUNNING` in **one** transaction | returns null when `claimParent` fails                                                                                          |
| `completeRun(taskId, result, retentionSec, audit)`  | `RUNNING → DONE`                                                              | stores ciphertext, `row_count`, `columns`, `executed_at`, `expires_at = now + retention`; runs `audit(c, meta)` in the same tx |
| `failRun(taskId, errorCode, onFailed)`              | `RUNNING → FAILED`                                                            | sets `expires_at = now + RESULT_RETENTION_SEC`                                                                                 |
| `cancelRun(taskId, onCancelled)`                    | `RUNNING → CANCELLED`                                                         | `error_code = 'approval.canceled'`, sets `expires_at`                                                                          |
| `meta(taskId)` / `accessFor(taskId)`                | reads                                                                         | latest child, `ORDER BY id DESC LIMIT 1`                                                                                       |
| `purgeExpired()`                                    | payload strip                                                                 | see INV-A7-10                                                                                                                  |
| `purgeExpiredEditorChildren()`                      | **DELETE**                                                                    | see INV-A7-10                                                                                                                  |
| `deleteResultsForTask(taskId)`                      | DELETE children                                                               | idempotent                                                                                                                     |
| `deleteEditorResultsForPrincipal(principal[, c])`   | **deletes EDITOR _tasks_**                                                    | see INV-A7-11                                                                                                                  |

`RESULT_RETENTION_SEC = 86_400` (24h).

🔒 **INV-A7-7 — `claimAndStartRun` closes the cancel window.** A separate
claim-then-start left a gap where a cancel arriving between the two saw an
`EXECUTING` parent with no `RUNNING` child yet, so `cancelRun` no-oped **and the
query ran anyway**. After this, an `EXECUTING` task always has a `RUNNING` child
for a cancel to catch. A claimed parent with no pending child is an invariant
violation that `error(...)`s and rolls the whole claim back (leaving the task
`APPROVED`).

**INV-A7-8 — the active child is selected by a separate read, then updated by
its own id, but the per-status guard stays on the UPDATE.** So the transition is
still a race-safe compare-and-set even though the select isn't locked
(`latestChildId` + `WHERE id = ? AND status = '…'`).

🔒 **INV-A7-9 — `accessFor` captures meta, the child's own `sql`, and the
ciphertext in ONE read, and decrypts lazily.** Two distinct properties:

- **Lazy decrypt** (`ResultAccess.decrypted` is `by lazy`): a caller that
  rejects on `meta` alone — an unauthorized viewer, a not-ready status — **never
  triggers a decrypt**.
- **One read**: a concurrent re-execute cannot swap the row between the
  authorization check on `meta` and the decrypt (TOCTOU).

Also: reading `qr.sql` from the **same row** as the ciphertext binds the view's
re-decision to the released bytes. Using the task's first-child `req.sql`
instead diverges once a task holds plural children. `QueryResultStoreDbTest`
case 7 pins it.

`accessFor` computes
`expired = meta.expiresAt != null && Instant.parse(...) < now`; if expired it
calls `purgeExpired()` opportunistically. The payload is handed to the lazy
closure **only** when `status == "DONE" && !expired` — anything else decrypts to
null so the route surfaces 409/410 rather than any bytes.

🔒 **INV-A7-10 — two different expiry semantics, and the ORDER they run in
matters.**

- `purgeExpired()`:
  `UPDATE query_result SET ciphertext = NULL, row_count = NULL, columns = NULL, expires_at = NULL WHERE expires_at <= now`.
  Keeps the child row and its `sql`/`sql_hash`/`status`/
  `error_code`/`executed_*` for durable audit and web preview. **Clearing
  `expires_at` is what makes the row fall out of the sweep's own `WHERE`** so it
  is not reprocessed.
- `purgeExpiredEditorChildren()`:
  `DELETE … WHERE expires_at <= now AND task_id IN (SELECT id FROM access_request WHERE creator_kind = 'EDITOR')`.
  An editor tab has no audit obligation, so its expired child is removed whole.

**This confirms A1 INV-A1-5 mechanically:** `purgeExpired` NULLs `expires_at` on
_every_ expired child including editor ones, so an editor sweep ordered after it
would never match `expires_at <= now`. Editor rows would linger forever,
payload-stripped. The A1 loop runs `purgeExpiredEditorChildren()` **then**
`purgeExpired()` — correct, and load-bearing.

🔒 **INV-A7-11 — `deleteEditorResultsForPrincipal` deletes the EDITOR _tasks_,
not just the children.** Dropping the whole `access_request` row (cascading to
`query_result`) terminalizes any task still EXECUTING when the session ended; a
child-only delete would strand the parent EXECUTING until the boot reconcile,
and leave empty editor task rows behind. Scoped
`creator_kind = 'EDITOR' AND principal = ?` so a WORKFLOW approval is never
touched. The connection overload lets it join the session-end transaction and
roll back with a failed deprovision teardown.

⚠️ **Engine-conditional binding in `completeRun`:** `columns` is bound as a
`PGobject(type="jsonb")` when `c.metaData.databaseProductName` contains
"PostgreSQL", else a plain string. The control-plane store is Postgres-only
(`Db.kt` hardcodes the driver), so the else-branch is for tests. Go's `pgx`
takes `[]byte`/string for `jsonb` directly, so the engine conditional has no Go
analogue at all — what must match is the stored value, which is `jsonb` either
way. Note `A8`'s `AuditStore` uses `?::jsonb` casts instead: **two different
idioms for the same problem, and both are REPRODUCE (F16).** Duplication and
inconsistency are explicitly not grounds for OMIT; picking one idiom for both
stores is a refactor to take after cutover.

---

## 5. Pure policy helpers

### `validateApprovalSource(decision: AuditEvent?, requestingPrincipal): SourceValidation`

`enum SourceValidation { OK, NOT_FOUND, NOT_DENY }`

```
decision == null || decision.principal != requestingPrincipal  -> NOT_FOUND
decision.decision != Decision.DENY                             -> NOT_DENY
else                                                           -> OK
```

🔒 A not-owned decision is `NOT_FOUND`, not a 403 — don't leak other principals'
decision ids.

⚠️ **This resolves A6 Q7, and the answer is a finding.** `Query.kt:818-820`
states: _"Structural DENY rows intentionally use the normal audit path and still
receive a decisionId. The current UI may offer approval for those rows; **the
minting path must refuse rows with `failed_stage='admission'`**."_
`validateApprovalSource` **does not check `failedStage`**, and no other guard in
the `hasSource` branch does either (the branch checks: source validation →
`pendingQueryRequestExists` → datasource exists → `mayRequest` →
`roleId != null`). `ApprovalsTest` has no admission-stage case.

So either the comment describes an intended guard that was never implemented, or
it was lost. **Do not replicate the gap silently** — see §11 Q1. Recorded as
**F15**.

### `validateProactiveCompose(datasourceId, sql, title, reason): String?`

Returns the first missing/blank field name in order `datasourceId`, `sql`,
`title`, `reason`; null when valid. Field **order matters** for the error
message.

### `discoverRoles(ownRoles, allRoles, decide): DiscoverRolesResponse`

1. `baseline = decide(ownRoles)`; `baselineMasked`, `baselineDenied`.
2. For each role **not already held**: `underR = decide(setOf(role.name))`.
   - `underR.action == DENY` ⇒ skip (R doesn't let Q run).
   - `unmasked = (baselineMasked - underR masks).sorted()`.
   - Offer iff `baselineDenied || unmasked.isNotEmpty()` — R must return
     _strictly more_; a role returning exactly what the requester already sees
     is noise.

🔒 **INV-A7-12 — PREVIEW PARITY: each candidate is previewed ALONE
(`decide(setOf(role.name))`), never unioned with the requester's own roles**,
because execute-under-R runs with `assumeRoles = {R}` alone (INV-A7-1). If
discovery previewed `ownRoles + role.name`, a role that only reads more
_through_ a column `ownRoles` already unlocks — a masked-write-payload gate, or
a role-scoped `unless`/`when` keyed off the union — could preview ALLOW yet DENY
at execute, offering a role the requester cannot actually run. Only the baseline
decision and the already-held filter stay keyed on the requester's own roles.
`ApprovalDiscoverPickSubmitRouteDbTest` case 1 is named for this ("_not
unmask-only (union trap)_").

⚠️ **INV-A7-13 — the parity is over the ROLE SET only; the channel/context axis
is knowingly open.** Discovery runs `decide` on the **EDITOR** channel in the
**requester's** live HTTP context, whereas execute-under-R runs on
**WORKFLOW_EXECUTOR** in the **approver's** context — and the approver (their
`requester_ip`, their identity) is not known at discovery time. So a policy
conditioned on `context.channel` or on a `requester_ip`-derived tag can still
make an offered R deny at execute, or hide an R that would in fact run.
**Discovery is a best-effort preview, not a promise of the execute verdict.**
Closing that axis is a separate design decision (`docs/approval-workflow.md`),
not something the helper can decide. Carry this caveat verbatim — a Go port that
"fixes" it by previewing on WORKFLOW_EXECUTOR changes behaviour without
resolving the unknown-approver problem.

`decide` **must be side-effect-free** — discovery is a dry-run and writes no
audit row.

### `decideResultView(...)` · internal → `ResultViewDecision`

`sealed class ResultViewDecision { Allowed(columns, rows, maskedColumns), Denied(reason) }`

**Seven deny gates, in order. Every uncertainty is a deny:**

1. `childSql == null` ⇒ `"saved result child has no SQL"`
2. `req.executeAs.toSet().isEmpty()` ⇒
   `"approval request has no execute-as roles"` (INV-A7-2)
3. `decideQuery(...)` with `providedRoles = {R}`, `channel` (WORKFLOW_VIEWER
   default, EDITOR for the editor view) ⇒ `action == DENY` ⇒
   `Denied(denyReason ?: detail ?: "view decision denied")`
4. `ctx.passthrough` ⇒ `"stored query result re-decided as passthrough"`
5. **Output-column drift**: size mismatch, or any positional mismatch
   (`equals(..., ignoreCase = true)`) ⇒
   `"stored result columns no longer match the live query decision"`
6. **Row-width drift**: any row whose size ≠ `columns.size` ⇒
   `"stored result row width does not match its columns"`
7. `bindMasks(ctx.masks, columns.size)` ⇒ `!allBound` ⇒
   `"required view mask could not be bound"`

🔒 **INV-A7-14 — gate 5 is A6 INV-A6-5's consumer.** A `SELECT *` re-expansion
between execute and view would slide a mask onto the wrong stored column and
leak a value. Comparison is **case-insensitive and positional**.

Then the masking application:

```kotlin
val kind = binding.byIndex[index]
if (kind == null) value else Masking.apply(value, kind)
```

🔒 **INV-A7-15 — do NOT collapse this to
`Masking.apply(value, kind) ?: value`.** `Masking.apply` returns **null** for a
full redaction (kind `NULL`), so the `?:` form would fall a redacted-to-null
cell back to the **cleartext value**. The explicit null-check on the _kind_ (not
the result) is the whole point. `ApprovalResultViewContextDbTest` case 2 pins it
("_a NULL-kind redaction of a derived output blanks the cell on view, not the
stored cleartext_").

🔒 **INV-A7-16 — `maskedColumns` is named from the BOUND indices, not from
`ctx.masks`.** Binding is what actually rewrote a cell, so a mask the decision
asked for but could not bind can never be reported as applied. (An unbound mask
denies at gate 7, so the two agree today — reading the binding keeps them
agreeing if that ever changes.)

### `autoApproveTask(principal, ownRoles, ds, rawCtx, authz, channel): Boolean` · internal

The shared self-approve gate for EDITOR and WIRE tasks.

1. `taskCtx = rawCtx.copy(channel = channel.contextValue)`;
   `tags = resolveContextTags(...)`.
2. `TASK_REQUEST` on the datasource with `taskCtx.copy(tags = tags)` — Deny ⇒
   false.
3. `TASK_APPROVE` via `authorizeWithContext` against
   `ApprovalRequest(requester = principal, approver = principal, datasourceName = ds.name)`
   — Deny ⇒ false.

🔒 **INV-A7-17 — a self-approved task must clear BOTH lifecycle checks a human
request+approve would.** Either Deny fails the task closed. `ownRoles` is the
request-side snapshot; the approve side re-resolves its own snapshot inside
`authorizeWithContext` (A2 INV-A2-10).

---

## 6. `approvalRoutes` — 9 routes

Three closure gates defined at the top:

| Helper                         | Action                            | `authDebug` bypass? |
| ------------------------------ | --------------------------------- | ------------------- |
| `mayRequest(call, ds)`         | `TASK_REQUEST` on the Datasource  | **yes**             |
| `mayDecide(call, action, req)` | the given action on the `Request` | **yes**             |
| `mayReadResult(call, req)`     | `TASK_ASSUME` on the `Request`    | **NO**              |

🔒 **INV-A7-18 — `mayReadResult` has no `authDebug` bypass.** Result rows are
data confidentiality, enforced in development too. Same rule as A6 INV-A6-25.

🔒 **INV-A7-19 — approver eligibility is a Cedar policy, never the datasource's
approver GROUP**, and `requester != approver` comes from the shipped
`no-self-approval` forbid, not app code.

`e3Record(principal, req, event, channel)` builds the lifecycle audit row:
`statement = "approval #<id> <event>"`, `decision = ALLOW`,
`detail = "APPROVER_EXEC <event>"`, `kind = "approval_lifecycle"`, `datasource`
= resolved name or `"?"`.

🔒 **INV-A7-20 — the lifecycle audit row deliberately carries NO result-derived
data.** No `row_count`, no requester name — `audit_decision` is exposed via the
shared feed, so it records only the event, the **actor** (`record.principal` =
whoever acted), and the approval id. The requester↔approval linkage is
reconstructable from `access_request` by an authorized auditor via the id, but
is not broadcast inline.

### `POST /api/approvals`

1. `requireApi`; blank `reason` ⇒ 400 `common.field_required{fields:"reason"}`.
2. **Exactly one** of `sourceDecisionId` / (`datasourceId`|`sql`) ⇒ else 400
   `approval.exactly_one_source_required` (both branches: both-set and
   neither-set).
3. **from-denied branch**: `auditStore.get(sourceDecisionId)` →
   `validateApprovalSource` (NOT_FOUND ⇒ 404 `decision`, NOT_DENY ⇒ 400
   `approval.only_denied_queries`) → `pendingQueryRequestExists` ⇒ 409
   `approval.pending_request_exists` → datasource **by name** from
   `source.datasource` (⇒ 409) → `mayRequest` ⇒ 403 → `roleId == null` ⇒ 400
   `approval.role_required` →
   `createQueryRequest(..., evaluatedDecision = "DENY")`, catching
   `DuplicatePendingQueryRequestException` ⇒ 409 → **201**
   `CreateApprovalResponse(request, wouldAllow = false)`.
4. **proactive branch**: `validateProactiveCompose` ⇒ 400 naming the field →
   datasource ⇒ 404 → `mayRequest` ⇒ 403 → `roleId == null` ⇒ 400 →
   **`decideQuery` on `Channel.EDITOR`** (server-side analysis only; nothing
   executes, no audit row) →
   `createQueryRequest(... evaluatedDecision = decision.action.name)` → **201**
   with `wouldAllow = (action == ALLOW)`.

**INV-A7-21 — the `roleId == null` check runs AFTER each branch's field
validation**, so an incomplete form names its missing field first.

🔒 **INV-A7-22 — the compose preview carries the server-attested
`requester_ip`.** A preview that dropped it would report a _different_ verdict
than the real editor execution whenever a policy conditions on `requester_ip` or
a derived tag. It also passes `systemClassification` so the preview's verdict
matches what execution will do.

### `POST /api/approvals/discover-roles`

`requireApi` → datasource ⇒ 404 → `ownRoles` →
**`discoverContext = call.httpAuthzContext(config)` resolved ONCE** outside the
closure (which runs `decideQuery` per candidate role), so every candidate is
previewed under the same server-attested context. Dry-run; no audit row.

### `GET /api/approvals` / `GET /api/approvals/inbox`

List: `listQueryRequests(status, principal)` — own requests. Inbox:
`listQueryRequests("PENDING", null).filter { mayDecide(TASK_APPROVE, it) }` — a
**forward filter** by Cedar, _not_ a group-membership join. `authDebug` shows
all.

### `GET /api/approvals/{id}`

`isWorkflowApproval` ⇒ 404. `isApprover = mayDecide(TASK_APPROVE)`.
`mayDecide(TASK_READ)` ⇒ 404.

🔒 **INV-A7-23 — metadata is redacted when the caller cannot assume R.**

```kotlin
queryResultStore?.meta(id)?.let { if (mayReadResult(call, req)) it else it.copy(rowCount = null, columns = emptyList()) }
```

`rowCount` and `columns` are **cardinality/existence oracles** the assume gate
must close. A caller with only `task.read` sees status/executor/timestamps/error
— never the result's shape.

`canExecute = queryResultStore != null && isApprover && status == "APPROVED" && req.decidedBy == principal`
— mirrors `/execute`'s gates, so a merely-eligible approver who did not approve
_this_ task gets no Run affordance that would just 403.
`canCancel = status == "EXECUTING" && mayDecide(TASK_CANCEL)`.

### `POST /{id}/approve` and `POST /{id}/reject`

Both: `isWorkflowApproval` ⇒ 404 → `status != "PENDING"` ⇒ 409
`approval.already_decided` → `mayDecide(TASK_APPROVE)` ⇒ 403
`approval.not_approver` → `decideQueryRequest(...)` (null ⇒ 409) → log →
respond. Reject additionally requires a non-blank `reason` (400 first,
**before** the request lookup).

🔒 **INV-A7-24 — reject asks the SAME `task.approve` Cedar question as
approve**, so a role-scoped approval policy governs both.

### `POST /{id}/cancel`

`isWorkflowApproval` ⇒ 404 → `mayDecide(TASK_CANCEL)` ⇒ 403
`approval.cancel_forbidden` → status switch: `EXECUTED`/`FAILED`/`CANCELLED` ⇒
**200 with the request** (idempotent); `DRAFT`/`PENDING`/`APPROVED`/ `REJECTED`
⇒ 409 `approval.not_cancelable`; `EXECUTING` ⇒ proceed; anything else ⇒ 409.
Then
`store.cancelRun(id) { markCancelled(id, conn) or throw; auditStore.insert(conn, e3Record(… "result-canceled", WORKFLOW_EXECUTOR)) }`,
then `runExecService.cancelActiveRun(id)` and a
`taskCompletionHub.publish([requester, decidedBy].filterNotNull(), CANCELLED)`.

**INV-A7-25 — the cancel pushes CANCELLED immediately** rather than waiting for
the run coroutine, which may not unwind for a while on a stuck run.

### `POST /{id}/execute`

Order is security-relevant:

1. `isWorkflowApproval` ⇒ 404.
2. 🔒 **`mayDecide(TASK_APPROVE)` ⇒ 403 BEFORE any status disclosure.** _"a
   caller who cannot approve this task gets a uniform 403 regardless of its
   status, so the 409 already_executed / not_approved distinctions below are
   never a state oracle for a non-approver."_
3. `status ∈ {EXECUTING, EXECUTED, FAILED, CANCELLED}` ⇒ 409
   `approval.already_executed`.
4. `status != "APPROVED"` ⇒ 409 `approval.not_approved`.
5. 🔒 **`req.decidedBy != executor` ⇒ 403 `approval.not_the_approver`. No
   `authDebug` bypass.**
6. `queryResultStore == null` ⇒ 503; datasource ⇒ 409; `req.sql == null` ⇒ 409
   `approval.no_sql`.
7. `executeAs.isEmpty()` ⇒ 409 `approval.no_execute_role` (INV-A7-2).
8. `claimAndStartRun(...)` ⇒ null ⇒ 409 `approval.already_executed`.
9. `appScope.launch { … }`; respond **202**
   `ExecuteApprovalResponse("EXECUTING")`.

🔒 **INV-A7-26 — the approver of record must be the one who executes.** This
pins `executedBy = decided_by = the approver`, so the run's identity always
falls inside the `task.assume` permit (requester **or** approver) and the saved
result stays readable by its parties — **without adding `executedBy` to the
permit**. An eligible approver who did not approve _this_ task cannot run it.

The async body mirrors A6's editor submit: `DENY` ⇒ `"approval.execute_denied"`;
success ⇒ `completeRun` with an audit hook that does `markExecuted` (throw if it
fails) **and** inserts
`e3Record(executor, …, "result-executed", WORKFLOW_EXECUTOR)` — all in **one**
transaction; failure ⇒ `failRun` + `markFailed` in one transaction; then publish
the **actual** terminal status to both parties. `maxRows = 5000` hardcoded.

🔒 **INV-A7-27 — if the parent has left EXECUTING (e.g. a restart already
reconciled it to FAILED), the `markExecuted` flip fails and aborts the WHOLE
commit** — the child stays RUNNING and the failure path transitions both
consistently.

### `GET /{id}/result`

1. `isWorkflowApproval` ⇒ 404.
2. 🔒 `userGroupStore.isDeactivated(principal)` ⇒ **404** (no result-existence
   oracle for a deprovisioned principal). The live `decideQuery` repeats this
   gate as defense in depth.
3. `accessFor(id)` ⇒ 404.
4. `mayReadResult` ⇒ **404** (not 403 — no existence oracle).
5. `meta.status != "DONE"` ⇒ 409 `approval.result_not_ready`.
6. `access.decrypted == null` ⇒ **410** `approval.result_expired`.
7. `decideResultView(...)` on `WORKFLOW_VIEWER`.
8. `Denied` ⇒ log warn, **insert
   `e3Record(… "result-view-denied", WORKFLOW_VIEWER)`**, 403
   `approval.result_view_denied`.
9. `Allowed` ⇒ classify the view event by the viewer's relationship, audit, then
   respond.

🔒 **INV-A7-28 — the view is audited BEFORE the rows are returned.** _"a failed
audit insert propagates (500) so PII is never returned without a durable
record."_ A Go port that audits after writing the response body breaks this.

**INV-A7-29 — the view event is classified by relationship, not
requester-vs-everyone:** `req.principal` ⇒ `result-viewed-by-requester`;
`req.decidedBy` ⇒ `result-viewed-by-approver`; else ⇒
`result-viewed-by-assumer`. A `system:auditor` (or any operator-defined
`task.assume` principal) is neither party and must not be miscredited to the
approver.

---

## 7. `RunExecService` — the CP-driven run transport

### Timing constants

| Constant                      | Value                                            | Purpose                                                                      |
| ----------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `RUN_TOKEN_TTL_FLOOR_SECONDS` | 900                                              | floor for a one-shot run token                                               |
| `EDITOR_SESSION_TTL_SECONDS`  | 8h                                               | persistent editor session token                                              |
| `TOKEN_TTL_GRACE_SECONDS`     | 180                                              | headroom over `PM_QUERY_TIMEOUT`                                             |
| `DIAL_TIMEOUT_MS`             | 120_000                                          | measured cold opens took ~26s; 10s failed them outright                      |
| `EXCHANGE_TIMEOUT_MS`         | 630_000                                          | **fallback only** — production always passes `Config.queryExchangeTimeoutMs` |
| `QUERY_TIMEOUT_MESSAGE`       | `"statement aborted: PM_QUERY_TIMEOUT exceeded"` | 🔒 must match `goproxy run.QueryTimeoutMessage` **verbatim**                 |

`runTokenTtlSeconds(q) = max(900, q + 180)` ·
`editorSessionTtlSeconds(q) = max(8h, q + 180)`

🔒 **INV-A7-30 — the run token must outlive the whole exchange it backs**
(dial + window + revalidation), else a genuine long query fails
`UNAUTHENTICATED` when the proxy revalidates the token mid-run. The run-token
TTL is the **top** rung of A1's timeout ladder — above `runStreamTimeoutMs`
(`Main.kt:20`), which is the rung below it.

🔴 **CORRECTION — this invariant is CONDITIONAL, not unconditional.** (Index
finding **F26**; full arithmetic in `01-bootstrap.md` §4 case 25.)
`runTokenTtlSeconds`'s result is clamped by `TokenStore.issue` →
`clampTtlSeconds` → `TOKEN_MAX_TTL_SECONDS = 24h` (`Tokens.kt:126,81,76`), while
`PM_QUERY_TIMEOUT` is bounded only by the overflow guard. **It holds only for
`PM_QUERY_TIMEOUT ≤ 86,220 s` (23h57m)** with the full 180s grace; the margin
erodes above that, hits zero at exactly 24h, and goes negative beyond — the
token then expires mid-statement, which is precisely the failure this invariant
claims to prevent. `ConfigGuardTest.kt:65-79` cannot catch it because it asserts
the pure function, never the stored `expires_at`.

⚠️ **Do not restate this as unconditional in the Go port.** Either bound
`PM_QUERY_TIMEOUT` at config-parse time or assert on the persisted expiry.

🔒 **INV-A7-31 — `QUERY_TIMEOUT_MESSAGE` is a cross-language string contract.**
A statement the proxy aborted at `PM_QUERY_TIMEOUT` carries this exact sentinel;
`collectResponse` matches it to attribute a timeout (→ `query.proxy_timeout`,
task FAILED) rather than a generic failure. **A Go control-plane and `goproxy`
can share the constant** — an improvement over the current hand-matched pair,
and worth doing.

### Registries

**`RunChannelRegistry`** — `ConcurrentHashMap<String, PendingSession>`.
`register` uses `check(putIfAbsent(...) == null)`. `attach(sessionId, outbound)`
**atomically removes** from the pending map and completes `ready` with
`Attached(outbound, Channel(BUFFERED))`.

🔒 **INV-A7-32 — a session can be claimed exactly once.** `attach`'s
remove-then-complete rejects an unknown or duplicate stream, so it can never
share another request's token or query.

**`RequesterIpRegistry`** — `ConcurrentHashMap<String, String>` keyed by **token
SHA-256 hash**, never the raw token.

🔒 **INV-A7-33 — `put` and `set` have deliberately different null semantics.**

- `put(hash, ip)` — mint-time write. A null `ip` is a **no-op**: the key doesn't
  exist yet, so there is nothing to refresh, and it must not plant an absent-key
  sentinel.
- `set(hash, ip)` — per-decision refresh. A null `ip` **removes** the entry. A
  persistent session queried from a network whose `requester_ip` can't be
  resolved must not inherit the (possibly trusted) open-time IP; the attribute
  goes absent ⇒ fail-closed, never stale.

Entry lifetime == token lifetime: `put` at issuance, `remove` on revoke (both
success and failure paths). An absent entry means `get` returns null ⇒
`requester_ip` simply absent on that decision — fail-closed, never a stale IP
resurrected from a since-revoked token.

This registry exists because the gRPC Decide handler sees only the resolved
**token**, not the HTTP request that minted it. Lives on `ControlPlaneCore` for
the same reason `runChannels` does (A1 INV-A1-1's neighbours).

### Exceptions — `sealed class RunExecException`

`NoProxyAttachedException` · `ProxyStreamWedgedException` ·
`ProxyRunTimeoutException` · `ProxyRunException` ·
`RunCanceledBeforeStartException`

🔒 **INV-A7-34 — `NoProxyAttached` and `StreamWedged` must stay distinct** (A12
INV-A12-14's consumer): nothing is missing in the wedged case, a live stream is
unusable, and it has been dropped so the proxy's own reconnect can replace it.
Retrying after that reconnect is the fix; hunting an absent proxy is not.

### The cancel gate — `ActiveRun`

```kotlin
private class ActiveRun(val outbound: SendChannel<ControlRunMsg>) {
    val gate = Mutex(); var canceled = false; var sent = false
}
```

🔒 **INV-A7-35 — the gate serializes "veto-or-send the query" against "cancel",
so a cancel is strictly ordered relative to the send.** Either the cancel wins
the gate first and **vetoes** the send (nothing leaves the CP, the run coroutine
throws `RunCanceledBeforeStartException`), or the query is sent first and the
cancel's `RunCancel` lands **after** it on the stream — never before, which an
idle proxy would drop, **letting a just-canceled query run anyway**. `preflight`
(a DB status re-check) runs inside the gate too.

`cancelActiveRun(taskId)`: under the gate, set `canceled = true`; if `sent`,
`trySend(RunCancel)`. Returns whether a run was registered.

**Go shape:** a `sync.Mutex` around the send plus a `canceled`/`sent` pair
reproduces this. The subtlety is that the **send happens while holding the
lock** — a Go port that computes the message under the lock but sends outside it
reintroduces the reordering bug.

### `run(...)` — the one-shot path

1. `mintForActivePrincipalLocked(principal, userGroupStore) { tokenStore.issue(kind, principal, roles = assumeRoles.toList(), ttl = runTokenTtlSeconds, c) }`
   — null ⇒ `ProxyRunException("principal is deprovisioned")`.
   `kind = APPROVER_EXEC` when `approverExec` else `EDITOR`.
2. `runRequesterIps.put(tokenHash(issued.token), requesterIp)`.
3. `connectionCatalog.open(Binding(ds.name, principal, kind), ds.defaultSchemas + ds.engine.systemSchemas, adoptHeldContent = ds.engine.catalogIsConnectionIndependent)`.
4. `sessionId = UUID.randomUUID()`; `runChannels.register(pending)`.
5. `proxyEventsHub.requestOpenRun(...)` — `NOT_ATTACHED` ⇒ throw, `WEDGED` ⇒
   throw.
6. `withTimeout(dialTimeoutMs) { pending.ready.await() }` — timeout ⇒
   `ProxyRunTimeoutException`.
7. Register `ActiveRun` (when `taskId != null`), `sendRunQuery(...)`.
8. `withTimeout(exchangeTimeoutMs) { collectResponse(...) }`.

**`finally` — cleanup order is contractual:**

```
activeRuns.remove(taskId, ar)
if (registered && attached == null && runChannels.remove(sessionId) == null)
    attached = withContext(NonCancellable) { pending.ready.await() }
attached?.outbound?.trySend(RunClose)
  finally tokenStore.revoke(issued.id, principal)
    finally { closeConnectionCatalog(...); runRequesterIps.remove(hash); if (registered) runChannels.remove(sessionId) }
```

🔒 **INV-A7-36 — the `attached == null && remove(...) == null` dance handles the
cancel/attach race.** If cancellation or timeout races the claim, `remove` wins
while still pending; otherwise `attach` already won and completed `ready`, so
cleanup must recover the outbound channel — under `NonCancellable`, because the
enclosing coroutine is already cancelling — to send the `RunClose`. Without it
the proxy holds a backend connection forever.

**INV-A7-37 — nested `try/finally` guarantees revoke-then-cleanup even if
`trySend` throws.** The token revoke and the registry removal must happen on
every path. `maxRows` is `coerceIn(0, 5000)`, with **0 preserved as the wire
sentinel** meaning "use the proxy's default (500)".

### `openSession` / `runOnSession` / `closeSession`

`openSession` mints an `EDITOR` token with `editorSessionTtlSeconds`, dials, and
stores `OpenEditorSession`. On **any** failure the same recovery dance runs,
then token revoke + catalog close + registry cleanup, then rethrow.

`runOnSession(sessionId, principal, sql, maxRows, requesterIp, taskId, preflight, exchangeTimeoutMs)`:

1. Look up the session **and check `principal` owns it** ⇒ else
   `ProxyRunException("no such editor session")`.
2. Under `session.mutex`:
   - 🔒 **Re-check `openSessions[sessionId] !== session`** — a concurrent
     lock-free `closeSession` (DELETE / idle sweep) may have removed and revoked
     it while we queued for the lock. `!==` identity is safe because `sessionId`
     is a fresh UUID, so a re-open can never resurrect the same object.
   - `session.lastUsedNanos = now`.
   - 🔒 **`runRequesterIps.set(tokenHash, requesterIp)`** — under the mutex,
     **before** the query is sent, so the gRPC decide it triggers reads _this_
     query's IP (INV-A7-33).
   - `sendRunQuery(...)`; a send failure ⇒ `closeSession` + `ProxyRunException`.
   - `withTimeout { collectResponse }`; timeout ⇒ `closeSession` + throw;
     `ProxyRunException` ⇒ `closeSession` + rethrow (a query-level error ends
     the persistent proxy session, so drop the CP-side one; the next submit
     reopens cleanly).
3. **Outer `finally`**: 🔒 if `openSessions[sessionId] !== session`,
   `runRequesterIps.remove(tokenHash)`. _"If a lock-free `closeSession` raced
   this query and won, the registry `set` above may have RE-CREATED an entry the
   close already swept — after the token was revoked."_ Idempotent with
   `closeSession`'s own remove; a no-op on the normal path.

🔒 **INV-A7-38 — enforcement stays PER-STATEMENT on a persistent session.** A
held connection is a data-plane fact, not an authz relaxation: each query
re-decides against the connection's live namespace/catalog on the EDITOR channel
under the caller's own roles.

`sessionDatasourceName(sessionId, principal)` and
`closeSessionOwnedBy(sessionId, principal)` are both **owner-scoped**, returning
null/false for an unknown _or_ not-owned id — so a leaked session id reveals
nothing and cannot tear down another user's connection.
`closeSessionsForPrincipal` is the session-end seam's hook.
`sweepIdleSessions(maxIdleMs)` reaps by `lastUsedNanos`.

`closeConnectionCatalog` wraps a `runBlocking` — the comment says _"Keep suspend
cleanup out of run()'s already-large state machine (JDK verifier sensitivity)."_
**OMIT**: the wrapper exists because of the JDK verifier, not because of the
contract, and it has no observable behaviour of its own, so Go calls the cleanup
directly. (Confirmed in `99-reconciliation-report.md`, A7 Q7.)

### `collectResponse(inbound, started)` — protocol validation

Loops over `ProxyRunMsg`. **Eight rejection cases**, each a `ProxyRunException`:

| Condition                              | Message                                                |
| -------------------------------------- | ------------------------------------------------------ |
| second `decision`                      | `"proxy sent more than one run decision"`              |
| `resultRows` before a decision         | `"proxy sent run rows before a decision"`              |
| `resultRows` after DENY                | `"proxy sent run rows after a deny decision"`          |
| row width ≠ first chunk's column count | `"proxy sent a run row with the wrong column count"`   |
| `done` with no decision                | `"proxy completed a run query before a decision"`      |
| `done` with no verdict                 | `"proxy completed a run query without a verdict"`      |
| `done` after DENY                      | `"proxy sent RunDone after a deny decision"`           |
| second `sessionReady`                  | `"proxy sent RunReady more than once"`                 |
| empty message                          | `"proxy sent an empty run message"`                    |
| stream closed with no terminal         | `"proxy run stream closed before a terminal response"` |

🔒 **INV-A7-39 — the decision's `EnfAction` goes through `knownOrDeny()`** (A6
INV-A6-3) and a DENY returns immediately with empty columns/rows. `error`
matching `QUERY_TIMEOUT_MESSAGE` ⇒ `ProxyRunTimeoutException`, else
`ProxyRunException`. `rowsAffected == -1` ⇒ null.

`response(...)` builds the `QueryResponse`, and looks up `piiTouched` by
re-reading the audit row for `decisionId` (0 ⇒ null).
`latencyMs = (nanoTime - started) / 1_000_000`.

---

## 8. `TaskCompletionHub`

`ConcurrentHashMap<String, CopyOnWriteArrayList<Channel<TaskEvent>>>` —
principal → one channel per tab. `subscribe` creates
`Channel(capacity = 64, onBufferOverflow = DROP_OLDEST)`. `unsubscribe` removes,
evicts the empty list, and **closes** the channel. `publish(principal, event)` —
`trySend` to each; `publish(principals, event)` de-duplicates via `toSet()`.

🔒 **INV-A7-40 — the push is a pure accelerator, never the source of truth.**
The web still polls to a terminal state, so a dropped event only delays the
update. Accordingly `publish` is **non-blocking** and a full buffer **drops the
oldest**, so a slow or stuck client can never make the run coroutine suspend or
grow memory unbounded. Single-replica by design; a multi-replica `LISTEN/NOTIFY`
fan-out is a documented follow-up (`docs/backlog.md`).

**Go shape:** buffered `chan TaskEvent` with a non-blocking `select`/`default`
gives "never block", but **Go has no `DROP_OLDEST`** — the default is
drop-_newest_. `TaskCompletionHubTest` case 7 asserts the buffer _"drops oldest
… keeping the newest event"_, so the port needs an explicit ring buffer or a
drain-one-then-send. Same class of gap as A12's `trySend`-on-closed.

---

## 9. `QueryHistoryStore` + `queryHistoryRoutes`

`add(principal, datasourceId, sql)` — trims; **blank is ignored** (no row).
`recent(principal, limit)` — `DISTINCT ON (sql)` inner query ordered
`sql, created_at DESC`, then outer `ORDER BY created_at DESC LIMIT ?`. Latest
occurrence of each distinct SQL wins. `clear(principal)`.

⚠️ `DISTINCT ON` is **PostgreSQL-specific**. The control-plane store is
Postgres-only so this is fine, but a Go port using a generic query builder must
not rewrite it to `GROUP BY` (which would need an aggregate over `created_at`
and a self-join to recover `datasource_id`).

Routes: `GET /api/query-history` (`requireApi`, `limit` default 50
`coerceIn(1, 200)`) · `DELETE /api/query-history` (`requireApi`, **204**). Both
fall back to `"debug-user"`.

⚠️ Both are **principal-scoped from the session only** — no admin view, no
cross-principal read. Note `add` is called best-effort from A6's `queryRoutes`
with `runCatching`, so a history write failure never blocks a query.

---

## 10. Test inventory — 13 suites, 2,489 LOC, **71 cases**

_(LOC corrected from 2,432 by the reconciliation pass — the headline
contradicted this section's own per-suite figures by 57. Case count 71 was
correct.)_

### `ApprovalsTest.kt` — 55 LOC, 9 cases · **pure unit, no DB**

`validateApprovalSource` (4): own DENY is OK · null source is NOT_FOUND ·
another principal's DENY is NOT_FOUND · own non-DENY decisions are NOT_DENY.
`validateProactiveCompose` (5): missing datasource · blank sql · blank title ·
blank reason · complete input is valid.

⚠️ **No case asserts refusal of a `failed_stage='admission'` source** — see F15
/ §11 Q1.

### `ApprovalSurfaceCreatorKindDbTest.kt` — 145 LOC, 3 cases · DB

1. 🔒 list surfaces only WORKFLOW tasks — WIRE and EDITOR never appear
2. 🔒 a WIRE task is not fetchable, decidable, executable, or viewable as an
   approval
3. 🔒 an EDITOR task is not fetchable, decidable, executable, or viewable as an
   approval

All three pin INV-A7-5. Cases 2–3 each sweep **five** surfaces.

### `ApprovalDiscoverPickSubmitRouteDbTest.kt` — 231 LOC, 3 cases · DB + route

1. 🔒 discover offers full-reader (**R-alone**) not unmask-only (**union
   trap**), pick it, submit carries `roleId` — INV-A7-12
2. a proactive compose missing a required field returns `common.field_required`
   naming that field
3. a compose with all fields but no elevation role is rejected `role_required`
   (single execute-under-R path)

### `ApprovalExecuteRouteDbTest.kt` — 596 LOC, 9 cases · DB + route

1. 🔒 a DENY-under-R at execute leaks no result and stores nothing (fail-closed
   floor)
2. 🔒 a second execute after a successful first is 409 `already_executed`,
   storing **exactly one** result
3. execute returns 202 EXECUTING while the run is in flight, then completes to
   EXECUTED and DONE
4. canceling an in-flight approval terminalizes both rows and emits RunCancel
   (INV-A7-35)
5. V46 allows the requester to cancel and denies an unrelated principal
   **without sending control**
6. cancel is idempotent after execution and rejects pending tasks
7. removed release and withhold routes return 404 — **negative route test**
8. 🔒 execute by an approver other than the approver of record is 403
   `not_the_approver` and runs nothing (INV-A7-26)
9. 🔒 `claimExecution` is race-safe — two concurrent callers on separate
   connections yield exactly one winner

### `ApprovalResultViewContextDbTest.kt` — 546 LOC, 12 cases · DB — **the view-decision suite**

1. the same stored result masks off-segregated and unmasks in-context for
   approver and requester
2. 🔒 a NULL-kind redaction of a derived output blanks the cell on view, **not
   the stored cleartext** (INV-A7-15)
3. the live decision uses the **viewer** principal rather than the requester
   identity
4. disabling the live unmask grant re-masks the next view **without changing
   storage** (INV-A7-3)
5. 🔒 a deactivated executor is hidden before any live result decision
6. 🔒 an outsider cannot assume the task role
7. a requester assumes R and reads their own result
8. approver and auditor assume R while **admin sees metadata only** (INV-A7-23)
9. 🔒 a stored query result that re-decides as passthrough is denied without
   sentinel data (gate 4)
10. 🔒 a live DENY on an ungranted table returns 403 without stored sentinel
    data (gate 3)
11. 🔒 **output-column drift fails closed before any partially matched row is
    returned** (gate 5, INV-A7-14)
12. 🔒 stored row-width drift fails closed instead of returning an unbound extra
    value (gate 6)

Cases 9–12 are the four drift/uncertainty gates. Port as a group — each is a
distinct leak path.

### `ApprovalResultDeactivationDbTest.kt` — 109 LOC, 2 cases · DB

1. an active viewer passes the deactivation gate and reaches the live
   re-decision — **positive control**
2. 🔒 a deactivated viewer is gated out before any result decision — NotFound,
   no existence oracle

Case 1 exists so case 2 can't pass vacuously. Worth keeping the pair.

### `ApprovalResultAssumeMysqlDbTest.kt` — 166 LOC, 2 cases · **DB, MySQL**

1. requester assumes R and sees the shipped production view for their live
   network
2. workflow executor stores R's execution-enforced masks and the viewer
   re-decides per context

### `QueryResultStoreDbTest.kt` — 210 LOC, 8 cases · DB

1. child transitions pending → running → done with encrypted rows
2. failed child stores a stable error code **without ciphertext**
3. 🔒 `claimAndStartRun` atomically claims the parent and starts the child,
   **closing the cancel window** (INV-A7-7)
4. `claimAndStartRun` is single-shot — a second claim on a non-APPROVED task
   loses
5. `cancelRun` atomically cancels child and parent and **wins late completion**
6. one task supports multiple children and latest metadata wins
7. 🔒 `accessFor` binds the **released child's own sql** to its ciphertext, not
   the first child's (INV-A7-9)
8. expiry purges the payload but keeps the child row and its sql for audit
   (INV-A7-10)

### `ResultCryptoTest.kt` — 53 LOC, 7 cases · pure unit

round-trips plaintext · ciphertext is not the plaintext and uses a random iv ·
🔒 tampered ciphertext fails to decrypt · 🔒 wrong key fails to decrypt · key
must be 32 bytes · too-short blob is rejected · empty plaintext round-trips.

**Port first** — 7 cases, no DB, and it validates the exact `iv || ct+tag`
layout a Go implementation must reproduce.

### `TaskCompletionHubTest.kt` — 85 LOC, 7 cases · pure unit

a subscriber receives an event published to its principal · publish with no
subscribers is a no-op · an event reaches every open stream of the same
principal · 🔒 a principal only receives its own events · publish to a party set
delivers once per principal even when a principal repeats · unsubscribe removes
and closes the channel · ⚠️ **a full subscriber buffer drops oldest and never
blocks the publisher, keeping the newest event** (INV-A7-40 — the Go gap).

### `TaskEventsRouteDbTest.kt` — 95 LOC, 2 cases · DB + SSE route

1. 🔒 the push `task_read` filter mirrors the poll — owner allowed, a forbid
   suppresses, absent denied (A1 INV-A1-10)
2. session liveness tracks minting and revocation (A1 INV-A1-10)

Subject is `taskEventsRoute`, defined in `App.kt` (A1) but task-centric; counted
here.

### `TaskReconcileStartupDbTest.kt` — 112 LOC, 1 case · DB

1. boot fails orphaned executions, spares not-started tasks, and is idempotent
   (A6 INV-A6-20)

### `RoleDiscoveryTest.kt` — 86 LOC, 6 cases · unit

1. a role that unmasks a baseline-masked column is offered with the unmasked
   column
2. a role that returns the same is not offered
3. a role under which Q is denied is not offered
4. when baseline is denied, a role that makes Q runnable is offered
5. a role the requester already holds is never offered
6. 🔒 **a candidate is previewed under R ALONE, not unioned with the requester's
   own roles** (INV-A7-12)

### Reassignment

`TokenTtlTest.kt` (35 LOC, 4 cases) tests `clampTtlSeconds` — verified at
`TokenTtlTest.kt:13-25`, which lives in the **`auth/` module**, not `RunExec`.
Counted in `14-auth.md`, **not** A7.

### Coverage gaps in A7

- 🔒 **No test for a `failed_stage='admission'` approval source** (F15). The one
  gap that is a possible live security issue.
- `RunExecService.run`'s `finally` recovery dance (INV-A7-36) — the
  cancel/attach race is not directly driven; `EditorSubmitRouteDbTest` covers
  the editor analogue but not the one-shot path.
- `collectResponse`'s ten protocol rejections — none appear to be asserted at
  unit level. These are the CP's defence against a misbehaving proxy.
- `runOnSession`'s outer-`finally` registry re-sweep (INV-A7-38's neighbour) —
  the specific `closeSession`-races-query interleaving.
- `RequesterIpRegistry.put` vs `set` null-semantics divergence (INV-A7-33) at
  unit level.
- `QueryHistoryStore` has **no dedicated test file** — `DISTINCT ON` dedup, the
  `limit` coercion, and blank-SQL skipping are all unasserted. (Second area
  after A9 with an untested store.)
- `sweepIdleSessions` / `closeSessionsForPrincipal`.
- `discoverRoles` with an empty `allRoles`, and the
  `baselineDenied && unmasked.isEmpty()` combination.

---

## 11. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                            |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | **F15.** `Query.kt:818-820` says the minting path must refuse `failed_stage='admission'` rows; `validateApprovalSource` does not check it and nothing else in the branch does. Is the guard missing, or is the comment stale? If missing: an inadmissible statement (never analyzable, e.g. malformed SQL) can be submitted for approval and then executed under R. |
| Q2  | `completeRun` binds `columns` via `PGobject` while `AuditStore` uses `?::jsonb` casts for the same job (F16). Both are **REPRODUCE**; the open question is which idiom a _later_ unification should keep, not what the port does.                                                                                                                                   |
| Q3  | `maxRows = 5000` is hardcoded at `/execute` while the editor passes the caller's value. Deliberate ceiling for approver-exec, or an oversight?                                                                                                                                                                                                                      |
| Q4  | `QueryHistoryStore` uses `DISTINCT ON` (Postgres-only) and has no tests. Confirm the store stays Postgres-only (it does per `Db.kt`) and add tests in Step 3.                                                                                                                                                                                                       |
| Q5  | INV-A7-13: is closing the discovery channel/context parity axis in scope for the port, or explicitly deferred? The port is a good moment to decide, but it is a **behaviour change**, not a port task.                                                                                                                                                              |
| Q6  | `TaskCompletionHub`'s `DROP_OLDEST` has no Go equivalent. Ring buffer, or drain-one-then-send? Affects `TaskCompletionHubTest` case 7.                                                                                                                                                                                                                              |
| Q7  | **ANSWERED — yes** (`99-reconciliation-report.md`, A7 Q7). `closeConnectionCatalog`'s `runBlocking` wrapper is a JVM verifier workaround, so **OMIT**: a plain direct call in Go. Nothing observable rides on the wrapper.                                                                                                                                          |
