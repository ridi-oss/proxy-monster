# Task execution — one enforcement path (`Decide`); the workflow is the task-backed trigger

## The model

There is one enforcement path. Every statement the proxy runs — wire, editor, or
workflow — round-trips to the control plane for a `Decide`: the sfacts contract
(statement facts → required grants) evaluated against Cedar under a role set R,
against the live per-connection catalog — then applies the returned masks. Wire
and editor run under the caller's own server-resolved roles; the approval
workflow elevates to an execute-as role set R the requester picked.

A **task** is the workflow's unit of authorized elevated execution: it carries
principal, datasource, `execute-as R`, lifecycle, and (when saved) encrypted
result children. Wire and editor do **not** create task rows — they enforce via
`Decide` only. The native wire, the web editor, and the approval workflow are
three entry points; they share `Decide` / masking, and only the workflow adds
request lifecycle, a human approver, and the encrypted result store.

## Concepts

- Task — the unit of authorized elevated execution for the WORKFLOW path.
  Carries the principal, the datasource, `execute-as R`, `creator_kind`
  (`WORKFLOW` for approval requests; the column CHECK also allows `WIRE` /
  `EDITOR` but only `WORKFLOW` is written today), a status, its `requester` and
  `approver` (Cedar attributes — who may assume R keys off them), and its
  statements (as `query_result` children). It carries no stored decision —
  enforcement is decided at run. Backed by the `access_request` table (kind
  `QUERY`).
- `execute-as R` — the role set the run is enforced under. For the editor and
  the wire it is the caller's own server-resolved roles (no elevation); for the
  workflow it is the elevation role set R the requester picked via role
  discovery (`access_request.role_id` / `execute_as`).
- Approval — the authorization that this SQL may run as R: it fixes _what may
  run_, _under which role R_, and _who approved_. It computes and stores no
  verdict or mask plan. Only the workflow has a human approve step; wire and
  editor have no task-approval lifecycle.
- Executor — the principal who performs the run. For wire and editor it is the
  caller; for the workflow it is the approver of record, who executes the
  approved SQL on a new connection. Distinct from `execute-as R`, which is only
  the role the enforcement runs _as_, not who runs it.
- Assuming R — to execute a workflow task or read its result, a principal
  assumes R: acts as exactly `{R}` for that operation (their own roles never
  add). Whether a principal may assume R is a Cedar decision keyed on the task's
  `requester`/`approver` attributes; the default grants it to the task's
  approver, its requester, or a `system:auditor`. Executing assumes R (only the
  approver of record initiates it); reading the result assumes R
  (requester/approver/auditor). A principal who cannot assume R — e.g. `admin` —
  sees the task's metadata but no result data. The code never hardcodes this: it
  asks Cedar, so an admin changes who may assume by editing the policy.
- Decision — the run-time output of one `Decide` round-trip, per statement: the
  sfacts `StatementFacts` (required grants + output columns + rewritten SQL, see
  [statement-facts-contract.md](./statement-facts-contract.md)) evaluated
  against Cedar under R → per-statement verdict + mask plan. Computed fresh at
  run against the live per-connection catalog, every statement. Never persisted
  as a task decision (audit rows are separate).
- `query_result` — a task's child rows, 1:N in schema (one task can hold several
  statements). The current approval routes create and run a single child per
  request. Each child carries its own SQL, status, and (when saved) the
  encrypted rows, masked per the run's decision.
- Execution context — a Cedar context attribute (`context.channel`: `wire`,
  `editor`, `workflow-executor`, `workflow-viewer`, `mcp`), authoritative from
  the entry point / token kind, never client-asserted. The run-time decision —
  including masking — is conditioned on it, not just on R (see
  [Masking is context-conditioned, and decided at run](#masking-is-context-conditioned-and-decided-at-run)).

## The enforcement path

1. Create (workflow only). `POST /api/approvals` creates a task (principal,
   datasource, SQL child, `execute-as R`, `creator_kind = WORKFLOW`), gated by
   `task.request` on the datasource. Status defaults to `PENDING`. Wire and
   editor skip this step — no `access_request` row.
2. Approve (workflow only). Approval authorizes "this SQL may run as R" —
   nothing more. It stores no verdict or mask plan. A human approver approves or
   rejects (`POST .../approve|reject`, Cedar `task.approve`).
3. Run. Per statement, the proxy round-trips `Decide` → sfacts + Cedar under the
   relevant role set, against the live per-connection catalog → verdict + mask
   plan — then runs the statement and applies the masks.
   - Wire: the native session's own target-DB connection; roles = caller's own;
     channel `wire`.
   - Editor: CP-driven `RunExec` on an editor session connection (or one-shot
     `/api/datasources/{id}/query`); roles = caller's own; channel `editor`.
   - Workflow: approver of record triggers `POST .../execute` (202); CP launches
     an application-scoped coroutine that dials a new `RunExec` stream with an
     `APPROVER_EXEC` token and `assumeRoles={R}`; channel `workflow-executor`.
     Execute-once CAS: `APPROVED → EXECUTING`.
4. Result. Wire streams the masked result on the socket. Editor returns rows on
   the HTTP response. Workflow saves encrypted rows under the `query_result`
   child (`PM_RESULT_KEY`, fail-closed when unset).
5. View (workflow saved results). Reading a saved result means assuming R — a
   Cedar decision (the default policy grants the assume to the task's
   `requester`, `approver`, or a `system:auditor`). `task.read`, which an
   `admin` holds broadly, only reveals that the task exists + its metadata,
   never the result data. Having assumed R, the viewer _is_ exactly `{R}` and
   sees each column masked/unmasked per `result.read.*` evaluated as R in the
   viewer's live context (`workflow-viewer` + the viewer's attested request
   context). Route: `GET /api/approvals/{id}/result`.

Approval grants no data access on its own: every statement is still gated at run
by the per-statement `Decide`.

## The three entry points

<!-- prettier-ignore -->
|  | native wire | editor | workflow |
| --- | --- | --- | --- |
| Origin | a native DB client (mysql/psql) sends a query on the socket | a web user hits "execute" | a web user composes a request |
| Task row | none | none | `access_request` + `query_result` (`creator_kind = WORKFLOW`) |
| Create | — | — | `POST /api/approvals` → `PENDING` (requires `roleId`) |
| Approval | — | — | the chosen approver approves or rejects (`task.approve`) |
| `execute-as R` | the connecting principal's own roles | the caller's own roles (no elevation) | the elevation role set R |
| Connection | the wire session's own target-DB connection | the editor session's held connection (or one-shot dial) | a new connection, dialed at run |
| Executor (runs it) | the connecting client (caller) | the caller | the approver of record |
| Run | per-statement `Decide` → apply masks (streams to socket) | per-statement `Decide` via `RunExec` → apply masks | per-statement `Decide` via `RunExec` under `{R}` → apply masks |
| Result | streams back on the socket | HTTP response rows | `save → query_result` ciphertext; view via `/api/approvals/{id}/result` |

## Masking is context-conditioned, and decided at run

Each statement's mask plan is computed at run under the effective role set
within the entry point's execution context (the Cedar `context.channel`
attribute plus the attested request context — requester IP, derived tags). A
trusted execution context can grant `result.read.unmasked` where the native wire
cannot, so the same role R can read a column unmasked via an editor/workflow
path but masked via the wire.

Because every statement is decided at run against the live per-connection
catalog, the masking always reflects the current schema. There is no stored plan
to go stale between approval and run.

A saved workflow result is decided a second time — at view, as R in the
_viewer's_ context (`workflow-viewer`). The stored result is what R produced at
execution (masked per `{R}` in the executor's context); a principal who may
assume R re-decides it under exactly `{R}` in _their_ context, masking further
where their context is more restrictive. The masking role is always `{R}`; only
the _context_ differs between the run (the executor's) and the view (the
viewer's). There is no precomputed "ceiling" — the execution context sets what
is stored and the view context re-masks it.

Worked example — the viewer sees R's view, not their own. Say R holds a
_context-conditioned_ grant: `result.read.unmasked` on `users.ssn` from the
trusted network, `result.read.masked` otherwise. A viewer V has no `ssn` grant
of their own — by their own roles V sees neither form. V is the task's
requester, so the Cedar policy lets V assume R. Now V _is_ `{R}`: viewing from
the trusted network V sees `users.ssn` unmasked; from outside, masked. V's own
roles never enter. This is a genuine widening — V sees unmasked despite holding
no unmask grant — and it is the point: while viewing, V is R. An `admin`, who
cannot assume R, sees neither form (only that the task exists).

Worked example — the execution channel is R's virtual ceiling. The widening
trigger need not be the network; it can be the _execution channel itself_. The
production preset seeds a policy: `system:production-pii-accessor` reads `pii`
unmasked `when context.channel == "workflow-executor"`. So the approval workflow
_is_ the trust signal — an approved run unmasks even off the trusted network.
Trace one task, R = `system:production-pii-accessor`, requester Q who holds no
`pii` unmask of their own:

- Execute. Approver A runs the task off the trusted network. The run's
  `context.channel` is `workflow-executor`, so the policy fires → `users.ssn` is
  stored unmasked (the maximal result R is entitled to).
- View, off-network. Q assumes R and views. The view's channel is
  `workflow-viewer`, which the executor-channel permit does not match; with no
  trusted-network tag either, evaluation falls through to the masked grant → Q
  sees `users.ssn` masked.
- View, on the trusted network. Q views again from the trusted network. The
  executor-channel permit still does not match (viewer channel), but the
  trusted-network permit now fires → Q sees `users.ssn` unmasked.

Same role, same stored bytes; the masking at each point is whatever R's
_context_ — channel and network — permits right there. The execution's
`workflow-executor` channel is R's virtual ceiling: it sets the maximal that
gets stored, and every later view re-masks down from it per the viewer's
context.

In this project's presets, dev datasources have no PII by definition and read
cleartext — masking is a production concern.

## The connect gate

`datasource.connect` is a connection-level authorization, separate from
per-statement enforcement — it is not part of the sfacts per-statement decision
(which emits `sql.*` / `result.read.*`, not `connect`). It is evaluated when a
connection is opened, under the relevant roles:

- wire — when the native client connects;
- editor — when the editor session opens / one-shot query dials;
- workflow — when the new connection is dialed at run.

On DENY the connection is refused with no target DB dial. `decideQuery` also
re-checks `datasource.connect` ahead of each statement as a mid-session
revocation guard, but the authoritative connect gate is at connection open.

## Async, timeout, and cancel

- Async execution (workflow). A run executes on an application-scoped coroutine
  (like the purge sweep in `App.kt`) so it outlives the HTTP request. Submit
  returns `202` with `decision: EXECUTING`; the task/child status is polled
  (`GET /api/approvals/{id}` / `.../result`). The coroutine does not poll or
  hold a thread — it awaits the proxy's completion signal (`RunDone` /
  `RunError`). Native wire blocks on the socket and streams rows live; editor
  waits on the HTTP response for that query.
- One timeout. A single configurable `PM_QUERY_TIMEOUT` — one value across
  triggers, default 600 s (10 min) — nested so the proxy's guard aborts first
  and the control plane sees a clean, attributable error rather than a raw
  stream timeout.
- Cancel / abort. There is no `RunCancel` control message on the run channel
  today (`ControlRunMsg` is only `RunQuery` | `RunClose`). In-flight aborts use
  the proxy timeout watchdog: PostgreSQL `CancelRequest` (via the session's
  `TargetDbKeyData`), MySQL `KILL QUERY <conn-id>`, without dropping the
  connection for a clean timeout path. A cancel is a control-plane-side
  terminalization: `POST /api/approvals/{id}/cancel` and
  `POST /api/editor/tasks/{taskId}/cancel` are `task.cancel`-gated, accept only
  an `EXECUTING` task (`approval.not_cancelable` otherwise), and write
  `CANCELLED` on both the task (`AccessStore.markCancelled`) and its `RUNNING`
  child (`QueryResultStore.cancelRun`, `error_code = approval.canceled`) in one
  transaction, then abandon the in-flight run (`cancelActiveRun`). A run that
  fails on its own lands `FAILED`. `DELETE /api/editor/tasks/{taskId}` deletes
  an owner's EDITOR task row outright (CASCADE to its children) rather than
  writing `DELETED`; the `markDeleted` / `resubmit` store helpers have no HTTP
  route.
- CP restart reconcile. On boot, before routing accepts traffic, orphaned
  `EXECUTING` tasks → `FAILED` and `RUNNING` children → `FAILED`. Fail-closed
  and idempotent; the `executing_at` / `executed_at` timestamps let the
  reconcile distinguish orphans from live work.

The control-plane-driven channel uses a neutral run protocol in code: `RunExec`,
`ProxyRunMsg` / `ControlRunMsg`, `RunQuery`, `RunReady`, `RunDecision`,
`RunResultRows`, `RunDone`, `RunError`, `RunClose`. The same channel serves
editor and workflow execution; only the result sink differs (editor returns on
HTTP; workflow saves under a result id).

## Completion observation

Workflow execute completion is observed by polling the task detail/result
endpoints (see `ExecuteApprovalResponse`). The poll is the source of truth. A
`TaskCompletionHub` and the `GET /api/tasks/events` SSE stream accelerate it by
pushing each task's terminal transition to the parties involved; every push is
re-filtered through the live `task.read` gate, and a missed event only delays an
update.

## Cedar actions

- Task lifecycle (workflow)
  - `task.request` — create/submit a task on a datasource.
  - `task.approve` — authorize that R may run the task (approve / reject /
    execute). Production ships a no-self-approval forbid.
  - `task.read` — metadata gate: whether a principal may see the task exists +
    its status/metadata. Broad (an `admin` holds it); it grants no result data.
  - `task.assume` — may this principal assume R for this task. This — not
    `task.read` — is the confidentiality boundary for result data: only an
    assumer reads the rows. The default policy permits the task's requester, its
    approver, or a `system:auditor`.
  - `task.cancel` — cancel an `EXECUTING` task, on both the approval and the
    editor cancel routes. `task.delete` is in the Cedar schema and admin seed;
    the editor's own delete-on-close route is owner-scoped instead.
- Connection gate — `datasource.connect`, evaluated at connection open (not per
  statement, not at approval).
- Execute gates — evaluated at run, per statement, under the effective roles,
  via the sfacts contract: the statement-kind gate on `stmt.kind.<k>` (Cedar
  maps it to its read/write/ddl/… category); plus `exception.unanalyzable` (a
  statement the analyzer cannot parse) and `exception.unmaskable` (a statement
  whose result cannot be masked). Unanalyzable/unmaskable are statement kinds
  like the rest — denied by default via Cedar, allowable by an admin policy.
- Result read — the per-column mask plan, evaluated as R (by whoever assumed R)
  in the reader's live context: `result.read.masked`, `result.read.unmasked`.
  Keyed to R, exercised by the assumer, never the viewer's own roles.
- Unchanged: `grant.revoke` on an `AccessGrant`, `admin.*`, `token.*`,
  `audit.read`.

The default policy set permits a task's requester, its approver, and
`system:auditor` to assume R. The production preset additionally seeds
`system:production-pii-accessor` reading `pii` unmasked via the executor
channel:

```cedar
permit(principal in Role::"system:production-pii-accessor",
       action == Action::"result.read.unmasked", resource)
  when { resource in Tag::"system:production" && resource in Tag::"pii"
         && context has channel && context.channel == "workflow-executor" }
  unless { resource in Tag::"system:activity" || resource in Tag::"system:data-leak"
           || resource in Tag::"system:critical" };
```

This is the channel half of the trusted-network unmask — the virtual ceiling
that lets an approved run store R's maximal result off the trusted network (see
the
[masking worked example](#masking-is-context-conditioned-and-decided-at-run)).

`audit_event` stays a separate record: it captures task approve/deny lifecycle
events (`kind = approval_lifecycle`) plus every per-statement Cedar allow/deny
with its channel and context tags, and post-relay `kind = completion` volume
rows. It is the audit trail, not the task itself. Wire and editor statements are
audited without a task row; workflow execute/view events reference the approval
id in the statement text.

Enforcement wiring (code, not policy): `GET /api/approvals/{id}/result`
authorizes `task.assume` (may the viewer assume R?), then evaluates
`result.read.*` as R in the viewer's context. Execute stays on `task.approve`
and runs as the approver under `{R}` + the execute-once CAS. The result is
stored as R's execution-enforced output — no ceiling.

## Task status states

```
PENDING → APPROVED | REJECTED
APPROVED → EXECUTING → EXECUTED | FAILED
```

plus `EXECUTING → CANCELLED` from the cancel routes above. `DRAFT` and `DELETED`
are CHECK-allowed but unwritten: the store helpers that would write them
(`resubmit`, `REJECTED → PENDING`; `markDeleted`,
`DRAFT|PENDING|REJECTED → DELETED`) have no HTTP route, and the editor's
delete-on-close removes the row instead. Timestamps: `created_at`,
`approved_at`, `executing_at`, `executed_at` — the executing/executed pair is
what CP-restart recovery keys on. The `APPROVED → EXECUTING` transition is the
single-winner execute-once CAS, made visible as a status.

Each `query_result` child has its own status:
`RUNNING → DONE | FAILED | CANCELLED`, and is null until the run claims it.

## Data model

task (backed by `access_request`, kind `QUERY`):

```
task
  id, principal, datasource_id
  role_id / execute_as   elevation role set R (WORKFLOW)
  creator_kind           WORKFLOW (CHECK also allows WIRE | EDITOR)
  status                 PENDING → APPROVED | REJECTED → EXECUTING → EXECUTED | FAILED
                         (+ DRAFT, CANCELLED, DELETED allowed by CHECK)
  decided_by / decided_at / approved_at
  executing_at, executed_at
  reason, title, source_decision_id, deny_reason, evaluated_decision
  created_at
```

No stored decision/mask plan — enforcement is decided per statement at run. No
`connection` or `save_result` columns: editor/wire connection binding is
session-side; workflow always saves the encrypted child on success.

query_result (child, 1:N per task in schema; workflow creates one):

```
query_result
  id, task_id      FK access_request
  sql, sql_hash
  status           RUNNING | DONE | FAILED | CANCELLED
  columns JSONB, row_count          (null until DONE)
  ciphertext BYTEA                  (rows masked-per-R, then AES-256-GCM at rest; null until DONE)
  error_code                        (FAILED only)
  executed_by, executed_at, created_at, expires_at
```

- The child is the execution job: created at request create (SQL only), claimed
  `RUNNING` at run, updated to a terminal state.
- Rows are stored as R's execution-enforced result (what R produced in the
  executor's context), encrypted (`PM_RESULT_KEY`, fail-closed when unset). A
  view re-decides under exactly `{R}` in the viewer's context, masking further
  where that context requires — no precomputed ceiling.
- TTL + GC: every completed child carries `expires_at` (24 h retention via
  `QueryResultStore.RESULT_RETENTION_SEC`); the purge sweep
  (`RESULT_PURGE_INTERVAL_MS`, 15 min in `App.kt`) nulls expired payloads.
