# Approval workflow — run a query under a role, once, via an approver

An approval request means _"run query Q under role R, once, and deliver the
result to the requester."_ It is the human-approval trigger of the unified task
model ([task-execution.md](./task-execution.md)): the workflow adds request
lifecycle, a human approver, and an encrypted result store on top of that model.
Everything authorization-shaped — who may approve, who may see the result, how
each column masks — is an ordinary Cedar decision, so the workflow owns
lifecycle and calls [authz-model.md](./authz-model.md) for decisions rather than
re-implementing policy.

Role R is the elevation unit — the same lever as JIT role-elevation, scoped to
one query's result instead of a time window. A workflow query runs on the proxy
at the `workflow-executor` channel under exactly `{R}`; its rows are stored as
R's execution-enforced output (masked per `{R}` in the executor's context) and
encrypted under AES-256-GCM. Reading a stored result requires assuming R (Cedar
`task.assume`), so a broad metadata admin who holds `task.read` sees that the
task exists but no rows.

## The request

- Request —
  `{ requester, datasource, sql, sql_hash, role_id (R), status, reason, title, source_decision_id, … }`
  on `access_request` (kind `QUERY`, `creator_kind = WORKFLOW`), with one
  `query_result` child holding the SQL. Queries needing different roles are
  separate requests. `source_decision_id` is the denied audit event a
  _from-denied_ request was raised from (null for a proactive compose).
- Role R (elevation unit) — an existing RBAC role whose grants let Q return what
  the requester needs (e.g. `ssn` cleartext). Found by role discovery, not typed
  by hand.
- Result — the executed rows, stored encrypted with short retention
  (`QueryResultStore.RESULT_RETENTION_SEC` = 24 h). It holds R's
  execution-enforced output; a later view re-masks further per the viewer's
  context but never reveals more than was stored.
- 망분리 / segregated — a network zone (Tailscale node identity), surfaced as a
  request-context tag (e.g. `trusted-network`).

## The flow

1. Compose. The requester writes Q + datasource, or arrives from a denied
   decision (auto-filled).
2. Role discovery. `POST /api/approvals/discover-roles` evaluates Q under
   candidate roles (preview via `decideQuery` on the `editor` channel in the
   requester's HTTP context) and offers the roles under which Q is not denied
   _and_ that return more than the requester's own roles (e.g. `ssn` unmasked).
   The requester picks R. Role-set parity with execute is `assumeRoles={R}`
   alone; channel/context can still diverge at run (execute uses
   `workflow-executor` in the approver's context).
3. Route + approve. Eligibility is exactly
   `authorize(approver, task.approve, request, context)` — the request is
   `in Role::R`, so approvers-of-R match. Single approval. Self-approval is not
   a workflow rule — it is whatever Cedar says (production typically ships a
   `forbid` requester ≠ approver; dev/eval may drop it). Create lands `PENDING`
   (default status); there is no separate DRAFT→submit step on the current
   routes.
4. Execute. After approval, the approver of record runs the query under role R
   at the `workflow-executor` channel (`POST /api/approvals/{id}/execute`,
   returns `202` with `decision: EXECUTING`; completion is polled). The proxy
   stores R's execution-enforced result encrypted on the `query_result` child.
   Gated by `task.approve`; an execute-once CAS (`APPROVED → EXECUTING` via
   `AccessStore.claimExecution`) rejects a second `/execute` with
   `409 approval.already_executed`.
5. View. `GET /api/approvals/{id}/result` first authorizes `task.assume` — may
   the viewer act as R for this task. An allowed viewer sees every column masked
   or unmasked by R's own grants, re-decided live at the `workflow-viewer`
   channel in the viewer's context. Expired payload → `410` with
   `approval.result_expired`.
6. Expire. Results expire → `410 Gone` + payload purge
   (`QueryResultStore.purgeExpired`, swept with `RESULT_PURGE_INTERVAL_MS` = 15
   min).

A new request must carry R — the create route rejects a null `roleId`
(`approval.role_required`) — so every approval is execute-under-R + view-as-R.

An approver is told a request is waiting, out of band
([notifications.md](./notifications.md)) — including the reverse lookup step 3's
per-caller eligibility check does not provide. They can also decide from there,
on the `slack` channel, which a policy can scope or forbid.

### Worked example

Column config: `users.ssn` is `tag:pii`. Role `pii-reader`: `read.masked` pii
anywhere, `read.unmasked` pii `when trusted-network`. Requester `alice` holds
`analyst` (masks ssn); she needs ssn.

- Compose: `SELECT id, name, ssn FROM users`.
- Discovery: under `analyst`, ssn masks; under `pii-reader`, ssn unmasks from a
  망분리 node. Offer `pii-reader`; alice picks it.
- Approve: approvers of `pii-reader` (Cedar). `bob` approves (`bob ≠ alice`).
- Execute: bob runs it under `pii-reader`, off-망분리. Off-network, R's verdict
  for `ssn` is MASK, so the encrypted stored result holds `ssn` masked — the
  run's own execution-enforced output, not a form widened and stashed for later
  viewing.
- View: Cedar permits alice to `task.assume` because she is the requester, so
  she is now exactly R. But the stored `ssn` is masked, so she sees `ssn` masked
  (`last4`) from both her desk and a 망분리 PC — a view re-decides under `{R}`
  and can mask further, never reveal what the execution masked. To deliver alice
  `ssn` cleartext, the run itself must execute from a 망분리 node (then storage
  holds it cleartext and an open-net view narrows it back to masked). bob (the
  approver) and a `system:auditor` may assume R too; a metadata-only admin may
  not.

## Viewing the result

The viewer must see the result as role R: each pii column masked from anywhere,
unmasked only from 망분리 — exactly R's own column grants, evaluated in the
viewer's context. This is the assume-R model of
[task-execution.md](./task-execution.md), two separate live Cedar decisions,
both keyed to R:

1. `task.assume` — may this principal act as R for this task. The metadata gate
   `task.read` (which an `admin` holds broadly) does not reach result data;
   `task.assume` is the confidentiality boundary that does. The default permits
   the task's requester, its approver, or a `system:auditor`, keyed on the
   request's `requester`/`approver` attributes and changeable by editing the
   policy.
2. `result.read.masked` / `result.read.unmasked` — per column, as exactly `{R}`
   in the viewer's live context (the `workflow-viewer` channel + the viewer's
   attested request context). The viewer's own roles never enter; while viewing,
   the viewer _is_ R. These are R's ordinary column grants — no new masking
   policy:

```cedar
permit(principal in Role::"pii-reader", action == Action::"result.read.masked",   resource in Tag::"pii");
permit(principal in Role::"pii-reader", action == Action::"result.read.unmasked", resource in Tag::"pii")
  when { context has tags && context.tags.contains("trusted-network") };
```

Because R's grants are re-evaluated live on every view, a view can mask further
than the stored form where the viewer's context is more restrictive — and
revoking R re-masks an un-purged result on the next view — but it can never
reveal a column the execution masked. So `ssn` reads cleartext at view only if
the run itself executed in an unmasking context (e.g. from 망분리).

A single "meta" policy cannot do this. One policy can gate on approval +
requester but cannot reference R's own `when trusted-network` condition (Cedar
has no meta-authorization), so it would return pii unmasked from anywhere.
Verified on the real Cedar engine in [docs/cedar-sim/](./cedar-sim/)
(`cedar-policy-cli 4.3.1`, the project's `cedar-java`).

## How it uses authz

- Approve / execute: `authorize(approver, task.approve, request, context)` — one
  action, `request in Role::R`.
- Execute run: `decideQuery` under `assumeRoles={R}` on the `workflow-executor`
  channel (via `RunExecService.run` + proxy `Decide`) → R's enforced result. A
  column R cannot read at all ⇒ Q-under-R denied ⇒ pick another role / narrow Q.
- Role discovery: the same `decideQuery(under candidate role, Q)`, one per
  candidate, with `assumeRoles={R}` alone — matching execute's role set (no
  offer-then-DENY skew on the role axis). Preview channel is `editor`, not
  `workflow-executor`.
- View: `task.assume` gates whether the viewer may act as R, then R's
  `result.read.*` grants mask each column as exactly `{R}` in the viewer's
  context.

## Data model

- `access_request` (kind `QUERY`, `creator_kind = WORKFLOW`) —
  `{ id, principal, datasource_id, role_id (R), execute_as, reason, title, source_decision_id, status PENDING|APPROVED|REJECTED|EXECUTING|EXECUTED| FAILED|CANCELLED|DELETED (+ DRAFT allowed by CHECK), decided_by, decided_at, approved_at, executing_at, executed_at, created_at }`.
  `role_id` / `execute_as` are the elevation target; the execute-once CAS is
  `APPROVED → EXECUTING` (`claimExecution`); `executed_at` is stamped only on
  terminal `EXECUTED`.
- `query_result` — the encrypted result child (`task_id` FK), holding R's
  execution-enforced rows (AES-256-GCM via `ResultCrypto` / `QueryResultStore`,
  24 h retention). Status `RUNNING|DONE|FAILED|CANCELLED`. No per-column
  decision is stored — masking is re-decided live at each view.

The full task-and-child shape (status states, timestamps) is in
[task-execution.md](./task-execution.md#data-model); the approval workflow is
the WORKFLOW creator over it.

## Security invariants

- Deny-by-default throughout; anything unresolved → deny. Fetch/store errors →
  no result.
- Self-approval is governed by Cedar policy, not the workflow — production
  typically ships a `forbid` (requester ≠ approver); dev/eval may drop it. The
  workflow only requires `authorize(task.approve)` = ALLOW.
- A viewer sees the result exactly as role R would in their live context — pii
  masked off-망분리, for the requester and the approver; never more, never less.
- Execution runs under R (not the approver's incidental roles) → the result is
  deterministic and is what R would see; the approver vouches by running it.
- Approvers need not hold R. A non-member approves and executes _under R_ —
  bounded to the approved query, audited, and still view-gated by R's conditions
  (they see pii only from 망분리). Deliberate consequence: no one has standing
  elevated access — even an approver must file and get a request approved to run
  an elevated query, so separation-of-duty falls out of the model.
- The result is encrypted at rest, short-retention, purged on expiry; every
  execute / view is audited.
- assume-R is view-scoped — it never lets a viewer run _new_ queries as R:
  assuming R applies only to the result-view (and execute) decision for that one
  task, never to ambient query authorization.
