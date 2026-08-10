# Web console

The `web/` console (Next.js App Router) is organized around five
role-appropriate areas: Editor, Workflows, Access, Audit, and Admin. The nav
lives in `components/app-shell.tsx`; Admin appears only when the viewer holds
admin permissions.

<!-- prettier-ignore -->
| Area | Route | What it is |
| --- | --- | --- |
| Editor | `/query` | SQL workbench |
| Workflows | `/workflows` | role-JIT + query approvals, unified |
| Access | `/access` | wire tokens |
| Audit | `/audit` | decision log |
| Admin | `/admin/*` | Datasources / Policies / Users / Groups (admin-gated) |

The Admin nav item and every `/admin/*` route render only when the viewer holds
`admin.*`. Nav visibility is a convenience — the server independently enforces
every admin API. The client learns the viewer's coarse capabilities from
`GET /api/me/permissions`, which returns
`{ isAdmin, canReadAllAudit, canApprove }` computed through `authorize()`.

## Editor — a DB workbench

`components/query/workbench.tsx` composes `schema-tree` + `sql-editor` +
`result-tabs`:

- Table list grouped by schema/database in `schema-tree` (collapsible, filter
  box, remembered expansion) rather than a flat list.
- Rich table detail (`table-view`, tabbed): columns (type, nullable,
  classification, mask function, default, size, index membership,
  auto-increment, comment, charset/collation), indexes, foreign keys (outbound
  and inbound), and metadata (engine, estimated rows, row format, on-disk size,
  table collation/comment). Live physical metadata is queried on demand so it
  reflects current DB state, captured proxy-side (the control-plane never dials
  a target) and returned over the table-detail channel — MySQL
  `information_schema` + `SHOW INDEX` / `SHOW TABLE STATUS`, PostgreSQL
  `information_schema` + `pg_index`/`pg_constraint`/`pg_class`
  (`goproxy/dialects/table_detail.go`); the control-plane overlays persisted
  column classification onto that payload. The admin Refresh
  (`POST /api/datasources/{id}/refresh`) nudges catalog freshness. A Data tab
  runs `SELECT * … LIMIT 100` through the same enforced editor session so
  masking and deny apply — not a bypass of the policy engine.
- A logs tab (`query-logs` in `result-tabs`): a SQL-console-style log of
  statements run this session — statement text, ALLOW/MASK/DENY with deny
  reason, rows, latency, errors, timestamp.
- The editor runs on a per-session target-DB connection (see
  [`connection-model.md`](./connection-model.md)), so `BEGIN…COMMIT`/`ROLLBACK`,
  `SET`/`USE`, and temp tables persist across statements. Enforcement stays
  per-statement: a statement referencing a masked column still denies
  mid-session.

## Workflows — an email-style request surface

`/workflows` is one place for all approval requests, read like a mailbox.
Master–detail: the left list has All / Incoming / Outgoing tabs; the right panel
shows the selected request. Incoming are pending requests the viewer may act on:
QUERY rows come from `/api/approvals/inbox` (filtered by
`authorize(task.approve)`); ROLE rows come from pending `/api/access-requests`
(list gated by `task.read`, with `task.approve` checked at decide time).
Outgoing are requests the viewer created. The two request kinds — role-JIT
(`ROLE`) and query approval (`QUERY`) — render in one list badged by kind,
aligning with [`approval-workflow.md`](./approval-workflow.md)'s shared request
spine. A new request opens as a draft inline in the main panel (compose →
submit). The nav badge is a single combined pending count.

## Audit — Cedar-gated, own-logs for non-admins

Searching the audit log is its own permission, and a non-admin sees only their
own decisions. One action `audit.read` covers two resource shapes:

- an individual record (`AuditRecord`, attr `principal`) — read your own:
  `permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };`
- the whole log as a collection (`AuditLog`) — admin-only:
  `permit(principal in Role::"system:admin", action == Action::"audit.read", resource);`

The resource carries the own-vs-all distinction, so there is no second
`audit.read.all` action. The list endpoint authorizes once against the
collection — `authorize(viewer, audit.read, AuditLog)` grants all rows,
otherwise it adds `WHERE principal = viewer` (the SQL projection of the
per-record condition). That is O(1) authz with no over-fetch; the per-record
form (`AuditRecord`) handles single-record reads. Cedar decides the capability;
the query filters the rows.

## Admin — one section, left-nav

`/admin` is a shell with a left sidebar for Datasources, Policies, Users, and
Groups. Only Policies has sub-nav: Roles, Assignments, Mask functions, and Cedar
policies surface as sidebar sub-items. The whole section is admin-gated.
