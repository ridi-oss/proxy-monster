# cedar-sim — verifying "view the result as role R"

Backs [Viewing the result](../approval-workflow.md#viewing-the-result). Runs the
real Cedar engine to show that a viewer who assumes an approved task's role R
sees each `pii` column masked from anywhere and cleartext only from a 망분리
(segregated) node — and that a naive single "meta" policy cannot do it.

## Run

```sh
cargo install cedar-policy-cli --version 4.3.1   # matches the project's cedar-java
./run.sh
```

## What it shows

- Assume-R works. The viewer holds role R (`pii-reader`), and R's own column
  grants decide each column: `result.read.masked` on `pii` from anywhere,
  `result.read.unmasked` on `pii` only
  `when context.network_zones.contains("segregated")`. So `users.ssn` reads
  masked from the open network and cleartext from a segregated node; a viewer
  holding no role is denied both.
- A single "meta" policy leaks. One policy can gate on approval + requester but
  cannot reference R's own `when segregated` condition (Cedar has no
  meta-authorization), so it returns `pii` unmasked from anywhere. This is why
  the view mechanism relies on R-membership, not a one-liner.
- `audit.read` shape. One action with two resource shapes: an own-record
  condition (`resource.principal == principal`) and a whole-log collection
  (`AuditLog`, auditor-only). A user reads only their own records; an auditor
  reads any record and the whole log.

## Files

- `roles.cedarschema` + `role-grants.cedar` — role `pii-reader`'s column grants
  (`read.masked` pii anywhere; `read.unmasked` pii when segregated).
- `entities-assumed.json` — the viewer holds `pii-reader` (assume-R).
  `entities-none.json` — the viewer holds nothing (control: must be denied).
- `naive-model.cedarschema` + `entities-naive.json` + `naive-c-leaks.cedar` —
  the Request/ResultColumn model and the single "meta" policy that leaks.
- `audit.cedarschema` + `audit-policies.cedar` + `audit-entities.json` (+
  `ctx-empty.json`) — the audit design (see
  [Audit](../web-console.md#audit--cedar-gated-own-logs-for-non-admins)): one
  `audit.read` action; own records via a per-record condition, the whole log via
  an auditor-only collection resource.
- `ctx-open.json` / `ctx-segregated.json` — `network_zones` empty vs
  `["segregated"]`.
