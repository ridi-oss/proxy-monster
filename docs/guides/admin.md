# Administering proxy-monster

For the person who configures proxy-monster: what to tag, which policies to
enable, how roles reach people, and how to drive it from an agent.

Developers querying through it want [usage.md](./usage.md) instead.

## The model

**Datasource.** One target database behind one proxy. It carries tags — strings
describing its posture.

**Column tags.** Strings attached to a column, stored apart from the catalog.
Tagging changes nothing until a policy mentions the tag.

**Roles.** What a person holds: from group membership, direct assignment, or a
time-boxed grant from the approval workflow. Always resolved server-side, never
asserted by the client.

**Actions.** What someone can do to a resource. Policy permits or forbids each:

<!-- prettier-ignore -->
| Action | On | Asked when |
| --- | --- | --- |
| `datasource.connect` | datasource | Every statement, before anything else |
| `stmt.cat.read` `stmt.cat.write.insert` `stmt.cat.write.update` `stmt.cat.write.delete` `stmt.cat.ddl` `stmt.cat.metadata` `stmt.cat.session` `stmt.cat.admin.*` | datasource | Running a statement of that category |
| `stmt.kind.<kind>` | datasource | The same, for one kind (`stmt.kind.select`, `stmt.kind.set_session_var`, …) |
| `exception.unanalyzable` `exception.unmaskable` | datasource | Relaying a statement the analyzer cannot prove safe, or a result the proxy cannot mask |
| `result.read.unmasked` `result.read.masked` | column, table, function, utility | Returning a value in cleartext, or masked |
| `result.cap` | column, table, datasource, … | Never for access; carries the `@cap` limits (below) |
| `native.invoke` | native resource | An Athena API call other than running a query |
| `task.request` | datasource | Raising a request |
| `task.approve` `task.assume` `task.cancel` `task.delete` | request | Deciding, viewing the result of, or withdrawing one |
| `task.read` | request, grant | Reading either |
| `grant.revoke` | grant | Ending a live grant |
| `token.mint` `token.list` `token.revoke` | token | Managing wire credentials |
| `audit.read` | audit record | Reading the decision log |
| `admin.datasources` `admin.policies` `admin.identity` | the instance | Administering it |

Each `stmt.kind.*` is a member of its category, so a permit on `stmt.cat.read`
covers `stmt.kind.select`, and a forbid on one kind overrides a category permit.
Match a category with `in`: `action in [Action::"stmt.cat.read"]`.
`get_policy_schema` over MCP returns the full schema.

**Policy.** [Cedar](https://www.cedarpolicy.com/) rules over principal × action
× resource, with the resource's tags in scope. A `forbid` overrides every
`permit`. Nothing runs without a matching `permit`: absence never means allow.
The one carve-out is a temp table your own session created.

## Tags are your vocabulary

`system:production`, `system:development`, and `pii` are not keywords. They are
the strings the shipped presets reference. A tag reaches Cedar as itself and the
policy decides what it means. Model your own scheme — `pci`, `gdpr`,
`team-finance` — by tagging the resource and writing a policy that mentions the
tag. A datasource tag covers everything under it; a column tag covers one
column.

- `system:` names belong to the product. A write naming any other `system:` tag
  is refused. The six that exist — `system:production`, `system:development`,
  and the classifications `system:critical`, `system:data-leak`,
  `system:activity`, `system:catalog` — you may set, and they reach policy like
  any tag. Do so deliberately: `system:catalog` on a datasource matches a permit
  that reads every column under it in cleartext, and `system:critical` on a
  column reaches the forbid that denies it.
- A datasource tag decides for everything under it. A datasource tagged `pii`
  masks every column beneath it under the presets. Classify columns when you
  mean columns.

## Configuring, in order

Each step is inert until the next.

### 1. Tag the datasource

Datasource tags arrive when its proxy registers (`PM_DATASOURCE_TAGS` on the
proxy), so posture is set where the proxy is deployed, not in the console.

### 2. Tag columns

Console: **Admin → Datasources → a datasource → a column's `+ classify`**. Set
tags and, optionally, a mask function. **Export** and **Import** move a
datasource's classifications as a file. Over MCP, `set_column_classifications`
writes up to 500 columns of one datasource in one all-or-nothing call.

A classification is stored against the datasource, not the catalog, and a
catalog refresh never removes one. So tag a column before its schema exists: the
row sits dormant and starts masking the moment the column appears. Tagging after
granting access leaves the data readable until someone notices.

The flip side:

- A dormant tag is invisible in `list_column_tags`, which is built from the
  catalog. Absence there means "not in this catalog", never "not tagged".
- A typo is stored the same way. `set_column_classification` accepts a column
  that does not exist and returns success. On a bulk run, check every name
  against `browse_catalog` first and reconcile afterwards.

### 3. Enable policy

The development presets ship enabled; every production preset ships disabled. A
`system:production` datasource denies everything until you enable them in
**Admin → Policies → Cedar policies**.

Shipped roles:

<!-- prettier-ignore -->
| Role | Production gets |
| --- | --- |
| `system:production-viewer` | `SELECT`; non-PII cleartext, PII masked |
| `system:production-pii-accessor` | Viewer, plus PII cleartext on the trusted network or as an approved run |
| `system:production-exporter` | Pii-accessor with no result cap or rate. Grant for a window, not permanently |
| `system:production-updater` | `INSERT`, `UPDATE` |
| `system:production-deleter` | `DELETE` |
| `system:production-architect` | DDL |
| `system:development-*` (five) | The same split on development; everything reads cleartext except `system:critical` |
| `system:admin` | Administration (`admin.*`), approving every request, the whole audit log. Reads no data |
| `system:auditor` | Viewing the saved result of any request |

`system:admin` and each production role have a same-named system group;
`system:developer` carries all five development roles.

Production presets, all disabled by default:

<!-- prettier-ignore -->
| Policy | Grants |
| --- | --- |
| `system:production-connect` | `datasource.connect` for all six production roles |
| `system:production-select` | `stmt.cat.read` for viewer, pii-accessor, exporter |
| `system:production-insert` / `-update` / `-delete` / `-ddl` | The write categories for updater, deleter, architect |
| `system:production-metadata` | `SHOW`, `DESCRIBE`, `SHOW WARNINGS`, … for anyone who can connect |
| `system:production-session` | `SET`, `USE`, `BEGIN`, `COMMIT`, … for anyone who can connect |
| `system:production-non-pii-read` | Unmasked read of everything not tagged `pii` or a `system:` classification |
| `system:production-pii-masked` | Masked read of `pii` columns |
| `system:production-pii-unmasked-trusted-network` | Cleartext `pii` for pii-accessor and exporter when the request carries the `trusted-network` context tag |
| `system:production-pii-unmasked-workflow-executor` | Cleartext `pii` for pii-accessor and exporter when an approved request runs |
| `system:production-explain-unmasked` | Cleartext `pii` for pii-accessor under a plan-only `EXPLAIN` |
| `system:trusted-network-tailscale-example` | Produces the `trusted-network` tag for `100.100.0.0/16` — a placeholder; set your range first |

A working production set is connect, select, non-PII read, PII masked, metadata,
and session. Without the session preset, `SET`/`USE`/`BEGIN` are denied, and
many drivers and GUI clients send a `SET` while connecting, so they fail right
away. Without metadata, `SHOW TABLES` and `DESCRIBE` are denied.

The PII presets key on the literal tag `pii`. A column tagged `pci` is covered
by neither the masked nor the unmasked preset, so it falls through to deny.
Enable them as-is and you adopt `pii` as your vocabulary, or copy them onto your
own tag.

For approved PII, the run and the view are decided separately. The run executes
on the `workflow-executor` channel, so the workflow-executor preset stores
cleartext. The view re-decides as the approved role on the `workflow-viewer`
channel from the viewer's network, so the requester sees cleartext only where
the trusted-network preset also applies; elsewhere the stored value comes back
masked.

Enabled guardrails you normally leave alone: `system:session-channel-forbid`
(session statements only on the editor and wire), the `system:` classification
floors (`system:critical-guard` and friends), and the result caps below.

### 4. Map groups to roles

The IdP's `groups` claim provisions local groups at login; local groups carry
roles (**Admin → Groups → a group → Map role**). The IdP never names a role. An
IdP group reaches a `system:` group only through an explicit entry in
`PM_OIDC_GROUP_MAP`:

```sh
PM_OIDC_GROUP_MAP='db-admins=system:admin,db-readers=system:production-viewer'
```

Reading someone else's effective roles takes composing: **Admin → Users** shows
their groups, a group shows its mapped roles, `list_role_assignments` shows only
direct assignments, and **Workflows → Active grants** shows JIT grants. A user
reads their own resolved set from the identity menu or `get_my_permissions`.

### Mask functions

A masked column shows `####` unless you assign a mask function — keep the last
four, preserve the format, or return `NULL`. Manage them in **Admin → Policies →
Mask functions** and pick one when classifying a column.

## Result caps

Limits are `@cap` annotations on permits for `result.cap`, an action that grants
nothing. The shipped, enabled rows:

```cedar
@cap("5000, 50MB, 10000/1h, 50000/1d, 100MB/1h, 500MB/1d")
permit (principal, action == Action::"result.cap", resource);            // system:result-cap-default

@cap("500, 5MB")
permit (principal, action == Action::"result.cap", resource)
when { resource is Column && resource.tagged && context has masked && !context.masked };  // system:result-cap-clear

forbid (principal in Role::"system:production-exporter", action == Action::"result.cap", resource);  // system:result-cap-exporter
```

A bare amount caps one result; `<amount>/<window>` is a rate over the
principal's relayed volume on that datasource. The tightest matching cap wins; a
`forbid` lifts every limit. With every row disabled the control plane still caps
at 5,000 rows / 50 MB. To change the numbers, disable a row and write your own.

A spent rate denies with `rate 10000/1h spent`. Reset it from **Admin → Users →
a user → Reset result rates**, `reset_principal_rate` over MCP, or by approving
the user's rate-reset request in **Workflows**.

## Approvals

`task.approve` decides who approves. The shipped `system:admin-approver` gives
it to `system:admin`; `system:no-self-approval` stops anyone approving their own
request. Write a `task.approve` permit scoped to a role or datasource
(`resource in Role::"…"`) to route approvals elsewhere.

Approvers are notified in Slack when `PM_SLACK_BOT_TOKEN` and
`PM_SLACK_APP_TOKEN` (Socket Mode) are set. Each approver is found by email and
gets a DM with **Approve and run**, **Deny**, and **Open request**; the message
offers approval only when it shows the whole statement. `PM_NOTIFY_STATEMENT`
(`omit`, `auto`, `full`) controls how much SQL appears. A Slack click is decided
on the `slack` channel with no `requester_ip`, so a policy conditioned on the
address denies it there.

## Deciding on where a request comes from

Every decision carries a context the control plane attests; a client cannot
supply it. A policy reads it with `context`:

- `channel` — `wire`, `editor`, `mcp`, `workflow-executor`, `workflow-viewer`,
  or `slack`.
- `requester_ip` — the client's source address, as a Cedar `ipaddr`.
- `tags` — named conditions you define (below).
- `stmt_kind` — the statement's kind (`select`, `explain`, …).
- `masked` — on a `result.cap` ask only: whether this column reads masked.
- `native_operation` — the Athena operation on a `native.invoke` ask.
- `network_zones` — declared, always empty; use `requester_ip` and tags.

### Context tags — name the condition once

Define a condition once as a rule on a `context.tag::<name>` action:

```cedar
permit (principal, action == Action::"context.tag::trusted-network", resource)
when { context has requester_ip && context.requester_ip.isInRange(ip("10.20.0.0/16")) };
```

Policies then read the name:

```cedar
permit (principal in Role::"pii-reader", action == Action::"result.read.unmasked", resource in Tag::"pii")
when { context has tags && context.tags.contains("trusted-network") };
```

Tags resolve before the real decision, so a tag rule may read `channel`,
`requester_ip`, the principal, and the datasource — never another tag.

Two ways this bites:

- A missing tag is silently false. A disabled or misspelled rule means
  `contains("…")` is false and the grant does not apply — a deny, no error.
  `GET /health` returns a `diagnostics` array naming any tag consumed with no
  producer or produced with no consumer. Check it after editing tag rules.
- Guard every read. Every context attribute is optional, and Cedar rejects an
  unguarded read: write `context has tags && context.tags.contains("…")`.

## Driving it from an agent (MCP)

The control plane is an OAuth 2.1 MCP server at `https://pm.example.com/mcp`.
Connect from the identity menu → **Connect an agent**, or:

```sh
claude mcp add --transport http pmon-prod https://pm.example.com/mcp
```

Name each instance distinctly — the tools are identical, so the name is all that
tells you which system you are about to change.

The server has about 80 tools. Admins use the datasource, catalog, tag, policy,
role, mask-function, user, group, token, and rate tools; developers use
`run_query` and the approval and access tools. `run_query` returns rows under
the caller's roles, masked exactly as in the console. No tool asks
`result.read.*`, `result.cap`, `native.invoke`, or `exception.*` directly; those
are decided only inside a query.

Tools worth knowing:

- `set_column_classifications` — bulk tagging, all or nothing, up to 500
  columns.
- `get_policy_schema`, `validate_policy` — check Cedar before `create_policy`.
- `create_datasource`, `update_datasource`, `refresh_datasource`,
  `test_datasource` — pre-provision a datasource, ask its proxy to re-push the
  catalog, check that a proxy is attached.
- `list_audit`, `get_audit_event` — the decision log.

Scope is a ceiling, never a grant. Cedar still decides every call; a write scope
without the role denies.

<!-- prettier-ignore -->
| Scope | Covers |
| --- | --- |
| `mcp:read` | Read tools, audit, own permissions, token listing |
| `mcp:query` | Queries, own tasks, approval and access requests, rate-reset requests |
| `mcp:approvals:write` | Approve, reject, and run approvals; decide access requests; revoke grants |
| `mcp:datasources:write` | Datasource writes and classifications |
| `mcp:policies:write` | Policies, roles, mask functions |
| `mcp:identity:write` | Users, groups, members, role assignments, rate resets |
| `mcp:tokens` | Mint and revoke your own wire tokens |

A pmon login grants `mcp:read` and `mcp:query`; `pmon login --scopes` asks for
more, approved on the browser page and lasting `PM_ELEVATED_SCOPE_TTL` (1 hour
by default). pmon's MCP tokens sit under an OAuth consent for the client `pmon`;
revoking that consent (`DELETE /oauth/consents/{id}`; `GET` lists them) revokes
its tokens and ends the pmon logins that used it. The console has no page for
it.

## FAQ

**Why do error messages differ through the proxy?**

A database's own error text quotes data. MySQL reports
`Truncated incorrect INTEGER value: '010-1234-5678'`; PostgreSQL adds
`DETAIL: Failing row contains (…)` with the whole row. So where the caller could
learn something masked, the proxy replaces the message with the code's name —
PostgreSQL `23514` becomes `check_violation`, MySQL `1146` becomes
`ER_NO_SUCH_TABLE` — and drops PostgreSQL's `Detail`. SQLSTATE, schema, table,
column, and constraint names survive. An unknown code becomes
`target-DB diagnostic details are redacted on this connection (proxy-monster)`.

It applies per statement and per column. A `MASK` or `DENY` always redacts. An
`ALLOW` redacts unless the caller reads unmasked every column the error could
echo: the referenced columns, plus the whole target row for a PostgreSQL write.
So two people can see different text for the same error.

**Everything is denied and I do not know why.**

Open the decision in **Audit**: the failed stage and reason are there. Then
check that the connect preset is on, the statement kind is permitted (session
and metadata included), and the person holds the role the policy names.

**I tagged columns and nothing changed.**

Tags do nothing until a policy mentions them.

**Should I write Cedar by hand?**

Prefer the presets. When you do write one, `validate_policy` (or the console's
validation) before enabling it. Shipped `system:` policies can only be enabled
or disabled; copy one to change it.

**Can an admin read production data?**

Not by being an admin: `admin.*` covers configuration, and `system:admin` holds
no read grant. An admin can grant themselves a role. Every admin write — console
or MCP — records an audit event: role assignments, group and user changes,
policy create, update, enable, and disable, classifications, and datasource
changes. So does every query they then run.
