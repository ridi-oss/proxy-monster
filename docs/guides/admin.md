# Administering proxy-monster

For the person who configures proxy-monster: what to tag, which policies to
enable, how roles reach people, and how to drive all of it from an agent.

Developers querying through it want [usage.md](./usage.md) instead — this guide
assumes you are the one deciding what they can see.

## The model

Five pieces. Once these fit together the rest of the guide is mechanics.

**Datasource.** One target database behind one proxy. It carries **tags** —
free-form strings describing its posture.

**Column tags.** Strings attached to a column, overlaid on the catalog. Tags are
data, not authorization: tagging a column changes nothing until a policy
mentions the tag.

**Roles.** What a person holds. Roles come from group membership, direct
assignment, or a time-boxed grant from the approval workflow. Never asserted by
the client — always resolved server-side.

**Actions.** What someone can do to a resource. Policy permits or forbids each
one:

<!-- prettier-ignore -->
| Action | On | Asked when |
| --- | --- | --- |
| `datasource.connect` | datasource | Connecting |
| `sql.select` `sql.insert` `sql.update` `sql.delete` `sql.ddl` | datasource | Running that kind of statement |
| `sql.unanalyzable` `sql.unmaskable` | datasource | A statement the analyzer cannot prove safe, or a result it cannot mask |
| `result.read.unmasked` | column, table, function, utility | Returning a value in cleartext |
| `result.read.masked` | column, table, function, utility | Returning it masked |
| `task.request` | datasource | Raising a request against it |
| `task.approve` `task.assume` `task.cancel` `task.delete` | request | Deciding, running, or withdrawing one |
| `task.read` | request, grant | Reading either |
| `grant.revoke` | grant | Ending a live grant |
| `token.mint` `token.list` `token.revoke` | token | Managing wire credentials |
| `audit.read` | audit record | Reading the decision log |
| `admin.datasources` `admin.policies` `admin.identity` | the instance | Administering it |

**Policy.** [Cedar](https://www.cedarpolicy.com/) rules over principal × action
× resource, with the resource's tags in scope. A `permit` allows; a `forbid`
overrides every permit.

Nothing runs without a matching `permit`. That is the whole security posture:
**an action nobody permitted is denied** — absence never means allow. The one
carve-out is a temp table on your own session: you created it, so reading it
back needs no grant.

## Tags are your vocabulary

`system:production`, `system:development`, and `pii` are not keywords. They are
the strings the shipped presets happen to reference. A tag reaches Cedar as
itself and the policy decides what it means, on a datasource and on a column
alike.

So model your own scheme. `pci`, `gdpr`, `internal-only`, `team-finance`,
`tier-1` all work: tag the resource, write a policy that mentions the tag, and
it carries exactly the weight you gave it. A datasource tag covers everything
under that datasource; a column tag covers one column. Either can hold several.
The presets are one worked example, not the model.

Two things to know:

- **`system:` names belong to the product.** You cannot coin one: a write naming
  `system:anything-else` is refused. The six that exist — the two postures plus
  the four shipped classifications `system:critical`, `system:data-leak`,
  `system:activity`, `system:catalog` — you may set on any resource, and they
  reach policy like any other tag.

  Do so deliberately. The shipped presets key on these names, so putting one
  where you did not mean it changes what those presets grant: `system:catalog`
  on a datasource matches a permit that reads every column under it in
  cleartext, and `system:critical` on a column reaches the forbid that denies
  it. The tags the shipped classifier applies to system tables come from its
  manifest per statement and are resolved separately from anything you write.

- **A datasource tag decides for everything under it.** Tables and columns
  inherit it, so a datasource tagged `pii` masks every column beneath it under
  the shipped presets, whatever each column's own classification says. Classify
  columns when you mean columns.

## Configuring, in order

Order matters — each step is inert until the one after it.

### 1. Tag the datasource

A datasource's tags arrive when its proxy registers (`PM_DATASOURCE_TAGS`), so
posture is set where the proxy is deployed, not edited in the console. A
datasource tag covers every table and column under it, which is what lets one
policy cover every production datasource at once — `system:production` if you
use the presets, or your own tag if you write your own policies.

### 2. Tag columns

Console: **Admin → Datasources → a table → a column**. Or over MCP (below),
which is how you tag two hundred columns without two hundred clicks.

A column can carry several tags. Tagging is idempotent — re-tagging replaces
that column's tag set.

**Tag before the schema arrives.** A classification is stored against the
datasource, not against the catalog, and a catalog refresh never removes one. So
you can tag a column that does not exist yet: the row sits dormant, and the
moment that schema appears in the datasource's catalog it starts masking.

That ordering is the safe one. The alternative — grant access to a new schema,
then remember to tag it — leaves the data readable in cleartext for exactly as
long as it takes someone to notice. Tag first and there is no such window.

Two consequences of storing tags independently:

- **A dormant tag is invisible in `list_column_tags`,** which is built from the
  catalog outward. Absence there means "not in this catalog", never "not tagged"
  — do not read a short listing as missing coverage.
- **This is the same mechanism as a typo.** A misspelled column and a
  not-yet-existing one are indistinguishable to the system, which is why the
  next section says to validate names against `browse_catalog` and keep your own
  record of what you intended to tag.

### 3. Enable policy

The **production** presets ship disabled; the development ones ship enabled,
along with the base capabilities (admin bootstrap, audit, the approval workflow,
tokens, and the system-object guards). So a `system:development` datasource is
connectable as soon as someone holds any `system:development-*` role, while a
`system:production` datasource denies everything until you turn its presets on.

Each role carries its own verbs: viewer and pii-accessor select, updater inserts
and updates, deleter deletes, architect runs DDL. Connect is the only one all
five share, so a deleter can attach and run nothing else.

That asymmetry is deliberate — production access is never granted by installing
something — and it is the most common "why is everything denied" surprise.

In **Admin → Policies → Cedar policies**, enable the ones you want. A working
production set is typically:

- connect, so people can reach it at all
- select (and insert/update/delete if they should write)
- masked read for columns tagged `pii`, so those come back `####` rather than
  denied
- unmasked read for everything else

Note the literal name: these two presets key on the tag `pii` specifically. A
column you tagged `pci` or `confidential` is not covered by either, so it falls
through to whatever else you have written — enable them as-is and you are
adopting `pii` as your vocabulary, or copy them onto your own tag.

Cleartext PII is a separate decision, and there are two independent presets for
it, both scoped to `system:production-pii-accessor` rather than to any
production role. One grants a standing unmask on a trusted network; the other
grants it only to the approval workflow's executor. Prefer the second — an
approved, audited, one-query release beats a standing grant — but note that it
must be **enabled** for approvals to return cleartext at all. Leave both off and
an approved query comes back masked if the masked-read preset is on, and denied
if it is not.

DDL is worth a separate decision. Enabling `sql.ddl` on a production datasource
means migrations can run through the proxy; leaving it off means they cannot.

### 4. Map groups to roles

Your IdP's group claim provisions a **local group**; the local group carries
roles. The IdP never names a role directly, so renaming a role does not require
touching the IdP, and an IdP group that maps nowhere grants nothing.

Reading back someone else's _effective_ roles is the gap. The account menu shows
the resolved set for whoever is signed in, not for another person.
`/admin/users` lists a person's group memberships, group detail lists a group's
mapped roles, and `list_role_assignments` over MCP shows only **direct**
assignments — so a person whose access comes from a group or a live JIT grant
appears in none of them as holding it. Compose the answer from the group
memberships plus the `group_role` map, and check Access for a live grant.

### Mask functions

A masked column returns a deterministic replacement. Assign a mask function per
column when the default is not what you want — for example preserving a value's
shape so an application still parses it, or nulling it entirely. Manage these in
**Admin → Policies → Mask functions**.

## Deciding on where a request comes from

Sometimes the answer depends on more than who is asking. "Cleartext PII, but
only from the office network" and "this role, but only through the approval
workflow" are conditions on the **request**, not the principal.

Every decision carries a context the control plane attests. A policy reads it
with `context`:

- `channel` — which surface the request came through: `wire`, `editor`,
  `workflow-executor`, `workflow-viewer`, `mcp`.
- `requester_ip` — the client's source address, as a Cedar `ipaddr`.
- `tags` — named conditions you define (below).

None of it is client-supplied. A caller cannot claim a channel or an address.

### Context tags — name the condition once

You could compare `requester_ip` in every policy that cares, but then a network
change means editing all of them. Instead define the condition once as a
**context tag**: a rule that grants a name, which other policies then read.

A tag rule is an ordinary Cedar policy on a `context.tag::<name>` action:

```cedar
permit(principal, action == Action::"context.tag::trusted-network", resource)
  when { context has requester_ip
         && context.requester_ip.isInRange(ip("100.100.0.0/16")) };
```

Policies then condition on the name:

```cedar
permit(principal in Role::"pii-reader",
       action == Action::"result.read.unmasked",
       resource in Tag::"pii")
  when { context has channel && context.channel == "workflow-viewer"
         && context has tags && context.tags.contains("trusted-network") };
```

Now the CIDR lives in one place. Changing the range is a one-line edit and every
consuming policy is untouched.

Tags resolve in a pre-pass before the real decision, so a tag rule may condition
on `channel`, `requester_ip`, the principal, and the datasource — but **never on
another tag**. There is no tag-on-tag.

Enabling a `context.tag::…` rule is what brings its name into existence. The
shipped `trusted-network` example is disabled and its range is a placeholder —
enable it only after setting your own CIDR.

### Two ways this bites

**A missing tag is silently false.** If a rule is disabled, misspelled, or does
not fire, `context.tags.contains("…")` is false and the grant conditioned on it
simply does not apply — deny, no error. That is the fail-closed behavior you
want, but it means a typo reads as "access denied" rather than "broken policy".
The control plane lints for this: `GET /health` returns a `diagnostics` array
naming any tag consumed with no producer (likely a typo) or produced with no
consumer (a dead rule). Check it after editing tag rules — nothing surfaces it
in the console.

**Guard every read.** Cedar rejects an unguarded read of an optional context
attribute, and every context attribute is optional. Always pair them:
`context has tags && context.tags.contains("…")`. Testing a policy against a
request that lacks the attribute is the fastest way to catch a missing guard.

## Driving it from an agent (MCP)

The control plane exposes an OAuth-2.1 MCP server, which is the practical way to
do bulk work — tagging a hundred columns, auditing what is classified, checking
which policies are enabled.

```sh
claude mcp add --transport http proxy-monster https://console.example.com/mcp
```

Then authenticate; the flow runs in your browser. Name the server per instance
if you administer more than one (`proxy-monster-dev`, `proxy-monster-prod`) —
the tools are identical, so the name is the only thing telling you which system
you are about to change.

**MCP is an admin surface only.** All 39 tools authorize as `admin.datasources`,
`admin.policies`, or `admin.identity`. Every SQL and result-read action is
excluded, so **MCP cannot read a row of data** — no query, no result set, not
even masked. An agent given these tools can reconfigure access; it cannot read
what access protects.

Roughly: datasources and catalog, column tags, Cedar policies, roles, users, and
groups — reads plus their corresponding writes.

Two things to know before pointing an agent at it:

**Scope is a ceiling, never a grant.** The OAuth scope (`mcp:read`,
`mcp:datasources:write`, `mcp:policies:write`, `mcp:identity:write`) bounds what
a token may attempt. Cedar still decides. Holding a write scope while lacking
the role denies, and there is no scope that substitutes for a role.

**Column tags are not validated against the catalog.**
`set_column_classification` accepts a column that does not exist and returns
success. That is deliberate — it is what makes pretagging possible — but it
means a typo is accepted just as readily, and the two are indistinguishable
afterwards. Neither appears in `list_column_tags`, so a misspelling looks like a
successful tag and then leaves no trace.

So on a bulk run, validate every name against `browse_catalog` first, keep the
intended list, and reconcile afterwards: for each column the listing does not
show, decide whether it is dormant (genuinely not in this catalog yet) or a
mistake. A count alone cannot tell you which, and "short by four" reads
identically in both cases.

## FAQ

**Why do error messages differ through the proxy?**

Because a database's own error text quotes the data. MySQL reports
`Truncated incorrect INTEGER value: '010-1234-5678'`; PostgreSQL adds
`DETAIL: Failing row contains (…)` and dumps the whole row — including columns
the statement never named. That is a side-channel around masking: the rows are
masked, and then the error hands the value over anyway.

So where the principal is not entitled to the cleartext, the proxy replaces the
free-form message with the code's canonical identity — PostgreSQL `23514`
becomes `check_violation`, MySQL `1146` becomes `ER_NO_SUCH_TABLE`. On
PostgreSQL it also drops `Detail`, and the structured fields survive — SQLSTATE,
schema, table, column, and constraint names — so a genuine error stays
diagnosable. Fields the proxy does not recognize are dropped, since their
content cannot be classified.

The engine decides when this applies. PostgreSQL can leak through a diagnostic
even on a plain `ALLOW`, because `Detail` dumps columns the statement never
named, so it is redacted there too. MySQL echoes only the value the statement
operated on, and reading a protected column's value is already denied — so a
MySQL `ALLOW` is not redacted, and the `Truncated incorrect INTEGER value`
message above is what you will actually see. Masked and denied decisions are
redacted on both engines.

The message is looked up from the numeric code, never rebuilt from the text the
database returned, because a crafted value can imitate the delimiters and
smuggle itself back through.

The exemption is one specific grant: `result.read.unmasked` **on the
datasource** — a full-cleartext reader, someone no diagnostic can leak anything
to. It is not computed per column, so a policy that unmasks every column a query
touched but grants nothing datasource-wide still gets redacted messages. Two
people can therefore see different text for the same error; that is the design,
not an inconsistency.

An unrecognized code degrades to a generic message rather than passing through.

**Everything is denied and I do not know why.**

Check in this order: is the datasource's connect policy enabled; is the
statement kind permitted; does the person actually hold the role the policy
names. The audit log gives you the answer directly — the failed stage and the
reason are on the decision.

**I tagged columns and nothing changed.**

Tags without a policy that mentions them do nothing. Enable the matching policy.

**Should I write Cedar by hand?**

Prefer the presets and the console. Hand-written policy is how an unintended
`permit` gets in, and a `forbid` you did not expect blocks something legitimate.
When you do write one, validate before enabling — `validate_policy` over MCP, or
the console's validation.

**Can an admin read production data?**

Not by being an admin. `admin.*` covers configuration; reading rows needs the
data actions like any other principal.

An admin can of course grant themselves the role. Every query they then run is
in the audit log — but the assignment itself is not: a role assigned through the
console or the REST API writes no audit event. Assignments made over MCP are
recorded as MCP operations, and toggling one of the **shipped** policies is
recorded; toggling a policy you wrote yourself is not. Treat `admin.identity` as
the powerful grant it is, and review assignments and your own policies directly
rather than expecting the audit log to surface them.
