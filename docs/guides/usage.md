# Using proxy-monster

For developers who query databases through proxy-monster. It covers the four
things you will actually do: run a query in the console, read a masked result,
ask for access you do not have, and connect a local SQL client.

Configuring it — tags, roles, policy — is [admin.md](./admin.md). Installing and
deploying it is [INSTALL.md](../../INSTALL.md).

Substitute your own values for these throughout:

<!-- prettier-ignore -->
| Placeholder | What it is |
| --- | --- |
| `https://console.example.com` | The web console / control-plane URL |
| `analytics-dev` | A datasource tagged `system:development` |
| `analytics-prod` | A datasource tagged `system:production` |

## The one thing to understand first

proxy-monster decides **per statement**, per column, against your roles. Three
outcomes, and telling them apart saves you most of the confusion:

<!-- prettier-ignore -->
| Decision | What happened |
| --- | --- |
| `ALLOW` | Every column you touched is readable by your roles |
| `MASK` | The query ran; sensitive columns came back masked |
| `DENY` | Nothing ran |

A `system:development` datasource is configured to read cleartext — it is meant
to hold no production data. A `system:production` datasource masks columns
tagged `pii`.

Both descriptions assume an administrator has already set the deployment up:
roles assigned to you, the relevant policies enabled, and the sensitive columns
tagged. None of it is automatic, and a production datasource whose policies were
never enabled denies everything rather than masking. If the outcomes below do
not match what you see, that configuration is the first thing to check —
[admin.md](./admin.md) covers it.

## 1. Run a query against dev

Open the console at `https://console.example.com`, sign in with SSO, and go to
**Query**. Pick `analytics-dev` in the datasource selector, write SQL, and press
Run (or `⌘/Ctrl + Enter`).

```sql
select * from app.users limit 5;
```

The result badge reads `ALLOW` and values are cleartext. The schema tree on the
left lists every table you can see; a table with classified columns shows a
badge with a count, whatever names your administrator tagged them with.

## 2. Run the same query against production

Switch the datasource to `analytics-prod` and run it again:

```sql
select id, email, name from app.users limit 5;
```

Assuming `email` and `name` are the tagged columns, the badge now reads `MASK`
with a summary like `masked email name` — whichever columns your deployment
tagged are the ones listed. Masked cells render as `####` and each affected
column header carries a `masked` chip. The **Details** tab lists the decision,
the masked columns, and how many rows came back.

`####` is a masked value. A cell showing `NULL` is genuinely null in the
database — masking and emptiness are distinguishable on purpose.

### Selecting a column masks it; filtering on it denies

This is the rule that trips people up. Reading a sensitive column is fine — it
comes back masked. Using one in a `WHERE`, a `JOIN` condition, or a subquery is
denied outright:

```sql
-- MASK: email comes back as ####
select id, email from app.users limit 5;

-- DENY: nothing runs
select id, email from app.users where email like '%@example.com';
```

A mask is applied to the result stream after the database answers. A predicate
is evaluated _inside_ the database, so a masked value cannot be used there
without leaking what it hides — one row matching `where email = 'x'` reveals the
email whether or not the output is masked. proxy-monster fails closed rather
than allow that.

Rewrite the query so the sensitive column is only ever selected, or ask for
access (§3).

### Finding out why a query was denied

The result panel reads **Query denied** and gives the reason — for the query
above:

```
sensitive column def.app.users.email used in a subquery/reference
position (cannot be masked)
```

It also offers the three ways forward: **Request approval**, **Request access**,
and **View audit entry**. A denial is a decision, not a failure, so the editor
hands you the next step rather than an error to interpret.

**Audit** has the same decision with more around it — the failed stage, your
resolved roles at the time, and the full SQL. Go there when the reason alone is
not enough, or to find a denial from earlier.

## 3. Ask for access you do not have

When your roles cannot run a query, request it instead of asking someone to hand
you credentials. The denial offers two different routes, and picking the right
one saves a round trip:

<!-- prettier-ignore -->
| | What you get |
| --- | --- |
| **Request approval** | This one query, run once under a role that can read it. The result comes back to you; you never hold the role. |
| **Request access** | A time-boxed grant of the role itself. Once granted, re-running the query — and others like it — just works until the grant expires. |

Reach for **Request approval** when you need one answer, and **Request access**
when you have ongoing work in that data. The rest of this section walks through
Request approval; Request access is the same shape with a duration instead of a
query.

1. **Start the request.** From a denied audit row, click **Request approval** —
   the datasource and SQL are filled in. Or go to **Workflows** and compose one
   from scratch.
2. **Pick the role.** proxy-monster runs your query under each role you do not
   already hold and offers the ones it would not deny, showing the outcome each
   would produce and, beside it, the columns that would still come back
   **masked**. Pick from that list rather than guessing a role name — and read
   that list, since a role can appear here and still mask exactly what you need.
3. **Add a reason and submit.** The reason is what the approver reads, so make
   it specific: what you are investigating and why this data answers it.
4. **Wait for approval.** Whoever your deployment's policy gives `task.approve`
   over that role sees the request in their Workflows tab — administrators by
   default. Holding the role yourself does not make you an approver of it.
5. **The approver runs it.** Approving does not execute the query — it marks the
   request approved. The same approver then presses **Run query** on it, and the
   query runs under the approved role. Nothing happens until they do, so a
   request can sit approved-but-unrun; say so if you are waiting on one.
6. **Read the result.** The rows are stored encrypted with short retention (24h
   by default) and shown in the request. Viewing them re-applies masking as the
   **approved role**, in your live context — your own roles never widen or
   narrow it. That is the point: the approval is what lets you see data your
   ambient roles could not read.

An approval covers that one query only — you never hold the role afterwards.
(Request access is the other choice: it grants the role for a while.)

## 4. Connect a local SQL client

`pmon` is a small daemon that brokers your connections. It holds a short-lived
token and exposes a **fixed local address with a password that never changes**,
so a saved connection in TablePlus or DataGrip keeps working.

```sh
brew trust --formula ridi-oss/tap/pmon   # Homebrew 6 requires this for third-party formulae
brew install ridi-oss/tap/pmon

pmon login --url https://console.example.com
```

`pmon login` prints a URL and a code; open the URL, enter the code, approve. The
daemon starts on its own and opens one loopback listener per MySQL datasource
you can reach — there is no separate "connect" step. PostgreSQL datasources are
listed but not brokered yet; use the console for those.

```
$ pmon status
daemon:    running since 14:46 (22h38m0s ago)
principal: you@example.com
cp:        https://console.example.com
token:     2026-08-01 01:24 (in 12h0m0s)
session:   2026-07-31 15:24 (in 2h0m0s)

DATASOURCE      ENGINE  LOCAL           CONNS  PROXY
analytics-dev   mysql   127.0.0.1:6100  0      proxy.internal:6033 (TLS verified)
analytics-prod  mysql   127.0.0.1:6101  0      proxy.internal:6034 (TLS verified)
```

Then get a connection string for the client you use:

```sh
pmon show analytics-prod --url    # mysql://you%40example.com:pmlocal_…@127.0.0.1:6101/appdb
pmon show analytics-prod --jdbc   # jdbc:mysql://127.0.0.1:6101/appdb?user=…&password=…
pmon show analytics-prod --cli    # mysql -h 127.0.0.1 -P 6101 -u '…' -p'…' appdb
```

**TablePlus** — new MySQL connection, host `127.0.0.1`, port from `pmon status`,
user and password from `pmon show --url`. The password is checked, so paste the
one `pmon show` prints rather than any placeholder. Leave TLS off: the loopback
hop is plaintext by design, and the daemon holds the encrypted hop to the proxy.

**DataGrip** — new MySQL data source, paste the `--jdbc` string into the URL
field.

Your `@` is percent-encoded as `%40` in these strings. Paste the whole string
rather than retyping it, and if a GUI splits user and password for you, use the
decoded form (`you@example.com`) in the user field.

Every statement is still authorized and masked exactly as in the console — the
local listener is a convenience, not a bypass.

### Two clocks

`pmon status` shows both. The **token** is re-minted silently before it expires,
so you are not interrupted mid-session. The **session** (`PM_SESSION_WINDOW`, 2h
by default) is the renewal wall: once it closes the daemon stops re-minting and
`pmon status` reports `reauth: REQUIRED`.

Your connections do not drop at that moment. The token already issued keeps
brokering until its own TTL runs out — so you can be told to log in again and
still be working. Run `pmon login` when you see it, rather than waiting for
queries to start failing.

## Troubleshooting

**"You do not have access to connect to this datasource."** Your roles do not
grant `datasource.connect` there. This is authorization, not an outage — request
access, or ask an admin whether you should hold that role.

**A query on production is denied.** Read the reason on the result panel — nine
times out of ten it is a sensitive column in a `WHERE`, a `JOIN` condition, or a
subquery. Select it instead and it comes back masked (§2).

**`pmon` lists a datasource but no local address.** PostgreSQL datasources are
discovered and listed with a reason, not brokered. Use the console for those.

**A saved client connection suddenly fails.** Run `pmon status`.
`reauth: REQUIRED` means the session window closed and the daemon has stopped
renewing — the token it already holds keeps brokering until its own TTL runs
out, so connections fail only once that expires. Either way `pmon login` fixes
it, and the local address and password do not change, so the saved connection
works afterwards without editing it.

**Writes work but a migration denies.** Whether `INSERT`/`UPDATE`/`DELETE` and
DDL are permitted on a production datasource is a policy choice, and DDL is
commonly left off. Check with whoever administers your deployment before
scripting a migration through the proxy.

## Where things are

<!-- prettier-ignore -->
| | |
| --- | --- |
| **Query** | The SQL workbench, schema tree, and per-query decision |
| **Workflows** | Approval requests you raised, and ones awaiting you |
| **Access** | Your wire tokens |
| **Audit** | Every decision, with the reason a query was denied |
| **Admin** | Datasources, policies, users, groups (admins only) |

Configuring any of it — what gets tagged, who holds which role, which policies
are on — is [admin.md](./admin.md). What the parts are and how they fit together
is [ARCHITECTURE.md](../../ARCHITECTURE.md); the enforcement model is
[DESIGN.md](../../DESIGN.md).
