# Using proxy-monster

For developers who query databases through proxy-monster: run a query in the
console, read a masked result, understand a denial, ask for access, and connect
SQL clients and agents.

Configuring it — tags, roles, policy — is [admin.md](./admin.md). Installing and
deploying it is [INSTALL.md](../../INSTALL.md).

Substitute your own values for these throughout:

<!-- prettier-ignore -->
| Placeholder | What it is |
| --- | --- |
| `https://pm.example.com` | The web console / control-plane URL |
| `acme-dev` | A MySQL datasource tagged `system:development` |
| `acme-prod` | A MySQL datasource tagged `system:production` |
| `you@example.com` | Your SSO principal |

## The one thing to understand first

proxy-monster decides per statement, per column, against your roles. There are
three outcomes:

<!-- prettier-ignore -->
| Decision | What happened |
| --- | --- |
| `ALLOW` | The statement ran; every column came back as stored |
| `MASK` | The statement ran; some columns came back masked |
| `DENY` | Nothing ran |

With the shipped presets, a `system:development` datasource returns cleartext
(it is meant to hold no production data), and a `system:production` datasource
masks columns tagged `pii`. That assumes an administrator has assigned you a
role, enabled the production presets, and tagged the sensitive columns. None of
it is automatic: a production datasource whose presets are off denies
everything. If what you see does not match this guide, that configuration is the
first thing to check.

Each statement is also gated by its kind, separately from the columns it reads:

<!-- prettier-ignore -->
| Kind | Examples | Cedar action |
| --- | --- | --- |
| read | `SELECT`, `WITH … SELECT`, `EXPLAIN SELECT` | `stmt.cat.read` |
| write | `INSERT`, `UPDATE`, `DELETE`, `REPLACE` | `stmt.cat.write.*` |
| DDL | `CREATE`, `ALTER`, `DROP`, `TRUNCATE` | `stmt.cat.ddl` |
| metadata | `SHOW TABLES`, `DESCRIBE`, `SHOW WARNINGS` | `stmt.cat.metadata` |
| session | `SET`, `USE`, `BEGIN`, `COMMIT`, `ROLLBACK` | `stmt.cat.session` |
| admin | `KILL`, `FLUSH`, `GRANT`, `LOAD DATA` | `stmt.cat.admin.*` |

Holding a role that reads a table does not let you run `SHOW TABLES` or `SET` on
it — those are their own grants. Session statements run only from the console
editor and a wire connection; through MCP or an approval they are always denied,
since each of those runs on a fresh connection.

## 1. Run a query against dev

Open `https://pm.example.com`, sign in with SSO, and go to **Query**. Pick
`acme-dev`, write SQL, and press **Run** (or `⌘/Ctrl + Enter`). Run executes the
statement under the caret, or the selected text. While it runs, **Cancel** stops
it.

```sql
select * from app.users limit 5;
```

The badge reads `ALLOW` and the values are cleartext. The schema tree lists what
you can see; a table with tagged columns shows a `{count} PII` badge, whatever
the tags are named. System schemas are hidden — **View options → Show system
schemas** reveals them.

## 2. Run the same query against production

Switch to `acme-prod`:

```sql
select id, email, name from app.users limit 5;
```

If `email` and `name` are tagged, the badge reads `MASK` followed by
`masked email name`, each masked column header carries a `masked` chip, and the
cells show the column's mask — `####` by default, or a format-preserving or
last-four mask if your admin chose one. The **Details** tab lists the decision,
effective roles, masked columns, and rows returned.

A `NULL` cell is usually a real null, but a column can also be masked to `NULL`
(a system-redacted column, or a `NULL` mask function). The `masked` chip on the
header tells you which.

### Selecting a column masks it; filtering on it denies

Reading a protected column is fine — it comes back masked. Using it anywhere the
database evaluates it — `WHERE`, a `JOIN` condition, a subquery, a write — is
denied:

```sql
-- MASK: email comes back masked
select id, email from app.users limit 5;

-- DENY: nothing runs
select id, email from app.users where email like '%@example.com';
```

Masking happens on the result stream after the database answers. A predicate
runs inside the database, so a masked value used there would leak — one row
matching `where email = 'x'` reveals the email whatever the output shows.

Rewrite the query so the column is only selected, or ask for access (§3).

### Why a query was denied

The result panel reads **Query denied** with the reason:

```
protected column def.app.users.email appears in a position that cannot be masked (a write payload or a subquery/reference)
```

Other reasons you will meet:

<!-- prettier-ignore -->
| Reason | Meaning |
| --- | --- |
| `no access to datasource 'acme-prod'` | No role of yours grants `datasource.connect` there |
| `statement kind 'set_session_var' is not permitted` | That statement kind is not granted (see the kind table above) |
| `policy denies column def.app.users.ssn` | A policy forbids that column, or no role of yours reads it |
| `rate 10000/1h spent` | Your result-volume rate is used up (§4) |

Below the reason are **Request approval**, **Request access**, and **View audit
entry**. **Audit** shows the same decision with the failed stage, your roles at
the time, client address, and full SQL.

A SQL client sees the same reason as a MySQL error:

```
ERROR 1142 (42000): proxy-monster denied: statement kind 'set_session_var' is not permitted
```

## 3. Ask for access you do not have

<!-- prettier-ignore -->
| | What you get |
| --- | --- |
| **Request approval** | This query, run once under a role that can read it. You see the result; you never hold the role. |
| **Request access** | A time-boxed grant of the role (30 minutes to 12 hours). Until it expires, the query and others like it just run. |

Request approval:

1. **Start it.** Click **Request approval** on a denial (the datasource and SQL
   are filled in), or **Workflows → New request** to compose one. Several
   statements separated by `;` are allowed; they run in order and stop at the
   first one denied.
2. **Pick the role.** proxy-monster tries your query under every role, as an
   approved run would execute it, and lists each role that would not deny it,
   marked `cleartext` or `masked`. A role is listed only if every statement
   passes under it; if none does you see `No role can run every statement.` Pick
   from the list, and check the outcome — a role can be listed and still mask
   what you need.
3. **Give a reason.** The approver reads it, so say what you are investigating.
4. **Wait.** Whoever policy grants `task.approve` on the request sees it under
   **Workflows → Incoming** — administrators by default, never yourself. If
   Slack is set up, approvers also get a DM with **Approve and run**.
5. **The approver runs it.** **Approve & run** approves and starts the query
   under the chosen role in one step. **Run query** appears only to retry a run
   that did not start.
6. **Read the result.** Rows are stored encrypted for 24 hours and shown on the
   request. Viewing re-decides each column as the approved role, from where you
   are now — your own roles play no part. A view can mask more than the run did,
   never less. With the shipped presets, PII reads in cleartext at view only
   from the network your admin marked trusted.

Request access is the same flow with a role and a duration instead of a query.
Once approved the grant appears under **Workflows → Active grants**, and you can
revoke it early.

## 4. Result caps

Every result is capped. The shipped defaults, per statement:

- 5,000 rows or 50 MB;
- 500 rows or 5 MB when a tagged column comes back in cleartext.

And per datasource, over a rolling window: 10,000 rows and 100 MB per hour,
50,000 rows and 500 MB per day.

A capped result is incomplete. The editor says
`The result cap stopped this at 5,000 rows — the set is incomplete.`; a SQL
client gets the rows up to the cap and then an error, with the session and any
open transaction intact:

```
ERROR 1317 (70100): proxy-monster: result exceeds the row cap (5000 rows); request unbounded access
```

When a rate is spent, statements that return rows are denied with
`rate 10000/1h spent` and the editor offers **Request rate reset**. An approver
resets every window at once; the per-statement cap stays. For a full export,
request access to `system:production-exporter`, which has no cap or rate.

## 5. Connect a SQL client with pmon

`pmon` is a local daemon. It holds a short-lived token and gives each datasource
a fixed local port with a password that never changes, so a saved connection in
TablePlus or DataGrip keeps working across logins. It brokers MySQL, PostgreSQL,
and Athena.

```sh
brew trust --formula ridi-oss/tap/pmon   # Homebrew 6 requires this for third-party formulae
brew install ridi-oss/tap/pmon

pmon login --url https://pm.example.com
```

`pmon login` opens your browser (set `PMON_NO_BROWSER=1` to stop that) and
prints the URL and a code; enter the code, approve, and the brokers open. There
is no separate connect step.

```
$ pmon status
daemon:    running since 09:12 (5m0s ago)

server:    default  https://pm.example.com
principal: you@example.com
token:     2026-10-05 21:12 (in 11h55m0s)
session:   2026-10-05 11:12 (in 1h55m0s)
scopes:    mcp:query mcp:read

SERVER   DATASOURCE   ENGINE    LOCAL           CONNS  PROXY
default  acme-dev     mysql     127.0.0.1:6100  0      proxy.example.com:3306 (TLS verified)
default  acme-prod    mysql     127.0.0.1:6101  0      proxy.example.com:3307 (TLS verified)
default  acme-pg      postgres  127.0.0.1:6102  0      proxy.example.com:5432 (TLS verified)
```

A datasource listed but not brokered shows `—` under `LOCAL` and the reason
under `PROXY`.

Print a connection string — the default is a URL:

```sh
pmon show acme-prod            # mysql://you%40example.com:pmlocal_…@127.0.0.1:6101/appdb
pmon show acme-prod --jdbc     # jdbc:mysql://127.0.0.1:6101/appdb?user=…&password=…&jdbcCompliantTruncation=false
pmon show acme-prod --go-dsn   # you@example.com:pmlocal_…@tcp(127.0.0.1:6101)/appdb?parseTime=true&charset=utf8mb4
pmon show acme-prod --cli      # mysql -h 127.0.0.1 -P 6101 -u 'you@example.com' -p'pmlocal_…' 'appdb'
pmon show acme-pg --cli        # psql 'host=127.0.0.1 port=6102 dbname=app user=… password=… sslmode=disable'
```

MySQL JDBC strings carry `jdbcCompliantTruncation=false` so Connector/J does not
issue `SHOW WARNINGS` behind your back; `--jdbc-with-truncation-diagnostics`
omits it.

An Athena datasource defaults to an AWS CLI command with local credentials;
`--format python`, `--format node`, and `--format aws-config` print a boto3
client, an AWS SDK v3 client, and a profile; `--url` prints the local endpoint.

In TablePlus use host `127.0.0.1`, the port from `pmon status`, and the user and
password from `pmon show`, with TLS off — the loopback hop is plaintext by
design. In DataGrip paste the `--jdbc` string into the URL field. `@` is `%40`
in URLs; a GUI field that takes the user alone wants `you@example.com`.

Every statement is authorized and masked exactly as in the console.

### How long a login lasts

One token lifetime: 12 hours by default (`pmon login --ttl <seconds>`; the
server may clamp it). About 30 minutes before the token expires the daemon tries
to renew it, which works only while the session window (the `session:` line, 2
hours by default) is still open — with the defaults it is not. So near the end,
`pmon status` shows

```
reauth:    REQUIRED — the session window closed; run `pmon login`
```

The token keeps working until its own expiry; run `pmon login` then. Ports and
the local password stay the same, so saved connections need no edit.

### Several servers

Each control plane is a named server; a command that names none addresses
`default`.

```sh
pmon server set dev --url https://pm-dev.example.com
pmon login dev
pmon show dev acme-dev
pmon logout dev           # or: pmon logout --all
pmon restart              # also: pmon start, pmon stop
```

## 6. Connect an agent (MCP)

proxy-monster is also an MCP server. An agent gets exactly your access: queries
run under your roles with the same masking, denials, and caps.

**Direct (OAuth).** Open the identity menu (your name, top right) → **Connect an
agent**. The page shows the MCP URL (`https://pm.example.com/mcp`), the server
name to install it under, and text to paste into Claude Code or Codex CLI. In
Claude Code, finish with `/mcp` → the server → Authenticate.

**Through pmon.** `pmon mcp [server]` is a local stdio MCP server that uses your
pmon login, so the agent needs no sign-in of its own. This is how Claude Desktop
connects. `pmon mcp --install` registers it with every AI app installed on your
machine (Claude Desktop, Claude Code, Codex) for every pmon server, replacing an
https entry for the same server. By hand: the **Connect an agent** page and the
`get_pmon_guide` tool name the pmon server after the instance; with the
`default` server:

```sh
claude mcp add --scope user pmon-acme -- pmon mcp
codex mcp add pmon-acme -- pmon mcp
```

Claude Desktop, in `claude_desktop_config.json`:
`"mcpServers": {"pmon-acme": {"command": "pmon", "args": ["mcp"]}}`. If the
server is not logged in, `pmon mcp` exits with the `pmon login` to run.

claude.ai and ChatGPT connect from the vendor's cloud, which cannot reach a
private proxy-monster; use Claude Desktop through pmon instead.

The tools a developer uses: `list_connectable_datasources` and
`describe_datasource` to see what you can query; `run_query` (waits up to 10 s
and returns the first 200 rows, else a `taskId` for `get_query_status` and
`get_query_result`); `discover_roles`, `request_approval`, and
`get_approval_result` for §3's approval; `request_access`; `reset_my_rate`;
`get_my_permissions` for your roles and where each comes from; and
`get_pmon_guide` for pmon setup. A denied statement in `run_query` carries a
`decisionId` to pass to `request_approval`.

### Scopes

A pmon login grants `mcp:read` and `mcp:query` — enough for everything above.
Approving requests, managing tokens, and admin writes need more:

```sh
pmon login --scopes mcp:read,mcp:query,mcp:approvals:write
```

`pmon login --help` lists them all. The browser page then shows
`This login asks for more than reading and querying` before you approve. Extra
scopes last 1 hour by default (`PM_ELEVATED_SCOPE_TTL`); `pmon status` shows
when, and once they lapse prints the `pmon login --scopes …` that gets them
back. A scope is a ceiling: it never grants what your roles do not.

## Troubleshooting

**`You do not have access to connect to this datasource.`** No role of yours
grants `datasource.connect` there. Request access, or ask an admin which role
you should hold.

**A client fails right after connecting, or `SHOW TABLES` is denied.** Session
and metadata statements are separate grants (the kind table at the top), and
many drivers send a `SET` while connecting. Ask your admin whether they are
enabled on that datasource.

**`proxy-monster: invalid or expired token`.** A direct connection's token
expired. Through pmon, run `pmon status`, then `pmon login`.

**A saved client connection stops working.** `pmon status`: an expired `token`
or `reauth: REQUIRED` means run `pmon login`. Nothing else changes.

**`The OAuth token does not include the required scope: mcp:approvals:write.`**
The agent's login lacks that scope. Log in again with `--scopes` (§6).

**Which server, and which version?** `GET <server>/api/instance` answers without
signing in, with the instance name, the server version, the MCP URL, and the
name its MCP server installs under. An agent connected over MCP is told the same
name and version when it connects.

**A write or migration is denied.** Writes and DDL on production are separate
roles (`system:production-updater`, `-deleter`, `-architect`) and are often left
off. Ask before scripting a migration through the proxy.

## Where things are

<!-- prettier-ignore -->
| | |
| --- | --- |
| **Query** | SQL editor, schema tree, per-query decision, history |
| **Workflows** | Approval, access, and rate-reset requests — yours and ones awaiting you; active grants |
| **Access** | Connection tokens for connecting without pmon |
| **Audit** | Every decision, with the reason a query was denied |
| **Admin** | Datasources, policies, users, groups (admins only) |
| Identity menu → **Connect an agent** | MCP setup |

How the parts fit together is [ARCHITECTURE.md](../../ARCHITECTURE.md); the
enforcement model is [DESIGN.md](../../DESIGN.md).
