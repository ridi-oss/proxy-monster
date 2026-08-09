# Notifications — task events delivered out of band

An approver used to find out about a request by opening the console and looking.
Nobody told them. This is that telling.

Built.

It changes no enforcement. Masking, lineage, and the per-query decision are
untouched. The one new authorization surface is deciding from Slack, and that is
a new value on the channel axis policy already conditions on.

## What it looks like

Alice needs `ssn` from production. She files a request. Bob and Carol can
approve it, so each gets a Slack DM:

> **alice** wants to run `SELECT ssn, name FROM users WHERE order_id = 8842` on
> **acme-mysql** as **pii-reader** _investigating a billing dispute_
> `[approve and run]` `[deny]` `[open request]`

Bob taps **deny**. His message and Carol's both become:

> **alice**'s request to run `SELECT ssn, name FROM users WHERE …` on
> **acme-mysql** was denied by **bob** `[open request]`

Had Bob tapped **approve and run**, the query runs and the message becomes
"approved by bob, running", then updates again to "finished, 3 rows" or
"failed". The rows themselves never appear in Slack — Alice reads them in the
console.

Alice's statement is short, so Bob sees all of it and can approve from the DM.
Had any of it been elided — too long for the configured limit, too long for
Slack, or withheld because it carried a protected value — the message would
offer only `[deny]` and `[open request]`. Nobody approves a statement they have
not read in full.

Everything below is how that works.

## Three layers

- **Event** — what happened. The workflow says it once and knows nothing about
  Slack.
- **Route** — who should hear it.
- **Transport** — how it reaches them. Slack first, email second.

Email is why the seam exists. Adding it should mean writing one transport, not
touching the workflow.

## Events

| Event                                          | When                 | Who hears it                           |
| ---------------------------------------------- | -------------------- | -------------------------------------- |
| `task.requested`                               | a request is filed   | everyone who could approve it          |
| `task.decided`                                 | approved or rejected | the requester, and everyone told above |
| `task.executed` `task.failed` `task.cancelled` | the run ends         | the requester and the approver         |

Anyone told about a request is told how it ended. That is what stops a stale
"needs your approval" sitting in a DM after someone else already handled it —
the original message is edited in place. A transport that cannot edit sends a
follow-up instead.

## Who can approve

This is the hard part, and it deserves plain statement.

Cedar answers "may **bob** approve request 42?" It does not answer "who may
approve request 42?" Every existing caller asks the first question about
themselves — the inbox page loads all pending requests and asks Cedar once per
request, for the one person looking at the page.

A notification needs the second question, so we ask the first one for everybody.

### The candidate list

"Every active principal" is not just the `app_user` table. A principal is a
plain string, and someone can hold a role through a direct assignment or a JIT
grant without ever having a directory row. So the list is the union of four
sources: active `app_user` rows, `principal_role`, group membership, and
unexpired `access_grant` rows. `RoleResolver` already walks exactly this union
in `hasActiveAssignee` to answer "does anyone hold this role"; the same query
returning names instead of a yes/no is what we need.

### The problem: we don't know where Bob is

Asking Cedar the ordinary way needs a full request, and part of one is missing
here. There is no HTTP request behind this loop, so there is no requester IP.

That breaks a policy like "approvers must be on the office network." Bob holds
the approver role and would sail through the moment he clicks from his desk —
but at routing time we cannot say where he is, and an absent attribute makes
Cedar deny. Measured, with Bob holding the role throughout:

```
policy requires ip in 10.0.0.0/8

  no requester_ip     ->  Deny     ← Bob is never told
  ip = 10.1.2.3       ->  Allow    ← but he can approve, from the office
```

Bob is a real approver and the loop drops him. That is the one failure this
design cannot have: a request nobody hears about waits forever.

### The fix: ask "could Bob ever?"

Cedar can be asked a weaker question. Mark what we do not know as **unknown**
instead of leaving it out, and instead of guessing it answers with a
**residual** — the conditions still outstanding:

```
for each active principal p:
    ask Cedar about p
      channel      = "workflow-viewer"        // the server always knows this
      requester_ip = UNKNOWN                   // nobody knows until they click

    Allow     -> notify     (certain)
    residual  -> notify     (possible — some address would allow it)
    Deny      -> skip       (impossible from anywhere)
```

Read only the verdict. There is no need to inspect which policies are
unresolved, and no special case for forbids: Cedar returns a definite `Deny`
when a forbid fires under every assignment, so anything short of that is a
genuine maybe.

The principal stays concrete — we loop over people anyway — so every term Cedar
_can_ settle still settles. Against "approver AND NOT contractor AND office
network":

| candidate                | routing  | notified | on clicking from the office |
| ------------------------ | -------- | -------- | --------------------------- |
| approver                 | residual | yes      | Allow                       |
| approver, but contractor | Deny     | no       | Deny                        |
| not an approver          | Deny     | no       | Deny                        |

The contractor is correctly excluded even though the answer is otherwise
undecided — a negated role term is knowable without knowing the address.

### Known, unknown, and absent are three different things

Which attributes to supply is the part that is easy to get wrong, because the
two failure modes sit on opposite axes.

Supply **everything the server knows**, always. `channel` is a fact about the
surface, not about the person, so it is never unknown here.

Mark as **unknown** only what is genuinely unknowable at routing time. Leaving
it out instead is not the same thing — an absent attribute makes a conditioning
policy deny, which is the bug this whole section exists to fix:

|                             | shipped policies     | a custom IP-conditioned policy |
| --------------------------- | -------------------- | ------------------------------ |
| omit `requester_ip`         | exact                | drops the approver             |
| mark `requester_ip` UNKNOWN | over-notifies by one | catches the approver           |

The shipped policies never read `requester_ip` for `task.approve`, so on a
default deployment either choice is correct. The unknown earns its place the
moment an operator writes "approvers must be on the office network."

### The one wart: the requester hears about their own request

Marking anything unknown costs one wrong notification, and it is worth stating
plainly because it looks alarming: the requester may be invited to approve their
own request.

The cause is a Cedar limitation, not a modelling mistake. Cedar treats the
context as a single record, and `context has channel` will not reduce while
_any_ unknown sits in that record — even though `channel` is right there with a
concrete value, and no address could change whether it exists. Our
[`system:no-self-approval`] forbid guards its editor/wire escape that way, so it
goes undecided and the requester reads as "maybe":

```
channel known, requester_ip omitted  ->  Deny   (correct, forbid resolves)
channel known, requester_ip UNKNOWN  ->  null   (undecided; the requester is notified)
```

It is bounded — one person per request, the requester themselves — and it does
not arise at all on a deployment with no IP-conditioned approval policy, since
nothing then needs to be unknown. Clicking the button denies exactly as it
should. Not worth filtering outside Cedar: a hardcoded "skip the requester"
would move an authorization rule out of the policy engine that owns it, to save
one message.

### What this costs, and what it means

One Cedar call per principal, once, when a request is filed — the same cost as
asking the ordinary way, against an already-compiled policy set.

The residual is a hint, never a grant. **Notifying is not authorizing**: every
action re-authorizes in full when taken, so an over-notified person simply gets
a 403. The notification only ever says something is waiting.

The API is experimental upstream — no formal model, no correctness proof.
[cedar-reverse-query.md](./cedar-reverse-query.md) has the measurements, the
failure modes, and the two upstream bugs found along the way.

## Delivery

Two tables.

`notification_outbox` is the queue — one row per thing-to-send. It is written in
the **same transaction** as the task change it describes, so a crash can never
leave a request approved with nobody told.

`notification_message` remembers where a message landed, so a later event can
edit it rather than pile on. For Slack that is the channel and timestamp; for
email, the `Message-Id` a reply threads onto.

A background loop drains the queue, next to the two housekeeping loops already
running. Failures retry with backoff a bounded number of times, then the row is
marked dead with its last error kept. **A delivery failure never touches the
task** — the console is the system of record and a notification is a courtesy.

The loop does not merely poll: it is **woken** the moment a row is enqueued, and
polls only as a backstop. A poll alone made an interactive click feel broken —
tap _approve and run_, and the message did not change to "running" until the
next tick, up to the full interval later, while the buttons sat there inviting a
second tap. The wake fires after the enqueuing transaction commits (an earlier
wake would race a row a separate connection cannot yet see), so the "running"
and "finished" edits land in about a second — the round-trip to Slack — rather
than seconds later. A missed wake only delays: the poll still sweeps the row.

This is the in-process form of Postgres `LISTEN`/`NOTIFY`, which is the
multi-instance version — there the wake must cross processes, and it stays a
hint, not the queue: a `NOTIFY` reaches only sessions listening at that moment,
so the table stays authoritative and the poll stays the backstop (`backlog.md`).

Editing an already-delivered message needs only its stored handle, not the
recipient's address, so an update skips address resolution entirely — for Slack
that is two saved round-trips per edit, which is most of what a watching user
feels after a click.

Messages about one task go to one recipient in order. If "approved" is ready to
send before "requested" has left the queue, it waits, so an edit never arrives
before the thing it edits. If the original never sends, the edit becomes a new
message instead of vanishing.

## Transports

```kotlin
interface NotificationTransport {
    val name: String
    /** Null when this person has no address here — the row drops rather than retries. */
    suspend fun addressOf(principal: String, user: AppUser?): String?
    suspend fun deliver(to: String, message: NotificationMessage): DeliveryResult
    /** False for email and anything else with no edit — an update sends a new message. */
    val supportsUpdate: Boolean
    suspend fun update(ref: String, message: NotificationMessage): DeliveryResult
}
```

`DeliveryResult` is `Sent(ref)`, `Retry(reason)`, or `Drop(reason)`. Only the
transport knows whether a 429 is worth another try and a 404 is not.

`NotificationMessage` carries a message key and its values, not finished prose —
so Slack can render Block Kit, email can render MIME, and both languages stay
reachable.

A transport with no configuration is simply absent, the same way an unset
`PM_SCIM_TOKEN` disables SCIM. Configure none and the whole layer does nothing.

## Language

A DM is user-facing copy, so it is localized like everything else.

The control plane has no message catalog today — it returns an error code and
the console renders it. Notifications need one, at
`control-plane/src/main/resources/messages/{en,ko}/notifications.json`, keyed
the same way and guarded by the same en/ko parity test.

Which language comes from the recipient. The console's toggle already knows it —
it just never told the server, because the locale lives in a browser cookie the
server does not read. So the toggle also `PUT`s it, and login records it on
first sight; `app_user.locale` holds the result, and a notification renders in
the recipient's own language rather than one instance-wide setting.

It is a display preference, not an authorization input: no policy reads it,
nothing fails closed on it. A null column means the user has never expressed a
preference, so delivery falls back to `PM_NOTIFY_LOCALE` and then to English.
Storing it needs a migration adding the column, a small self-service route
(`PUT /api/me/locale`, validated against the same `en | ko` set the console
enforces — this is the user's own row, so it is not an admin surface), and one
call from the toggle.

## The statement in the message

Sending the SQL is not automatically safe. Consider:

```sql
SELECT name FROM users WHERE ssn = '987-65-4320'
```

The protected value is in the query itself. Masking never sees it, because
masking acts on results. Forward that text and the thing the policy protects has
left the building.

So `PM_NOTIFY_STATEMENT` picks one of:

- `truncated` (default) — first 200 characters, enough to recognize the query
- `full` — the whole statement
- `omit` — no SQL at all; requester, datasource, role, and the link only

It lives in the environment because that is where all configuration lives here.
There is no settings table, and adding the first one belongs to its own change.

### Never approve what you cannot see

**`[approve and run]` appears only when the rendered message contains the entire
statement.** The test is what the recipient can actually read, not which mode
the operator configured:

- `truncated` with a statement shorter than the limit — nothing was cut, so the
  button appears.
- `truncated` with a longer one — cut, no button.
- `full` — usually the button, but not always: a transport has its own length
  ceiling (a Slack section block's text field caps at 3000 characters), and a
  statement that overruns it is elided on the way out. Elided is elided, whoever
  did it.
- `omit` — no button.

So the flag is an input to rendering, and the button is decided **after**
rendering, from whether the text survived intact. Writing the gate against the
mode instead would get both edge cases backwards.

Approving is vouching for a specific statement. A truncated one is worse than
none: `SELECT id, name FROM users WHERE …` looks harmless and the elided tail is
exactly where a dangerous predicate would sit. One tap on a query nobody read in
full is not an approval, it is a rubber stamp with an audit trail.

`[deny]` stays available throughout — refusing something you have not fully read
is always safe.

### Hiding a statement that carries the value it asks for

`PM_NOTIFY_STATEMENT` is a blunt instrument: an operator picks one setting for
every query, so `full` would send `WHERE ssn = '987-65-4320'` verbatim. The
protected value is in the query, and masking never sees it because masking acts
on results. That is the case where `full` needs a floor, and it has one.

The analyzer emits a `predicate_literals` fact: for every `WHERE`, `HAVING`,
`QUALIFY`, and join predicate that compares a **literal** against a column, the
resolved base column and the clause it sat in. It comes through the same lineage
resolution the rest of enforcement uses, so aliases, CTEs, and derived tables
are followed. A comparison between two columns emits nothing — there is no value
to leak.

The control plane intersects that against classification: a literal landing on a
classified column means the statement's own text carries a protected value, so
the text is withheld whatever the mode, and the message loses
`[approve and run]` by the rule above.

**The verdict is deliberately reader-independent.** It keys on whether the
column is classified, not on what the requester may read. A notification goes to
every eligible approver at once and they do not share entitlements, so "can the
composer read this column" answers the wrong question. It also survives the
enforcement shape: a masked column in a predicate already denies the statement
outright, so a per-reader test would come back empty for exactly the statements
worth withholding.

**Absence is never proof of safety.** A value also reaches a predicate through a
function, a `CASE`, a subquery, an `IN (...)` list, or a bound parameter, none
of which this sees. So the flag is three-state and only one state discloses:
known clean shows the text, known dirty withholds it, and **never analyzed
withholds it too**. A from-denied request — which copies a statement nothing
re-analyzed — is in that third state by construction.

This is an extra layer, not the boundary: `omit` remains the setting for a
deployment that cannot let query text leave at all.

## Slack

### How it connects

Socket Mode. The control plane opens an outbound WebSocket to Slack, and button
clicks arrive back over it.

The alternative is giving Slack a public URL to POST to — a new inbound
endpoint, reachable from the internet, that approves database queries. Socket
Mode avoids that entirely. The control plane keeps doing what it already does:
only outbound calls, the same as it makes to the IdP.

Two tokens, both required: `PM_SLACK_BOT_TOKEN` for the API and
`PM_SLACK_APP_TOKEN` for the socket.

The workspace is **derived, not configured**: `auth.test` on the bot token names
the one workspace it belongs to, resolved once at connect. Asking an operator to
restate it would add a value they can mistype — and one they can leave unset,
which is worse, because an absent pin is an unpinned workspace. Derived, it
fails closed: a workspace that cannot be resolved refuses every click.

### Who is who

Email, both directions, which is the same directory the IdP uses.

Going out: take the principal, ask Slack for the user with that email, open a
DM. If the principal is not itself an address, fall back to `app_user.email`.

Coming in: a click carries a Slack user id. Look it up **fresh, every time** —
never from a cached table, because that mapping is what proves who is clicking.
Then match it to an active `app_user`. No match, an unverified email, or a
workspace other than the bot token's own gets a private "not recognized" reply
and nothing happens.

### Approving from Slack

A click is a weaker claim than a console session — no OIDC session, no known IP.

Rather than hide that behind a boolean, `slack` becomes a sixth value on the
channel axis alongside `wire`, `editor`, `workflow-executor`, `workflow-viewer`,
and `mcp`. An operator can then write, per datasource or per role:

```
forbid (principal, action == Action::"task.approve", resource)
when { context.channel == "slack" };
```

and the buttons stop working while the deep link still does. It ships enabled.

Because there is no IP, any policy that requires one denies. That is the same
fail-closed behaviour the system already has for a missing attribute.

The no-self-approval rule needs no change. It exempts only the server-attested
`editor` and `wire` channels, so Alice still cannot approve her own request from
Slack.

### The buttons

**approve and run** does both steps, because whoever approves is the one who
must execute. It is offered only when the message shows the full statement (see
[above](#never-approve-what-you-cannot-see)). **deny** rejects, and is offered
whatever the message shows. **open request** links to the console and is always
there, even when the other two are policy-disabled.

Both go through the same code the HTTP routes use. Today approve, reject, and
execute live inside the route handlers; they move into an `ApprovalService`, and
the routes become one caller of it while Slack becomes another. **This is a real
refactor of `Approvals.kt`, not an incidental one** — it is the part of this
design most worth reviewing before building.

Two people tapping approve at once resolve exactly as two console users do — one
wins the same compare-and-swap, and the loser's message is rewritten to show
what actually happened.

Results never reach Slack. A finished run says "3 rows" or "failed", nothing
more. The rows stay in the console, which is the only place that re-checks who
may see them.

## Configuration

| Variable                  | Default     | Meaning                                                                                               |
| ------------------------- | ----------- | ----------------------------------------------------------------------------------------------------- |
| `PM_SLACK_BOT_TOKEN`      | unset       | Slack API token; unset = no Slack                                                                     |
| `PM_SLACK_APP_TOKEN`      | unset       | Socket Mode token; unset = no Slack                                                                   |
| `PM_NOTIFY_STATEMENT`     | `truncated` | `truncated` · `full` · `omit`. Approve-and-run needs the statement to render whole, whatever the mode |
| `PM_NOTIFY_STATEMENT_MAX` | `200`       | characters kept when truncating                                                                       |
| `PM_NOTIFY_LOCALE`        | `en`        | fallback when the recipient has saved no language                                                     |

## What this exposes

Slack becomes a place where the requester, the datasource, the role, and (unless
`omit`) part of the query are readable by anyone who can read the DM — and a
place from which a query can be approved. `ARCHITECTURE.md` gains the outbound
edge. The workspace is pinned, and the tokens are standing secrets like
`PM_SCIM_TOKEN`: absent means the feature is off, never degraded.

## Not covered

- Per-user opt-out. Language is now stored per user; a mute switch is the same
  shape and a natural follow-up.
- Posting to a channel. Eligibility is per person; a channel cannot express it.
- Digests and reminders. One event, one message.
- Multi-replica delivery. The queue assumes one instance, like the rest of the
  system.
- Role-elevation (JIT access-grant) requests. Only query approvals notify today;
  a `Grant` resource and its own event are the natural extension.
