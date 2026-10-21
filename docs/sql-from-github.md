# SQL from GitHub — reviewed files, approved in proxy-monster, run as they merge

Built.

A team keeps its schema changes (and occasional data fixes) as `.sql` files in
its own repository. A pull request adds a file; CI proves it applies cleanly in
a local environment; a proxy-monster approver approves the exact SQL; when the
PR is ready to merge, proxy-monster runs it on the target DB through the proxy,
and the PR merges only if the run succeeded. The PR is the review surface and
git the record of order: query executions in a named scope happen one PR at a
time, so the order they ran in is the order they merged in. proxy-monster stays
the authority: who may approve, what may run, and when is decided by the control
plane.

Each SQL file becomes an ordinary approval request
([approval-workflow.md](./approval-workflow.md)): it is stored, approved, and
run the same way as a request made in the console, under the role its Action
step names. Three things are new: the request is approved without running, the
run starts when the PR is ready to merge, and query executions in a named scope
happen one PR at a time.

## What it looks like

```
acme/shop
  db/orders/
    init.sql                     # bootstraps an empty schema (replay only)
    golden.sql                   # schema export after replay (replay only)
    0041_add-status-index.sql
    0042_backfill-status.sql     # new in this PR
```

```yaml
# .github/workflows/sql.yml
on:
  pull_request: { types: [opened, synchronize, reopened] }
permissions: { id-token: write, contents: read }
jobs:
  file:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with: { fetch-depth: 0 }
      - uses: acme/sql-replay@v1 # the team's own replay; see CI checks
        with: { dir: db/orders, engine: mysql:8.0.36 }
      - uses: tailscale/github-action@v4
        with:
          oauth-client-id: ${{ secrets.TS_OAUTH_CLIENT_ID }}
          oauth-secret: ${{ secrets.TS_OAUTH_SECRET }}
          tags: tag:ci
      - uses: ridi-oss/proxy-monster/sql-action@v1
        with:
          server: https://proxy-monster.internal.example
          dir: db/orders
          datasource: shop-mysql
          schema: orders
          role: schema-migrator
```

Alice opens a PR adding `0042_backfill-status.sql`. The team's replay step runs
`init.sql` and every file in the order they merged on a throwaway MySQL, exports
the schema, and fails if it differs from the committed `golden.sql`. The
proxy-monster Action then files a request for `0042`. Bob, an approver of
`schema-migrator` on `shop-mysql`, approves it in the console, Slack, MCP, or a
GitHub review. Alice enables auto-merge. Once every other check is green,
proxy-monster runs `0042`, turns `query executed` green, and GitHub merges the
PR. The PR gets a comment:

> `0042_backfill-status.sql` on **shop-mysql/orders** — executed. Statements
> run: 2. Approved by **bob**.

## Scope

Each Action step names a directory and where its files run: `datasource`,
`schema`, and `role`. The run's connection opens with that schema as its default
namespace, so files carry no `USE` (session statements are forbidden on workflow
runs). The control plane never sees repository layout. One repository may have
several steps.

A scope is one line of runs: query executions in a named scope happen one PR at
a time. It defaults to `<datasource>/<schema>`, and a step may set it to any
string:

```yaml
with:
  dir: db/orders
  datasource: shop-mysql
  schema: orders
  scope: orders-migrations # optional; default "shop-mysql/orders"
```

A scope belongs to one Action step; two steps sharing a scope are not supported.
Repositories that target the same schema share the default scope, so their runs
never overlap.

The step's `files` pattern picks which files run and gives each its key. The
default, `^(?P<key>[0-9]+)_.+\.sql$`, matches only names that start with digits
and an underscore, so `init.sql` and `golden.sql` never run. A file's key is the
pattern's `key` group, or the whole name when the pattern has none. Within one
PR, files run in key order, ties broken by path. The step's `order` says how
keys compare: `numeric` (the default) compares them as integers, `string` byte
by byte. Under `numeric`, a file whose key is not an integer fails the filing
(`approval.github_key_not_numeric`).

Name files `NNNN_description.sql`; nothing enforces it. Four digits leave room
for 9,999 files, and numeric order still runs `9999_` before `10000_` if they
run out. A team that names files `V9_…`, `V10_…` sets
`files: '^V(?P<key>[0-9]+)_.+\.sql$'`.

Keys order files only within one PR. Across PRs the order of runs is the order
PRs run and merge in.

## Keys

```
content_hash = "n:" || sqlGrantHash(content)    -- or "r:" || sha256(raw bytes)
change_key   = sha256(file_key || '\n' || content_hash)
```

The file key comes from the name without its directory, so moving a directory
changes no key. A change key ties an approval to the exact SQL, and tells "this
file already ran" (same file key and content, e.g. after a branch update) apart
from a new file with the same SQL under another key, which must run.

`sqlGrantHash` is the hash one-time query grants already use: it ignores
whitespace, comments, and keyword case, and keeps literals, names, and operators
exact. A push that only reformats or comments a file keeps its key and its
approval; the run uses the newest text. MySQL executable comments and optimizer
hints (`/*!50000 … */`, `/*+ … */`) change what runs, so the normalizer refuses
them; such a file is keyed on its raw bytes (`r:`), and any edit to it needs a
new approval.

Every request stores `file_key` and `content_hash` beside `change_key`, so a
diagnosis can tell an edited file from a renamed one. `file_key` is not unique
in a scope: a file that failed is fixed by new content under the same key, which
files a second request with that key.

The control plane computes every key. The Action sends the PR's new files; a
file whose change key already EXECUTED in the scope is not run again. A request
carries
`{scope, file key, content hash, change key, path, sql, PR URL, head commit}`,
where the head commit is the one the Action filed from.

## Running

`query executed` is a required check posted by the control plane's GitHub App,
named Proxy Monster. The ruleset requires it with its source pinned to the App,
so an Actions job cannot post a passing check under that name, and the ruleset's
bypass list is empty. For a PR that adds no matching file, `query executed`
completes as `skipped` at once, which GitHub counts as passing.

For a PR that adds files, the control plane runs them when all of these hold:

- every scope's latest filing is for the PR's current head. Alice pushes a fix
  to `0042`; until the Action files that push, the control plane has not seen
  the new `0042`, so the old one must not run;
- the PR is not a draft. Workflows that skip drafts have not run yet, so no
  check would hold the SQL back;
- auto-merge is enabled on the PR;
- every request in the current set is approved: per scope, the newest request
  for each path in that scope's latest filing;
- every other required check on the head commit is green. The required contexts
  are the branch's rulesets
  (`GET /repos/{owner}/{repo}/rules/branches/{branch}`) plus its classic branch
  protection, read with the App's metadata permission and cached for 5 minutes,
  and those the check rollup marks required. A context missing from the rollup,
  a missing rollup, or a failed lookup keeps the PR pending. `lint` still
  running, or a required context no workflow has reported yet, is not green: the
  PR could not merge, and SQL that ran would sit on the target without `main`.
  Any other check still running on the head also waits, so a branch that
  requires no checks does not run the SQL ahead of CI; a finished optional check
  does not block, whatever its conclusion;
- GitHub would merge the PR once `query executed` passes. A PR approved by a
  reviewer who is not the required code owner, one with conflicts, or one whose
  branch is behind under a strict rule waits. The control plane reads GitHub's
  `mergeable`, `mergeStateStatus` and `reviewDecision`. While `query executed`
  is required, GitHub reports the PR as `BLOCKED` until it passes, so the
  control plane also checks the ruleset rules behind that verdict: review
  conversations resolved, the auto-merge method allowed (and, for a rebase, that
  GitHub can rebase), and the head containing the base under a strict
  status-check rule. A rule that can block a merge and that it does not check (a
  merge queue, required deployments, signed commits, …) keeps the PR waiting,
  named in the check's title. So does classic branch protection, which shows the
  App only its required checks: protect the base with rulesets only;
- the PR's head contains the scope's last merged run from the same repository.
  PR B branched before PR A's `0041` merged; B's `0042` may depend on the schema
  `0041` creates, and B's CI never ran on top of it
  ([Branches that are behind](#branches-that-are-behind));
- no other PR's request in the scope is EXECUTING, or EXECUTED but not yet
  merged, unless that PR's current version of some file has failed. A ran `0041`
  and waits to merge, so B waits. If A's `0042` failed, A cannot merge until its
  author pushes a fix, so A stops holding the scope and B is not blocked by a PR
  that may never merge.

It runs the PR's files in key order, each on its own connection whose statements
share it, and stops at the first failure. It re-checks a PR on every poll (see
[Reaching the control plane](#reaching-the-control-plane)). Without auto-merge
nothing runs and `query executed` stays pending, so a PR cannot merge un-run
SQL.

While auto-merge is off on an approved PR, two places tell the author to enable
it:

- The pending check, next to the merge button: "Approved — enable auto-merge to
  run and merge".
- The Slack message the author already gets when their request is approved.

With auto-merge on, neither mentions it: the check says what it is waiting on
("waiting for other checks", "waiting for #A to merge", "update your branch").

On success `query executed` turns green; it is the last pending check, so GitHub
merges at once. On failure it turns red and nothing merges.

### One PR at a time

The last condition is checked and the run claimed in one transaction under a
per-scope lock:

```sql
SELECT pg_advisory_xact_lock(hashtext(:scope));
SELECT 1 FROM access_request r
 WHERE r.scope = :scope AND r.pr <> :pr
   AND (r.status = 'EXECUTING'
        OR (r.status = 'EXECUTED' AND r.merged_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM access_request f
                             WHERE f.scope = r.scope AND f.pr = r.pr AND f.status = 'FAILED'
                               AND NOT EXISTS (SELECT 1 FROM access_request n
                                                WHERE n.scope = f.scope AND n.pr = f.pr AND n.path = f.path
                                                  AND n.id > f.id
                                                  AND n.status NOT IN ('DELETED', 'ALREADY_RAN', 'CANCELLED')))));
-- none → the execute-once claim on the request
```

`merged_at` and the merge commit are recorded when GitHub reports the PR merged.
Without this rule, PR A runs, and before A merges PR B runs too; the database
then holds both while `main` holds only one. With it, B waits ("waiting for #A
to merge").

### Branches that are behind

Once A has merged, B runs only if its head contains A's merge commit. The
control plane asks GitHub
(`GET /repos/{owner}/{repo}/compare/{A_merge}...{B_head}`): `ahead` or
`identical` means B contains it; `behind` or `diverged` leaves B pending with
"update your branch — #A merged first". B's replay CI then runs on top of A.
This applies only to SQL PRs in the scope, not to the whole repository. A run
from another repository cannot be in B's history, so repositories sharing a
scope are kept one at a time but not checked against each other.

Two PRs that add `0042_a.sql` and `0042_b.sql` merge in git without a conflict.
The second one simply waits until it contains the first one's merge; the names
do not need to differ.

### Escape hatch

An admin can force a request past two checks: freshness (the head contains the
scope's last merged run) and one PR at a time. Everything else still applies:
the approval, the run under role R with its Cedar decisions, auto-merge, the
PR's other required checks, and filing for the current head. Use it when a check
can never pass, for example after `main` was force-pushed and the last merged
run's merge commit is no longer in its history.

Forcing needs Cedar `task.force_run` on the request, seeded only to
`system:admin`. It is **Force run** on the request in the console,
`POST /api/approvals/{id}/force-run`, or `force_run_approval` over MCP. The PR
gets a comment naming the admin, and approvers and the request's parties get a
`task.force_run` message.

### Reaching the control plane

The control plane usually sits on an internal network, so GitHub cannot deliver
webhooks to it. GitHub Actions reach it over the tailnet instead, and the
control plane reads GitHub through the API, outbound.

- Filing: the repository's workflow runs on `pull_request` (`opened`,
  `synchronize`, `reopened`). It joins the tailnet as an ephemeral node with
  `tailscale/github-action` under a tag the tailnet ACL lets reach only the
  control plane, authenticates by the GitHub OIDC token exchange, and files a
  step's files at `POST /api/github/requests` with
  `{repository, pr, headSha, scope?, datasource, schema, role, files: [{path, key, content}], order?}`,
  where `headSha` is the full SHA of the commit the files were read from and
  `order` is `numeric` (the default) or `string`.
- Poll: every 15 seconds the control plane re-reads the PRs that have a request
  not yet run, or run but not yet merged, with one GraphQL query per repository
  (head SHA, auto-merge, merged, reviews, check rollup); that is how it notices
  reviews, checks, and merges. Polling costs about 240 points an hour per
  repository against the App's 5,000; polls run one at a time and back off when
  the remaining budget runs low.

Webhooks delivered through Tailscale Funnel are in the
[backlog](./backlog.md#control-plane-as-a-tailnet-node).

### After the run

- A push after the run that leaves the files' keys unchanged, such as merging
  `main` into the branch, does not run them again: the keys are already
  EXECUTED, so `query executed` turns green on the new commit without running.
- A push that edits a file after it ran gives it a new key, so it needs a new
  approval and then runs as written. The run-result comment already on the PR
  shows what ran before; the author and approver keep the two from overlapping.
- A PR that merges without a file whose SQL ran (the file was removed after the
  run) leaves the target with SQL `main` does not have. Admins are alerted on
  Slack with the SQL; the request keeps the record of what ran.
- A PR closed without merging after its SQL ran leaves the same mismatch. Admins
  are alerted on Slack, and the scope stays blocked by the one-PR-at-a-time rule
  until that file reaches `main`: the PR is reopened and merged, or a new PR
  adds the identical file, which has the same key and so turns green without
  running.

## Sources

A request has a source: `console`, `mcp`, or `github`. Requests from every
source are one kind of task, created through the same approval service the
console and MCP tools already call, and decided by the same Cedar actions. A
source supplies only the parts that differ:

|                   | console              | mcp                       | github                           |
| ----------------- | -------------------- | ------------------------- | -------------------------------- |
| Files the request | user, in the console | user, through an MCP tool | the Action, for the PR author    |
| Requester         | the signed-in user   | the signed-in user        | the PR author, mapped            |
| Approved in       | console, Slack, MCP  | console, Slack, MCP       | console, Slack, MCP, a PR review |
| Starts the run    | the approver         | the approver              | the PR becoming ready to merge   |
| Reports to        | console, Slack       | console, Slack            | console, Slack, the PR           |

Approving a GitHub request, from any of these, never runs it; the run waits for
the PR to be ready to merge.

Everything that talks to GitHub sits behind one adapter: read a PR's state
(head, files, auto-merge, checks, merged), compare commits, post the status
check, read and dismiss reviews, and map a GitHub user. Another forge is another
adapter. Requests, scopes, keys, and the one-PR-at-a-time rule do not depend on
the source.

The GitHub App lives in `cp-go`: it signs the App's JWTs, keeps installation
tokens, and makes every GitHub call, and the Kotlin control plane reaches it
over loopback. Set `PM_GITHUB_APP_ID` and exactly one key:

- `PM_GITHUB_APP_KMS_KEY_ID`: an AWS KMS key (`RSA_2048`, `SIGN_VERIFY`) holding
  the App's private key, imported once. `cp-go` signs with `kms:Sign`
  (`RSASSA_PKCS1_V1_5_SHA_256`, message type `DIGEST`), so the key never leaves
  KMS.
- `PM_GITHUB_APP_PRIVATE_KEY` or `PM_GITHUB_APP_PRIVATE_KEY_FILE`: the PEM.

`PM_GITHUB_API_URL` points at GitHub Enterprise Server (`…/api/v3`), and
`PM_GITHUB_CA_FILE` adds the CA certificates (PEM) it is signed with.

Outcomes reach Slack and the PR through the existing notifications
([notifications.md](./notifications.md)): the run's result, a failure, a PR
merged without a file that ran, and a PR closed after its SQL ran are task
events, and a PR comment is one more transport beside Slack.

## Identities

- Requester: the PR author, mapped to a proxy-monster user (see
  [Mapping GitHub users](#mapping-github-users)), so the existing `forbid`
  requester ≠ approver applies. An unmapped author gets a PR comment and no
  request. The author is mapped once, at the PR's first filing; later filings
  reuse that user.
- Approver: `authorize(approver, task.approve, request, context)`, unchanged.
  The approval comes from the console, Slack, MCP, or a GitHub review (see
  [Approving from GitHub](#approving-from-github)). For a request from GitHub,
  Slack and the console offer "approve", not "approve and run", and the human
  execute route refuses it: the merge trigger runs it.
- Filing: the Action exchanges its GitHub Actions OIDC token for a short-lived
  control-plane token. The exchange accepts the trusted OIDC issuers in
  `PM_CI_OIDC_ISSUERS=<name>=<issuerUrl>,…` with the audience
  `PM_CI_OIDC_AUDIENCE` (the control plane's public origin by default), so other
  CI systems that issue OIDC tokens work the same way. The caller is the Cedar
  principal `Workload::"<name>"`, whose `issuer` attribute is the issuer URL and
  whose optional attributes are the token's `repository`, `repository_id`,
  `ref`, `base_ref`, `workflow_ref`, `event_name`, and `actor` claims
  ([auth-model.md](./auth-model.md#ci-oidc-token-exchange)). On a `pull_request`
  run, `base_ref` is the PR's target branch:

  ```cedar
  permit(principal == Workload::"github", action == Action::"task.request", resource in Datasource::"shop-mysql")
    when { principal has repository && principal.repository == "acme/shop" &&
           principal has base_ref && principal.base_ref == "main" };
  ```

  The shipped `workflow.request-default` permit
  (`permit(principal, action == Action::"task.request", resource)`) covers
  Workload principals too, so a deployment that wants repository scoping
  disables it or adds a `forbid`.

  Independent of policy, a filing whose `repository` differs from the token's
  `repository` claim, or whose token has no such claim, is refused
  (`approval.github_repository_mismatch`, 403). A filing whose `headSha` is no
  longer the PR's head is refused before anything is written
  (`approval.github_stale_head`, 409); the Action for the newer head files
  instead.

- Executor: the run executes under exactly `{R}` on the `workflow-executor`
  channel, without the executor's own roles or groups, recorded as triggered by
  the user who enabled auto-merge and approved by the approver. It does not run
  as the approver. The user who enabled auto-merge is mapped like a requester.

## Approving from GitHub

An approving review on the PR is an approval in proxy-monster, decided by Cedar
like any other.

- On a poll, the control plane's GitHub App reads the review through the API:
  reviewer user ID and state. CI never says who approved.
- On each push the control plane recomputes the keys. If the PR's set of keys
  changed — a file edited, added, or removed — the App dismisses the PR's
  approving reviews ("0042 changed; please re-approve"), so the PR page matches
  proxy-monster. A push that leaves every key unchanged, such as a comment or
  formatting edit, dismisses nothing. A review counts while it is approving and
  not dismissed. Dismissing needs the App's `pull_requests: write` permission,
  and the App must be allowed to dismiss reviews if the ruleset restricts it.
- The reviewer is mapped to a proxy-monster user, then
  `authorize(user, task.approve, request, context)` runs with
  `context.channel == "github"`. The requester ≠ approver `forbid` applies, and
  a policy can allow or forbid approving from GitHub per datasource. A GitHub
  review carries no requester IP, so a policy that needs a network tag fails
  closed for it.
- Only a review submitted after the request was filed, or last edited, and on
  the commit it was filed for approves it, so a review started before a push
  cannot approve the SQL the push brought; the request records that review's ID.
  If that review is later dismissed, or the same reviewer later requests
  changes, the request returns from APPROVED to PENDING if it has not started.
  Other reviews, and approvals from the console, Slack, or MCP, are not
  withdrawn by GitHub reviews.
- The approval is recorded as `decided_by` the mapped user on the `github`
  channel, with the review URL in the audit event.

### Mapping GitHub users

A GitHub user maps to a proxy-monster user through an ordered list of resolvers:

```
PM_GITHUB_IDENTITY=external-identity,verified-email,commit-email
```

- `external-identity`: the user's external identity in the organization
  (`externalIdentities`), whose SAML `nameId` is matched against the OIDC
  principal claim. The IdP vouches for it, so it is preferred where the
  organization uses SAML SSO with the same IdP.
- `verified-email`: the user's emails in the organization's verified domains
  (`organizationVerifiedDomainEmails`), matched against the user's email.
- `commit-email`: the git author email of the user's own non-merge commits in
  the PR (commits GitHub links to that user's account), matched against the
  user's email. For the requester and the user who enabled auto-merge, not for
  reviewers. Anyone can set a commit email, so with this resolver the requester
  ≠ approver `forbid` can be evaded by committing under someone else's email.
  The App reads the PR's first 100 commits.

The first resolver that matches wins. If none matches, the user is unmapped: a
review does not count, and a PR author gets no request. A resolver whose lookup
fails, such as `external-identity` when the App cannot read SAML identities,
fails the mapping rather than fall through to the next; leave it out of
`PM_GITHUB_IDENTITY` instead.

An organization with neither SAML nor a verified domain uses `commit-email` for
requesters and approves in the console or Slack.

## Team approval

Say two teams and one DBA: the DBA approves anything, and each team's leads
approve requests from their own team. Teams are IdP groups, so this is a Cedar
policy on the requester's groups:

```cedar
permit(principal in Role::"dba", action == Action::"task.approve", resource);

permit(principal in Group::"team-a-leads", action == Action::"task.approve", resource)
  when { resource.requester in Group::"team-a" };

permit(principal in Group::"team-b-leads", action == Action::"task.approve", resource)
  when { resource.requester in Group::"team-b" };
```

A lead may also be one person (`principal == User::"alice@acme.com"`), and
`&& resource.source == "github"` limits a lead to requests from GitHub.

## Statements and failure

A file may hold several statements. Each is a `query_result` child, run in order
on one connection. MySQL commits implicitly around each DDL, so a failure at
statement 3 of 5 leaves 1–2 applied; the request is FAILED at statement 3.

A failed file stops its own PR. `query executed` turns red, the PR comment shows
the failed statement, and the author and admins get a Slack message. Other PRs
in the scope keep running: a PR with a failed file does not hold the scope, even
when an earlier file of it already ran. That file stays EXECUTED, so the fix
does not run it again. The author pushes a fix, which is a new key and so a new
request to approve, and it runs once approved; from then on the PR holds the
scope again until it merges. When statements before the failed one were applied,
an admin reconciles: undoes them, or has the author leave them out of the fix
and accepts that `main` does not record them. Recommending one statement per
file keeps that case rare; on MySQL a single DDL statement either completes or
rolls back.

Recovery steps for authors are in the
[usage guide](./guides/usage.md#sql-from-a-github-pull-request-when-a-run-fails),
and for admins in the
[admin guide](./guides/admin.md#recovering-a-sql-run-from-github).

Results are stored like any request's, readable in the console by whoever may
assume the role. The PR comment and Slack message never carry rows: they carry
the outcome and, on failure, the failed statement and the target's error after
diagnostic redaction ([diagnostic-redaction.md](./diagnostic-redaction.md)),
which strips the values a DB error can quote.

## CI checks

The proxy-monster Action fails a PR that modifies or deletes a merged matching
file: that SQL already ran, and `main` records it. Renames and directory moves
pass, since file names carry no order and keys use the name without its
directory. A rename that also edits the file fails, like a modification, when
its new path is a matching file.

Testing the SQL itself is a separate step the team owns, because how to build a
database to test against differs per project. A typical one starts the target's
engine at its exact version and settings, runs a bootstrap (`init.sql`), then
every file in the order they merged (from git:
`git log --diff-filter=A --reverse --name-only`), exports the schema
deterministically (no comments, no dump date, `AUTO_INCREMENT` counters
stripped), and fails if the export differs from a committed `golden.sql`, so the
reviewer reads the change's effect as a `golden.sql` diff. proxy-monster may
ship such an action as an example; nothing in the control plane depends on it.

## Known gap

A requester is the PR author as mapped at the PR's first filing, not everyone
who pushed to the PR. An approver who pushes a commit to someone else's PR can
then approve it; GitHub does not expose who pushed a commit. The approver still
approves the exact final SQL, and the audit records them.

## Data model

Every request, whatever its source:

| Column         | Meaning                                                                         | Set when          |
| -------------- | ------------------------------------------------------------------------------- | ----------------- |
| `source`       | `console`, `mcp`, or `github`; also the Cedar `Request` attribute `source`      | filed             |
| `scope`        | the line of runs the request belongs to                                         | filed from GitHub |
| `file_key`     | the file's key from its name, e.g. `0042`                                       | filed from GitHub |
| `content_hash` | `n:` and the SQL's grant hash, or `r:` and its raw bytes' hash                  | filed from GitHub |
| `change_key`   | `sha256(file_key \|\| '\n' \|\| content_hash)`; ties approval and "already ran" | filed from GitHub |

`creator_kind` stays `WORKFLOW` for all three sources.

GitHub requests only:

| Column               | Meaning                                                                 | Set when                                    |
| -------------------- | ----------------------------------------------------------------------- | ------------------------------------------- |
| `path`               | the file's path in the repository                                       | filed                                       |
| `repository`         | `owner/name`                                                            | filed                                       |
| `pr`, `pr_url`       | the PR number and its link                                              | filed                                       |
| `head_sha`           | the PR head the request was last filed for                              | filed; moved by a filing that keeps its key |
| `filed_head`         | the head of the scope's latest filing                                   | every filing in the scope, on all its rows  |
| `key_order`          | the latest filing's `order`: `numeric` or `string`                      | every filing in the scope, on all its rows  |
| `approved_review_id` | the review that approved it; null for a console, Slack, or MCP approval | approved by a review                        |
| `merged_at`          | when the PR merged                                                      | the PR merges                               |
| `merge_sha`          | the PR's merge commit                                                   | the PR merges                               |

A request belongs to the PR's current filing when its `head_sha` equals
`filed_head`. Push 1 at head `abc` files `0041`: its request has
`head_sha = abc` and `filed_head = abc`. Push 2 at head `def` edits `0041`, and
its request takes the file through the same edit as a console edit: SQL whose
content hash changed is analyzed again and returns the request to PENDING under
the next `revision`; SQL with the same hash keeps the stored text, the revision,
and the approval. Either way `head_sha` becomes `def`, and a file moved to
another path with the same key keeps its request under the new path. A request
that already ran, failed, or was rejected is never edited; new SQL gets a new
request.

A push that removes a file ends its request as `DELETED`. A new status,
`ALREADY_RAN`, marks a request whose change key already ran in the scope from
another PR; it is kept so the merge can be recorded. A request whose PR closes
or merges before its SQL ran becomes `CANCELLED`.

## Alternative: a prerequisite chain

An earlier version ordered files by name and chained them, so each request named
the file it had to follow.

```
access_request (+) prerequisite_key, ignore_prerequisite
key(file) = sha256(key(previous file) || sqlGrantHash(content))

filing:  the Action also sends previousFile, the last matching file on main
         p = key of the EXECUTED request whose SQL matches previousFile ("" if none)
         for each new file in filename order: k = sha256(p || norm(sql)); p = k
run:     require the prerequisite EXECUTED (unless ignore_prerequisite)
         require no other PR's started request with the same prerequisite   -- branch behind
         require the one-PR-at-a-time rule above
```

It needed filename order to mean run order, an order check in the Action, a
`task.ignore_prerequisite` override for onboarding a directory that already had
files, and a previous file the Action had to identify. Running right before
merge with one PR at a time already fixes the order, and the commit check above
catches a branch that is behind, so the chain added rules without adding safety.
It also broke when two directories shared a scope, since each step only sees its
own directory's previous file.

## Open questions

- Run window: run as soon as the PR is ready, or keep `query executed` pending
  until a configured window.
- Whether another reviewer's "changes requested" blocks a request that already
  has a valid approval. proxy-monster needs one approval; GitHub would block.
