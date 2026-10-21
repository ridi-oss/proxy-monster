# SQL files from GitHub, against real GitHub

`run.py` checks [SQL files from GitHub](../../docs/sql-from-github.md) end to
end on real GitHub: it opens pull requests in a test repository and checks how
the control plane files, approves, runs, and merges them. It is run by hand,
before a release that touches this flow. CI runs the `github` leg of
`smoke/run.sh` instead, which drives the same flow against a fake GitHub.

| Scenario | What it checks                                                                                                  |
| -------- | --------------------------------------------------------------------------------------------------------------- |
| S1       | a file that fails partway turns the check red and leaves the PR open                                            |
| S2       | another PR still runs and merges                                                                                |
| S1b      | the fix needs a new approval and an update onto S2's merge                                                      |
| S3       | of two approved PRs, one merges first and the other waits for an update                                         |
| S4       | SQL changed after approval edits the same request, which needs approval again                                   |
| S5       | editing a file that already merged fails the Action                                                             |
| S6       | numeric keys run `9_` before `10_`                                                                              |
| S7       | an admin's force-run lets a PR that is behind run without an update                                             |
| S8       | a push that only reformats the SQL keeps the approval                                                           |
| S9       | a PR without SQL gets the check as skipped from the workflow and merges, also while the control plane is paused |

A full run takes about 20 minutes and leaves its tables in the target database.

`configs.py` checks that the run waits until GitHub would merge, under
base-branch configurations it sets up itself. Each scenario's base branch gets
its own ruleset, and the branches it merges into carry back into `main` at the
end.

| Scenario | Base branch configuration                | What it checks                                  |
| -------- | ---------------------------------------- | ----------------------------------------------- |
| C1       | `query executed` required                | a draft waits until it is marked ready          |
| C2       | `query executed` required                | an optional check still running holds the run   |
| C3       | one approving review required            | a missing review holds the run                  |
| C4       | code-owner review with no approval count | the rule is unchecked and holds the run         |
| C5       | `query executed` required                | a conflict with the base holds the run          |
| C6       | strict status checks                     | a branch behind the base waits for an update    |
| C7       | conversation resolution required         | an unresolved review thread holds the run       |
| C8       | only rebase merges allowed               | a squash auto-merge holds the run               |
| C9       | signed commits required                  | a rule the gate does not evaluate holds the run |
| C10      | classic branch protection                | classic protection holds the run                |
| C11      | no ruleset                               | a PR merged before approval runs once approved  |

It takes about 30 minutes. It mints the App's token from `PM_GITHUB_E2E_APP_KEY`
(default `~/.cache/proxy-monster/github-e2e/app-key.pem`) to post a check run of
its own.

## Setup

You need a target MySQL the control plane registers through a wire proxy (a
datasource tagged `system:development`), a control plane the runner can reach
with `PM_AUTH_DEBUG=true`, `gh` signed in with rights to create repositories and
Apps in the owner, Go, and `openssl`.

```sh
python3 smoke/github/setup.py --owner <org or user> --datasource <name> \
  --cp <control-plane URL> --mysql "mysql -h<host> -P<port> -u<user> -p<password> <database>"
```

It creates, recording each step so a rerun skips what is done:

1. a GitHub App with checks and pull requests write, contents, metadata, and
   members read, through GitHub's manifest flow: it opens a page where you click
   **Create**, and keeps the App's private key (mode 600);
2. a private repository (`--repo`, default `pm-github-e2e`) with auto-merge
   allowed, and [sql.yml](./sql.yml) as its workflow, filled with your
   control-plane URL, audience, datasource, schema, role, and directory;
3. the App's installation on that repository only: it opens the install page,
   where you click **Install**;
4. the ruleset in [ruleset.json](./ruleset.json), requiring the
   `github-e2e/query executed` check;
5. a self-hosted runner labeled `pm-github-e2e`, running a pm-ci built from this
   checkout;
6. a control-plane user whose email is your commit email, so the author and the
   auto-merge enabler map to it.

GitHub asks a person to confirm creating and installing an App, so those two
steps wait for your click. If your browser is on another machine, pass
`--callback-host <name it reaches this one by>` and `--callback-bind 0.0.0.0`.

It ends by printing the control-plane settings to restart it with
(`PM_INSTANCE_NAME=github-e2e`, `PM_GITHUB_APP_ID`,
`PM_GITHUB_APP_PRIVATE_KEY_FILE`, `PM_GITHUB_IDENTITY`, `PM_CI_OIDC_ISSUERS`,
`PM_CI_OIDC_AUDIENCE`) and the env file `run.py` reads. Its state lives in
`~/.cache/proxy-monster/github-e2e` (`--state-dir`).

## Running it

```sh
source ~/.cache/proxy-monster/github-e2e/run.env
python3 smoke/github/run.py
python3 smoke/github/configs.py
```

`PM_GITHUB_E2E_APPROVER` is the principal that approves (default
`approver@example.com`, signed in through the debug login as `system:admin`). It
prints a line per check and exits non-zero if any failed.

## Teardown

```sh
python3 smoke/github/teardown.py
```

It stops and removes the runner, deletes the repository (`gh` needs the
`delete_repo` scope: `gh auth refresh -s delete_repo`), overwrites and removes
the App's private key, and removes the state directory. GitHub has no API to
delete an App, so it opens the App's settings page for that last click.
