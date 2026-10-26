# proxy-monster SQL action

Runs reviewed SQL files from a pull request through proxy-monster: it files the
PR's new SQL files under `dir` as approval requests. The design and a full
workflow are in [sql-from-github.md](../docs/sql-from-github.md).

| Input        | Default                     | Description                                                              |
| ------------ | --------------------------- | ------------------------------------------------------------------------ |
| `server`     | (required)                  | Control-plane base URL                                                   |
| `audience`   | the server's origin         | OIDC audience the control plane trusts                                   |
| `dir`        | (required)                  | Directory of SQL files                                                   |
| `datasource` | (required)                  | Datasource the files run on                                              |
| `schema`     | (required)                  | Default schema of the run's connection                                   |
| `role`       | (required)                  | Role the files run under                                                 |
| `instance`   | `''`                        | The control plane's `PM_INSTANCE_NAME`; posts the skipped check itself   |
| `scope`      | `''`                        | Scope whose query executions happen one PR at a time                     |
| `files`      | `^(?P<key>[0-9]+)_.+\.sql$` | Regex a file name must match; its `key` group, else the name, is the key |
| `order`      | `numeric`                   | How keys sort: `numeric` (9 before 10) or `string`                       |
| `version`    | `latest`                    | `latest`, a pm-ci release such as `0.1.0`, or `source`                   |

Requirements:

- The job has `permissions: { id-token: write, contents: read }`, plus
  `checks: write` with `instance`: a PR that adds no SQL then gets
  `<instance>/query executed` as skipped from the workflow, even while the
  control plane is down. A mismatched `instance` fails the step on the next PR
  that files SQL.
- `actions/checkout` runs with `fetch-depth: 0`: the base...head diff needs both
  commits.
- When the control plane is on an internal network, a `tailscale/github-action`
  step joins the tailnet first.
- The control plane trusts GitHub's OIDC issuer:
  `PM_CI_OIDC_ISSUERS=github=https://token.actions.githubusercontent.com`. Its
  audience, `PM_CI_OIDC_AUDIENCE`, defaults to its public origin, which is the
  `server` origin here; set the input only when the control plane overrides it.
- It runs on `pull_request` events of types `opened`, `synchronize`, `reopened`
  and `ready_for_review`: a draft files its SQL once it is marked ready.

The action runs `pm-ci`, a small Go binary in this directory, released on its
own train (`pm-ci-v*` tags). Released binaries cover Linux and macOS on x64 and
arm64. `version: source` builds it from the action's own ref with
`actions/setup-go`; use it on Windows or for a pm-ci that is not released yet.
