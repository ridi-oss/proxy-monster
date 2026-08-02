# Contributing to proxy-monster

Thanks for your interest in contributing. This page covers how to build and
test, and the conventions a change is expected to follow. Start by reading
[AGENTS.md](./AGENTS.md) — the project entry point: intent, module layout, the
stack, and the settled decisions.

## Build, test, run

The toolchain and the tasks are both pinned in `mise.toml`, so `mise install`
once and then, from anywhere in the repo. JDK 24 is the floor — the Gradle build
compiles with `--release 24` and targets JVM 24 — and `mise` supplies it:

```sh
mise run dev      # the whole local stack: datastores, control plane, both proxies, web console
mise run lint     # prettier over md/json/yaml/css + eslint over the web sources
mise run verify   # the whole gate: lint, JVM tests, Go tests, web unit tests + build
```

Run `mise run verify` before opening a pull request — it is the gate documented
in [AGENTS.md](./AGENTS.md#build-test-run). `mise tasks ls` lists the
per-component tasks for running one piece at a time; install, run locally, and
deploy is [INSTALL.md](./INSTALL.md).

Prettier owns the prose-and-config formats (`.md`, `.json`, `.yml`/`.yaml`,
`.css`); eslint owns TypeScript. `mise run lint` checks both and
`mise run format` rewrites what prettier owns, so a formatting-only diff never
has to be argued about in review.

MySQL is the primary, fully-enforced target and the correctness bar; verify it
first. PostgreSQL support is experimental.

The Go modules live under a root `go.work`, so Go commands take root-relative
package paths and never need a `cd` — `go test ./goproxy/...` from the repo
root. Bare `go test ./...` does not work there: the root is a workspace, not a
module. `mise run verify` enumerates the modules for you.

Every task that runs the Go tests passes `-race`, so a hand-run `go test`
without it is a weaker check than the gate: a data race reads as a pass.

## Tests are DB-backed

Enforcement is exercised against real databases, not mocks. Write MySQL and
PostgreSQL tests with Testcontainers, and reuse containers across tests where
you can. They are required, not optional: without a Docker environment they fail
rather than skip, so Docker must be running for `mise run verify`.

`PM_REQUIRE_DB_TESTS=true` turns a missing-Docker skip into a hard failure. CI
sets it so a security test can never pass by skipping. Locally, leaving it unset
lets the DB-backed tests skip on a machine without Docker. The catalog and wire
tests use a hard gate that ignores it and fails on missing Docker either way.

A few tests are `@Disabled` in source, so even a fully passing run reports a
handful of skips; zero skips is not the signal to look for.

## Conventions

- English for all docs, code comments, and identifiers. US spelling: canceled,
  color, catalog, behavior, favor.
- Comments and docs describe the current state in present tense. No task, phase,
  or workstream codes in comments or docs — they go stale. Commit messages may
  keep such references.
- A comment states what the code cannot: a constraint from outside the file, a
  non-obvious failure mode, why this and not the obvious alternative. It never
  narrates how the code came to be — no review findings, no what-was-tried, no
  "previously X", no account of a debugging session. **This repository is
  public.** A comment recounting how something was arrived at tends to carry
  what was around at the time: host names, directory layouts, internal tooling,
  network topology, who asked for what. Commit messages and pull requests are
  where that history belongs; they are equally public, so the same rule about
  naming internal systems applies there too.
- Localization is non-negotiable. Every user-facing string is localized
  (currently English and Korean). The server returns a stable dot-namespaced
  code and params, never English prose; the web client resolves it through a
  `next-intl` namespace. Every message key must exist in every supported locale
  under `web/messages/<locale>/` (see [docs/l10n.md](./docs/l10n.md)).
- Fail-closed, always. When the analyzer cannot prove a statement safe, route it
  through the deny-by-default Cedar gate rather than a hardcoded error in code.
  Coverage gaps are security gaps.
- Kotlin uses standard conventions and Gradle (Kotlin DSL); Go uses the standard
  toolchain.
- Commit subjects and pull request titles follow
  [Conventional Commits](https://www.conventionalcommits.org):
  `type(scope)!: subject`. The type is one of `feat`, `fix`, `perf`, `refactor`,
  `build`, `docs`, `test`, `ci`, `chore`, `style`, `revert` — the component goes
  in the scope, so `fix(web): wrap long Cedar lines`, not `web: ...`. A `!`
  marks a breaking change. CI checks this on every pull request.

Design docs follow the house style of
[docs/authz-model.md](./docs/authz-model.md): lead with a short decision,
justify after, stay grounded in real files, show worked examples, and name the
failure modes. The design-doc index is [docs/README.md](./docs/README.md).

## Releases

Three release trains, each with its own version and changelog
(`release-please-config.json`). Merging a release PR tags and publishes; a push
to `main` only opens or updates the PR.

<!-- prettier-ignore -->
| Train | Tag | Covers |
| --- | --- | --- |
| Server | `server-v0.1.0` | `goproxy`, `control-plane`, `auditmon`, `engine`, `auth`, `proto`, `web` |
| Client | `pmon-v0.1.0` | `pmon`, the client CLI |
| Library | `mysqlwire/v0.1.0` | `mysqlwire`, published for `go get` |

The paths a commit touches decide its train, so a `pmon/` change never bumps the
server. Subjects follow
[Conventional Commits](https://www.conventionalcommits.org):
`feat:`/`fix:`/`perf:` appear in the changelog, `chore:`/`test:`/`ci:` do not,
and `!` or a `BREAKING CHANGE:` footer drives the major bump.

`mysqlwire`'s tag carries a slash because Go requires that prefix for a module
outside the repository root. Inside the workspace `go.work` still resolves the
in-repo modules locally, so an unreleased `mysqlwire` edit reaches `goproxy` and
`pmon` immediately; only a standalone build (`GOWORK=off`) uses the pinned
version.

## License

proxy-monster is licensed under the [Apache License 2.0](./LICENSE). Section 5
of that license already places every contribution intentionally submitted for
inclusion in the work under the same terms, so opening a pull request licenses
your contribution under Apache-2.0 and there is no separate CLA to sign.

Keep [NOTICE](./NOTICE) to attribution that redistributors are obliged to carry
forward. Documentation belongs in the docs, not in a file every downstream
distribution has to reproduce.

## Code of conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By taking
part you agree to uphold it; report unacceptable behavior through the private
channel named there.

## Security issues

Do not file security vulnerabilities as public issues or pull requests. Report
them privately as described in [SECURITY.md](./SECURITY.md).
