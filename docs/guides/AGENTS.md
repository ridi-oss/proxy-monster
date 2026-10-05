# AGENTS.md — docs/guides

These guides exist to be read by an **agent**, which then walks a human through
proxy-monster. They are onboarding material, not design docs: someone points
their coding agent at one of these and asks to be shown how to use the system.

<!-- prettier-ignore -->
| Guide | Reader it onboards |
| --- | --- |
| [usage.md](./usage.md) | A developer who queries databases through proxy-monster |
| [admin.md](./admin.md) | An admin who configures policy, tags, and access |

Everything else under `docs/` is a design doc — the territory, written for
people building proxy-monster. These two are the map handed to people using it.

## Writing them

- **Answer from the guide, not from the model.** The point of a single
  authoritative file is that an agent stops improvising. Anything a reader needs
  belongs here; anything absent will be guessed.
- **Verify against a running system before writing a behavior claim.** Screens,
  badges, error strings, and CLI output are what a reader matches against, and
  they drift. A claim read out of another doc is not verified — that is how a
  guide inherits a stale statement and hands it to every reader.
- **Verification has a timestamp.** `main` moves. A behavior confirmed against a
  deployment describes the build that was running, so re-check the flows a
  change touched rather than trusting an earlier pass.
- **Keep the two audiences apart.** A developer never needs the admin guide.
  Cross-link them; do not merge them.
- **Say what fails and where the reason is.** These guides earn their keep on
  the denial paths, not the happy paths — the reader arrives already stuck.
- Repo doc conventions (house style, l10n, structure) are in
  [../../CONTRIBUTING.md](../../CONTRIBUTING.md#conventions).
