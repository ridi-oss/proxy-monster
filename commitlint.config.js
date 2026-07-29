// Conventional Commits, checked in CI (.github/workflows/commit-convention.yml).
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // The types release-please-config.json declares, plus style and revert. A type outside this set
    // parses as conventional but matches no changelog section, so the change would be absent from the
    // release notes and bump no version — which is why the component goes in the scope, `fix(web): …`
    // rather than `web: …`.
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'perf', 'refactor', 'build', 'docs', 'test', 'ci', 'chore', 'style', 'revert'],
    ],
    // Subjects are truncated wherever they are displayed; the default 100 is the spec's own guidance.
    'header-max-length': [2, 'always', 100],
  },
}
