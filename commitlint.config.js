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
    // config-conventional rejects any leading capital, which Dependabot always writes ("Bump x
    // from a to b") and cannot be told not to. release-please parses it identically, so the only
    // effect was renaming every dependency PR by hand. PascalCase and ALL CAPS stay rejected.
    'subject-case': [2, 'never', ['pascal-case', 'upper-case']],
  },
}
