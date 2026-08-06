// Package config owns the PM_* environment contract: the ~30 variables, their defaults and parsers,
// the eleven validation rules that all fail startup, and the derived values.
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §1-2. Kotlin source: Config.kt (307 LOC),
// plus parseDuration and runStreamTimeoutMs.
//
// # The injected-env seam is mandatory
//
// Kotlin reads the environment exactly once, through Config.fromEnv(env: (String) -> String?). The
// lambda is injected, and that is what lets ConfigGuardTest drive all 25 cases without touching the
// real process environment. PRESERVE THIS SEAM: a Go port calling os.Getenv directly loses the whole
// config test suite (01-bootstrap.md §1).
//
// The Kotlin Config is constructed by name in ~40 test files, so most fields carry defaults. The Go
// equivalent needs the same "specify only what the test cares about" ergonomic.
//
// # parseDuration is hand-written, not time.ParseDuration (D19, 01-bootstrap.md §2)
//
// It must REJECT what Go's time.ParseDuration accepts (1.5h, 300ms, -5m, unit-less) and ACCEPT the
// bare-integer-seconds form Go rejects. The unit matches must be contiguous from offset 0 — 1h30m is
// valid, "1h x 30m" is not — and overflow from the exact-math must surface as the
// "duration is too large: …" invalid-argument error, not a wrapped arithmetic error.
//
// # Two vars do NOT go through the ordinary parser
//
// PM_IDP_RECHECK_INTERVAL uses toLong, not parseDuration. PM_QUERY_TIMEOUT uses toLongOrNull and
// THROWS on garbage rather than falling back to a default. Both are REPRODUCE.
//
// PM_DB_REPAIR_CHECKSUMS is read in Db.migrate(), NOT here — the only env var outside fromEnv
// (01-bootstrap.md §1). It stays in internal/store; do not fold it in for tidiness.
//
// # What is DONE in this package
//
// config.go — the whole env table, all eleven validation rules and the derived values (Config.kt).
// duration.go — parseDuration. uri.go — canonicalMcpResource (V10), mcpOrigin, requireSecureOidcUri
// (V8), and the java.net.URI-vs-net/url divergences those depend on. timing.go — runStreamTimeoutMs.
// auth_borrowed.go — the two auth/-module symbols Config.fromEnv reaches across the module boundary.
// config_test.go — ConfigGuardTest's 25 cases, 1:1, plus four ADDED tests that say why they exist.
//
// # F26 is REPRODUCEd, not fixed
//
// V4's overflow guard is the only upper bound on PM_QUERY_TIMEOUT, while the run token minted for a
// statement is separately clamped to 24h — so above 23h57m the token expires mid-statement. The port
// policy makes that a separate decision, never part of the migration. TestF26TimeoutLadderIsNotTotal
// pins the defect so a later fix has to change a test deliberately. See 00-INDEX.md F26.
//
// A7's run-transport timings — DialTimeoutMS, ExchangeTimeoutMS, TokenTTLGraceSeconds and the two TTL
// derivations — live in timing.go and internal/runexec consumes them from there. That resolves A1 Q5
// ("in Go it needs a shared package, not a per-area copy") the opposite way round from the earlier
// TODO's guess, and the reason is forced rather than stylistic: internal/config is the only import LEAF
// all three consumers (RunExecService, runStreamTimeoutMs, A5's TableDetailExec) can reach. See
// timing.go's header. config_test.go's local copies of the two formulas are GONE; case 25 and the F26
// pin bind to the shipped symbols.
// TODO(A12): unusableTrustedProxyEntries warns at startup and must NOT refuse to boot; a malformed
// entry fails closed (that hop is untrusted) — see 01-bootstrap.md §2 and 12-request-context.md.
// TODO(A14): OidcGroupMapping.parse for PM_OIDC_GROUP_MAP / PM_OIDC_GROUP_PREFIX and clampTtlSeconds
// for the two PM_OAUTH_*_TTL vars live in the Kotlin auth/ module — see 14-auth.md. They are in
// auth_borrowed.go for now; move them and leave a type alias mirroring Config.kt:6's typealias.
package config
