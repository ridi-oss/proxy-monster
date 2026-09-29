// Package dbtest is the DB-backed test harness for the Go control plane: the ONE shared PostgreSQL
// backend (the control plane's own store) and the ONE shared MySQL backend (a *target* engine the
// enforcement suites broker queries to), plus the fixtures every DB-backed suite builds on.
//
// It is the Go equivalent of the Kotlin `control-plane/src/test/.../support/` package, which
// 00-INDEX.md:336-338 calls "the porting critical path: 5 files gate the other 116".
//
//	Kotlin support file            Go equivalent here
//	───────────────────────────    ─────────────────────────────────────────────────────────
//	TestDatabases.kt               backend.go (SharedPostgres/SharedMySql) + freshdb.go
//	EnforcementFixture.kt          fixture.go  (+ seed.go for the rows it writes)
//	EnforcementHarness.kt          harness.go  (QueryRows, ExecOnTarget, the decide/audit seam)
//	PerConnectionCatalogFixture.kt TODO(A5) — needs ConnectionCatalog, which is not ported yet
//	WebSessionTestSupport.kt       TODO(A4) — needs the session cookie codec
//
// # The contract, in three rules
//
//  1. ONE container per engine for the whole suite. Started once, REUSED across every test, every
//     package binary and every subsequent `go test` run (testcontainers Reuse keyed on a fixed Name).
//     Starting a database is the expensive part; per-test isolation comes from a fresh logical
//     database, never a fresh container.
//
//  2. DB-backed tests FAIL, they never skip. If no Docker provider is available, [Postgres] and
//     [MySQL] call t.Fatal. A suite that silently skips its security regressions is how a port ships
//     broken — and this port's whole method (differential conformance against the Kotlin) is void the
//     moment a leg reports a pass it never ran.
//
//     ⚠️ Deliberate DIVERGENCE from the Kotlin, recorded rather than hidden. `TestDatabases.kt:20-27`'s
//     `requireDockerOrSkip()` *skips* unless `PM_REQUIRE_DB_TESTS=true`, which only CI and the version
//     matrix set (`mise.toml:252`, `:334`, `.github/workflows/db-matrix.yml:96` — all read this
//     session); `mise run verify` does NOT set it, so a developer without Docker gets a green JVM run
//     over skipped DB tests. Kotlin's own hard gate `requireDocker()` (`:29-35`) is what the security
//     suites use. The Go side adopts the hard gate everywhere, matching
//     `goproxy/internal/dbtest/dbtest.go:1-5` and what `mise.toml:191-193` already *claims* is true
//     ("The JVM tests are DB-backed (Testcontainers) and fail rather than skip"). This is test
//     infrastructure, not observable control-plane behaviour, so the PORT POLICY's REPRODUCE default
//     does not reach it.
//
//  3. The version a leg runs is asserted against the image it was configured with. A container reused
//     from another image, or a tag that resolved elsewhere, would otherwise let a matrix leg report a
//     pass for a version it never ran — indistinguishable from real coverage. See [Backend.Series].
//
// # Images
//
// db-support.json at the repo root is the single source of truth for the supported set;
// `DbSupportMatrixTest` (Kotlin) keeps it honest against the engine's bundled classification
// manifests. The defaults here are the NEWEST supported series of each engine, so a plain `go test
// ./...` covers the version most installs run, and `PM_TEST_POSTGRES_IMAGE` / `PM_TEST_MYSQL_IMAGE`
// override them — which is how one matrix leg pins one version (`mise.toml:252`).
//
// The two default constants are duplicated from db-support.json rather than parsed from it at
// runtime, exactly as `TestDatabases.kt:84,136` and `goproxy/internal/dbtest/dbtest.go:119-121` both
// do. What is NOT duplicated is the *claim* that they agree: [TestDefaultImagesTrackDbSupportJson]
// locates db-support.json and fails if either default is not the newest declared series for its
// engine. F9 in 00-INDEX.md flags a fixed `../../` path into another module as a cutover hazard, so
// the lookup walks up from the working directory instead of hardcoding a depth.
//
// # Version skew
//
// testcontainers-go is pinned to v0.34.0 to match `goproxy/go.mod` (D13, 99-library-decisions.md:63),
// and `docker/go-connections` to v0.5.0 for the same reason. go.work resolves ONE version per module
// across the whole workspace, so bumping either here rebuilds goproxy, auditmon and pmon too (§3.4).
// Bump deliberately, in a change that re-runs their suites.
//
// `go-sql-driver/mysql` is required at v1.8.1, goproxy's version. Verified this session: the workspace
// already resolves it to v1.9.3 because `auditmon/go.mod` requires that, so this require raises
// nothing — `go list -m` reports the same versions before and after. Requiring v1.9.3 here would look
// harmless and would silently make the control plane the reason goproxy cannot go back.
//
// # Testcontainers environment
//
// 00-INDEX.md:346-349 warns that `control-plane/build.gradle.kts:104-137` carries five Testcontainers
// workarounds and that "whatever Go containerisation is chosen will hit the same environment; budget
// for it rather than rediscovering it." Measured here: exactly one of the five is needed, and it is
// mandatory — the reaper (see disableRyuk in backend.go). The macOS socket-discovery and
// API-version pins are docker-java problems that testcontainers-go does not have; it resolved
// `unix:///var/run/docker.sock` on this machine unaided.
//
// # Increment status
//
// Landed: the shared backends, fresh-database isolation, the migrated control-plane store, the
// seeding vocabulary, the target-execution half of the enforcement harness, and the DB-backed proof
// that internal/store's Flyway runner works against a real PostgreSQL.
//
// TODO(A6): [EnforcementFixture.Run] — the decide → execute → mask composition
// (`EnforcementHarness.kt:106-169`). Its Decide/DecisionRecord seams are function fields precisely so
// that, when A6 and A8 land, they are wired to the PRODUCTION `decideQuery` and `decisionRecord`.
// 🔒 The Kotlin harness reuses production `decisionRecord`, which is what makes the audit shape the
// suites assert THE PRODUCTION AUDIT SHAPE. Never satisfy those seams with a harness-local
// reimplementation — a fixture that re-derives the record proves only that the fixture agrees with
// itself.
//
// TODO(A2): [EnforcementFixture.PolicyStore] reads the `policy` table directly. Replace it with the
// production CedarPolicyStore when A2's store half lands.
//
// TODO(A3): [EnforcementFixture.RoleSource] resolves `principal_role` ∪ `group_role` only. The
// production RoleResolver ALSO unions active JIT grants and short-circuits to the empty set for a
// deactivated principal (RoleResolver.kt:45-54, read this session). Replace it with RoleResolver
// rather than growing this one — a fixture that grows its own role resolution is a second source of
// truth for the one question authorization is about.
package dbtest
