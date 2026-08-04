// Package query is the enforcement core — `decideQuery`, the function every protected statement in
// the product passes through (area doc: plans/proxy-monster-go-port/06-query-decision.md).
//
// Kotlin source: `Query.kt` (1,238 LOC). `Access.kt`'s half of A6 is already ported, in
// internal/access.
//
// # The step order IS the security contract
//
// 06-query-decision.md §3 specifies the pipeline as an ORDERED table of 32 steps with every exit
// condition, precisely because the outputs alone do not pin the behaviour. [DecideQuery]'s body
// carries a `// STEP n —` comment on every block so a reviewer can diff it against that table line by
// line. Reversing any of the following turns the port FAIL-OPEN:
//
//   - INV-A6-7  — role resolution is STEP 6, deliberately AFTER admission (steps 4-5). An
//     inadmissible statement hard-denies before any role resolution or grant walk runs at all.
//   - INV-A6-8  — the deactivation gate (step 5) sits BEFORE the metadata/session passthrough
//     dispatch (step 14), so a deprovisioned principal cannot ride a readonly-meta passthrough
//     to an ALLOW.
//   - INV-A6-9  — contract validation (steps 8-11) runs BEFORE any Cedar verdict and INDEPENDENTLY
//     of it, so an UNMASKED column can never ride a malformed disposition or an out-of-range
//     ordinal to ALLOW.
//   - INV-A6-10 — a grant naming no resource is INVISIBLE to the has*-filtered category walk, so it
//     would silently ride a resolved-METADATA statement to a passthrough ALLOW. "Exactly one
//     resource" (step 8) is therefore a hard deny, never a skipped grant.
//   - INV-A6-11 — `row.isTemp` forces UNMASKED, BYPASSING column authz (step 24). Safe ONLY because
//     a write cannot launder a masked value into a temp (the MASKED + DENY_STATEMENT write branch,
//     ~100 lines away in the same loop). ONE COUPLED INVARIANT — see unmasked_temp_linchpin_db_test.go.
//   - INV-A6-12 — first-wins per output ordinal. Appending and letting the last win inverts it.
//   - INV-A6-6  — the delimiter guard's INTENTIONAL asymmetry (slash AND dot for columns/tables,
//     slash ONLY for functions/utilities) lives in internal/authz and is not "harmonised" here.
//
// # What landed
//
//	channel.go   Channel (5 values incl. MCP) + the EnfAction wire codec, fail-closed (INV-A6-3)
//	decision.go  DecisionContext (18 fields), the four deny/allow constructors, decisionRecord,
//	             redactsDiagnostics + leaksDiagnosticsOnAllow, grantAction, parseRequesterIp
//	catalog.go   CatalogColumnIndex, buildCatalogColumnIndex, catalogCoverage
//	dto.go       QueryRequest / QueryResponse
//	decide.go    effectiveAuthzContext + the 32-step DecideQuery
//
// # Seams, and why they are interfaces rather than concrete types
//
// `decideQuery`'s Kotlin signature names `PolicyStore`, `UserGroupStore` and `RoleResolver`
// concretely. Here they are one-method seams ([MaskFnLister], [UserGroupStore], [RoleResolver]) and
// that is NOT a design flourish — it is what lets internal/dbtest's EnforcementFixture call THIS
// package's production [DecideQuery] and [DecisionRecord] rather than reimplementing them.
// internal/policy's and internal/identity's own DB tests are IN-PACKAGE (`package policy`,
// `package identity`) and import internal/dbtest; if internal/query named those two packages then
// `policy [policy.test] → dbtest → query → policy` would be an import cycle in the test binary, and
// the fixture would have to grow a second, silently diverging decision path instead.
//
// *identity.RoleResolver and *identity.UserGroupStore satisfy their seams structurally, with no
// adapter at all. *policy.PolicyStore needs a three-line one, because Go cannot convert
// []policy.MaskFn to []query.MaskFn implicitly — see `maskFnsOf` in
// statement_facts_grant_loop_db_test.go, which wires the PRODUCTION store into the fixture.
//
// One consequence to know before adding a test here: because internal/dbtest imports this package,
// a test file that uses the fixture must be `package query_test`, not `package query`. Unexported
// helpers are covered by the in-package files that do not touch internal/dbtest.
//
// # Port policy notes carried in the code
//
//   - F12 (`decideQuery`'s unused `accessStore` parameter) — **OMIT**, the disposition 00-INDEX.md
//     records. It is read nowhere in the body, so it has no observable behaviour, and no Go caller
//     can bind arguments positionally past a struct field name (Q2's "confirm no test binds
//     positionally" is answered by construction: [DecideQueryInput] is a named-field struct).
//   - F13 (`denyReason`/`detail` are English prose reaching REST) — **REPRODUCE**. Every deny
//     message below is the Kotlin's verbatim English. Do NOT localise them; A1 INV-A1-13's
//     ApiError-codes-only rule and this surface genuinely conflict, and 06-query-decision.md §8 Q3
//     is the open question, not this port.
//   - The two dead locals at `Query.kt:307-308` are reproduced, including the fact that one of them
//     (`ds.engine.dialect`) throws for an engine that is neither MySQL nor Postgres. See [DecideQuery].
//
// # The test-only seam
//
// [DecideQueryInput.FactsOverride] is the ONLY way to reach the fail-closed contract branches
// (steps 8-11) that a resolved Go analyzer can never emit. 21 of `StatementFactsGrantLoopTest`'s
// cases depend on it — see statement_facts_grant_loop_db_test.go. Production callers leave it nil;
// the catalog and analyzer are still built, so column-grant resolution stays real.
package query
