// Package tracing makes the Kotlin→Go test port FALSIFIABLE.
//
// The Go control plane has more tests than the Kotlin has cases (1,423 Go test functions against 903
// Kotlin cases), but they were written FROM THE SPEC under plans/proxy-monster-go-port/, not migrated
// from the Kotlin suite. A bigger number proves nothing: it cannot show that any particular Kotlin
// case is reproduced, and it cannot show that one is missing. Before this package, coverage of the
// Kotlin suite was unfalsifiable in BOTH directions.
//
// This package fixes that with three pieces:
//
//   - kotlin_cases.txt — the authoritative inventory: one line per Kotlin @Test case, 903 lines.
//   - the KT: marker convention (below) — how a Go test declares which Kotlin case it ports.
//   - coverage_test.go — a Go test (so `go test ./...` enforces it) that reads the inventory, scans
//     every *_test.go in the module for markers, and reports mapped/903 with the unmapped list.
//
// # The inventory
//
// kotlin_cases.txt is generated from, and must stay in sync with, the Kotlin test tree:
//
//	control-plane/src/test/kotlin/com/ridi/oss/proxymonster   847 cases
//	engine/src/test/kotlin/com/ridi/oss/proxymonster           56 cases
//	                                                     ------------
//	                                                          903 cases in 121 suite files
//
// The authoritative count — the one every other number here is checked against — is
//
//	grep -rhoE '@Test\b' --include='*.kt' <path> | wc -l
//
// `grep -c @Test` OVER-counts (it matches @TestInstance too). `@Test[[:space:]]*$` UNDER-counts (many
// cases are written `@Test fun `name`()` on one line). Counting backticked funcs UNDER-counts (a few
// cases use plain camelCase identifiers). Use the form above and nothing else.
//
// Note 121 suite files, not the 116 that earlier notes claimed; 126 .kt files exist, 5 of which are
// support/ fixtures with zero cases. TestInventoryMatchesTheKotlinTree in coverage_test.go re-derives
// both numbers from the Kotlin tree when it is reachable, so the inventory cannot drift silently.
//
// # Case identity
//
// One line per case, in the form
//
//	<SuiteFileBasename>.kt#<case name verbatim>
//	<SuiteFileBasename>.kt#<DeclaringClass>.<case name verbatim>
//
// Case names are VERBATIM: backticked Kotlin names appear without their backticks, plain identifiers
// appear as written. Spaces, punctuation, em dashes, apostrophes and parentheses are all preserved.
//
// The <DeclaringClass>. prefix is present iff the FILE declares more than one class holding @Test
// cases. That is not cosmetic — EnforcementDbTest.kt declares two top-level classes,
// EnforcementPostgresDbTest and EnforcementMysqlDbTest, with MANY IDENTICAL case names. They are
// different tests against different engines and must be distinguishable:
//
//	EnforcementDbTest.kt#EnforcementPostgresDbTest.masked query returns masked rrn, never cleartext
//	EnforcementDbTest.kt#EnforcementMysqlDbTest.masked query returns masked rrn, never cleartext
//
// The same shape covers ApprovalsTest.kt (ValidateApprovalSourceTest + ValidateProactiveComposeTest),
// ForwardedAuthorityTest.kt (ForwardedAuthorityTest + TrustedEdgeCidrTest) and SchemaThreadingDbTest.kt
// (a contract plus two per-engine subclasses that add cases of their own).
//
// Where the cases live in ONE abstract contract that per-engine subclasses merely instantiate
// (PerConnectionCatalogDbTest.kt, WireTaskDecideDbTest.kt, PerConnectionCatalogAdversarialDbTest.kt),
// the @Test appears once in the Kotlin and so appears once here, under the contract's name. Both
// engines running it is a JUnit fact about that one case, not two cases.
//
// # The marker convention
//
// A Go test declares its Kotlin origin with a line comment. Three markers exist:
//
//	// KT: <identity> — <optional note>
//	// KT-OMIT: <identity> — <why porting it is deliberately not done>
//	// KT-DEFER: <identity> — <what it is blocked on, and where that is tracked>
//
// KT: is a claim of coverage: "this Go test asserts what that Kotlin case asserts". Under the binding
// PORT POLICY in plans/proxy-monster-go-port/00-INDEX.md that means asserting what the KOTLIN asserts,
// including where the Kotlin pins a defect. A marker on a test that asserts something else is worse
// than no marker at all, because it reads as coverage.
//
// KT-OMIT: and KT-DEFER: are the two honest ways to NOT cover a case. Both count as "accounted for"
// and neither counts as mapped. A reason is mandatory: the checker rejects a bare identity.
//
// # Marker rules
//
// The identity must match kotlin_cases.txt EXACTLY. The checker resolves it by longest inventory
// prefix, so a trailing ` — note` is optional and free-form; it does not need escaping even though 40
// case names contain an em dash themselves. TestNoIdentityIsAPrefixOfAnother proves that resolution is
// unambiguous, and fails if a future Kotlin case ever makes it ambiguous.
//
// Attachment — which Go test a marker belongs to:
//
//   - Inside a test function's body, the marker belongs to that function. Put it on the line above the
//     t.Run(...) it describes and the report will name the subtest too.
//   - In the doc comment DIRECTLY above a test function (comment lines only, no blank line between the
//     marker and the func), the marker belongs to that function.
//   - Anywhere else it is unattached. KT-OMIT: and KT-DEFER: may be unattached — a whole suite can be
//     omitted from a file header. KT: may NOT: a coverage claim has to name a Go test.
//
// Cardinality, all three of which are legitimate and all three of which the checker allows:
//
//   - One Go test may port SEVERAL Kotlin cases — several KT: lines on the one test.
//   - Several Go tests may split ONE Kotlin case — the same KT: identity on each of them. This is
//     common here: WebSessionRoutesDbTest.kt case 1 is split into a pure config test and a DB route
//     test, and each carries the marker.
//   - A subtest may carry its own marker.
//
// What is NOT legitimate: the same identity twice on the same Go test and subtest. That is a
// copy-paste, not a split, and the checker fails on it.
//
// # Worked examples
//
// A pure test whose doc comment already named its origin:
//
//	// KT: AuthzTest.kt#no roles is denied on admin actions — the 'admin = any session' hole stays closed
//	func TestNoRolesIsDeniedOnAdminActions(t *testing.T) { ... }
//
// A split, with the same identity on two tests:
//
//	// KT: WebSessionRoutesDbTest.kt#auth config exposes default session UX timings — pure half
//	func TestAuthConfigExposesDefaultSessionUxTimings(t *testing.T) { ... }
//
//	// KT: WebSessionRoutesDbTest.kt#auth config exposes default session UX timings — route half
//	func TestAuthConfigThroughTheRealModule(t *testing.T) { ... }
//
// A per-engine subtest inside one Go test:
//
//	func TestEnforcementPostgresDb(t *testing.T) {
//	    // KT: EnforcementDbTest.kt#EnforcementPostgresDbTest.IN subquery oracle is denied
//	    t.Run("IN subquery oracle is denied", func(t *testing.T) { ... })
//	}
//
// Deliberate non-coverage:
//
//	// KT-OMIT: AuditCanonicalGoldenTest.kt#canonical bytes and row hashes match the cross-language
//	//          golden vectors — covered by auditmon/canon's own golden test, which reads the SAME
//	//          fixture. Porting it would be a third implementation of the same assertion.
//	// KT-DEFER: <identity> — blocked on <what>, tracked as <where>
//
// A wrapped identity like that one does NOT parse: the identity ends at the newline. Keep the identity
// on one line however long it is, and wrap only the note.
//
// # The ratchet
//
// The checker does not demand 100% today. minMappedCases in coverage_test.go is a ratchet: coverage
// may not go DOWN. Raising it is the deliverable of every porting increment — see
// plans/proxy-monster-go-port/96-traceability.md for the procedure and for what the checker will and
// will not catch.
package tracing
