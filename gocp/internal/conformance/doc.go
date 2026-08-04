// Package conformance is the CROSS-LANGUAGE contract suite: the tests that fail when the Go port and
// the Kotlin control plane stop agreeing, without a JVM anywhere in the loop.
//
// # Why this exists as its own package
//
// Every other test in this module asks "does the Go code do what the Go code is supposed to do".
// These ask a different question: "do the Go BYTES equal the Kotlin BYTES". That question can only be
// answered against an ORACLE, and there is no Java runtime on this machine — `java -version` reports
// "Unable to locate a Java Runtime" (recorded in cedar-spike/corpus/README.md, which was built under
// the same constraint). So every expectation here is sourced from exactly one of two things, named
// per assertion:
//
//	(a) a checked-in golden fixture the Kotlin CI itself replays
//	    — control-plane/src/test/resources/atrail/canonical-golden.json;
//	(b) a frozen assertion in the Kotlin TEST SOURCES, cited to file:line
//	    — via the spike corpus vendored under testdata/ (see cedar_policies_test.go).
//
// Nothing here is derived from a remembered or imagined cedar-java / kotlinx run. Where the repo pins
// nothing, the assertion says so rather than inventing an expectation.
//
// The reason it is a SEPARATE package rather than more cases inside internal/audit, internal/authz
// and internal/types is blast radius in the other direction: a conformance failure must be readable
// as "the cross-language contract moved", not as "a unit test broke". Unit tests are free to change
// with the implementation. These are not — changing an expectation here is a coordinated
// cross-language format change, and the package doc says so where a reviewer will see it.
//
// # The four contracts
//
//	audit_canonical_test.go  the audit hash preimage — golden bytes, byte-for-byte, plus the four
//	                         structural rules (domain separator, chain version, 0xFFFFFFFF null
//	                         marker, INV-A8-5's split sort) asserted DIRECTLY against the encoding
//	                         rather than only through a hash.
//	cedar_policies_test.go   all 186 Cedar policy records in the spike corpus, replayed through
//	                         authz.DefaultSchema.Validate, with AGREE / DISAGREE counts reported.
//	cedar_decisions_test.go  the corpus's frozen cedar-java verdicts, replayed through the exported
//	                         internal/authz surface, expectations READ FROM the corpus JSON.
//	wire_json_test.go        golden JSON BYTES for the ported DTOs — INV-A1-4's two rules
//	                         (always emit [], always omit absent optionals) frozen as literal files.
//	instant_test.go          java.time.Instant.toString()'s variable-precision fraction, across
//	                         every boundary Go's RFC3339Nano gets wrong.
//
// # ⚠️ F9 — the audit golden fixture needs a language-neutral home (PROPOSAL, NOT PERFORMED)
//
// 00-INDEX.md:188 already records F9: canonical-golden.json is read by auditmon through a fixed
// `../../control-plane/src/test/...` hop that BREAKS AT CUTOVER. This package makes the problem
// strictly worse in the useful way — it adds a THIRD reader — so the proposal is recorded here.
//
// Today, three consumers read one fixture that lives inside the module cutover deletes:
//
//	auditmon/canon/canonical_test.go:90       filepath.Join("..","..","control-plane",...)  — FIXED HOP
//	gocp/internal/audit/canon_test.go findUpwards("control-plane/src/test/...")     — walks up
//	gocp/internal/conformance         findUpwards(...) — same walk, same doomed suffix
//
// PROPOSED HOME: a repo-root, language-neutral directory
//
//	testdata/audit-canonical/canonical-golden.json
//	testdata/audit-canonical/README.md
//
// chosen because (1) it is outside every language module, so no module's deletion takes it; (2) the
// repo root is already the anchor all three readers walk up to, so each becomes a one-line suffix
// change and no reader needs a new lookup mechanism; (3) `testdata/` is the one directory name the Go
// toolchain refuses to compile, so a top-level one cannot become an accidental package; and (4) the
// existing README.md moves WITH it, keeping the format spec next to the bytes it specifies.
//
// The move itself is a cutover task and is DELIBERATELY NOT PERFORMED here: it touches the Kotlin
// module's Gradle test resources and auditmon's fixed hop, both outside this worktree's scope. What
// this package does instead is make its own reader move-proof (goldenFixturePath below tries the
// proposed home FIRST and falls back to today's location), so when the move happens this suite keeps
// passing and is not a fourth thing to remember.
package conformance
