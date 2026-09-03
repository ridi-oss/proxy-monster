# 96 — Traceability: proving which Kotlin case each Go test ports

Coverage is a **measured** number, not a claimed one: run
`go test ./internal/tracing/ -run Coverage -v` for the current mapped total,
unmapped list and per-suite breakdown. The ratchet in `coverage_test.go` records
the last measured value and fails if it drops, so coverage can only go up as the
series lands.

The denominator moves too — the Kotlin suite grows and renames — so the
inventory is **derived**, never hand-maintained:

```sh
go run ./internal/tracing/geninventory.go          # regenerate kotlin_cases.txt
go run ./internal/tracing/geninventory.go -check   # fail if it is stale (CI)
```

**Increment log** — each row is a porting increment, not a re-seed:

| Increment           | mapped | Δ   | What it added                                                                                                                                                                   |
| ------------------- | ------ | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Machinery + seed    | 465    | —   | two mechanical passes over the existing Go tests                                                                                                                                |
| A7 `RunExecService` | 497    | +32 | `GrpcRunExecDbTest` (14), `EditorSubmitRouteDbTest` (9 + 1 deferred), `EditorSessionDecideTimingDbTest` (1), `TokenTtlTest` (4), `ApprovalExecuteRouteDbTest`'s 4 RunExec cases |

## Why this exists

The Go control plane will end with more test functions than the Kotlin has
cases, and `go test ./...` will be green throughout. Neither fact says anything
useful about the port, because the Go tests were written **from the area docs in
this directory**, not migrated from the Kotlin suite. A test count exceeding the
case count is a flattering number that proves nothing.

The measurement that mattered was different: of the Kotlin suites, **83 were
"mentioned somewhere" in the Go tests and 38 were not mentioned at all**. And a
mention is not a mapping — `internal/mcp/routes_test.go:13` says
"`ForwardedAuthorityTest.kt` (A12) covers `resolveForwardedAuthority`", and not
one of that suite's 15 cases is asserted anywhere in the Go module. So coverage
of the Kotlin suite was **unfalsifiable in both directions**: nobody could prove
a case was covered, and nobody could prove one was not.

This document defines the machinery that makes it falsifiable. The deliverable
is not more tests — it is a machine-checkable mapping from each of the Kotlin
cases to a named Go test.

## The three pieces

| Piece                                                   | Path                                           |
| ------------------------------------------------------- | ---------------------------------------------- |
| Authoritative case inventory (one line per case)        | `gocp/internal/tracing/kotlin_cases.txt`       |
| Marker convention (normative)                           | `gocp/internal/tracing/doc.go`                 |
| Inventory loader + marker scanner                       | `gocp/internal/tracing/{inventory,markers}.go` |
| The checker (a Go test, so `go test ./...` enforces it) | `gocp/internal/tracing/coverage_test.go`       |
| Self-tests proving the checker can fail                 | `gocp/internal/tracing/machinery_test.go`      |

## 1. Counting the Kotlin cases

**The only correct count.** Every other number in this document is checked
against it:

```sh
grep -rhoE '@Test\b' --include='*.kt' <path> | wc -l
```

- `grep -c @Test` **over**-counts — it matches `@TestInstance` too.
- `@Test[[:space:]]*$` **under**-counts — many cases are written
  `@Test fun \`name\`()` on one line.
- Counting backticked funcs **under**-counts — a few cases use plain camelCase
  identifiers.

| Tree                                                      | Cases                           |
| --------------------------------------------------------- | ------------------------------- |
| `control-plane/src/test/kotlin/com/ridi/oss/proxymonster` | 1136                            |
| `engine/src/test/kotlin/com/ridi/oss/proxymonster`        | 56                              |
| **Total**                                                 | **1192** in **155** suite files |

Those totals are as of the commit this slice is cut from; regenerate rather than
trust them.

`TestInventoryMatchesTheKotlinTree` re-derives both numbers from the Kotlin tree
on every run (and skips only where the Kotlin tree is not checked out beside the
Go module), so the inventory cannot drift silently.

## 2. Case identity

One line per case in `kotlin_cases.txt`:

```
<SuiteFileBasename>.kt#<case name verbatim>
<SuiteFileBasename>.kt#<DeclaringClass>.<case name verbatim>
```

Case names are **verbatim**: backticked Kotlin names without their backticks,
plain identifiers as written. Spaces, punctuation, em dashes, apostrophes,
parentheses all preserved. No line has leading or trailing whitespace, and the
loader rejects the file if one does — whitespace is significant here.

The `<DeclaringClass>.` prefix appears **iff the file declares more than one
class holding `@Test` cases**. That is load-bearing, not cosmetic:
`EnforcementDbTest.kt` declares two top-level classes with many identical case
names, run against different engines.

```
EnforcementDbTest.kt#EnforcementPostgresDbTest.masked query returns masked rrn, never cleartext
EnforcementDbTest.kt#EnforcementMysqlDbTest.masked query returns masked rrn, never cleartext
```

The five files that need the prefix, and why:

| File                                       | Classes with cases                                                                      |
| ------------------------------------------ | --------------------------------------------------------------------------------------- |
| `EnforcementDbTest.kt`                     | `EnforcementPostgresDbTest` (23) + `EnforcementMysqlDbTest` (12) — many identical names |
| `SchemaThreadingDbTest.kt`                 | `SchemaThreadingDbContract` (8) + `…PostgresDbTest` (6) + `…MysqlDbTest` (3)            |
| `PerConnectionCatalogAdversarialDbTest.kt` | contract (3) + `…Mysql…` (3) + `…Postgres…` (2)                                         |
| `ApprovalsTest.kt`                         | `ValidateApprovalSourceTest` (4) + `ValidateProactiveComposeTest` (5)                   |
| `ForwardedAuthorityTest.kt`                | `ForwardedAuthorityTest` (8) + `TrustedEdgeCidrTest` (7)                                |

Where the cases live in ONE abstract contract that per-engine subclasses merely
instantiate (`PerConnectionCatalogDbTest.kt`, `WireTaskDecideDbTest.kt`), the
`@Test` appears once in the Kotlin and so appears once here, under the
contract's name. Both engines running it is a JUnit fact about that one case,
not two cases.

## 3. The marker convention

A Go test declares its Kotlin origin with a **line comment**:

```go
// KT: <identity> — <optional note>
// KT-OMIT: <identity> — <why porting it is deliberately not done>
// KT-DEFER: <identity> — <what it is blocked on, and where that is tracked>
```

`KT:` is a claim of coverage: _this Go test asserts what that Kotlin case
asserts_. Under the binding PORT POLICY in `00-INDEX.md` that means asserting
what the **Kotlin** asserts, **including where the Kotlin pins a defect**. A
marker on a test that asserts something else is worse than no marker, because it
reads as coverage.

`KT-OMIT:` and `KT-DEFER:` are the two honest ways to _not_ cover a case. Both
count as "accounted for"; neither counts as mapped. **A reason is mandatory** —
the checker rejects a bare identity.

### Rules

**Identity must match `kotlin_cases.txt` exactly.** The parser recovers it by
_longest inventory prefix_ within the cited suite, so a trailing note is
free-form and needs no escaping — necessary because many case names contain `—`
themselves and would be truncated at their own em dash by any split-on-separator
scheme. `TestNoIdentityIsAPrefixOfAnother` proves the resolution is unambiguous
(no inventory identity is a prefix of another) and fails if a future Kotlin case
breaks that.

**A note needs a separator: `—` (or `--`).** Without one,
`#…on admin actions extra` would resolve to `#…on admin actions` with note
`extra` — silently mapping a typo onto a real case. With one, the typo does not
resolve and the checker names it.

**The identity may not be wrapped.** The parser reads to end of line. Keep the
identity on one line however long, and wrap only the note (on plain comment
lines, which are ignored).

**Attachment** — which Go test a marker belongs to:

| Placement                                                                                 | Owner                                                                              |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Inside a test function's body                                                             | that function (put it above the `t.Run(...)` and the report names the subtest too) |
| In the doc comment **directly** above a test function (comment lines only, no blank line) | that function                                                                      |
| Inside a **shared contract helper** a test calls                                          | _every_ test that transitively reaches it — see below                              |
| Anywhere else                                                                             | unattached                                                                         |

`KT-OMIT:`/`KT-DEFER:` may be unattached — a whole suite can be omitted from a
file header. **`KT:` may not**: a coverage claim has to name a Go test.

**The contract-helper rule is the Kotlin's own shape, not a convenience.**
`SchemaThreadingDbTest.kt` declares an abstract `SchemaThreadingDbContract`
whose 8 cases run once per concrete subclass, one per engine. Go has no
inheritance, so `internal/query/schema_threading_db_test.go` makes the contract
a function that `TestSchemaThreadingPostgresDb` and `TestSchemaThreadingMysqlDb`
both call. A marker in there is genuinely ported by both, so the scanner walks
the file's call graph backwards and emits one mapping per reaching test. That is
why the report says _"472 marker lines → 480 mappings"_.

**Cardinality** — all three legitimate, all three allowed:

- One Go test may port **several** Kotlin cases (several `KT:` lines).
- Several Go tests may **split** one Kotlin case (the same identity on each).
  Common here: `WebSessionRoutesDbTest.kt` case 1 is split into a pure config
  test and a DB route test; `AuditCanonicalGoldenTest.kt` case 1 into
  `internal/conformance` and `internal/audit`.
- A **subtest** may carry its own marker.

**Not legitimate:** the same identity twice on the same Go test _and_ subtest.
That is a copy-paste, not a split, and the checker fails on it. The duplicate
key is `Owner` + `/` + `Subtest`, because `go test -run 'TestX/sub'` addresses a
subtest on its own.

## 4. The checker

```sh
go test ./internal/tracing/                        # enforce (also runs inside go test ./...)
go test ./internal/tracing -run Coverage -v        # the human report
KT_COVERAGE_REQUIRE_FULL=1 go test ./internal/tracing/   # demand the whole inventory
```

| Test                                | What it enforces                                                                                                                      | Gated?                                  |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `TestCoverageMarkersAreValid`       | unknown identity · `KT:` unattached · `KT-OMIT`/`KT-DEFER` with no reason · duplicate on one target · a case both claimed and omitted | **no — always fails**                   |
| `TestCoverageRatchet`               | mapped ≥ `minMappedCases`, accounted ≥ `minAccountedCases`                                                                            | yes                                     |
| `TestCoverageReport`                | nothing; prints the per-suite table + full unmapped list under `-v`                                                                   | n/a                                     |
| `TestNoIdentityIsAPrefixOfAnother`  | marker resolution stays unambiguous                                                                                                   | no                                      |
| `TestInventoryMatchesTheKotlinTree` | inventory totals + per-suite counts vs the real `@Test` count                                                                         | no (skips if the Kotlin tree is absent) |

An unknown identity is deliberately **not** behind the ratchet: a fabricated or
mistyped mapping is worse than a gap, because it reads as coverage. The failure
message offers the three closest inventory identities.

`internal/tracing` is excluded from the scan — its doc and self-tests quote
example markers, and a checker that counted its own examples would be the very
thing it exists to prevent.

### Raising the ratchet

`minMappedCases` in `coverage_test.go` is currently **497** (`minAccountedCases`
**498**). To raise it:

1. Add markers.
2. `go test ./internal/tracing -run Coverage -v`, read `MAPPED` off the summary.
3. Put that number in `minMappedCases` **and** `minAccountedCases`; commit both
   with the markers.

**Never lower it.** If a change legitimately removes a Go test and so unmaps a
case, the case must gain a `KT-DEFER:` marker in the same commit —
`minAccountedCases` is what stops a deletion from looking like progress. On the
day the port claims completeness, CI flips `KT_COVERAGE_REQUIRE_FULL=1`.

## 5. What the checker does NOT prove

Being explicit about this matters more than the number it prints.

- **It does not verify the assertion.** A `KT:` marker is a human claim that the
  Go test asserts what the Kotlin case asserts. The checker verifies the
  _citation_, not the _semantics_. Reviewing whether a mapped test really
  reproduces the Kotlin — defects included, per the PORT POLICY — is a reading
  task the checker cannot do.
- **It does not measure completeness within a case.** A Kotlin case with six
  assertions mapped to a Go test that makes two of them counts as mapped.
  Partial ports are the main residual risk in the seeded set (see below).
- **It does not see the Kotlin's own duplication.** Where the Kotlin runs one
  abstract case twice via two subclasses, the inventory has one line, by design.

## 6. How the first 465 were seeded

Two mechanical passes over the existing Go tests. No mapping was guessed.

**Pass 1 — verbatim quote (341 cases).** The Kotlin case name appears _verbatim_
in a Go doc comment or `t.Run` name. Guards: whole-token match (so
`no roles at all is denied` cannot capture `…is denied on every column`);
insertion only onto a comment / `t.Run` / table-`name:` line, never inside a
string literal; engine discriminator where a file declares the same case name in
two classes (`EnforcementPostgresDbTest` → a Go test named `…Postgres…`); suite
affinity where one case name exists in two Kotlin suites
(`count(star) on an ungranted table is denied` is in both `KnownGapsTest` and
`ScannedTableMySqlTest`).

**Pass 2 — CamelCase transliteration (112 cases).**
`norm(caseName) == norm(goFuncName)` after stripping `Test` and any topical
prefix, **plus** the Go file must cite the Kotlin suite basename — without that
constraint a similarly-worded case in another suite captures the mapping.

**Hand-resolved (12 cases).** Where a Go file header states the mapping in
prose: `internal/audit`, `internal/policy` (a documented two-test split),
`internal/oidc` → `internal/device` (the OIDC↔device import cycle forces the
device-login cases into `internal/device`), `internal/session` (three named
`case N` subtests of `TestTheThreeDistinctRenewalRefusals`), and the audit
golden vectors.

### ⚠️ A rejected approach worth recording: "case N" citations do NOT index the Kotlin declaration order

Many Go files cite their origin as `Case 4 — …` or `case 7's …`, which looks
like a rich third mechanical pass. **It was tested against the 183
already-verified mappings that sit next to such a citation and falsified: 159
agreed, 24 disagreed**, and `internal/config/config_test.go` disagrees
_systematically_ — its "case 2" is Kotlin declaration position 14, "case 3" is
16, "case 5" is 8. The numbering follows the Go file's own ordering or the area
doc's, not the Kotlin's. **Do not map on case numbers.** Map on the case name.

## 7. Where the remaining 406 are

44 suites are at zero. The largest holes, in order (the four struck rows landed
with A7):

| Suite                                | Cases | Unmapped | Note                                                                                                                                                                                                                                                                                                        |
| ------------------------------------ | ----- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GrpcRegistrationHandlerDbTest.kt`   | 22    | 22       | not cited anywhere in the Go tests                                                                                                                                                                                                                                                                          |
| `GrpcDecideHandlerDbTest.kt`         | 18    | 18       |                                                                                                                                                                                                                                                                                                             |
| `ProvisionMergeDbTest.kt`            | 18    | 18       |                                                                                                                                                                                                                                                                                                             |
| `ForwardedAuthorityTest.kt`          | 15    | 15       | _cited_ in `internal/mcp/routes_test.go:13`, zero cases asserted — the exact failure mode this document exists to expose                                                                                                                                                                                    |
| ~~`GrpcRunExecDbTest.kt`~~           | 14    | **0**    | ✅ ported 1:1 in `internal/app/runexec_grpc_db_test.go`                                                                                                                                                                                                                                                     |
| `ApprovalResultViewContextDbTest.kt` | 12    | 12       |                                                                                                                                                                                                                                                                                                             |
| `DaemonSessionStoreDbTest.kt`        | 17    | 12       |                                                                                                                                                                                                                                                                                                             |
| `HttpRequesterIpResolutionTest.kt`   | 11    | 11       |                                                                                                                                                                                                                                                                                                             |
| ~~`EditorSubmitRouteDbTest.kt`~~     | 10    | **1**    | ✅ 9 ported in `internal/app/runexec_routes_db_test.go`; case 9 is `KT-DEFER:` — blocked on a test-only login seam on `app.HTTPSurface` (the Kotlin mounts its own `POST /test/session/{principal}` route, which `NewHTTPSurface` has no hook for). The ASSERTION is already ported in `internal/approval`. |
| `GrpcPerConnectionCatalogDbTest.kt`  | 11    | 10       |                                                                                                                                                                                                                                                                                                             |
| `WireTaskDecideDbTest.kt`            | 10    | 10       |                                                                                                                                                                                                                                                                                                             |

The whole of A10 (gRPC) is the biggest single block of unmapped cases.
`SystemClassificationTest.kt` (19), `EnginesTest.kt` (13) and
`PerConnectionCatalogStateTest.kt` (17) were in this list before pass 2 and are
now fully mapped.

`go test ./internal/tracing -run Coverage -v` prints the full 438, grouped by
suite. That list is the work queue for the next increment.
