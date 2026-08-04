# 98 — Cedar spike report (S1..S7)

**Date:** 2026-08-01 · **Decides:** whether A2's authorization layer has a Go
path at all. **Subject:** `cedar-policy/cedar-go v1.8.0` vs
`com.cedarpolicy:cedar-java 4.3.1` (`control-plane/build.gradle.kts:20`).
**Environment:** Go 1.25.3 darwin/arm64. **No Java runtime on this machine** —
no cedar-java was executed, and none of the numbers below are cedar-java output.
See [§ What we could not determine](#what-we-could-not-determine).

---

## Verdicts

| #      | Question                                                                                   | Verdict                   |
| ------ | ------------------------------------------------------------------------------------------ | ------------------------- |
| **S1** | Do the seeded policies + SYSTEM migration rows validate identically under cedar-go strict? | **GO**                    |
| **S2** | Never-throws for policy-shaped input; parse vs semantic errors distinguishable?            | **GO_WITH_WORK**          |
| **S3** | Does the `schemaFor` schema-**text** augmentation trick work?                              | **GO**                    |
| **S4** | Is an engine **error** distinguishable from a **deny** (fail-closed mapping)?              | **GO_WITH_WORK**          |
| **S5** | Which IP literals diverge between the two engines?                                         | **GO_WITH_WORK**          |
| **S6** | Does any test assert cedar-java's duplicate-entity error?                                  | **GO** (answered: **no**) |
| **S7** | Is `x/exp/schema/validate` stable enough to pin, or is out-of-process validation needed?   | **GO_WITH_WORK**          |

### Overall recommendation

> **Proceed with `cedar-go` v1.8.0, in-process. Out-of-process validation (a
> Rust CLI sidecar) is NOT needed. This is not a NO_GO and it does not change
> the migration strategy.**

The sharpest question — S3, whether the derived-tag mechanism survives — is a
clean GO: cedar-go ships a human-readable `.cedarschema` **text** parser, the
string-concatenation trick works verbatim, and the mechanism needs **porting,
not rewriting**. Every one of the 186 corpus policy records reproduces its
frozen accept/reject oracle with zero disagreements, and the fingerprint is
stable across five cedar-go releases.

What is _not_ free: four behavioural divergences that are real, wire-visible,
and unpinned by any Kotlin test. Two of them (**W1** engine-error mapping,
**W2** multi-statement policy source) are security-relevant. Budget them
explicitly — see [§ Work items](#work-items).

---

## Verification performed by this agent

Probe agents overstate. Every claim carried forward below was re-derived here,
not copied.

| What                     | How                                                                                                                                                     | Result                                                                                     |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| S3 whole suite           | re-ran `S3/run-all.sh` (7 probes)                                                                                                                       | reproduced; `G-3 rows=20 oracle mismatches=0`, `H-TOTAL pass=13 fail=0`                    |
| S1 whole corpus          | re-ran `cd S1S2 && go run .`                                                                                                                            | reproduced; `AGREE 184 / DISAGREE 0 / N-A 2`                                               |
| S4 whole suite           | re-ran `S4/RUN.sh` (3 probes + audit)                                                                                                                   | reproduced incl. §3 E10 and §13                                                            |
| S5 conformance           | re-ran `S5/conformance && go run .`                                                                                                                     | reproduced; faithful 16/16, naive 15/16                                                    |
| S6 dedupe                | re-ran `S6S7/s6_dedupe && go run .`                                                                                                                     | reproduced                                                                                 |
| S7 version sweep         | re-ran `S6S7/run_versions.sh` (5 versions, real `go get`)                                                                                               | reproduced; identical fingerprint                                                          |
| Rust oracle              | re-ran `wasm-oracle/oracle.js` under node                                                                                                               | reproduced; cedar 4.3.3, `AGREE 184`, `DISAGREEMENTS (none)`                               |
| Golden posture digest    | re-ran `check_digest.py`                                                                                                                                | `alnum-primary md5 : 6a1bb6ff914c542db83ba609cdd945f4 MATCH` vs `PolicyOriginDbTest.kt:69` |
| Corpus case count        | `grep -cE '^\s*@Test\s*$'` over the 14 A2 files                                                                                                         | **90**, matching §10                                                                       |
| Corpus scope corrections | `ls .../db/migration/`, `grep -oE "permit\(                                                                                                             | forbid\("`                                                                                 | **V1–V10 only**; V8 has **40**, not 52 |
| S6's premise             | `grep -rn "duplicate entity\|dedupeByEuid" control-plane/src/test/`                                                                                     | **zero hits**                                                                              |
| S4's premise             | `grep -rn "authorization engine error\|denied by policy\|no policy permits"` in tests                                                                   | **zero hits** in tests; `Authz.kt:270`/`:276` in main only                                 |
| S2 multi-statement       | re-ran `S1S2/s2b && go run .` + a fresh single-policy Rust `validate` call                                                                              | Go accepts + drops stmt 2; Rust rejects `unexpected token \`permit\``                      |
| Kotlin citations         | read `CedarEngine.kt:67,72,82-89,120,124`; `Authz.kt:254-278`; `schema.cedarschema:114-119`; `ChannelContextAuthzTest.kt:82-89`; `AuthzTest.kt:145-165` | all as cited                                                                               |

**Nothing was downgraded to UNKNOWN for lack of program output.** Every probe's
evidence field contained real transcript text and every transcript re-ran. Two
claims _were_ re-scoped — see
[Corrections to the probe agents](#corrections-to-the-probe-agents).

### A second oracle appeared, and it matters

The S1/S2 probe found something the charter did not anticipate:
**`@cedar-policy/cedar-wasm@4.3.3` installs and runs on this machine.**
cedar-java 4.3.1 is a JNI binding over the Rust `cedar-policy` crate; cedar-wasm
4.3.3 is a WASM binding over the _same core_. It is **not** cedar-java, but it
is a far better proxy than training-data recall.

```
$ cd .../S1S2/wasm-oracle && node oracle.js
cedar version      : 4.3.3
cedar SDK version  : 4.3.3
cedar lang version : 4.2
ValidationMode type: "strict" only (cedar_wasm.d.ts:199) — no permissive in 4.3.x

=== Rust-Cedar 4.3.3 vs the frozen expectation, 186 records ===
  AGREE                         184
  not-reached(rust rejects)     2
  wasm threw on: 0
=== DISAGREEMENTS ===
  (none)
```

So S1's GO rests on **two independent oracles agreeing**: the frozen Kotlin
assertions, and the Rust core cedar-java wraps. Treat every Rust-oracle claim
below as `Hypothesis (Rust-corroborated)` for cedar-java, never as measured
cedar-java behaviour — the version differs (4.3.3 vs 4.3.1) and the Java binding
layer is not exercised.

---

## S1 — Do the policies validate identically? **GO**

**Asked:** do all seeded policies + SYSTEM migration rows accept/reject
identically under cedar-go strict validation?

**Run:**

```
$ cd .../cedar-spike/S1S2 && env -u GOROOT go run .
base schema: parsed + resolved OK (11972 bytes)
policies.json: 186 records

=== S1 SUMMARY (all 186 records) ===
  AGREE                        184
  N/A(not-reached,go-rejects)  2

=== by slice ===
  SYSTEM (V8__seed.sql, 40)          total=40   AGREE=40   DISAGREE=0
  expected reject (10)               total=10   AGREE=10   DISAGREE=0
  non-templated (accept/reject)      total=124  AGREE=122  DISAGREE=0
  templated (after substitution)     total=62   AGREE=62   DISAGREE=0

=== DISAGREEMENTS (full) ===
  (none)
```

The 10 pinned rejects reproduce with the _right error class_ too — 8 semantic, 2
parse:

```
  src  : permit(principal in Role::"system:admin", action == Action::"totally.unknown", resource);
  prov : .../CedarPolicyStoreTest.kt:120
  go   : valid=false class=semantic
  err  : for policy `candidate`, unrecognized action `Action::"totally.unknown"`
  err  : for policy `candidate`, unable to find an applicable action given the policy scope constraints

  src  : permit(principal, action == Action::"datasource.connect", resource) when { context.channel == "wire" };
  prov : .../ChannelContextAuthzTest.kt:81
  go   : valid=false class=semantic
  err  : for policy `candidate`, unable to guarantee safety of access to optional attribute `channel` in context for Action::"datasource.connect"

  src  : this is not cedar at all
  prov : .../CedarPolicyStoreTest.kt:108
  go   : valid=false class=parse
  err  : parse error at <input>:1:6 "is": unexpected effect: this
```

Negative controls confirm the validator is actually _doing_ something rather
than accepting everything (`s1b/s1b_run.log`): mutating a real seed row's action
id, entity type, `has`-guard, or a comparison operand each flips
`valid → REJECTED` with a specific message.

Strict vs permissive makes **no difference** on this corpus (`s2/s2_run.log`):
all 10 rejects reject in both modes; all 112 accepts accept in both. That is
worth knowing because Cedar 4.3.x's WASM binding exposes **only** strict — so
the shipped corpus does not depend on the mode at all.

**What it means for the port:** the policy corpus is not the risk. Go strict
validation is a drop-in.

**Work item:** none for the GO. See **W10** for the 62 templated records, which
are blocked on A5/A13 catalog resolution and are needed for _full_ conformance,
not for this verdict.

---

## S2 — Never-throws, and parse vs semantic errors **GO_WITH_WORK**

**Asked:** does `validate` still satisfy "never throws for policy-shaped input",
and can parse errors be distinguished from semantic errors so the concatenated
`CedarValidateResult.errors` list is reproducible?

**Never-throws: yes.** 20 adversarial inputs, every one returning a message
rather than panicking (`s2/s2_run.log`), including embedded NUL, unterminated
string, unterminated paren, annotation-only, and 130-deep nesting.

**Parse vs semantic: yes, cleanly.** cedar-go splits the two at different call
sites, so the Kotlin concatenation (`response.errors` ++
`response.success.validationErrors`) maps 1:1:

| Kotlin                                      | cedar-go                                         | measured class |
| ------------------------------------------- | ------------------------------------------------ | -------------- |
| `Policy(src, id)` throw / `response.errors` | `(*cedar.Policy).UnmarshalCedar` returns `error` | `parse`        |
| `response.success.validationErrors`         | `validate.Validator.Policy(...)` returns `error` | `semantic`     |

Measured classes across the 20 probes: 2 blank · 6 parse · 10 semantic · 2 ok.
The classification agrees with the Rust oracle on **20 of 34** probes, and the
_text_ is byte-identical on **11**, all semantic.

### Three divergences, all wire-visible, none pinned by CI

**(a) 🔴 Multi-statement source is silently truncated — security-relevant.**

```
$ cd .../S1S2/s2b && env -u GOROOT go run .
  UnmarshalCedar: OK (no error)
  input  (118 bytes): permit(... Action::"sql.select" ...); | forbid(... Action::"sql.ddl" ...);
  MarshalCedar round-trip: permit ( ... Action::"sql.select" ... );
  -- (3) does the dropped statement affect a DECISION?
    action=sql.select   decision=allow
    action=sql.ddl      decision=deny        <- statement 2 was DROPPED
```

Rust Cedar, on the same source through the single-named-policy path (the
analogue of cedar-java's `Policy(src, "candidate")` at `CedarEngine.kt:105`):

```
$ node -e "... cedar.validate({policies:{staticPolicies:{candidate: two}}}) ..."
two-stmt -> ["parse",["failed to parse policy with id `candidate` from string: unexpected token `permit`"]]
```

So: `POST /api/policies` with `permit(...); forbid(...);` is **rejected** by the
Kotlin service (`Hypothesis`, Rust-corroborated) and **accepted** by a naive Go
port, which then enforces only the first statement. If statement 2 is the
`forbid`, that is a silently dropped security control. This is the single
highest-value work item in S2 → **W2**.

**(b) `isBlank()` differs on 8 code points.** `CedarEngine.kt:104` returns
`"cedar policy source must not be blank"` for `cedarSrc.isBlank()`. Java
`Character.isWhitespace` and Go `unicode.IsSpace` disagree on `U+001C..U+001F`
(Java yes, Go no) and `U+0085`, `U+00A0`, `U+2007`, `U+202F` (Go yes, Java no).
A source made only of such a rune returns the blank message on one side and a
parse error on the other. Wire-visible in `CedarValidateResult.errors` → **W5**.

**(c) Parse-error _text_ differs on every parse error.** Go:
`parse error at <input>:1:6 "is": unexpected effect: this`. Rust:
`failed to parse policy with id \`candidate\` from string: unexpected token
\`is\``. Semantic text is identical; parse text never is. Nothing in CI pins it — but the web policy editor renders `errors`
verbatim → **W8**.

---

## S3 — The `schemaFor` augmentation trick **GO** (the sharpest question, cleared)

**Asked:** does appending generated `action "context.tag::<name>"` declarations
to the schema **TEXT** and re-parsing work, or is cedar-go's schema API AST-only
for construction?

**Answer: the text path exists and works.**
`(*x/exp/schema.Schema).UnmarshalCedar([]byte)` parses the human-readable
`.cedarschema`; `.Resolve()` yields the `*resolved.Schema` that `validate.New`
consumes.

```
$ cd .../S3 && ./run-all.sh     # corpus schema sha256 c3acd118…e311b8
A1  OK   x/exp/schema.Schema.UnmarshalCedar parsed the human-readable text
A2  OK   Resolve() -> entities=15 actions=24 enums=0 namespaces=0
B1  OK   SchemaFor([trusted-network derived editor-origin segregated]) re-parsed the concatenated text
B2  augmented: entities=15 actions=28  (base actions=24)
B5  generated action context declares `tags`? false  (must be false — INV-A2-12)
```

**Both directions hold**, which is what makes the mechanism meaningful rather
than vacuous:

```
C1  vs BASE      -> REJECT (2 errors): unrecognized action `Action::"context.tag::trusted-network"`
C2  vs AUGMENTED -> ACCEPT (0 errors)
C3  via self-augmenting Validate() -> ACCEPT (0 errors)
C5  consumer vs BASE -> ACCEPT (0 errors)      # the consuming side needs no declaration
D1  unguarded tag-on-tag via Validate() -> REJECT (1)   [oracle: REJECT]   # TagResolutionTest case 6
D3  guarded   tag-on-tag via Validate() -> ACCEPT (0)   [oracle: ACCEPT]   # case 7
G-3 rows=20  oracle mismatches=0
H-TOTAL  pass=13 fail=0
```

`INV-A2-12`'s **both** closures survive independently. Half 1 (schema omits
`tags`) is `D1`/`D3` above. Half 2 (`includeTags = false` at evaluation) is
measured directly:

```
  guarded tag-on-tag rule, pass-1 context (no `tags` key) -> deny (errors=0)
  same rule if `tags` LEAKED into pass 1                  -> allow   (recursion hole)
```

The **shipped** pair also passes: V8 row `-300`
(`context.trusted-network-tailscale`, the producer) and `-258`
(`preset.production-pii-unmasked`, the consumer) both ACCEPT, matching their
oracle.

**The generated declaration's byte-exact template is at
`CedarEngine.kt:86-87`:**

```kotlin
"action \"context.tag::$name\" appliesTo { principal: [User, Role], resource: [Datasource], " +
    "context: { channel?: String, requester_ip?: ipaddr, tailscale_caps?: Set<String> } };"
```

with `tagNames.sorted()` ordering and a `"$text\n$decls"` join
(`CedarEngine.kt:85,89`).

**Pathological tag names behave.** `CedarEngine.kt:116-117` names the mechanism
exactly: a trailing backslash from a `\"` escape. `Action::"context.tag::a\"b"`
is valid Cedar; the extraction regex `[^"]+` (`CedarEngine.kt:~40`) stops at the
first raw quote and captures `a\`, whose generated declaration is an
unterminated string literal:

```
    extracted  : ["a\\"]
    SchemaFor  : ERROR (recoverable) -> schema parse: schema.cedarschema+tags:237:8: unterminated string literal
    Validate   : REJECT (1): invalid context.tag action name: schema parse: … unterminated string literal
```

cedar-go returns a plain `error`, not a panic — so Kotlin's
`catch (e: Exception) → "invalid context.tag action name: …"`
(`CedarEngine.kt:123-124`) maps 1:1 to a Go error check. No probe in any suite
produced a panic.

**Work item → W4.** Two parts, and note the second overrides the probe agent's
recommendation.

---

## S4 — Engine error vs deny **GO_WITH_WORK** (the one real security decision)

**Asked:** does cedar-go surface an engine **error** distinguishable from a
**deny**, so `toAuthzDecision`'s fail-closed branch 1 survives?

**Distinguishable: yes.** `Diagnostic.Errors` is a separate slice from
`Diagnostic.Reasons`, each entry carrying `PolicyID`, `Position`, `Message` —
printed by reflection, not from docs:

```
$ cd .../S4 && ./RUN.sh
  cedar.Authorize        : func(cedar.PolicyIterator, types.EntityGetter, types.Request) (types.Decision, types.Diagnostic)
  types.Diagnostic fields  : Reasons []types.DiagnosticReason; Errors []types.DiagnosticError;
  types.DiagnosticError    : PolicyID types.PolicyID; Position types.Position; Message string;
  NOTE: Authorize's result list has NO error slot.
```

Kotlin branches 2, 3 and 4 reproduce **byte-exact**:

```
  branch 2 Allow         got=Allow                                             match=true
  branch 3 no reasons    got=Deny(no policy permits this action)               match=true
  branch 4 with reasons  got=Deny(denied by policy: policy--2, policy--258)    match=true
```

**Branch 1 has no state-for-state counterpart, and that is the finding.**
cedar-go's error channel is **per-policy and non-fatal** — it can return `Allow`
_and_ an error simultaneously, a state cedar-java's present-or-absent `success`
payload cannot express:

```
--- E10 THE SHARP ONE: an ERRORING policy alongside a PERMITTING policy
  RAW: decision=allow reasons=[policy-ok] errors=[{policy-bad: `User::"alice"` does not have the attribute `dept`}]
  errors-first mapping : Deny("authorization engine error: …")
  verdict-first mapping: Allow
```

### Why the choice is load-bearing, not academic

Replayed against the **actually shipped** policy set (`run3.txt`), with an
entity-marshalling failure — the class the port is most likely to introduce:

```
### policy set = migration(-1,-2,-3)
  HEALTHY (AuthzTest case 6 oracle: Deny)      deny   [policy--2] []
  Request entity OMITTED                       allow  [policy--3] [policy--2: entity `Request::"alice#-"` does not exist]
                                               errors-first : Deny(authorization engine error: …)
                                               verdict-first: Allow
  Request entity present, `requester` MISSING  allow  [policy--3] [policy--2: `Request::"alice#-"` does not have the attribute `requester`]
                                               errors-first : Deny(…)
                                               verdict-first: Allow
```

The `system:no-self-approval` FORBID (`-2`) errors out, cedar-go drops it, and
the `system:admin` PERMIT (`-3`) stands. **A verdict-first mapping lets a
system-admin approve their own request** — precisely the hole `AuthzTest` case 6
exists to keep closed. Same result on `AuthzTest.seedPolicies`.

Two structural facts bound the blast radius:

- **Errors cannot poison unrelated requests.** Scope
  (`principal`/`action`/`resource`) is evaluated first and short-circuits, so a
  broken policy injects nothing into a request whose scope it does not match
  (`run2.txt` §9, §9b, §9c). Errors-first is not a global fail-shut.
- **A `has`-guarded read never errors**, not even when the whole entity is
  absent from the EntityMap (`run2.txt` §8a-8c). Since
  `ChannelContextAuthzTest.kt:82-89` asserts an unguarded optional read is
  rejected at engine construction, every _optional_ read in the enabled set is
  guarded. The only production-reachable error surface is an unguarded read of a
  schema-**required** attribute:

```
ENABLED shipped rows with an unguarded required-attr read: 10 -> [-25,-24,-23,-21,-20,-18,-15,-14,-4,-2]
  of which FORBIDs (a dropped forbid can turn a co-resident permit into an ALLOW): 2 -> [-20, -2]
```

**No Kotlin test pins either mapping.** Verified this session: zero test-source
hits for `authorization engine error`, `denied by policy`, or
`no policy permits this action`; the only hits are `Authz.kt:270` and
`Authz.kt:276` in main. So this is a **new decision**, not a port → **W1**.

**Also settled here:** `evaluatesInCedar` (`Authz.kt:301-315`) does not survive
as an authorize round-trip. Its probe request matches no policy scope under the
shipped set, so `len(Errors) == 0` is true for _every_ parseable IP, and it
errors spuriously if any policy reads a context key the probe omits. S5 §7
reached the identical conclusion independently. It collapses to
`types.ParseIPAddr` → **W3**.

---

## S5 — IP literal divergence **GO_WITH_WORK**

**Asked:** which IP literals does cedar-java accept that cedar-go rejects, and
vice versa? `/auth/debug` 400s on failure (INV-A1-7), so a divergence is
user-visible.

The oracle is `DebugRequesterIpDbTest.kt:156-195` — 16 pinned literals.

```
$ cd .../S5/conformance && env -u GOROOT go run .
  --> 16/16 of DebugRequesterIpDbTest.kt:156-195's pinned outcomes reproduced, 0 FAIL   [faithful port]

=== NAIVE: neither L1 nor range guard - just ParseIPAddr ===
  FAIL  expect 400  got 200  100.100.1.0/24
  --> 15/16 …, 1 FAIL
```

**Exactly one pinned literal breaks a naive port: `100.100.1.0/24`.**
`types.ParseIPAddr` accepts a CIDR _as a value_ (Cedar's `ipaddr` type covers
prefixes). Kotlin rejects it at layer 1, the charset allowlist that forbids `/`.
Keeping L1 _or_ an explicit range guard reproduces the 400.

Where the two agree on the outcome but **the rejecting layer moves** — harmless
for the wire, but it means the Kotlin layering is not evidence for the Go
layering:

| literal                        | Kotlin rejecting layer                    | Go                                                           |
| ------------------------------ | ----------------------------------------- | ------------------------------------------------------------ |
| `100.100.001.010`, `010.1.1.1` | **L3** (`InetAddress`); L2 regex accepts  | rejected at parse (`IPv4 field has octet with leading zero`) |
| `100.100.1.10�`, `…�12`        | L1; L2 accepts (`RequesterIp.kt:204-205`) | rejected at parse                                            |

Divergences the repo **does not pin** (`[U]` = unknown for cedar-java):

- `::ffff:100.100.1.10` — cedar-go **rejects** dotted v4-mapped v6
  (`ipaddr.go:21-23`: _cannot parse IPv4 addresses embedded in IPv6 addresses_)
  while accepting the hex form `::ffff:6464:010a` of the same address.
  Asymmetric.
- **`IPAddr.String()` is not round-trip safe** for v4-mapped v6:
  `::ffff:6464:010a` renders as `::ffff:100.100.1.10`, which `ParseIPAddr` then
  **rejects**. Any store that persists `String()`/`MarshalJSON()` output loses
  the value on reload.
- `١٠٠.1.1.1` (Arabic-Indic digits) passes Kotlin's `Char.isDigit()` L1 and
  fails an ASCII-only Go allowlist — a genuine L1 divergence.
- `100.100.1.10/32`, `0.0.0.0/0`, `::/0` — accepted by `ParseIPAddr`, rejected
  by Kotlin's L1.

**Adjacent (A12, `cidrContains`):** both Go variants — `netip` with and without
`.Unmap()` — pass **24/24** of `ForwardedAuthorityTest.kt:110-171`. The oracle
does not discriminate them. They differ on v4-mapped peers (`::ffff:10.0.0.1` vs
`10.0.0.0/8`), where A12 §5 Q1 _claims_ Java's 4-byte `getByName().address`
matches — **unverified**. And `netip.ParsePrefix` is stricter than Kotlin's
hand-rolled split on six malformed `PM_TRUSTED_PROXIES` entries
(`10.10.0.0/016`, `10.10.0.0/ 16`, …). Every one of those divergences narrows
trust, so the fail-safe direction is right — but under PORT POLICY they are
still REPRODUCE, not "Go is stricter, ship it".

---

## S6 — Duplicate-entity error **GO** (answered: no test asserts it)

**Asked:** does any test assert cedar-java's duplicate-entity **error**, which
decides whether `dedupeByEuid` (`Authz.kt:254-257`) is portable or droppable?

**Verified this session:**

```
$ grep -rn "duplicate entity\|duplicate.*[Ee]uid\|dedupeByEuid" control-plane/src/test/
(no output)
```

cedar-go collapses silently, **last-wins**:

```
$ cd .../S6S7/s6_dedupe && env -u GOROOT go run .
A1 EntityMap.UnmarshalJSON(2 entities, same UID) err = <nil>
A1 len(map)=1  surviving attrs={"who":"second"}  parents=1  => LAST WINS
```

The one live collision — `AuthzTest.kt:145-165`, a `Request` scoped to
`Role::"pii-reader"` while the principal already holds that role — is
unobservable, because both colliding entities are **bare** (`Authz.kt:348`
`Entity(it)`; `Authz.kt:388` `Entity(roleEuid)`):

```
  first-wins (Kotlin dedupeByEuid)   entities=3 decision=allow reasons=1 errors=0
  last-wins (naive Go map)           entities=3 decision=allow reasons=1 errors=0
  Entity.Equal(roleFromRoles, roleFromResource) = true  <- collapse ORDER cannot matter
```

The test asserts `assertEquals(AuthzDecision.Allow, decision)` — an Allow, not
an error. All seven call sites were audited; every possible collision is between
structurally equal entities.

**But order _is_ observable in general** — the probe proved it with a synthetic
case: first-wins (untagged survives) → `allow`, last-wins (pii-tagged survives)
→ `deny`. And `authorizeColumns` (`Authz.kt:502`) appends one entity per
`ColumnRef` with **no** identity-keyed dedup; two `ColumnRef`s sharing an
identity but carrying different tags would collide _unequally_. That is
unreachable today via `Query.kt:223` + `CatalogApi.kt:107-110`, but it is one
refactor away.

**Disposition:** `dedupeByEuid` is **OMIT-able** — no observable behaviour at
any reachable call site. Add an invariant guard so it stays that way → **W7**.

---

## S7 — Is `x/exp` stable enough to pin? **GO_WITH_WORK** — pin it; no sidecar needed

**Asked:** is `x/exp/schema/validate` stable enough to pin, or is out-of-process
validation (a Rust CLI) needed?

**The upstream warning is real and citable** (`cedar-go@v1.8.0/README.md`):

```
:44   the schema validator (experimental support is provided in x/exp/schema - please give us feedback!)
:128  x/exp/schema - Experimental support for Cedar schema, including parsing …, and validation
:140  x/exp - code in this directory is not subject to the semantic versioning constraints of the
      rest of the module and breaking changes may be made at any time.
```

**But the measured stability is perfect.** The identical harness, five releases,
real `go get`:

```
$ cd .../S6S7 && ./run_versions.sh
########## cedar-go v1.6.0 ##########   seeded=40 accept=40 reject=0   VERDICT-FINGERPRINT 56af35d135a2649d975c9674
########## cedar-go v1.6.1 ##########   seeded=40 accept=40 reject=0   VERDICT-FINGERPRINT 56af35d135a2649d975c9674
########## cedar-go v1.6.2 ##########   seeded=40 accept=40 reject=0   VERDICT-FINGERPRINT 56af35d135a2649d975c9674
########## cedar-go v1.7.0 ##########   seeded=40 accept=40 reject=0   VERDICT-FINGERPRINT 56af35d135a2649d975c9674
########## cedar-go v1.8.0 ##########   seeded=40 accept=40 reject=0   VERDICT-FINGERPRINT 56af35d135a2649d975c9674
```

Not only the verdicts — the seven never-throws error _messages_ are
byte-identical across all five, including the pathological tag name and the
tag-on-tag reject. The API compiled unchanged for four releases.

**Blast radius is one file.** The probe firewalled every `x/exp` identifier into
a single wrapper:

```
## x/exp identifiers named by authzschema (the ONLY wrapper):
xast.Policy · xresolved.Schema · xschema.Schema · xvalidate.New · xvalidate.WithStrict
## x/exp identifiers named by any other package:
(empty above == no leak)
## transitive x/exp deps, AUTHORIZE-ONLY program:
github.com/cedar-policy/cedar-go/x/exp/ast
```

Note the last line precisely: the **decision** path also reaches `x/exp/ast`
transitively, so "only validation touches x/exp" is not quite right — the _API
surface_ the port names is stable (`cedar.Authorize`, top-level); the _internal
dependency_ is not. That does not change the verdict — it means an x/exp break
could in principle affect more than validation, and the CI fingerprint gate must
cover decisions too, not just validation.

**Recommendation: pin exactly, firewall, gate in CI. Do not build a sidecar.**
An out-of-process Rust validator buys nothing today (validation is
verdict-identical for five releases) and costs a second runtime, a second
deployment artifact, and an IPC failure mode on the _validate-on-write_ path —
the path that must never throw. If a future cedar-go release breaks the
fingerprint, revisit then; five releases of evidence say that is not the
expected case → **W6**.

---

## What we could not determine

**This is the section to read before trusting any GO above.**

### 1. No cedar-java was executed. Not once.

There is no Java runtime on this machine and no cedar-java jar in
`~/.gradle/caches` (searched this session; also `find / -name "cedar-java*.jar"`
→ nothing). Every "cedar-java does X" statement in this report is one of:

- **`[T]` pinned** — a frozen Kotlin test assertion that would fail if
  cedar-java did otherwise. Trustworthy.
- **`[C]` commented** — stated by a source comment (e.g.
  `CedarEngine.kt:104-108`'s "verified empirically against cedar-java 4.3.1").
  Trustworthy only to the extent the comment's author was.
- **`Hypothesis (Rust-corroborated)`** — cedar-wasm 4.3.3 behaviour, same Rust
  core, different binding and a patch version apart.
- **`[U]` unknown** — nothing in the repo pins it.

### 2. The extractable fraction: 67 / 90 = 74.4 %

Of A2's 90 test cases (count verified: `grep -cE '^\s*@Test\s*$'` over the 14
files → 90):

|                                                                       | count           |
| --------------------------------------------------------------------- | --------------- |
| extractable to a pure `(policies, entities, request) → verdict` tuple | **67**          |
| Cedar-relevant                                                        | 69              |
| **extractable AND Cedar-relevant** — the real usable ceiling          | **64 (71.1 %)** |
| touch no Cedar at all (`kind: not_cedar`)                             | 26              |
| blocked                                                               | 23              |

The 23 blocked cases, by cause:

- **5** (`PresetPolicyDbTest` 3–7) route through `decideQuery` and need the
  sqlglot-go analyzer, a pushed `information_schema` catalog, and the
  system-classification manifest. §10 calls exactly these _"the single best
  end-to-end check that the ported Cedar layer decides identically."_ **They are
  unavailable to this spike.** The production-posture core (dev-vs-prod PII
  masking) is therefore **not** verified by anything here.
- **6** need HTTP status / `ApiError` mapping · **4** need live store mutation
  (`stateVersion`, `buildCount`) · **8** need SQL constraints, audit rows,
  version counters, or the golden digest.

**Also 62 of the 186 policy records carry unresolved Kotlin interpolation**
(`${ds.name}`, `$usersEuid`, `${enforcement.role}`). They agreed _after
mechanical substitution_; the `Table::` EUIDs need A5/A13's catalog+schema
resolution rules to substitute for real → **W10**.

### 3. Specifically unverified, and it matters

| Unknown                                                                                                                     | Why it matters                                                                                                                                                                                                                                                 | Where it bites                                                                                         |
| --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **What cedar-java's absent `success` payload actually means** — request-level failure only, or any policy evaluation error? | Decides whether errors-first or verdict-first is the _faithful_ port. If `success` is present whenever the request was processed, then cedar-java Allows in the E10 case and **verdict-first is faithful** — the opposite of what the security argument wants. | **W1**. Resolvable without a local JVM: run one differential probe against the running Kotlin service. |
| Whether cedar-java rejects a two-statement policy source                                                                    | A dropped `forbid` is a security hole. Rust rejects; Go accepts.                                                                                                                                                                                               | **W2**                                                                                                 |
| A12 §5 Q1's claim that Java's `InetAddress.getByName().address` is 4 bytes for v4-mapped v6                                 | Decides `netip` vs `netip+Unmap()` in `cidrContains`. The 24-assertion oracle does not discriminate.                                                                                                                                                           | **W3**                                                                                                 |
| cedar-java's acceptance of `::ffff:…`, `010.1.1.1`, `100.100.1`, integer-form IPv4                                          | Not on `/auth/debug`'s pinned list; reachable from `X-Forwarded-For`                                                                                                                                                                                           | **W3**                                                                                                 |
| The exact `CedarValidateResult.errors` strings cedar-java emits for parse failures                                          | Rendered verbatim in the web policy editor; zero CI coverage                                                                                                                                                                                                   | **W8**                                                                                                 |
| Concurrent `rebuildIfStale` (the `@Synchronized` / torn-cache guarantee)                                                    | §10 already lists it as an existing coverage gap; the spike did not close it                                                                                                                                                                                   | out of spike scope                                                                                     |

### 4. Reproduction is bounded, not proven, in two places

- The schema-**injection** result (a crafted tag name escaping into the
  generated declaration) is _"a bounded empirical result over 5 payloads, not a
  proof."_ The extraction regex `[^"]+` can never capture a raw quote, and the
  only escape vector — a trailing backslash — always produced an unterminated
  string. Believable; not proven.
- The **20/20** S3 corpus match covers only records touching the tag mechanism.
  It is not the whole 186.

---

## Surprises vs `02-authz.md` §9

§9's mapping table was written from pkg.go.dev. Five things it got wrong or
understated.

**1. The schema API is TWO-step, and the cache must hold the resolved form.** §9
maps `Schema.parse(Cedar, text)` → "`x/exp/schema` text parser". Measured:
`UnmarshalCedar` yields a `*schema.Schema` (an AST wrapper); `.Resolve()` yields
the `*resolved.Schema` that `validate.New` requires. **Consequence:**
`CedarEngine.kt:72`'s `augmentedSchemas: ConcurrentHashMap<Set<String>, Schema>`
must cache the **resolved** schema in Go, or the non-trivial resolve cost is
paid on every `validate` call.

**2. `validate.Validator.Policy` being "per-policy only" is NOT a risk — close
that row.** §9 flags it. But `CedarEngine.kt:120` already validates exactly one
candidate (`PolicySet(setOf(policy))`), and the startup loop already iterates
source-by-source. Verified this session by reading both call sites. The
per-policy API is an _exact_ match.

**3. §1's shared context shape is wrong about `network_zones`.** §9/§1 line 35
writes `network_zones: Set<String>` (required). `schema.cedarschema:114-119`
declares:

```
type RequestContext = {
    network_zones?: Set<String>,
    channel?: String,
    requester_ip?: ipaddr,
    tags?: Set<String>,
};
```

**All four are optional.** So an unguarded `context.network_zones` read fails
strict validation, even though `toCedarMap` always emits the key (§6 step 1).
Measured: `I-2b network_zones, UNguarded -> REJECT`;
`I-2a network_zones, guarded -> ACCEPT`, and the guarded rule then genuinely
fires (`network_zones=[office] -> allow`).

**4. A doc/code divergence a Go port will copy from the wrong side.**
`CedarEngine.kt:87`'s generated context is
`{ channel?, requester_ip?, tailscale_caps? }`. `docs/authz-context.md:255`
documents it as `{ network_zones?, channel?, requester_ip? }` — the doc **has**
`network_zones` and **lacks** `tailscale_caps`; the code is the exact inverse.
Verified: `tailscale_caps` appears in exactly two places repo-wide
(`CedarEngine.kt:87` and a `docs/backlog.md:61` mention). **Port from
`CedarEngine.kt`, not from `authz-context.md`.** This answers §11 Q4 partially:
`tailscale_caps` is vestigial-but-live — no deployment injects it (nothing reads
it), but removing it would change what validates.

**5. §1 and §10's corpus scope are both wrong.** Verified this session:

| §-claim                                                               | reality                                                                                                                                                                       |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "**52** `permit`/`forbid` statements in `V8__seed.sql`"               | **40** (`grep -oE "permit\(\|forbid\(" V8__seed.sql \| wc -l` → 40)                                                                                                           |
| "migration-owned SYSTEM rows (**V20, V24, V32** referenced in tests)" | those files **do not exist**. `ls .../db/migration/` → `V1..V10` only. Every policy row lives in V8; the V20/V24/V32 names survive only in test comments as squashed history. |

Neither changes any verdict — the corpus was built from the real V8 and the
golden digest reproduces — but the docs should be corrected so the next reader
does not go looking for 12 missing policies.

**6. Two probe-agent claims this synthesis re-scoped** (see below) — §9's
framing was not at fault there, the probe's was.

### Corrections to the probe agents

- **S3's recommendation to use the programmatic AST path is rejected under PORT
  POLICY.** The AST merge is `reflect.DeepEqual`-identical and elegant, and the
  probe proved it works. But it _removes_ the malformed-declaration rejection,
  which is **observable Kotlin behaviour** (`CedarEngine.kt:124` emits
  `invalid context.tag action name: …` and `POST /api/policies` 400s). The probe
  proposed replacing it with a tag-name charset guard "that rejects the same
  inputs" — but the equivalence of those two input sets is exactly the
  bounded-5-payload result, not a proof. **REPRODUCE the text path.** Keep the
  AST path as a documented post-cutover option.
- **`tagfixtures.json`'s S3-a `go_failure_mode` is wrong for cedar-go**, and the
  consequence is a coverage gap. It predicts that reusing `RequestContext` for
  the generated action would let the tag-on-tag rule validate, opening the
  recursion hole, with `TagResolutionTest` case 6 as the catch. Measured:
  cedar-go strict rejects the unguarded read **either way** — by a different
  rule
  (`unable to guarantee safety of access to optional attribute \`tags\``instead of`attribute
  \`tags\` … not found`). **Same verdict, different reason ⇒ case 6 does not
  discriminate the correct narrow-context implementation from the lazy one in
  Go.** Folded into **W4**.

### Environment trap for whoever picks this up

This machine has mise Go 1.25.3 first on `PATH` but `GOROOT` pointing at a
1.26.4 install. Every `go build`/`go run` fails with
`compile: version "go1.26.4" does not match go tool version "go1.25.3"` before
reaching any cedar-go code. Run everything as `env -u GOROOT go run .` (baked
into `S3/run-all.sh`) or pin `GOROOT` to the 1.25.3 install (`S4/RUN.sh`).

---

## Work items

Ordered by (blocks-a-decision → security → correctness → hygiene). Sizes are
engineering time for the item alone, not the surrounding port.

| #       | S     | Item                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Size                                         | Disposition         |
| ------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- | ------------------- |
| **W1**  | S4    | **Resolve and pin the engine-error mapping.** First _measure_ it: run one differential probe against the running Kotlin service — `task.approve`, `system:admin` principal, `Request` entity with `requester` omitted — and record whether it Allows or Denies. That single observation settles errors-first vs verdict-first without a local JVM. Then implement it in `toAuthzDecision` **and** all five batch call sites (`Authz.kt:525,603,672,737,825`) **and** `resolveContextTags` (INV-A2-13), and write the test. If the probe cannot be run, default to **errors-first** — Kotlin's own batch paths already read `.success.orElse(null)?.isAllowed == true`, i.e. false-on-absent, so the _intent_ is unambiguous even where the mechanism is not. | **1d** (0.5d probe+decision, 0.5d impl+test) | REPRODUCE **+ PIN** |
| **W2**  | S2    | **Reject multi-statement policy source explicitly.** cedar-go's `UnmarshalCedar` accepts `permit(…); forbid(…);` and silently keeps statement 1; a dropped `forbid` is a security control lost at load time. Add a statement-count check in the Go `validate` **and** in the policy-load path, emitting the same reject shape. Applies to `POST /api/policies`, `PUT`, `/validate`, and `setEnabled`.                                                                                                                                                                                                                                                                                                                                                        | **0.5d**                                     | REPRODUCE **+ PIN** |
| **W3**  | S5    | **Port `isStorableIpLiteral` faithfully; delete the engine round-trip.** Keep the L1 charset allowlist **and** the `/`-rejecting range guard (without them `100.100.1.0/24` returns 200 instead of 400 — the one pinned failure). Replace `evaluatesInCedar` with `types.ParseIPAddr` (S4 §15 and S5 §7 concur it is dead weight). Decide `netip` vs `netip+Unmap()` for `cidrContains` — the oracle does not discriminate; A12 §5 Q1's Java claim is unverified. **Never persist `IPAddr.String()`** — it is not round-trip safe for v4-mapped v6.                                                                                                                                                                                                          | **1d**                                       | REPRODUCE           |
| **W4**  | S3    | **Port `schemaFor` as TEXT concatenation** (not the AST path — see Corrections). Byte-identical template from `CedarEngine.kt:86-87`, `sorted()` ordering, `"$text\n$decls"` join. Cache the **resolved** schema keyed by the tag-name set. **Add a direct assertion on the generated action's resolved context shape** — `{channel?, requester_ip?, tailscale_caps?}`, no `tags` — because porting `TagResolutionTest` case 6 alone does not cover the narrow-context requirement in Go.                                                                                                                                                                                                                                                                    | **1d**                                       | REPRODUCE           |
| **W5**  | S2    | **Reproduce Kotlin `isBlank()` exactly.** Explicit predicate matching `Character.isWhitespace`, not `strings.TrimSpace`. 8 code points diverge (`U+001C..1F`, `U+0085`, `U+00A0`, `U+2007`, `U+202F`); the payoff is which of two wire messages `CedarValidateResult.errors` carries.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | **2h**                                       | REPRODUCE           |
| **W6**  | S7    | **Pin cedar-go exactly; firewall `x/exp`; gate in CI.** `v1.8.0` with no range. Keep every `x/exp` identifier inside one wrapper package (proven achievable: 5 identifiers, 1 file). Add a CI job running the 186-record corpus + the decision corpus and asserting the fingerprint `56af35d135a2649d975c9674` — the gate must cover _decisions_ too, since `cedar.Authorize` reaches `x/exp/ast` transitively. **No Rust sidecar.**                                                                                                                                                                                                                                                                                                                         | **2h** + ongoing                             | new control         |
| **W7**  | S6    | **Drop `dedupeByEuid`; add the invariant that keeps it droppable.** Safe at all seven call sites today (every collision is between structurally equal entities). Add a test asserting no Go entity builder emits two _unequal_ entities for one UID — last-wins would otherwise change a decision silently (proven: first-wins `allow` vs last-wins `deny`). Note `authorizeColumns` (`Authz.kt:502`) is the one site with no identity-keyed dedup.                                                                                                                                                                                                                                                                                                          | **3h**                                       | OMIT + guard        |
| **W8**  | S1/S2 | **Decide the `CedarValidateResult.errors` text contract.** Go's parse-error text differs from Rust's (hence, `Hypothesis`, from cedar-java's) on every parse error; semantic text is byte-identical on 11/11 measured. Zero CI coverage, but the web policy editor renders it verbatim. Either accept Go's text as a documented divergence or normalise it. **Ask `web/` before choosing** — same class of question as §11 Q3 (`updatedAt` precision).                                                                                                                                                                                                                                                                                                       | **0.5d** decision                            | DEFER → decide      |
| **W9**  | S3    | **Make `setEnabled`'s revalidation self-augmenting.** Measured: shipped row `-300` (`context.trusted-network-tailscale`) is **REJECTED** against the base schema and ACCEPTED only against the self-augmented one. A Go `setEnabled` that validates against the base schema makes row `-300` permanently un-enableable, breaking INV-A2-21 for the shipped seed.                                                                                                                                                                                                                                                                                                                                                                                             | **2h**                                       | REPRODUCE           |
| **W10** | S1    | **Resolve the 62 templated corpus records.** Blocked on A5/A13 catalog+schema EUID resolution. Needed for _full_ differential conformance, not for the S1 GO. Track with the harness, not with A2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | **1–2d**, deferred                           | follow-on           |
| **W11** | docs  | **Correct `02-authz.md`.** §1: 40 seeded statements not 52; V20/V24/V32 do not exist (V1–V10 only); `network_zones` is **optional** in `RequestContext`. §9: close the `validate.Validator.Policy` risk row; note the two-step schema API. Also flag `docs/authz-context.md:255` as diverging from `CedarEngine.kt:87`.                                                                                                                                                                                                                                                                                                                                                                                                                                      | **1h**                                       | doc fix             |

**Total A2-specific spike-driven work: ~5 days**, of which **~1.5 days (W1 + W2)
is security-decision work that must land before cutover**, not after.

---

## Artifacts

All under
`/private/tmp/claude-502/-Users-donggyukim-ClaudeProjects-ridi/0197f609-239e-43b7-814b-53ec27fad20f/scratchpad/cedar-spike/`
(scratch — **copy anything you need to keep before the session is reaped**).

| Path                | Contents                                                                                                                                                                                                                          |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `corpus/`           | `schema.cedarschema` (sha256 `c3acd118…e311b8`), `policies.json` (186), `verdicts.json` (90 cases / 188 assertions / 11 policy sets), `ip-corpus.json`, `tagfixtures.json`, `README.md`                                           |
| `S1S2/`             | `s1_run.log`, `s1_results.json`, `s1b/s1b_run.log` (negative controls), `s2/s2_run.log`, `s2b/s2b_run.log`, `cedarvalidate.go` (the ported `validate`)                                                                            |
| `S1S2/wasm-oracle/` | **the Rust Cedar 4.3.3 oracle** — `oracle.js`, `rust_oracle.json`, `probe_one.js` (per-process isolation; a WASM memory fault poisons the module instance, so a single-process sweep silently corrupts results), `isolated.jsonl` |
| `S3/`               | `run-all.sh`, `RESULTS.txt` (361 lines), `kport/kport.go` (the ported `schemaFor`/`Validate`), `cmd/probe{A,B,E,F,G,H,I}`                                                                                                         |
| `S4/`               | `RUN.sh`, `run1.txt` (API shape + 12 error classes), `run2.txt` (reachability + batch mapping), `run3.txt` (the self-approval replay), `audit_unguarded_required_attrs.txt`                                                       |
| `S5/`               | `divergence-table.md`, `out-{parseprobe,evalprobe,cidrprobe,addendum,conformance}.txt`                                                                                                                                            |
| `S6S7/`             | `results-s6.txt`, `results-s7-versions.txt`, `results-s7-blastradius.txt`, `run_versions.sh`                                                                                                                                      |

---

## Appendix — independent re-verification (main agent, after the toolchain fix)

The three probes that died on a session limit (S1S2, S5, S6S7) were re-run to
completion here, and the two that had completed (S3, S4) were re-run as a check.
**All six verdicts reproduce.**

| Suite | Command                         | Result                                                                                                                                          |
| ----- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| S3    | `bash run-all.sh`               | `H-TOTAL pass=13 fail=0`                                                                                                                        |
| S1    | `cd S1S2 && go run .`           | `AGREE 184 / DISAGREE 0 / N-A 2` over 186 records                                                                                               |
| S4    | `bash RUN.sh`                   | E10 reproduced — see below                                                                                                                      |
| S5    | `cd S5/conformance && go run .` | FAITHFUL **16/16, 0 FAIL**; NAIVE 15/16                                                                                                         |
| S6    | `cd S6S7/s6_dedupe && go run .` | reproduced, incl. the per-call-site collision analysis                                                                                          |
| S7    | `zsh run_versions.sh`           | `VERDICT-FINGERPRINT 56af35d135a2649d975c9674` **identical across v1.6.0, v1.6.1, v1.6.2, v1.7.0, v1.8.0**; `seeded=40 accept=40 reject=0` each |

### The two findings this re-run sharpened

**S4/E10 — cedar-go can return `Allow` AND an error at the same time.**
Verbatim:

```
RAW: decision=allow reasons=[policy-ok] errors=[{policy-bad: `User::"alice"` does not have the attribute `dept`}]
  errors-first mapping : Deny("authorization engine error: ...")
  verdict-first mapping: Allow
```

`Diagnostic.Errors` is **per-policy and non-fatal**, unlike cedar-java where an
error means no success payload at all. So the port faces a real fork, and only
one arm is faithful:

- **errors-first** — any error ⇒ Deny. Preserves INV-A2-8 / INV-A2-13
  fail-closed. **This is the port's required behaviour.**
- **verdict-first** — `decision == Allow` wins. **Fail-OPEN.** A single erroring
  policy alongside a permitting one would silently allow.

No Kotlin test pins this (`grep` for the three `Deny` reason strings: zero hits
in tests). ⇒ **REPRODUCE

- PIN** under the port policy — write the assertion the Kotlin suite never had.

**S5 — the IP failure MOVES from the engine to the constructor.**
`types.ParseIPAddr` rejects `100.100.001.010`, `010.1.1.1`, `999.1.1.1`,
`100.100.1.10:5432` outright, where cedar-java's Java-side regex _accepts_ them
and the Rust engine rejects them later. Kotlin's `isStorableIpLiteral` is
therefore two-stage (allowlist → engine probe); Go's is one-stage. Measured
consequence:

| Port shape                                                                         | Result vs `DebugRequesterIpDbTest.kt:156-195`                                                      |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **FAITHFUL** — port the L1 character allowlist + range guard, _then_ `ParseIPAddr` | **16/16**                                                                                          |
| **NAIVE** — delegate wholly to `ParseIPAddr`                                       | 15/16 — accepts `100.100.1.0/24`, which Kotlin's allowlist rejects (`/` is not in the allowed set) |

⇒ **REPRODUCE the two-stage structure.** Do not collapse it just because Go's
parser is stricter; the one place it is _laxer_ (CIDR literals) is exactly where
the allowlist is load-bearing.

### Toolchain note (not a code issue)

Builds initially failed with
`compile: version "go1.26.4" does not match go tool version "go1.25.3"`. Cause:
the **tool shell's** PATH carried a stale `mise/installs/go/1.25.3/bin` ahead of
the pinned 1.26.4, while `GOROOT` was exported to 1.26.4. A pristine interactive
shell is unaffected (`go1.26.4`, `stdlib compiles OK`), so this is **not** a
machine or repo defect and needs no fix. Anything re-running these probes from a
non-interactive shell should prepend
`~/.local/share/mise/installs/go/1.26.4/bin` to PATH, or `unset GOROOT` (which
`run_versions.sh` already does).
