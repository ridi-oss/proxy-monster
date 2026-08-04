# A6 — Query Decision Path & Access Elevation

Files: `Query.kt` (1,238) · `Access.kt` (714). Total 1,950 LOC. Fully read.
Tables: `access_request`, `access_grant`, `query_result` (V3, V5).

**The enforcement core.** `decideQuery` is the function every protected
statement passes through. Its _step order_ is the security contract — not just
its outputs — so §3 specifies the pipeline as an ordered list with every exit.
180 test cases, the largest area by both LOC and coverage.

## Purpose

Two things that share a table and a Cedar vocabulary:

1. **`Query.kt`** — the per-statement enforcement decision (`decideQuery`), the
   channel model, the query/editor HTTP surface, and the audit-row shape for a
   decision.
2. **`Access.kt`** — the JIT elevation store (`AccessStore`: requests, grants,
   and the _task_ lifecycle state machine shared by WORKFLOW / EDITOR / WIRE
   origins) plus the `/api/access-*` routes.

---

## 1. Channel model

### `enum Channel(val contextValue: String)`

`WIRE("wire")` · `EDITOR("editor")` · `WORKFLOW_EXECUTOR("workflow-executor")` ·
`WORKFLOW_VIEWER("workflow-viewer")` · `MCP("mcp")`

🔒 **INV-A6-1 — the channel is server-attested.** It comes from the entry point
or the ephemeral-token kind and is **never** client-asserted.
`effectiveAuthzContext` overwrites any caller-supplied `channel`.

🔒 **INV-A6-2 — only persistent-connection channels may pass through session
statements.** `WIRE` and `EDITOR` hold a connection, so
`TX_CONTROL`/`SESSION_MUTATING` statements are re-decided per statement and
relayed. `WORKFLOW_EXECUTOR`, `WORKFLOW_VIEWER`, and `MCP` refuse them, because
each workflow run uses a **fresh** connection and session state would silently
not carry.

⚠️ Note `Channel` has **five** values but `AuthzContext.channel` is a plain
`String` in Cedar. The `MCP` channel was added after the doc comments were
written — several comments still enumerate four.

---

## 2. Types

### `EnfActionSerializer` · object, `KSerializer<EnfAction>`

The proto `EnfAction` enum is not kotlinx-`@Serializable`, so this
(de)serializes **by name** to keep REST JSON at exactly
`"ALLOW"`/`"MASK"`/`"DENY"`.

🔒 **INV-A6-3 — deserialization fails closed.** Anything that is not the literal
`"ALLOW"` or `"MASK"` — including `"DENY"`, an unknown string,
`ENF_ACTION_UNSPECIFIED`, or `UNRECOGNIZED` — becomes `DENY`. A verdict never
falls open.

### `EnfAction.knownOrDeny()` · ext fn

`ALLOW`/`MASK`/`DENY` pass through; the proto3 zero value and the generated
`UNRECOGNIZED` sentinel collapse to `DENY`. **Call at every point a proto
`EnfAction` enters from an untrusted source.**

**Go shape:** protobuf-go exposes unknown enum values as the raw `int32`, with
no `UNRECOGNIZED` sentinel — so the Go port must switch on the three known
values and `default: DENY`, rather than relying on an enum-exhaustiveness check
that will silently accept `EnfAction(7)`.

### `DecisionContext` · data class — 18 fields

The verdict for a statement without executing it.

| Field                 | Type               | Default | Meaning                                                                                                                                                     |
| --------------------- | ------------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `action`              | `EnfAction`        | —       | ALLOW / MASK / DENY                                                                                                                                         |
| `denyReason`          | `String?`          | —       |                                                                                                                                                             |
| `masks`               | `List<ColumnMask>` | —       | output column → mask kind, carries `ordinal`                                                                                                                |
| `piiTouched`          | `List<String>`     | —       |                                                                                                                                                             |
| `effectiveRoles`      | `List<String>`     | —       |                                                                                                                                                             |
| `failedStage`         | `String?`          | —       | `admission` \| `policy` \| `catalog` \| `mask-binding` \| `explain-masked` \| `deprovisioned`                                                               |
| `detail`              | `String?`          | —       |                                                                                                                                                             |
| `passthrough`         | `Boolean`          | —       | relay verbatim, no mask binding                                                                                                                             |
| `structural`          | `Boolean`          | `false` | a non-grant-overridable deny                                                                                                                                |
| `rewrittenSql`        | `String?`          | `null`  | ALLOW/MASK only: the `*`-expanded SQL the proxy must send **instead of** the client's, so backend column order matches mask ordinals. Null = send verbatim. |
| `outputColumns`       | `List<String>`     | `[]`    | analyzer's ordered output names; empty for passthrough                                                                                                      |
| `contextTags`         | `List<String>`     | `[]`    | derived tags this decision ran under                                                                                                                        |
| `unmaskablePermitted` | `Boolean`          | `false` | MASK-only capability grant                                                                                                                                  |
| `sanitizeDiagnostics` | `Boolean`          | `false` | strip backend diagnostics to code + severity                                                                                                                |
| `catalogChanging`     | `Boolean`          | `false` | success may change persistent catalog structure                                                                                                             |
| `catalogMiss`         | `Boolean`          | `false` | deny may be caused by absent catalog rows → refetch+retry                                                                                                   |
| `referencedSchemas`   | `Set<String>`      | `∅`     | non-temp schemas resolved/touched                                                                                                                           |
| `schemaCandidates`    | `Set<String>`      | `∅`     | dotted-identifier candidates for the catalog-miss retry                                                                                                     |

🔒 **INV-A6-4 — `contextTags` is stamped on EVERY post-derivation decision** —
ALLOW, MASK, DENY (structural _and_ policy), and passthrough alike — so an audit
row carries the attested tags whatever the outcome. The **only** rows that
legitimately leave it empty are the two pre-derivation early denies
(admission-reject, deactivated principal), which return before any tag is
derived. See the pipeline steps 4–5 in §3.

🔒 **INV-A6-5 — `outputColumns` is a drift detector, not decoration.** Approval
live-result viewing compares it against the stored execute-enforced result to
catch catalog drift between execute and view: a `SELECT *` re-expansion could
otherwise slide a mask onto the wrong stored column and leak a value. A mismatch
is DENY. (Consumed in A7.)

🔒 **INV-A6-6 — `unmaskablePermitted` is a _capability grant_, not permission to
skip masking.** A proxy may relay an unmaskable binary result unmasked **iff**
this is true **AND** the proxy's own local feature capability says that relay
path is supported. Two independent conditions; the CP owns only one.

### `QueryRequest` / `QueryResponse`

`QueryRequest{sql: String, maxRows: Int = 500}`

`QueryResponse{decision: EnfAction (custom serializer), decisionId: Long? = null, denyReason: String? = null, maskedColumns: [] , piiTouched: [], effectiveRoles: [], columns: [], rows: List<List<String?>> = [], rowsAffected: Int? = null, latencyMs: Long = 0}`

Note `rows` is `List<List<String?>>` — **every cell is a nullable string**, not
a typed value. Go: `[][]*string`, and `encodeDefaults` means `rows`/`columns`
must always serialize as `[]`.

---

## 3. `decideQuery` — the pipeline

```kotlin
fun decideQuery(
  principal: String, ds: Datasource, sql: String, channel: Channel,
  catalog: List<CatalogColumn>, policyStore: PolicyStore, accessStore: AccessStore,
  userGroupStore: UserGroupStore, roleResolver: RoleResolver, authz: Authz,
  providedRoles: Set<String>? = null, context: AuthzContext = AuthzContext(),
  liveSearchPath: List<String>? = null, liveAnsiQuotes: Boolean = false,
  systemClassification: SystemClassificationService? = null,
  tempColumns: List<CatalogColumn> = emptyList(),
  factsOverride: StatementFacts? = null,   // TEST-ONLY seam
): DecisionContext
```

⚠️ `accessStore` is a parameter but **is never used in the body** — dead
parameter. Do not carry it.

`factsOverride` is a **test-only seam**: the only way to exercise the
fail-closed contract branches (UNSPECIFIED action/disposition/class, invalid
ordinal, malformed grant) that a resolved Go analyzer can never emit. Production
callers pass null. **Keep this seam** — 21 of `StatementFactsGrantLoopTest`'s
cases depend on it.

### Ordered steps, with every exit

| #     | Step                                                                                                                                                                                                                                                                                                                                                                                                                        | Exit on failure                                                                                                                                                                    |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | `liveSearchPath` non-null but **empty** while catalog is non-empty                                                                                                                                                                                                                                                                                                                                                          | `structuralDeny(CATALOG_CONFIGURATION_DENY, stage="catalog")`, `catalogMiss=true`                                                                                                  |
| 2     | `resolvedSearchPath = (liveSearchPath ?: ds.defaultSchemas).ifEmpty { [ds.dbName.ifBlank{"public"}] }`                                                                                                                                                                                                                                                                                                                      | —                                                                                                                                                                                  |
| 3     | Build namespace + `EngineConfig`(engine, engineVersion, `mysqlLowerCaseTableNames`, `mysqlAnsiQuotes`), `effectiveCatalog = catalog + tempColumns`, specs, `analyzerFor(...)`, `buildCatalogColumnIndex`, `facts = factsOverride ?: analyzer.analyze(sql)`                                                                                                                                                                  | any exception ⇒ `structuralDeny("$CATALOG_CONFIGURATION_DENY: <msg>", stage="catalog")`, `catalogMiss=true`                                                                        |
| 4     | `failureClass == INADMISSIBLE` **or** (`UNSPECIFIED` **and** `!resolved`)                                                                                                                                                                                                                                                                                                                                                   | `structuralDeny(facts.detail ?: "statement is inadmissible")` — stage `admission`, **no contextTags**                                                                              |
| 5     | `userGroupStore.isDeactivated(principal)`                                                                                                                                                                                                                                                                                                                                                                                   | `structuralDeny(DEACTIVATED_PRINCIPAL_DENY, stage="deprovisioned")` — **no contextTags**                                                                                           |
| **6** | **`roles = providedRoles ?: roleResolver.resolve(principal)`**                                                                                                                                                                                                                                                                                                                                                              | —                                                                                                                                                                                  |
| **7** | **`context = effectiveAuthzContext(context, channel, authz, principal, roles, ds.name, ds.tags)`**; `derivedTags = context.tags`                                                                                                                                                                                                                                                                                            | —                                                                                                                                                                                  |
| 8     | Contract check: each grant names **exactly one** resource, and a non-datasource grant **must** carry `RESULT_READ`                                                                                                                                                                                                                                                                                                          | `structuralDeny("fail-closed: analyzer emitted a malformed required grant", stage="policy")`                                                                                       |
| 9     | `resolved` ⇒ `statementClass ∈ {ANALYZED, METADATA, SESSION}`                                                                                                                                                                                                                                                                                                                                                               | `structuralDeny("fail-closed: resolved statement has no statement class", stage="policy")`                                                                                         |
| 10    | Every `outputOrdinal` is a valid index into `outputColumns`                                                                                                                                                                                                                                                                                                                                                                 | `structuralDeny("invalid mask output ordinal", stage="mask-binding")`                                                                                                              |
| 11    | Every column grant has a recognized `maskedDisposition`                                                                                                                                                                                                                                                                                                                                                                     | `structuralDeny("fail-closed: column grant has no masking disposition", stage="policy")`                                                                                           |
| 12    | Cedar `datasource.connect` on `ds.name`                                                                                                                                                                                                                                                                                                                                                                                     | `policyDeny("no access to datasource '<name>'")`                                                                                                                                   |
| 13    | **Utility gate** (if any utility grants): `systemClassification != null` **and** `engineVersion` non-blank; every command must resolve a `system:` tag via `tagForCommand`; `authorizeUtilities` must return `USE` for all                                                                                                                                                                                                  | `structuralDeny("$SYSTEM_UTILITY_DENY '<cmd>'", stage="policy")` at each sub-step                                                                                                  |
| 14    | If `resolved` **and** no column/table/function/datasource grants → dispatch on `statementClass`: `METADATA` ⇒ ALLOW passthrough `"passthrough (readonly-meta)"`; `SESSION` ⇒ WIRE/EDITOR: passthrough `"passthrough (session-mutating)"`, else `structuralDeny(EDITOR_SESSION_STATEMENT_DENY)`; `UNSPECIFIED`/`UNRECOGNIZED` ⇒ `structuralDeny("statement class is unspecified")`; `ANALYZED` ⇒ fall through                | as listed                                                                                                                                                                          |
| 15    | For each **datasource** grant: `grantAction(action)` must map (else `policyDeny("statement kind 'other' is not permitted")`), then Cedar `sql.<kind>`                                                                                                                                                                                                                                                                       | `policyDeny("no <action> grant for datasource '<name>'")`                                                                                                                          |
| 16    | If `!resolved`: `failureClass != UNANALYZABLE` ⇒ `structuralDeny(facts.detail)`. Else classify `facts.functions` (`tagForFunction` **?:** `BaselineDangerousFunctions.classify`), `authorizeFunctions` must be `ALLOWED` for all (else `structuralDeny(SYSTEM_FUNCTION_DENY)`). Then Cedar `sql.unanalyzable`: Allow ⇒ ALLOW passthrough `"unanalyzable relay (sql.unanalyzable)"`; Deny ⇒ `deny(reason, catalogMiss=true)` | as listed                                                                                                                                                                          |
| 17    | Build `columnKeys` from column grants — key = `"$catalog.$schema.$table.$column"`, `putIfAbsent`                                                                                                                                                                                                                                                                                                                            | —                                                                                                                                                                                  |
| 18    | `catalogCoverage(index, columnKeys)`                                                                                                                                                                                                                                                                                                                                                                                        | `Denied` ⇒ Cedar `sql.unanalyzable`: Allow ⇒ ALLOW passthrough `"uncovered-column relay"` (`catalogMiss=true`); Deny ⇒ `structuralDeny(reason, stage="catalog", catalogMiss=true)` |
| 19    | `maskKinds = policyStore.listMaskFns()`                                                                                                                                                                                                                                                                                                                                                                                     | exception ⇒ `structuralDeny(CATALOG_CONFIGURATION_DENY, stage="catalog")`, `catalogMiss=true`                                                                                      |
| 20    | `columnRefs` from the catalog index rows (carrying `classification.tags`)                                                                                                                                                                                                                                                                                                                                                   | —                                                                                                                                                                                  |
| 21    | `allTableIds` = columnRef tables ∪ `facts.sources` ∪ table-grant tables; `systemTags` = `tagForTable` per id                                                                                                                                                                                                                                                                                                                | —                                                                                                                                                                                  |
| 22    | **Function gate** (resolved path): names = function grants ∪ `facts.functions`; any _function grant_ whose name has no tag ⇒ deny; `authorizeFunctions` must be `ALLOWED` for all tagged                                                                                                                                                                                                                                    | `structuralDeny("$SYSTEM_FUNCTION_DENY '<name>'", stage="policy")`                                                                                                                 |
| 23    | `columnVerdicts = authorizeColumns(...)` (skipped when `columnRefs` empty)                                                                                                                                                                                                                                                                                                                                                  | —                                                                                                                                                                                  |
| 24    | **Mask binding loop** — per column grant, see below                                                                                                                                                                                                                                                                                                                                                                         | `deny(...)` per case                                                                                                                                                               |
| 25    | **Table gate**: table grants **excluding temp tables** → `authorizeTables` must be `READ`                                                                                                                                                                                                                                                                                                                                   | `deny("no read grant for scanned table '<schema>.<table>'")`                                                                                                                       |
| 26    | `action = masks.isEmpty() ? ALLOW : MASK`                                                                                                                                                                                                                                                                                                                                                                                   | —                                                                                                                                                                                  |
| 27    | `facts.explainOfQuery && action == MASK`                                                                                                                                                                                                                                                                                                                                                                                    | `structuralDeny(EXPLAIN_MASK_DENY, stage="explain-masked")`                                                                                                                        |
| 28    | `pii` = column keys whose classification tags contain `"pii"`                                                                                                                                                                                                                                                                                                                                                               | —                                                                                                                                                                                  |
| 29    | `referencedSchemas` = `facts.sources` schemas ∪ column-grant schemas, **minus** anything starting `pg_temp` (case-insensitive)                                                                                                                                                                                                                                                                                              | —                                                                                                                                                                                  |
| 30    | `unmaskablePermitted = action == MASK && sql.unmaskable Allow`                                                                                                                                                                                                                                                                                                                                                              | —                                                                                                                                                                                  |
| 31    | `sanitizeDiagnostics = redactsDiagnostics(ds.engine, action) { result.read.unmasked on ds }`                                                                                                                                                                                                                                                                                                                                | —                                                                                                                                                                                  |
| 32    | Return the full `DecisionContext`                                                                                                                                                                                                                                                                                                                                                                                           | —                                                                                                                                                                                  |

🔒 **INV-A6-7 — role resolution happens at step 6, deliberately AFTER
admission.** An inadmissible statement hard-denies (step 4) before any role
resolution or grant walk. `authorizeColumns`' doc in A2 calls this out as a
**SECURITY INVARIANT**. Moving resolution earlier would let an inadmissible
statement trigger role/grant work, and — worse — would change the ordering
guarantees the deactivation gate (step 5) depends on.

🔒 **INV-A6-8 — the deactivation gate dominates passthrough.** Step 5 sits
_before_ the metadata/session passthrough dispatch (step 14), so a deprovisioned
principal cannot ride a `readonly-meta` passthrough to an ALLOW.
`DeactivationEnforcementDbTest` case 3 pins exactly this.

🔒 **INV-A6-9 — contract validation (steps 8–11) runs BEFORE any Cedar verdict,
and is independent of it.** In particular, disposition and ordinal validity are
checked up front rather than only inside the eventual `MASKED` branch, so an
**UNMASKED** or allowed column can never ride a malformed disposition or a bogus
ordinal to ALLOW. `StatementFactsGrantLoopTest` cases 15–16 pin the UNMASKED
variants specifically.

🔒 **INV-A6-10 — a grant with no resource would be invisible.** The
has*-filtered category walk (steps 14/15/22/24/25) skips a grant that names no
resource, so it would silently ride a resolved-METADATA statement to a
passthrough ALLOW. Hence step 8's "exactly one resource" check is a hard deny,
not a skipped grant.

### Step 24 — the mask binding loop

For each column grant, key = `"$catalog.$schema.$table.$column"`, row =
`catalogIndex.rowsByKey[key]`:

```
verdict = if (row.isTemp) UNMASKED else columnVerdicts[key] ?: DENIED
```

| Verdict                                                  | Action                                                                                                                                                                                                           |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UNMASKED`                                               | nothing                                                                                                                                                                                                          |
| `DENIED`                                                 | `deny("policy denies column <key>")`                                                                                                                                                                             |
| `MASKED` + `DENY_STATEMENT`/`UNSPECIFIED`/`UNRECOGNIZED` | `deny(...)` — message branches on `facts.isWrite`: _"write references protected column X (a write cannot be masked)"_ vs _"sensitive column X used in a subquery/reference position (cannot be masked)"_         |
| `MASKED` + `MASK_OUTPUT`                                 | per ordinal, **first-wins** (`masks.none { it.ordinal == ordinal }`): `ColumnMask(column = outputColumns[ordinal], maskFn = row.classification?.maskFnName ?: "mask", kind = maskKinds[fn] ?: "FIXED", ordinal)` |
| `MASKED` + `REDACT_OUTPUT_NULL`                          | per ordinal, first-wins: `ColumnMask(column = outputColumns[ordinal], maskFn = "redact", kind = "NULL", ordinal)`                                                                                                |

⚠️ 🔒 **INV-A6-11 — `row.isTemp` unconditionally forces UNMASKED, bypassing
column authz.** This is safe **only** because a write cannot launder a masked
value into a temp — enforced elsewhere (the `MASKED`+`DENY_STATEMENT` write
branch above, plus the analyzer's read-set membership rules).
`ChannelDecideAuditDbTest` case 6 is named _"a write cannot launder a masked
column into a session temp (the unmasked-temp linchpin)"_ and is the regression
test for the pair. **A Go port that keeps the temp bypass but weakens the write
rule opens a cleartext exfiltration path.** Treat these two as one coupled
invariant.

**INV-A6-12 — first-wins per ordinal.** Two grants targeting the same output
ordinal apply the _first_. `StatementFactsGrantLoopTest` case 7 pins it. A Go
`map[int32]ColumnMask` with a presence check reproduces it; appending and
letting the last win inverts the semantics.

### Deny constructors

| Fn                                                                           | `failedStage`                 | `structural` | Grant-overridable?                               |
| ---------------------------------------------------------------------------- | ----------------------------- | ------------ | ------------------------------------------------ |
| `structuralDeny(reason, roles, failedStage = "admission", contextTags = [])` | caller's, default `admission` | `true`       | **no**                                           |
| `policyDeny(reason, roles, contextTags = [])`                                | `"policy"`                    | `false`      | **yes** — a JIT grant could add the missing role |
| `passthroughAllow(roles, detail, contextTags)`                               | `null`                        | —            | —                                                |
| `wireTaskForbiddenDeny(roles, contextTags)`                                  | `"policy"`                    | `false`      | —                                                |

🔒 **INV-A6-13 — the structural/policy split drives approval eligibility.**
Structural DENY rows still get a `decisionId` and use the normal audit path, but
_the minting path must refuse rows with `failed_stage = 'admission'`_ (source
comment at `Query.kt:818-820`). The UI may offer approval for those rows, so the
refusal has to live server-side. Cross-check when specifying A7.

`wireTaskForbiddenDeny` surfaces a forbidden native-wire self-approve as an
**ordinary policy DENY** (SQLSTATE 42501/1142), never a gRPC status, so the
client sees the same shape as any other denied statement.

### `deny(reason, catalogMiss)` — the local closure (step ~13)

`policyDeny(reason, roleList, derivedTags).copy(catalogMiss = …, schemaCandidates = facts.schemaQualifierCandidates)`

🔒 **INV-A6-14 — a catalog-miss deny must carry the schema qualifiers.** Without
them the connection layer cannot issue its bounded refetch of a
possibly-newly-created schema, and the query stays denied until an unrelated
refresh (`ConnectionDecide.markCatalogMiss`, A5).

---

## 4. Other `Query.kt` symbols

### `redactsDiagnostics(engine, action, mayReadUnmasked: () -> Boolean): Boolean` · internal

```
if (!engine.leaksDiagnosticsOnAllow && action == ALLOW) return false
return !mayReadUnmasked()
```

🔒 **INV-A6-15 — redact iff the diagnostic could carry a protected value AND the
principal is not a full-cleartext reader.** `mayReadUnmasked` is a **thunk** so
the Cedar call is skipped when the diagnostic cannot leak anyway. Keyed on Cedar
authz + engine capability, **never** a datasource-tag check.

### `Engine.leaksDiagnosticsOnAllow` · internal ext val

`this == Engine.POSTGRES`. The one place this engine fact lives. PostgreSQL can
leak a protected value through a diagnostic even on an ALLOW (the whole-row
`DETAIL: Failing row contains (…)`); MySQL cannot (it echoes only the
operated-on value, and any value-exposing read of a protected column is denied).
**The redaction logic branches on the capability, never the engine name.**

### `effectiveRoles(baseRoles, grantRoles, groupRoles): Set<String>`

`(baseRoles + grantRoles + groupRoles).toSet()`. A pure union kept separate
purely so it stays unit-testable; `RoleResolver.resolve` is the sole production
caller and passes server-resolved sets.

### `CatalogColumnIndex` / `buildCatalogColumnIndex(catalog, specs, analyzer)` · internal

`CatalogColumnIndex(specs, rowsByKey: Map<String, CatalogColumn>)`. Built by
zipping `catalog` against `analyzer.columnKeys` — **reusing the analyzer's own
keys** rather than re-deriving them with a second full-catalog walk, so a
fold-rule divergence is impossible by construction. Two `require`s: count match,
and no ambiguous key. Both are defense-in-depth against a wiring bug
(`analyzerFor` already validates key uniqueness and would have thrown).

### `catalogCoverage(index, touched): CatalogCoverage` · internal

`Covered`, or
`Denied("fail-closed: analyzer emitted column absent from catalog: <key>")` for
the first missing key.

⚠️ Long comment at `Query.kt:531-544` worth preserving: this is **not** a
stale-fragment path. A column truly absent from the catalog fails to _resolve_
(the analyzer is built from the same catalog) and takes the `!resolved`
`sql.unanalyzable` route at step 16. So step 18 is a fail-closed guard for an
**analyzer↔CP key-rendering divergence** — a contract bug. It routes through the
same `sql.unanalyzable` escape hatch rather than hard-denying, on the principle
that _authorization belongs to Cedar_: a principal without `sql.unanalyzable`
stays fail-closed, while a holder may relay. The relay drops masks for
**co-selected covered columns too**, which is no new capability over the step-16
relay.

### `effectiveAuthzContext(caller, channel, authz, principal, roles, datasource, datasourceTags)` · internal

```
raw = caller.copy(channel = channel.contextValue)
return raw.copy(tags = authz.resolveContextTags(principal, roles, datasource, raw, datasourceTags))
```

🔒 **INV-A6-16 — `channel` and `tags` are both authoritative overwrites.**
`channel` overrides any caller value; `tags` is derived by pass-1 and
**overwrites** any caller value. Raw CP-attested inputs (`requesterIp`,
`networkZones`) are preserved. Pass-1 runs over the channel-overlaid raw context
with tags omitted (no recursion — A2 INV-A2-12). `TagResolutionTest` case 8 pins
it.

### `grantAction(GrantAction): AuthzAction?` · private

`SQL_SELECT`/`INSERT`/`UPDATE`/`DELETE`/`DDL` map; `UNSPECIFIED`, `RESULT_READ`,
`UNRECOGNIZED` ⇒ `null` (→
`policyDeny("statement kind 'other' is not permitted")`).

### `decisionRecord(principal, ds, sql, clientAddr, ctx, latencyMs, effectiveNamespace, channel)` · internal

Builds the `AuditEvent`. `EnfAction` → `Decision`: ALLOW→ALLOW, MASK→MASK,
**everything else → DENY** (fail-closed).
`maskedColumns = ctx.masks.map { it.column }`. Shared with `decideConnection`
(A5) and `support/EnforcementHarness.kt`, so the audit shape cannot drift
between them.

### `parseRequesterIp(clientAddr): String?` · internal

The wire-path counterpart of A12's `stripToBareIp`, for a proxy-supplied
`client_addr` arriving as `/1.2.3.4:5432` or `/[::1]:5432`. Strips leading `/`,
then: `[` ⇒ take between `[` and `]`; exactly one `:` ⇒ take before it; else
bare. Returns null when nothing is parseable.

⚠️ **Deliberately laxer than `stripToBareIp`** — it parses Netty's
always-well-formed `SocketAddress.toString()`, not attacker-adjacent header
text. A residual non-IP survivor is dropped defensively at
`AuthzContext.toCedarMap` (A2 INV-A2-8). **Do not unify the two without
re-checking that assumption** (A12 Q4).

### Deny message constants

`EDITOR_SESSION_STATEMENT_DENY`, `MASK_BIND_DENY` (internal),
`EXPLAIN_MASK_DENY`, `SYSTEM_FUNCTION_DENY`, `SYSTEM_UTILITY_DENY`,
`DEACTIVATED_PRINCIPAL_DENY`, `CATALOG_CONFIGURATION_DENY`,
`WIRE_TASK_FORBIDDEN_DENY`.

⚠️ These are **English prose on the wire** via `denyReason`/`detail`, which sits
uneasily with A1 INV-A1-13 (`ApiError` codes only). They reach the client as
SQLSTATE messages on the wire path, not as REST bodies — but
`QueryResponse.denyReason` _is_ a REST field. Flagged: §7 Q3.

---

## 5. `Access.kt` — the task lifecycle store

### Wire DTOs

`AccessRequest` — 24 fields: `id`, `principal`, `roleId?`, `roleName?`,
`datasourceId?`, `datasourceName?`, `reason?`, `requestedDurationSec`, `status`,
`decidedBy?`, `executedBy?`, `decidedAt?`, `rejectionReason?`, `createdAt`,
`kind = "ROLE"`, `sql?`, `sqlHash?`, `denyReason?`, `sourceDecisionId?`,
`title?`, `evaluatedDecision?`, `approvedAt?`, `executingAt?`, `executedAt?`,
`executeAs = []`, `creatorKind?`.

`AccessRequestInput{roleId, datasourceId?, reason?, requestedDurationSec = 3600}`
·
`AccessGrant{id, principal, roleId, roleName, grantedBy?, grantedAt, expiresAt?, revokedAt?}`
· `ApproveInput{durationSec: Long? = null}` · `RejectInput{reason: String}`

All timestamps are Java `Instant.toString()` (variable precision) — same wire
concern as A2/A8.

`sql`, `sqlHash`, and `executedBy` are **correlated subqueries** over
`query_result` in `REQ_SELECT`, each `ORDER BY qr.id LIMIT 1` — i.e. the
**earliest** child. A WIRE task has no child, so all three read null.

### The three task origins — one table, one state machine

🔒 **INV-A6-17 — `creator_kind` is what keeps the three origins apart.** All are
`access_request.kind = 'QUERY'`:

| `creator_kind` | Created by           | Starts                     | Child? | On `/api/approvals`? |
| -------------- | -------------------- | -------------------------- | ------ | -------------------- |
| `WORKFLOW`     | `createQueryRequest` | `PENDING` (human-decided)  | 1      | **yes**              |
| `EDITOR`       | `createEditorTask`   | `APPROVED` (self-approved) | 1      | **no**               |
| `WIRE`         | `createWireTask`     | `APPROVED`                 | **0**  | **no**               |

`listQueryRequests` filters `creator_kind = 'WORKFLOW'`. Without that filter,
editor tabs' saved results and per-statement wire authorizations would surface
on the human approval queue. `wireTaskIdForDecision` likewise filters
`creator_kind = 'WIRE'`, because WORKFLOW tasks _also_ carry the DENY decision
that spawned them and a proxy completion must never terminalize one.

### Status machine — every transition is a guarded conditional UPDATE

| Method                                                | Transition                           | Guard                                                                      |
| ----------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------- |
| `decideQueryRequest(id, approved, reason, decidedBy)` | `PENDING → APPROVED\|REJECTED`       | `kind='QUERY' AND status='PENDING'`; `approved_at` set only when approving |
| `claimExecution(id[, c])`                             | `APPROVED → EXECUTING`               | stamps `executing_at`                                                      |
| `markExecuted(id[, c])`                               | `EXECUTING → EXECUTED`               | stamps `executed_at`                                                       |
| `markFailed(id[, c])`                                 | `EXECUTING → FAILED`                 |                                                                            |
| `markCancelled(id[, c])`                              | `EXECUTING → CANCELLED`              |                                                                            |
| `markDeleted(id)`                                     | `DRAFT\|PENDING\|REJECTED → DELETED` | never from a live state                                                    |
| `resubmit(id)`                                        | `REJECTED → PENDING`                 | clears `decided_by`/`decided_at`/`rejection_reason`                        |

🔒 **INV-A6-18 — every transition is a single conditional UPDATE returning
`rows > 0`.** That is the concurrency control: exactly one of N concurrent
`claimExecution` callers wins, with no explicit lock. `TaskStoreDbTest` case 3
(_"two concurrent claims on separate connections yield exactly one winner"_)
pins it. **A Go port must not read-then-write**; keep the guard in the `WHERE`
clause.

🔒 **INV-A6-19 — terminal transitions compose onto a caller's connection so
parent and child commit together.** `markExecuted(id, c)` / `markFailed(id, c)`
exist so the parent's flip commits in the _same_ transaction as the child's
`DONE`/`FAILED` (A7's `QueryResultStore.completeRun`/`failRun` hooks). A crash
can then never leave a readable DONE child under a still-EXECUTING task, nor the
inverse.

### `reconcileOrphanedExecutions()`

One transaction: `access_request EXECUTING → FAILED`, then
`query_result RUNNING → FAILED` with `error_code = 'task.orphaned_on_restart'`
**and `expires_at = now + RESULT_RETENTION_SEC`**.

🔒 **INV-A6-20 — the orphan sweep must set `expires_at`.** Otherwise a
NULL-expiry FAILED row accumulates on every restart-with-orphan — no ciphertext,
but unbounded growth, since `purgeExpired` matches on `expires_at`. Same class
of bug as A1 INV-A1-5.

Called twice at boot (`Main.kt:50` and `App.kt:351`); idempotent.

### `createQueryRequest(...)`

`sqlHash = SHA-256(sql).hex`. In one transaction: insert the `access_request`
with
`ON CONFLICT (source_decision_id) WHERE kind='QUERY' AND status='PENDING' AND source_decision_id IS NOT NULL DO NOTHING RETURNING id`
— **no row returned ⇒ throw `DuplicatePendingQueryRequestException`** — then
insert the `query_result` child.

🔒 **INV-A6-21 — a partial-index upsert is what makes "one pending request per
denied decision" atomic.** A read-then-insert would race. Note `executeAs` is
resolved _inside_ the transaction by looking up `app_role.name` for `roleId`.

### `createEditorTask(...)` / `createWireTask(c, ...)`

Both born `APPROVED` with `decided_by`/`decided_at`/`approved_at` stamped,
`requested_duration_sec = 3600` hardcoded, and `execute_as` as a `jsonb` array.

🔒 **INV-A6-22 — an editor task's `executeAs` is the caller's OWN
freshly-resolved roles, never an elevation and never frozen across submits.** A
re-run resolves again, so a revoked role fails closed on the next submit.
`createWireTask` takes the caller's connection so the decision event and its
task commit atomically.

### Grants

`listGrants(principal?, activeOnly)` — `activeOnly` adds
`revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. `getGrant`,
`revoke(id)` (guarded `revoked_at IS NULL`),
`revokeAllForPrincipal(principal[, c])` — the deprovisioning backstop, paired
with `TokenStore.revokeAllForPrincipal`.

### `approve(id, durationSec, decidedBy)` — the ROLE elevation path

Returns null if the request or its `roleId` is absent. Then **manual
transaction** (`autoCommit=false` / `commit` / `rollback` /
`finally autoCommit=true`): UPDATE the request to `APPROVED`, INSERT the
`access_grant` with `expires_at = now + (durationSec ?: requestedDurationSec)`.

⚠️ This is the **only** place in the file using manual `autoCommit` juggling
instead of the `dataSource.inTx {}` helper used everywhere else. Behaviourally
equivalent, so **REPRODUCE (F14)** — port the hand-rolled form as-is with a
comment naming the finding. Inconsistency is not grounds for OMIT, and folding
it into the shared helper is a refactor; a refactor during the port is a fix
during the port. Unify afterwards, as its own change.

`reject(id, reason, decidedBy)` — checks existence, then an **unguarded** UPDATE
(no status predicate), so rejecting an already-decided request silently
overwrites it. Contrast `decideQueryRequest`, which guards on `PENDING`. §7 Q1.

---

## 6. Routes

### `queryRoutes` — 1 route

`POST /api/datasources/{id}/query` · `requireApi` · bad id ⇒ 400, unknown ds
⇒ 404. Best-effort `historyStore.add` (never blocks). Delegates to
`runExecService.run(...)`. Exception → status mapping:
`NoProxyAttachedException` ⇒ **503** `query.no_proxy_attached` ·
`ProxyStreamWedgedException` ⇒ **503** `query.proxy_stream_wedged` ·
`ProxyRunTimeoutException` ⇒ **504** `query.proxy_timeout` · `ProxyRunException`
⇒ **502** `query.failed{detail}`.

### `editorSessionRoutes` — 6 routes

All `requireApi`. Principal falls back to `"debug-user"` when there is no
session.

| Method | Path                                     | Notes                                                                                |
| ------ | ---------------------------------------- | ------------------------------------------------------------------------------------ |
| POST   | `/api/editor/sessions`                   | opens one proxy-dialed stream = one backend connection; same 503/504/502 mapping     |
| POST   | `/api/editor/sessions/{sessionId}/query` | **202 Accepted** + `EditorSubmitResponse{taskId, childId}`; runs async on `appScope` |
| GET    | `/api/editor/tasks/{taskId}`             | poll status + child meta                                                             |
| POST   | `/api/editor/tasks/{taskId}/cancel`      |                                                                                      |
| GET    | `/api/editor/tasks/{taskId}/result`      | rows                                                                                 |
| DELETE | `/api/editor/tasks/{taskId}`             | delete-on-close, **idempotent 204**                                                  |
| DELETE | `/api/editor/sessions/{sessionId}`       | owner-scoped, **idempotent 204**                                                     |

**Submit sequence** (`POST …/query`), in order:

1. blank `sql` ⇒ 400 `common.field_required{fields: "sql"}`
2. `ownRoles = roleResolver.resolve(principal)`; **empty ⇒ 403**
   `common.forbidden`
3. `sessionDatasourceName(sessionId, principal)` — **owner-scoped**, so a leaked
   session id cannot target another principal's connection ⇒ 404
   `editor session`
4. datasource by name ⇒ 404
5. `queryResultStore` null ⇒ **503** `approval.result_storage_not_configured`
6. unless `authDebug`:
   `autoApproveTask(principal, ownRoles, ds, ctx, authz, Channel.EDITOR)` ⇒ 403.
   🔒 Must clear **both** `task.request` and `task.approve` (A7 owns
   `autoApproveTask`).
7. `createEditorTask(...)`, `editorChildId(...)`
8. `store.claimAndStartRun(task.id, principal) { accessStore.claimExecution(task.id, c) }`
   — null ⇒ **409** `approval.already_executed`
9. launch on `appScope`; respond **202**

🔒 **INV-A6-23 — the execution claim is atomic across parent and child.**
`APPROVED → EXECUTING` and the child `NULL → RUNNING` commit in **one**
transaction, so a cancel cannot slip into an EXECUTING-but-no-RUNNING-child gap.

The async body maps outcomes to `failureCode`: `DENY` ⇒
`"approval.execute_denied"`; success ⇒ `completeRun` (child DONE + parent
EXECUTED in one transaction) or `"approval.query_failed"`;
`RunCanceledBeforeStartException` ⇒ **null** (not a failure); proxy exceptions ⇒
their codes; any `Throwable` ⇒ logged + `"approval.query_failed"`. Then, if
failed, `failRun` (child + parent FAILED in one transaction). Finally publishes
the **actual** terminal status to `taskCompletionHub`.

🔒 **INV-A6-24 — no task-level audit row is written on the success path.** The
run's per-statement `Decide` round-trip already wrote the real audit decision
with its `decisionId`; adding one here would duplicate it as a **false ALLOW**.

**Gate layering on the read paths** — worth stating precisely, since it is easy
to collapse:

| Route                        | Owner guard                                                | Cedar gate                                      | `authDebug` bypasses Cedar? |
| ---------------------------- | ---------------------------------------------------------- | ----------------------------------------------- | --------------------------- |
| GET `/api/editor/tasks/{id}` | `kind=QUERY ∧ creatorKind=EDITOR ∧ principal==owner` ⇒ 404 | `TASK_READ` ⇒ 404                               | **yes**                     |
| POST `…/cancel`              | same ⇒ 404                                                 | `TASK_CANCEL` ⇒ 403 `approval.cancel_forbidden` | **yes**                     |
| GET `…/result`               | same ⇒ 404                                                 | `TASK_ASSUME` ⇒ 404                             | **NO**                      |

🔒 **INV-A6-25 — the result route has no `authDebug` bypass.** Rows are data
confidentiality; metadata gates bypass, the row gate does not.

🔒 **INV-A6-26 — the owner guard is not a substitute for Cedar, and Cedar is not
a substitute for the owner guard.** A Cedar forbid (e.g. `task.read` denied from
an untrusted zone) must still override the self-read permit — hence both.
Conversely, the result route's owner check is load-bearing because a
`task.assume` grantee (e.g. `system:auditor` via V40) could otherwise read
_another_ user's editor rows, which the frozen contract forbids.

The result route also: re-checks `isDeactivated` before result lookup (defense
in depth), takes **one** read capturing ciphertext + meta with **lazy decrypt**
(so an unauthorized viewer never triggers a decrypt and a concurrent re-run
cannot swap the row between check and decrypt), then `status != "DONE"` ⇒
**409** `approval.result_not_ready`, absent plaintext ⇒ **410**
`approval.result_expired`, and finally re-decides live via
`decideResultView(..., channel = Channel.EDITOR)` (A7).

🔒 **INV-A6-27 — the response's `decision` is derived server-side from whether
the view actually masked anything** (`maskedColumns.isEmpty() ? ALLOW : MASK`).
Deriving it client-side from "are there rows" is what previously let a masked
result display as a clean ALLOW.

### `accessRoutes` — 6 routes

| Method | Path                                | Gate                                                                                                                      |
| ------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/access-requests`              | `requireApi` + **forward-filter** each row by `TASK_READ`                                                                 |
| POST   | `/api/access-requests`              | `requireApi`; if a datasource is named and `!authDebug`, `TASK_REQUEST` on it ⇒ 403 `approval.request_not_permitted`      |
| POST   | `/api/access-requests/{id}/approve` | `requireApi`; `kind != "ROLE"` ⇒ 400 `approval.use_query_approval_endpoint`; `TASK_APPROVE` ⇒ 403 `approval.not_approver` |
| POST   | `/api/access-requests/{id}/reject`  | same as approve                                                                                                           |
| GET    | `/api/access-grants`                | `requireApi` + forward-filter by `TASK_READ` on `AccessGrant`                                                             |
| POST   | `/api/access-grants/{id}/revoke`    | loads the grant first, then `requireAuthz(GRANT_REVOKE, AccessGrant(owner=…))`                                            |

🔒 **INV-A6-28 — list routes forward-filter per row rather than trusting a query
parameter.** An arbitrary `?principal=` on `/api/access-grants` does not leak
another principal's grants: every row is kept only if the caller may read it.
Under `authDebug` (no session) the full list is returned, matching
`requireApi`'s dev bypass.

🔒 **INV-A6-29 — `/api/access-grants/{id}/revoke` loads the grant BEFORE the
gate.** This is what closes the IDOR where any authenticated principal could
revoke anyone's grant by enumerating ids — Cedar must decide against the grant's
**owner**, which requires reading it first. Note this route calls `requireAuthz`
(not `requireApi`), so it is the one `accessRoutes` endpoint with no
`requireApi` call.

🔒 **INV-A6-30 — self-approval is governed entirely by Cedar, never a hardcoded
rule.** The `no-self-approval` forbid (V11 seed) is the mechanism; a deployment
may disable it for dev/eval. These routes only ever ask authz "may this
principal do this?". `roleName` is passed so a policy can scope approval by the
**role being requested** (`resource in Role::…`) — without it that capability is
unreachable here.

⚠️ `POST /approve` reads its body with
`runCatching { call.receive<ApproveInput>() }.getOrDefault(ApproveInput())` — a
**missing or malformed body is tolerated** and falls back to the requested
duration. `/reject` uses a plain `receive<RejectInput>()`, so a missing body is
a 400. Asymmetric but intentional (reason is mandatory, duration is not).

---

## 7. Test inventory — 24 suites, 4,730 LOC, **183 cases**

_(Corrected by the reconciliation pass. The earlier headline said "24 files,
4,833 LOC, 180 cases": the LOC was stale by 197 and one suite was missing.
`SchemaKeyWiringTest.kt` — 94 LOC, 3 cases — was owned by no area; case 1 drives
`buildCatalogColumnIndex`/`catalogCoverage`/`CatalogCoverage`
(`Query.kt:213,236,230`) and cases 2–3 assert `analyzerFor` throws, which is the
only direct test anywhere of the analyzer-key injectivity invariant in
`13-engine.md`. Assigned here; `13-engine.md` cross-references it.)_

### Decision core

**`EnforcementDbTest.kt`** — 392 LOC, **35 cases** · DB, real engines. ⚠️ Two
top-level classes in one file: `EnforcementPostgresDbTest` (:20) and
`EnforcementMysqlDbTest` (:258). Many case names repeat across both — they are
_different_ tests against different engines. Per `AGENTS.md:17-26`, **MySQL is
the correctness bar**; keep the split, and do not dedupe by name.

Postgres (23): masked query returns masked rrn never cleartext · scalar subquery
leak denied · IN subquery oracle denied · correlated subquery oracle denied ·
INTERSECT membership oracle denied · no-FROM `query_to_xml` data reader denied ·
no-FROM metadata chatter still runs · 🔒 zero-grant principal cannot enumerate
schema via readonly-meta passthrough · non-sensitive query allowed · 🔒
ungranted table denied end-to-end · LATERAL correlated leak denied · recursive
CTE anchoring on rrn denied · benign correlated exists allowed · INSERT without
`sql.insert` denied with a clean reason (not a parse failure) · 🔒 `sql.select`
without `datasource.connect` denied **first** · DDL without `sql.ddl` denied
cleanly · CTAS reading a masked column denied even with `sql.ddl` · CTAS over
non-sensitive columns allowed · 🔒 no-FROM `SELECT INTO` cannot bypass the
`sql.ddl` gate via readonly-meta passthrough · 🔒 no-FROM SELECT reading a table
via `UNION TABLE` cannot exfiltrate cleartext · upsert INSERT denied without
`sql.update` even with `sql.insert` · UPDATE/DELETE without their grants denied
cleanly · a provably-total transform of a masked column redacts in full and the
rest of the row returns.

MySQL (12): masked query returns masked rrn · scalar subquery leak denied · IN
subquery oracle denied · 🔒 error-based extraction via `extractvalue` over a
masked column denied end-to-end · 🔒 `SET` user-variable from a subquery denied
(session-state exfiltration) · ungranted table denied · INSERT without
`sql.insert` denied cleanly · `sql.select` without `datasource.connect` denied
first · CTAS reading a masked column denied · 🔒 no-FROM `SELECT INTO OUTFILE`
cannot bypass `sql.ddl` (MySQL file-write) · no-FROM SELECT via `UNION TABLE`
cannot exfiltrate · 🔒 `SELECT INTO` after a parenthesized branch cannot bypass
`sql.ddl`.

**`StatementFactsGrantLoopTest.kt`** — 367 LOC, **21 cases** · unit, uses
`factsOverride`. The fail-closed contract suite; the only way to reach steps
8–11. all-granted analyzed allows · MASK_OUTPUT applies the configured mask ·
REDACT_OUTPUT_NULL redacts to NULL · DENY_STATEMENT denies · write read-set
membership of a masked column denies · denied verdict denies regardless of
disposition · 🔒 multi-grant same ordinal is first-wins (INV-A6-12) · output
columns and rewritten sql preserved · 🔒 grant with no resource fails closed
(INV-A6-10) · 🔒 resource grant with a non-RESULT_READ action fails closed · 🔒
unspecified disposition fails closed · 🔒 out-of-range ordinal fails closed · 🔒
unspecified statement class fails closed · 🔒 unspecified class with a column
grant fails closed independent of the verdict · 🔒 **unspecified disposition on
an UNMASKED column fails closed** (INV-A6-9) · 🔒 **out-of-range ordinal on an
UNMASKED column fails closed** (INV-A6-9) · unanalyzable deny carries schema
candidates for a bounded refetch (INV-A6-14) · datasource grant with an
unspecified action is a policy deny · ungranted table denies through table
dispatch · metadata with no grants is an allow passthrough · session statement
passes through only on persistent-connection channels (INV-A6-2).

**`SchemaThreadingDbTest.kt`** — 698 LOC, **17 cases** · DB.
`docs/schema-threading-problem.md`. explicit default schema masks while explicit
analytics stays unmasked · bare `users` resolves to the captured default
namespace and masks · 🔒 unknown table schema and foreign catalog deny without
rows · qualified star preserves schema-specific classification · 🔒 whole-row
JSON cannot bypass default PII and analytics does not inherit it ·
alias/composite resolution keeps the physical schema identity · 🔒 protected
bare-target update is valid and mutating on the backend but enforcement denies
it · explicit analytics update allowed, executes and rolls back without
persistence · live search path pivots unqualified resolution without changing
the default · 🔒 invalid/unresolvable live search paths fail closed (step 1) ·
missing pg-temp catalog entry skips to the next live search path schema ·
`decideAndAudit` threads and audits the live search path · 🔒 relation-valued
`UPDATE … RETURNING` cannot disclose protected rrn · system catalogs
introspected as first-class resources, not shadowed · live current database
pivots unqualified resolution · 🔒 invalid/unresolvable live current databases
fail closed · 🔒 `lctn=0` CTE output-column write cannot smuggle masked rrn.

### Gate suites (each isolates one pipeline step)

| Suite                                        | LOC | Cases | Step                                                                                                                                                                      |
| -------------------------------------------- | --- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UnanalyzableGateDbTest`                     | 67  | 1     | 16 — unanalyzable denies on the floor, then a `sql.unanalyzable` permit relays verbatim                                                                                   |
| `UnmaskableGateDbTest`                       | 83  | 1     | 30 — 🔒 `unmaskablePermitted` is fail-closed and populated **only** on the final MASK path                                                                                |
| `UtilityGateDbTest`                          | 131 | 2     | 13 — a data-bearing SHOW denied on the floor, relaxed on `system:development`; 🔒 **an unclassifiable utility is hard-denied even against a broad Datasource read grant** |
| `CatalogCoverageGateDbTest`                  | 121 | 2     | 18 — PG and MySQL coverage miss deny on the floor, then a `sql.unanalyzable` permit relays                                                                                |
| `BaselineDangerousFunctionEnforcementDbTest` | 225 | 7     | 16/22                                                                                                                                                                     |
| `SystemClassificationEnforcementDbTest`      | 212 | 7     | 21/22                                                                                                                                                                     |
| `DeactivationEnforcementDbTest`              | 113 | 4     | 5                                                                                                                                                                         |
| `DiagnosticsRedactionTest`                   | 51  | 5     | 31 (unit)                                                                                                                                                                 |
| `DiagnosticRedactionDecideDbTest`            | 64  | 2     | 31 (DB)                                                                                                                                                                   |
| `ChannelDecideAuditDbTest`                   | 210 | 7     | 7/14/24                                                                                                                                                                   |
| `GateSqlglotRegressionTest`                  | 129 | 9     | whole pipeline, both engines                                                                                                                                              |
| `RedTeamDmlTest`                             | 46  | 2     | 24 write branch                                                                                                                                                           |
| `ScannedTableMySqlTest`                      | 48  | 4     | 25                                                                                                                                                                        |
| `KnownGapsTest`                              | 96  | 7     | 25                                                                                                                                                                        |
| `EffectiveRolesTest`                         | 26  | 4     | `effectiveRoles` (unit, no DB)                                                                                                                                            |

⚠️ `UtilityGateDbTest` case 2 is the **only** test of A2's INV-A2-11
utility-marshalling inversion — contradicting what `02-authz.md` §10 recorded as
an untested gap. **Correction: F4 in the index is partially covered.** The
utility half is tested; the _function_ half (`authorizeFunctions` with an
unclassified name) still is not.

`BaselineDangerousFunctionEnforcementDbTest`: a null classifier STILL denies via
the static baseline · every former `dangerousFuncs` name denies WITH a FROM on a
governed PG datasource · …and STILL denies on a no-manifest PG datasource (the
baseline) · manifest-only dangerous functions deny on a no-manifest datasource
via the union floor · safe functions and a user UDF unaffected · 🔒 **a
dangerous function is denied on a `system:development` datasource, NOT relayed
via `sql.unanalyzable`** · MySQL `load_file` denies WITH a FROM on both governed
and no-manifest datasources.

`SystemClassificationEnforcementDbTest`: 🔒 a user column classification cannot
claim a reserved system tag (A2 INV-A2-7) · on PG-17, catalog structure browses
and dangerous surfaces deny · 🔒 the dangerous forbids override even a broad
datasource read grant · 🔒 without `engine_version`, system schemas stay
deny-by-default · a dangerous system function denies by policy on a versioned
datasource · the function forbid overrides a broad read grant · **the
dangerous-function deny wins over the uncovered-table deny** (deny precedence).

`ChannelDecideAuditDbTest`: the audit record carries the channel through the
real run path · the editor channel passthrough-allows a session statement while
workflow phases still deny (INV-A6-2) · a DENY's audit row carries the derived
context tag (INV-A6-4) · 🔒 a channel-gated grant follows the **server** channel
and ignores a client-injected one (INV-A6-1) · a session temp resolves and reads
unmasked via the overlay, unresolvable without it · 🔒 **a write cannot launder
a masked column into a session temp (the unmasked-temp linchpin)** (INV-A6-11) ·
a bare count over a session temp is allowed (uncovered-scan gate skips temps).

`DiagnosticsRedactionTest`: MySQL ALLOW never redacts whatever the principal ·
MySQL ALLOW skips the Cedar unmasked-reader check (cannot leak on allow — the
thunk) · MySQL MASK/DENY redacts unless the principal reads the datasource
unmasked · PostgreSQL redacts even an ALLOW unless unmasked · only PostgreSQL
leaks diagnostics on an allowed query.

`KnownGapsTest` / `ScannedTableMySqlTest` overlap deliberately — both cover the
uncovered-scan gate, `KnownGapsTest` on PG and `ScannedTableMySqlTest` on MySQL:
`count(*)` on an ungranted table denied · `select 1` denied · `EXISTS` denied ·
a cross-join scanning an ungranted table denied even when only the granted side
is projected · a CTE that _shadows_ a real ungranted table name is allowed (the
physical table is not read) · a CTE _body_ reading the real ungranted table is
denied · `count(*)` on a read-granted table allowed.

### Access / editor / task suites

| Suite                              | LOC | Cases | Subject                                               |
| ---------------------------------- | --- | ----- | ----------------------------------------------------- |
| `TaskStoreDbTest`                  | 340 | 14    | `AccessStore` status machine                          |
| `EditorTaskStoreDbTest`            | 195 | 7     | `createEditorTask`/`createWireTask` + child lifecycle |
| `EditorSubmitRouteDbTest`          | 514 | 10    | the async submit route                                |
| `EditorSelfApproveAuthzDbTest`     | 74  | 4     | `autoApproveTask`                                     |
| `ElevationContextRouteAuthzDbTest` | 434 | 8     | `accessRoutes` + approval wiring                      |

`TaskStoreDbTest`: `claimExecution` moves APPROVED→EXECUTING and stamps
`executing_at` · fires only from APPROVED · 🔒 **two concurrent claims on
separate connections yield exactly one winner** (INV-A6-18) · `markExecuted`
only from EXECUTING and stamps `executed_at` · `markFailed` only from EXECUTING
· `markCancelled` only from EXECUTING and blocks later terminal transitions ·
no-child WIRE tasks use the shared terminal lifecycle · `markDeleted` fires from
DRAFT/PENDING/REJECTED but never from live states · `resubmit` moves
REJECTED→PENDING but never other states · `execute_as` and `creator_kind`
round-trip · a task carries one-to-many statement children, latest wins in meta
· `reconcileOrphanedExecutions` terminalizes EXECUTING tasks and RUNNING
children, idempotently (INV-A6-20) · `createQueryRequest` persists `execute_as`,
`creator_kind`, and a not-started child · `decideQueryRequest` approve stamps
`approved_at`, reject leaves it null.

`EditorTaskStoreDbTest`: `createEditorTask` is born APPROVED as EDITOR with own
roles and one child (INV-A6-22) · `createWireTask` is born APPROVED as WIRE
linked to its decision with **no** child · the born-APPROVED editor task runs
the same single-execution status machine · `deleteResultsForTask` drops the
child but leaves the task, idempotently · `deleteEditorResultsForPrincipal`
drops only that principal's editor children · `purgeExpiredEditorChildren`
deletes only expired editor children (A1 INV-A1-5) · `deleteEditorTask` cascades
the child and is owner + EDITOR scoped.

`EditorSubmitRouteDbTest`: submit returns 202 then the run completes async,
saves the result, polls DONE, and delete-on-close removes it · submit pushes a
terminal task event to the owner's stream · a DENY at execute marks task and
child FAILED and saves **no rows** · result on a still-running task is 409
not_ready, then gates status codes · cancel terminalizes an in-flight task and
emits RunCancel **without closing the session** · canceling a _queued_ task
sends no cancel or query for the queued statement · delete of an executing task
emits RunCancel then removes it · submit guards — blank sql 400, unknown session
404 · 🔒 a `task.read` forbid denies the **owner's** poll with 404 (INV-A6-26) ·
🔒 poll and result for a non-owner editor task are 404.

`EditorSelfApproveAuthzDbTest`: `autoApproveTask` allows non-admin self-approve
on server-attested channels · 🔒 self-approve stays denied outside editor and
wire · 🔒 server-attested channel permits do not open cross-user approval ·
self-approve is explicitly allowed on editor and wire.

`ElevationContextRouteAuthzDbTest`: 🔒 ROLE access-request approve fires the
tag-gated permit only through a trusted edge · 🔒 query-approval approve
likewise · **query-approval approve mutates only authorization state and never
runs the query** · 🔒 query-approval execute is forbidden without the trusted
edge even for an already-approved request · query-approval execute clears the
R-scoped authority gate through a trusted edge (then fails on no attached proxy)
· catalog browse is gated by `datasource.connect` · ROLE request creation
against a datasource is gated by `task.request` · datasource list is filtered by
connect only when `connectable` is requested.

### Suites that touch A6 but are owned elsewhere

`ApprovalDiscoverPickSubmitRouteDbTest`, `ApprovalResultAssumeMysqlDbTest`,
`RoleDiscoveryTest` → A7 · `CatalogRefreshCommandDbTest`,
`ManifestCommandCoverageDbTest`, `EnginesTest` (13) → A5 · `PresetPolicyDbTest`,
`TagResolutionTest`, `ElevationContextTagTest` → A2 · `DeprovisionDbTest` → A3 ·
`grpc/GrpcDecideHandlerDbTest`, `grpc/WireTaskDecideDbTest` → A10 ·
`TaskEventsRouteDbTest` (2) → A7.

### Fixtures — port these first

`support/EnforcementHarness.kt` and `support/EnforcementFixture.kt` gate
**every** gate suite above. `EnforcementHarness` reuses `decisionRecord`
directly, so its audit shape is the production one.

### Coverage gaps in A6

- `parseRequesterIp` has only 2 cases (in `RequesterIpParseTest`, counted in
  A12); the bracket and multi-colon branches are thin.
- `redactsDiagnostics`' thunk-skip is asserted for MySQL ALLOW but not for a PG
  ALLOW where the Cedar call _is_ required to run.
- `reject`'s unguarded UPDATE (§5) — no test asserts what happens when rejecting
  an already-decided request.
- `resubmit` → re-approve → re-execute round trip.
- `markDeleted` from `DRAFT` specifically (the status exists but no route
  reaches it in A6).
- `EnfActionSerializer`'s deserialize path (the wire-inbound direction) — only
  serialize is exercised.
- Step 19's `policyStore.listMaskFns()` failure branch.

---

## 8. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                           |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | `AccessStore.reject` UPDATEs with no status guard, unlike `decideQueryRequest`. Can a REJECTED or APPROVED ROLE request be re-rejected, overwriting `decided_by`? Looks like a bug (F11) — but the disposition is **REPRODUCE** regardless: the unguarded UPDATE is observable on the wire. The question is what the fix should be afterwards, not whether the port replicates it. |
| Q2  | `decideQuery`'s `accessStore` parameter is unused (F12). Disposition **OMIT** — an unread parameter has no observable behaviour. Confirm first that no test constructs the call positionally and would silently rebind arguments.                                                                                                                                                  |
| Q3  | `DecisionContext.denyReason`/`detail` are English prose and reach REST via `QueryResponse.denyReason`, which conflicts with A1 INV-A1-13 (`ApiError` codes only). Is `web/` displaying them raw? If so this is an unlocalized surface.                                                                                                                                             |
| Q4  | `Channel` has 5 values; several doc comments enumerate 4 (pre-`MCP`). Confirm `MCP` belongs in the same passthrough-refusing set as the workflow channels (the code says yes, step 14).                                                                                                                                                                                            |
| Q5  | `approve()` uses manual `autoCommit` juggling while everything else uses `inTx {}` (F14). Was there a reason? The port **REPRODUCEs** the hand-rolled form either way; unification is a follow-up decision taken against a working Go service.                                                                                                                                     |
| Q6  | `requestedDurationSec = 3600` is hardcoded in both `createEditorTask` and `createWireTask` on a column the ROLE path uses meaningfully. Confirm it is genuinely inert for QUERY tasks.                                                                                                                                                                                             |
| Q7  | INV-A6-13: does A7's minting path actually refuse `failed_stage='admission'` rows? The comment says it must.                                                                                                                                                                                                                                                                       |
