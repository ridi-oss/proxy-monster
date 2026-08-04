# A13 — Engine (analysis facade, system classification, masking)

Files: `classification/SystemClassifier.kt` (183) ·
`classification/SystemClassificationStore.kt` (157) · `probe/CatalogApi.kt`
(118) · `probe/TableDetail.kt` (82) · `classification/SystemManifest.kt` (68) ·
`classification/BaselineDangerousFunctions.kt` (59) · `probe/Sqlglot.kt` (52) ·
`probe/SqlNormalize.kt` (34) · `probe/Masks.kt` (26) · `probe/Masking.kt` (22) ·
`probe/Dialect.kt` (3). **Total 804 LOC. Fully read.**

Resources (part of the contract, not code):
`engine/src/main/resources/system-classification/{postgres/16, postgres/17,mysql/8.0,mysql/8.4}.json`
— 2,384 JSON lines, 50,748 bytes total.

**DB tables: none.** The module holds no JDBC and opens no connection. It reads
only classpath resources. Its outputs land in tables owned by other areas:
`mask_fn.kind` (V2, the `kind` vocabulary §4.1), `column_classification` (V2,
the `Classification` DTO §3.2), and `datasource.engine_version` (the input
`SystemClassificationStore.resolve` is keyed off, A5).

> **Depth note:** MEDIUM. Small module, but three of its four concerns are
> security controls consumed by the two highest-risk areas (A6, A7), and about a
> quarter of it is already ported to Go — so the doc's first job is to say
> precisely _what must not be re-derived_.

## Purpose

`engine/` is the enforcement code shared between the control-plane's decision
path and (by hand-maintained twin) the wire proxy. Four separable concerns:

1. **Masking** (`Masking.kt`, `Masks.kt`) — deterministic value masking and
   mask-to-result-column binding. Applied by the control plane when a _stored_
   approval result is viewed (A7), and by the proxy inline on the wire. The two
   implementations must agree byte-for-byte.
2. **System classification** (`classification/`) — the shipped, curated,
   per-engine-major manifests that assign one of four `system:` tags to every
   object in an exposed system schema, plus the classifier, the version
   resolver, and a version-independent dangerous-function floor. Consumed by
   A5's `SystemClassificationService` and, through it, A6 steps 13/16/21/22.
3. **The analyzer facade** (`CatalogApi.kt`, `Sqlglot.kt`) — builds the
   per-request analyzer snapshot, validates the catalog's identities are
   collision-free, and wraps the sqlglot-go probe fail-closed.
4. **Shared DTOs** (`TableDetail.kt`) — the table-browser shape the proxy
   produces and the control-plane serves through unchanged.

Plus one **production-dead** concern: `SqlNormalize.kt` + `Dialect.kt` (§4.2,
finding F21).

---

## 1. Porting status — establish this before writing any Go

The area guidance flagged parts of this module as already ported. Verified this
session:

| Kotlin                                                              | Existing Go                                                                                                                                                                          | Verdict                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `probe/Masking.kt` + `probe/Masks.kt` (48)                          | `goproxy/engine/masking.go` (80 — `wc -l`) + `MaskBinding` in `goproxy/engine/engine.go:160-168`                                                                                     | **Twin exists and still agrees** — see §1.1. `docs/backlog.md:374-380` flags the duplication for elimination ("Make Go the canonical implementation … Masking is the clearest case … which must stay identical by hand. Medium priority."). |
| `probe/Sqlglot.kt` (52) + `analyzer/jvm` (342: 174 main + 168 test) | `analyzer/probe` (a Go module: `analyzer/go.mod`)                                                                                                                                    | **Confirmed DELETE, not port.** §1.2.                                                                                                                                                                                                       |
| `probe/TableDetail.kt` (82)                                         | `goproxy/spi/spi.go:101-177`                                                                                                                                                         | **Twin exists, and it is NOT in `00-INDEX.md`'s "Already twinned" table.** New finding **F24**. §1.3.                                                                                                                                       |
| `classification/**` (467)                                           | _nothing_                                                                                                                                                                            | **Port in full.** No Go counterpart anywhere (`grep -rn 'SystemTag\|classifyBareFunction' --include='*.go'` → no matches).                                                                                                                  |
| `probe/CatalogApi.kt` (118)                                         | partially: the Go probe builds its own `schema.Mapping` from the flat list (`analyzer/probe/wire.go:83`), but the **collision validation and the rendered-key list are Kotlin-only** | **Port the validation and `columnKeys`.** §4.3.                                                                                                                                                                                             |

### 1.1 Do the two masking implementations still agree? — **Yes.**

Read both. Rule-by-rule:

| Rule                | `Masking.kt:11-21`                                              | `masking.go:33-61`                                             | Agree                                                                   |
| ------------------- | --------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------- |
| null value          | `value == null -> null`                                         | `value == nil \|\| kind == "NULL" -> nil`                      | ✔ (Kotlin checks value first, then kind; the disjunction is equivalent) |
| `NULL`              | `-> null`                                                       | same branch                                                    | ✔                                                                       |
| `FIXED`             | `"####"`                                                        | `"####"`                                                       | ✔                                                                       |
| `LAST_N`            | `n=4`; `len <= 4` ⇒ `"*"*len`; else `"*"*(len-4) + takeLast(4)` | UTF-16-encodes, `visible=4`, same arithmetic on code units     | ✔                                                                       |
| `FORMAT_PRESERVING` | `value.map { if (it.isLetterOrDigit()) '*' else it }`           | iterates UTF-16 units, `isKotlinCharLetterOrDigit(rune(unit))` | ✔                                                                       |
| anything else       | `"****"`                                                        | `default: "****"`                                              | ✔                                                                       |

The Go side carries two deliberate JVM-parity hacks whose **reasons must survive
the port**, quoted:

- `masking.go:31-32` — _"Kotlin String length, takeLast, and Char mapping
  operate on UTF-16 code units, so this deliberately does not use Go rune
  counts."_ A naive Go port using `len([]rune(v))` changes the mask length of
  any value containing an astral character (emoji, some CJK ext) —
  `masking_test.go:29` pins it: `"😀1234"` → `"**1234"` (the emoji is **two**
  starred units, not one).
- `masking.go:63-66` — _"isKotlinCharLetterOrDigit mirrors JDK 24
  `Character.isLetterOrDigit(char)`. Go 1.23 uses Unicode 15 tables while JDK 24
  uses Unicode 16, whose eight new BMP letters must also be masked.
  Supplementary letters are represented by surrogate halves in Kotlin Char
  iteration and therefore intentionally remain unclassified here."_ The eight
  literals are `0x1c89 0x1c8a 0xa7cb 0xa7cc 0xa7cd 0xa7da 0xa7db 0xa7dc`
  (`masking.go:75`), pinned by `TestKotlinCharLetterOrDigitUnicode16Parity`.

⚠️ **The Unicode-table patch is a maintenance trap the port inherits, not one it
escapes.** Once the JVM side is gone, "JDK 24 `Character.isLetterOrDigit`" stops
being the definition of correct — but the _stored ciphertext of every
already-masked approval result was produced under it_, and A7's view path
re-masks live from stored cleartext on every read (INV-A7-3), so a semantics
change silently changes what a viewer sees for an old task. The Go port should
keep the hardcoded set and treat "what does letter-or-digit mean" as a **frozen
product decision**, not a library version detail. See §7 Q1.

Two shape differences that are **not** behavioural: Kotlin's `byIndex` is a
`LinkedHashMap` where Go's is a plain `map[int]string` (no consumer iterates it
in order — A7 looks up `byIndex[index]` per column, `RowMasker.Apply` writes
each index independently), and Kotlin's `unbound` is an empty `ArrayList` where
Go's is a `nil` slice (both sides only ask `isEmpty`/`len == 0`).

**The Go control-plane should import `goproxy/engine`, not re-implement it.**
That collapses the twin (backlog item satisfied) instead of creating a third
copy.

### 1.2 `Sqlglot.kt` + `analyzer/jvm` — confirmed delete

`probe/Sqlglot.kt` exists only to marshal a protobuf `AnalyzeRequest`, hand the
bytes across the FFM boundary (`analyzer/jvm/.../Sqlglot.kt:73`
`analyzeStatement(ByteArray): ByteArray`), and parse the `StatementFacts` back.
`SqlNormalize.kt` likewise wraps `Sqlglot.sqlNormalize(sql, dialect): String?`.

The Go side already exposes both natively, in-process, with no serialization:

- `analyzer/probe/wire.go:18` —
  `func AnalyzeStatement(req *pb.AnalyzeRequest) (*pb.StatementFacts, error)`
- `analyzer/probe/wire.go:35` —
  `func AnalyzeStatementSafe(reqBytes []byte) (out []byte)`, documented as
  _"total, panic-safe … ALWAYS returning a validly-encoded StatementFacts, never
  an error, never a panic escaping to the caller (which, across a cgo boundary,
  would crash the host process)"_
- `analyzer/probe/sqlnormalize.go:15` —
  `func SqlNormalize(sql, dialect string) (normalized string, ok bool)`

A Go control-plane calls `probe.AnalyzeStatement` directly. `probe/Sqlglot.kt`,
`probe/SqlNormalize.kt` and the whole of `analyzer/jvm` are **deleted**. What
must be _carried over_ from `Sqlglot.kt` is not code but its fail-closed mapping
(INV-A13-15) and the `--enable-native-access` / JDK-24 constraint disappearing
with it.

⚠️ One mapping detail the deletion loses if nobody writes it down:
`AnalyzeStatement` returns `(facts, error)`, and the Kotlin wrapper's catch-all
set `failedStage = "LINEAGE"`, whereas the Go `AnalyzeStatementSafe` labels a
decode/build failure `"VALIDATE"` (`wire.go:43,48`). Finding **F28**.

### 1.3 `TableDetail.kt` ↔ `goproxy/spi/spi.go` — a third undocumented twin (F24)

`goproxy/spi/spi.go:101-177` declares `TableDetail`, `TableDetailColumn`,
`TableIndexColumn`, `TableIndex`, `TableRelation`, `TableMetadata`,
`Classification` with JSON tags matching the Kotlin property names exactly. The
proxy produces the JSON; `TableDetailExec.kt:138` (A5) decodes it with **`Json`
default configuration** — strict: unknown keys throw, and a
nullable-without-default property must be _present_. So the two structs are a
hand-maintained wire pair today, and `00-INDEX.md`'s twinned table should gain a
row.

Load-bearing consequence for whichever side stays Go: **every** slice in the
table-detail builder is deliberately allocated non-nil. A `nil` slice marshals
to `null`, and strict kotlinx rejects `null` for a non-nullable `List` — a table
with no foreign keys (or no indexes, or an index with no columns) would fail
table-detail entirely. Verified:
`grep -n 'make(\[\]spi\.\|make(\[\]string' goproxy/dialects/table_detail.go`
returns **14** sites, and `grep -nE 'var [a-z]+ \[\]spi\.'` returns none — i.e.
there is no nil-slice path at all. They cover both dialect paths: MySQL `:83`
columns, `:183` index columns, `:210` indexes, `:289-290` relation column lists,
`:645` relations; PostgreSQL `:418`, `:520`, `:541`, `:625-626`, `:854`.
Kotlin's non-nullable `List` fields that depend on this are
`TableDetail.{columns,indexes,foreignKeys,referencedBy}`, `TableIndex.columns`
and `TableRelation.{sourceColumns,targetColumns}` — seven fields, not one. Also
verified: **no `omitempty` anywhere in `spi.go:100-177`**, which is what makes
the strict decode work at all (a nullable-without-default Kotlin property needs
the key _present_). Once both ends are Go the hazard is gone, but do not
"simplify" any of those allocations, or add an `omitempty`, while the Kotlin end
still exists.

---

## 2. Routes

**None.** Verified this session:
`grep -rnE '\b(get|post|put|patch|delete|sse)\("' engine/src/main/kotlin/` → no
matches. The module registers no Ktor routes and exposes no HTTP surface. Its
DTOs reach the wire through other areas: `TableDetail` via
`GET /api/datasources/{id}/table-detail` (A5 — route declared at
`Datasources.kt:924`, handler body `Datasources.kt:937` →
`ManagementServices.getTableDetail` at `management/ManagementServices.kt:93`,
A11) and via MCP `get_table_detail` (`mcp/McpServer.kt:458-460`, A11);
`Classification` additionally via the classification set/clear routes (A5) and
MCP (A11). Gates are those areas'; nothing here gates anything.

---

## 3. Wire contract

Two independent serialization surfaces with **different** codec configurations.
Getting the configurations crossed is the failure mode.

### 3.0 Codec configurations (both are contract)

| Surface                                    | Config                                                                            | Where                             |
| ------------------------------------------ | --------------------------------------------------------------------------------- | --------------------------------- |
| HTTP responses → `web/`                    | `Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }` | `App.kt:340`                      |
| proxy → control-plane table-detail payload | `Json` **defaults** — strict: unknown keys **throw**, nulls explicit              | `TableDetailExec.kt:68`           |
| classpath manifests                        | `Json { ignoreUnknownKeys = true }`                                               | `SystemClassificationStore.kt:90` |

🔒 **INV-A13-32 — `explicitNulls = false` on the HTTP surface means a null field
is OMITTED, not emitted as `null`, while `encodeDefaults = true` means an empty
list IS emitted as `[]`.** A Go port must reproduce both halves: `omitempty` on
a pointer field but **not** on a slice field. Emitting `"defaultValue": null`
where Kotlin omitted the key, or omitting `"tags": []`, are both wire changes
`web/` can observe.

### 3.1 Manifest JSON (`SystemManifest.kt`) — the shipped classification data

Decoded with `ignoreUnknownKeys = true`, so a manifest may carry extra
provenance keys. All fields use the Kotlin property name (verified:
`grep -rn '@SerialName' engine/src/main/kotlin/` → no matches, so no field is
renamed anywhere in the area).

**Why the manifests are shipped code and not a DB table** — the reason belongs
with the contract (`SystemManifest.kt:6-9`, quoted): _"Every object in an
exposed system schema is one of four `system:` tags; only the dangerous
overrides are enumerated — everything else defaults to `system:catalog` (open
browsing). **These tags are a product fact, immutable and bundled per engine
MAJOR version; policy over them lives in Cedar** (`access-model.md`)."_ That is
why §head says "DB tables: none": an operator can change the _policy_ over a tag
but never the tag, so there is nothing to migrate and no admin route to build. A
Go port that moved the manifests into the database would turn a product fact
into operator-editable data — i.e. into a way to downgrade `pg_authid` from the
admin console.

**`SystemManifest`**

| JSON field               | Type             | Nullable | Default    | Notes                                                          |
| ------------------------ | ---------------- | -------- | ---------- | -------------------------------------------------------------- |
| `engine`                 | string           | no       | — required | must equal the resource path's directory (`load` cross-checks) |
| `series`                 | string           | no       | — required | must equal the resource file stem                              |
| `manifestVersion`        | int              | no       | — required | read but **not** validated or compared anywhere                |
| `curatedThrough`         | string           | no       | — required | provenance only; never read by code                            |
| `systemSchemas`          | `SystemSchema[]` | no       | `[]`       | the exposed system surface                                     |
| `logicalFunctionSchemas` | `SystemSchema[]` | no       | `[]`       | resource-only Function namespaces (MySQL `def/__builtin__`)    |
| `relations`              | `ObjectRule[]`   | no       | `[]`       |                                                                |
| `relationFamilies`       | `FamilyRule[]`   | no       | `[]`       |                                                                |
| `functions`              | `ObjectRule[]`   | no       | `[]`       |                                                                |
| `functionFamilies`       | `FamilyRule[]`   | no       | `[]`       |                                                                |
| `commands`               | `CommandRule[]`  | no       | `[]`       |                                                                |

**`SystemSchema`** — `catalog: string` (required), `schema: string` (required).
`catalog: "*"` = any. **`ObjectRule`** — `schema`, `name`, `tag` (all required
strings). `schema: "*"` legal on a _function_ rule only. **`FamilyRule`** —
`schema`, `prefix`, `tag` (all required strings). Prefix match, no regex.
**`CommandRule`** — `id`, `resource`, `tag` (all required strings). ⚠️
**`resource` is never read by any code in the repo** (verified: `commandTags` at
`SystemClassifier.kt:33` consumes only `id` and `tag`) — it is documentation
inside the data file. Finding **F31**.

`tag` is always one of the four literal strings `system:critical`,
`system:data-leak`, `system:activity`, `system:catalog`; anything else aborts
boot (INV-A13-19). Tags are **strings** in the manifest, not a serialized enum —
`SystemTag` is not `@Serializable`.

### 3.2 Table-browser JSON (`TableDetail.kt`)

**`Classification`** — the persisted column classification the control plane
overlays onto live introspection.

| Field        | Type       | Nullable | Default  |
| ------------ | ---------- | -------- | -------- |
| `schema`     | string     | no       | required |
| `table`      | string     | no       | required |
| `column`     | string     | no       | required |
| `tags`       | `string[]` | no       | `[]`     |
| `maskFnId`   | int64      | **yes**  | `null`   |
| `maskFnName` | string     | **yes**  | `null`   |

**`TableDetail`** — `schema: string`, `table: string`,
`columns: TableDetailColumn[]`, `indexes: TableIndex[]`,
`foreignKeys: TableRelation[]`, `referencedBy: TableRelation[]`,
`metadata: TableMetadata`. **All seven required, none nullable, no defaults.**

**`TableDetailColumn`**

| Field                    | Type             | Nullable | Default                                                                                                                                                                                                                           |
| ------------------------ | ---------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                   | string           | no       | required                                                                                                                                                                                                                          |
| `dataType`               | string           | no       | required                                                                                                                                                                                                                          |
| `ordinal`                | int32            | no       | required                                                                                                                                                                                                                          |
| `nullable`               | bool             | no       | required                                                                                                                                                                                                                          |
| `defaultValue`           | string           | **yes**  | none — key must be present on decode                                                                                                                                                                                              |
| `characterMaximumLength` | int64            | **yes**  | none                                                                                                                                                                                                                              |
| `numericPrecision`       | int32            | **yes**  | none                                                                                                                                                                                                                              |
| `numericScale`           | int32            | **yes**  | none                                                                                                                                                                                                                              |
| `partOfIndex`            | bool             | no       | required                                                                                                                                                                                                                          |
| `autoIncrement`          | bool             | no       | required                                                                                                                                                                                                                          |
| `comment`                | string           | **yes**  | none                                                                                                                                                                                                                              |
| `charset`                | string           | **yes**  | none                                                                                                                                                                                                                              |
| `collation`              | string           | **yes**  | none                                                                                                                                                                                                                              |
| `classification`         | `Classification` | **yes**  | none — **always `null` from the proxy**; the control plane overlays it (`spi.go:111-112`: _"Classification is always nil at the proxy; the control plane owns that overlay"_, and `spi.go:167`: _"The proxy never populates it"_) |

**`TableIndexColumn`** — `name: string`, `position: int32`,
`direction: string?`. **`TableIndex`** — `name: string`,
`columns: TableIndexColumn[]`, `unique: bool`, `type: string`.
**`TableRelation`** — `name`, `sourceSchema`, `sourceTable`,
`sourceColumns: string[]`, `targetSchema`, `targetTable`,
`targetColumns: string[]`, `onUpdate: string?`, `onDelete: string?`.
**`TableMetadata`** — `engine: string`, `estimatedRows: int64?`,
`rowFormat: string?`, `onDiskBytes: int64?`, `collation: string?`,
`comment: string?`.

⚠️ **None of the nullable fields carries a Kotlin default.** Under the strict
decoder used for the proxy payload that makes the key **mandatory** (value may
be `null`). Under the HTTP encoder (`explicitNulls = false`) the same fields are
**omitted** when null. Both directions are contract.

### 3.3 Proto types used AS data classes

`engine/build.gradle.kts:19-21` records the decision, quoted: _"The gRPC wire
types are used AS the data classes across the engine and control plane (proto
types are safe beyond the gRPC boundary): ColumnMask is proto ColumnMask, so
masking speaks proto directly."_ So `bindMasks` takes `List<ColumnMask>` and
`Analyzer` holds `Namespace`/`ColumnSpec`/`EngineConfig`/`StatementFacts` —
there is **no** hand-written mirror type to port. The relevant proto shapes:

`ColumnMask` (`proto/src/main/proto/controlplane.proto:207-216`):
`column: string = 1`, `mask_fn: string = 2`, `kind: string = 3`,
**`optional int32 ordinal = 4`**. The `optional` is load-bearing and its reason
is in the proto, quoted: _"`optional` gives explicit presence so an absent
ordinal is distinguishable from a legitimate 0. Without it, proto3's
implicit-zero default would silently bind a malformed/omitted mask to result
column 0 — masking the wrong column and leaking the intended one."_ (INV-A13-7.)

`Namespace` (`analyzer.proto:42-49`): `catalog: string = 1`,
`repeated string search_path = 2`; fields 3 and 4 **reserved**
(`mysql_lower_case_table_names`, `mysql_version_id` moved to `EngineConfig`).
`ColumnSpec` (`analyzer.proto:32-37`): `catalog = 1`,
`RelationIdentity identity = 2`, `data_type = 3`, `bool pii = 4`.
`RelationIdentity` (`:23-27`): `schema`, `table`, `column`. `EngineConfig`
(`analyzer.proto:56-72`): `Engine engine = 1`, `engine_version: string = 2`,
`optional int32 mysql_lower_case_table_names = 3`,
`optional bool mysql_ansi_quotes = 4`. **Two of the four carry reasons the
engine passes through and must not lose** (quoted from `analyzer.proto`):

- `engine_version` (`:58-61`) — _"Required and validated for MySQL: analysis
  fails closed at **VALIDATE** without a parseable version. PostgreSQL carries
  the value for the wire contract but does not currently use it during
  analysis."_ So `failedStage = "VALIDATE"` is an **already-live production
  signal from the probe**, distinct from a call failure — which constrains §7
  Q2's answer (see F33).
- `mysql_ansi_quotes` (`:66-71`) — _"Whether the backend's live MySQL session
  `sql_mode` has ANSI_QUOTES active. When true the analyzer builds the MySQL
  dialect with the `mysql_ansi_quotes` tokenizer state, so `"col"` parses as a
  quoted IDENTIFIER (a masked column read) rather than a string literal —
  matching the server, **so a masked column quoted with `"` is still masked
  instead of leaking cleartext**. `sql_mode` is mutable per session, so this is
  observed and forwarded **per statement**."_ See INV-A13-34.
- The proto also records why `EngineConfig` exists as a message at all
  (`:52-55`): _"Every engine-specific analysis setting, grouped so the analyzer
  builds its sqlglot-go Dialect once from one input … The caller (control-plane)
  forwards this as-is from what the proxy already reported at introspection
  time; **it does not re-derive or re-parse any of these values itself**."_ A Go
  control-plane must keep that division — no version parsing, no case-mode
  inference of its own.

`AnalyzeRequest` (`analyzer.proto:74-83`): `sql = 1`, `namespace = 3`,
`repeated catalog = 4`, `engine_config = 6`; fields 2 (`dialect`) and 5
(`engine_version`) reserved. `ColumnSpec`'s flatness is also a recorded decision
(`analyzer.proto:29-31`): _"flat (no nested tree) — Go builds its own
`schema.Mapping` tree from the flat list; the Kotlin caller already holds a flat
`List<ColumnSpec>` natively (`CatalogApi.kt`), so this needs no tree-walking
encoder or decoder on either side."_ The Go half is `schemaMappingFromProto`
(`analyzer/probe/wire.go:83`); keep the flat contract.

---

## 4. Symbols

Invariants are inlined next to the symbol they govern, so their numbers are
**not** in reading order. Index:

| Invariant  | Governs                                                                                                          | §   | 🔒  |
| ---------- | ---------------------------------------------------------------------------------------------------------------- | --- | --- |
| INV-A13-1  | `Masking.apply` returns null iff value is null or kind is `NULL`                                                 | 4.1 | 🔒  |
| INV-A13-2  | unrecognized kind masks fully                                                                                    | 4.1 | 🔒  |
| INV-A13-3  | `LAST_N` on ≤4 units reveals nothing                                                                             | 4.1 | 🔒  |
| INV-A13-4  | `FORMAT_PRESERVING` is UTF-16-code-unit-wise, JDK letter/digit semantics                                         | 4.1 |     |
| INV-A13-5  | control-plane and wire masking must produce identical output                                                     | 4.1 | 🔒  |
| INV-A13-6  | `bindMasks` binds by ordinal, never by name                                                                      | 4.1 | 🔒  |
| INV-A13-7  | absent ordinal never binds                                                                                       | 4.1 | 🔒  |
| INV-A13-8  | out-of-range ordinal is unbound; caller fails closed                                                             | 4.1 | 🔒  |
| INV-A13-9  | duplicate ordinal: first wins, loser not reported unbound                                                        | 4.1 |     |
| INV-A13-10 | `normalizeSql` returns null on every failure                                                                     | 4.2 | 🔒  |
| INV-A13-11 | raw lexeme spellings preserved byte-exactly                                                                      | 4.2 |     |
| INV-A13-12 | `sqlGrantHash` is 64 lowercase hex chars or null                                                                 | 4.2 |     |
| INV-A13-13 | the analyzer key must be injective; a collision is a hard failure                                                | 4.3 | 🔒  |
| INV-A13-14 | no SQL pre-cleaning before `analyze`                                                                             | 4.3 |     |
| INV-A13-15 | `SqlglotProbe.analyze` never throws                                                                              | 4.3 | 🔒  |
| INV-A13-16 | `columnKeys[i]` corresponds to input column _i_                                                                  | 4.3 |     |
| INV-A13-17 | the request snapshot is fixed per `Analyzer`; only `sql` varies                                                  | 4.3 |     |
| INV-A13-18 | enum declaration order IS the strength order                                                                     | 4.4 | 🔒  |
| INV-A13-19 | any manifest problem aborts startup                                                                              | 4.4 | 🔒  |
| INV-A13-20 | wildcard schema `"*"` is function-rule-only                                                                      | 4.4 | 🔒  |
| INV-A13-21 | reject a manifest that merely looks like it relies on ordering                                                   | 4.4 | 🔒  |
| INV-A13-22 | `classifyRelation`: null outside a system schema, `CATALOG` floor inside                                         | 4.4 | 🔒  |
| INV-A13-23 | `classifyBareFunction` never adds the `CATALOG` default                                                          | 4.4 | 🔒  |
| INV-A13-24 | a cross-schema function rule applies in any schema                                                               | 4.4 | 🔒  |
| INV-A13-25 | matching is case-insensitive and scoped to manifest schemas                                                      | 4.4 | 🔒  |
| INV-A13-26 | `catalog: "*"` matches any; a pinned catalog must match                                                          | 4.4 |     |
| INV-A13-27 | fallback off + uncertified major ⇒ null (system schemas unavailable)                                             | 4.4 | 🔒  |
| INV-A13-28 | nearest-series rule; never crosses engines                                                                       | 4.4 |     |
| INV-A13-29 | the no-manifest function floor is derived, never hand-listed                                                     | 4.4 | 🔒  |
| INV-A13-30 | checksum is over `BUNDLED.sorted()` and over raw file text                                                       | 4.4 |     |
| INV-A13-31 | `BaselineDangerousFunctions` is a floor that never lowers, never classifies a safe name                          | 4.4 | 🔒  |
| INV-A13-32 | HTTP encode omits nulls but emits empty lists; the proxy decode is strict                                        | 3.0 | 🔒  |
| INV-A13-33 | no normalization or case folding happens in `CatalogApi`                                                         | 4.3 |     |
| INV-A13-34 | an `Analyzer` is per-STATEMENT, never cached per datasource (`mysql_ansi_quotes` is a per-statement observation) | 4.3 | 🔒  |
| INV-A13-35 | duplicate-key manifest rules must be REJECTED, not last-wins                                                     | 4.4 | 🔒  |

### 4.1 Masking — `probe/Masking.kt`, `probe/Masks.kt`

#### `object Masking` · object

Kotlin: `fun apply(value: String?, kind: String): String?`

**Contract:** total. Never throws. Returns the masked rendering of an
already-stringified cell value, or `null` for a full redaction.

**Behavior** (in evaluation order — `Masking.kt:11-21`):

1. `value == null` ⇒ `null`.
2. `kind == "NULL"` ⇒ `null`.
3. `kind == "FIXED"` ⇒ `"####"` (literal, four hashes, independent of input
   length).
4. `kind == "LAST_N"` ⇒ `n = 4`. If `value.length <= 4` ⇒
   `"*".repeat(value.length)` (a short value is **fully** masked; nothing is
   revealed). Else `"*".repeat(value.length - 4) + value.takeLast(4)`.
   `length`/`takeLast` are **UTF-16 code units**.
5. `kind == "FORMAT_PRESERVING"` ⇒ per `Char`: letter-or-digit ⇒ `'*'`,
   everything else kept verbatim.
6. **Any other `kind`** ⇒ `"****"`.

**The complete `kind` vocabulary** (A7's INV-A7-15 depends on knowing it
exactly):

| `kind`              | Result for non-null input              | Source of truth              |
| ------------------- | -------------------------------------- | ---------------------------- |
| `NULL`              | **`null`** — full redaction            | `V2__catalog.sql:70` comment |
| `FIXED`             | `"####"`                               | ditto                        |
| `LAST_N`            | last 4 units visible                   | ditto                        |
| `FORMAT_PRESERVING` | alphanumerics starred, separators kept | ditto                        |
| _anything else_     | `"****"`                               | the `else` branch            |

⚠️ `mask_fn.kind` is a **bare `TEXT` column with no `CHECK` constraint** —
`V2__catalog.sql:67-71` documents the four values in a comment only. An admin
creating a mask fn through `POST /api/mask-fns` (A9 `Policies.kt:214`) can store
any string, so the `else` branch is **reachable in production, not defensive**.
A6 compounds this: its mask-binding loop uses `kind = maskKinds[fn] ?: "FIXED"`
(A6 §"Mask binding loop"), so a _missing_ mask-fn row also yields a real
transform rather than an error.

🔒 **INV-A13-1 — `apply` returns `null` for exactly two inputs: a null value,
and kind `NULL`.** Therefore a caller must branch on the **kind**, never on the
result. A7's view path does this and states why (`Approvals.kt:244-248`, and
INV-A7-15): collapsing it to `Masking.apply(value, kind) ?: value` would fall a
`NULL`-redacted cell back to the **cleartext value**. That is the whole reason
the null-check is on `kind`. The same pattern is duplicated in the test harness
(`support/EnforcementHarness.kt:156-161`) with the same comment — so a port that
"fixes" one must fix both.

🔒 **INV-A13-2 — an unrecognized kind masks fully (`"****"`), never passes
cleartext through.** Fail-closed on an unknown mask kind: given the
unconstrained `mask_fn.kind` column, the alternative is a typo in an admin form
silently disabling a mask.

🔒 **INV-A13-3 — `LAST_N` on a value of ≤ 4 units reveals nothing.** Without the
guard, `"*".repeat(len - 4)` would be `"*".repeat(negative)` (a Kotlin
exception) or, worse, a rewrite that emitted the whole short value. Short PII (a
4-digit PIN, a 2-character name) is exactly the case where revealing "the last
four" is revealing everything.

**INV-A13-4 — `FORMAT_PRESERVING` is defined on UTF-16 code units with JDK
`Character.isLetterOrDigit(char)` semantics.** Consequence, deliberate and
pinned by `masking_test.go:30`: a **supplementary** letter (e.g. U+10400
DESERET) arrives as two surrogate halves, neither of which is a letter, so it
passes through **unmasked**. Over-revealing in an exotic case, accepted, and
_observable_ — do not "fix" it silently.

🔒 **INV-A13-5 — the control-plane and wire implementations must produce
identical output for the same `(value, kind)`.** The same stored cell is
rendered by the proxy on the live path and by the control plane on the
stored-result view path (A7). A divergence means the same task shows different
values depending on how it is read — and the wire path is the one whose output
was never persisted, so the discrepancy is unreconstructable after the fact.

**Deps:** none (pure). **Go shape:**
`func applyMaskKind(value *string, kind string) *string` already exists — import
it. If it must be re-derived: a nullable-string-in/nullable-string-out pure
function over UTF-16 code units. `⟦LIB⟧` UTF-16 code-unit string operations
(JVM-parity `length`/`takeLast`/per-`Char` mapping).

#### `data class MaskBinding` · data class

Kotlin:
`data class MaskBinding(val byIndex: Map<Int, String>, val unbound: List<ColumnMask>)`
with `val allBound: Boolean get() = unbound.isEmpty()`

**Contract:** `byIndex` maps a **result-set column index** to the mask `kind` to
apply there. `unbound` holds every input mask that could not be placed.
`allBound` is the caller's fail-closed test.

#### `fun bindMasks(masks: List<ColumnMask>, resultColumnCount: Int): MaskBinding` · top-level fn

**Behavior** (`Masks.kt:18-26`):

1. `byIndex = LinkedHashMap()`, `unbound = ArrayList()`.
2. For each mask `m`, in input order: if
   `m.hasOrdinal() && m.ordinal in 0 until resultColumnCount` then
   `byIndex.putIfAbsent(m.ordinal, m.kind)`; **else** `unbound += m`.
3. Return `MaskBinding(byIndex, unbound)`.

🔒 **INV-A13-6 — binding is BY OUTPUT POSITION, never by column name.** The
source states the reason (`Masks.kt:11-13`), quoted: *"Position is immune to
alias/case/EXPR$0 name mismatch — **name binding was the
fail-open bug**."* A Go port that reintroduces a name lookup reintroduces a known leak. `BindMasksTest` case 2
(`name is ignored`) exists solely to pin it — it passes `column = "EXPR$0"`,
a name that can never match a catalog column.

🔒 **INV-A13-7 — an ABSENT ordinal never binds; it is reported unbound.**
`hasOrdinal()` is checked _before_ the range test, because proto3's implicit
zero would otherwise place a malformed or omitted mask on **result column 0** —
masking a column that needed no mask and leaving the intended one cleartext.
Both suites pin it (`BindMasksTest` case 4, `masking_test.go` "absent ordinal is
unbound"). ⚠️ **In Go this is the single easiest mistake in the whole area**:
`mask.GetOrdinal()` returns `0` for `nil`. `masking.go:13-14` warns in so many
words: _"do NOT use GetOrdinal(), which returns 0 for nil and would silently
bind a malformed/omitted mask to result column 0."_

🔒 **INV-A13-8 — an out-of-range ordinal is reported unbound, and the caller
MUST fail closed.** The contract is stated in `Masks.kt:13-14`: _"Any mask whose
ordinal is out of range of the live result set is reported as unbound so callers
can fail closed (**"every required mask must bind, else DENY"**)."_ Both
consumers honour it — A7's view gate 7 (`!allBound` ⇒
`"required view mask could not be bound"`), and the proxy's `NewRowMasker`
returning `nil` (`engine.go:179-186`: _"a mask the proxy cannot bind means the
intended column would otherwise reach the client unmasked"_). `bindMasks` itself
denies nothing; it only reports.

**INV-A13-9 — duplicate ordinals: FIRST wins, and the loser is NOT reported
unbound.** `putIfAbsent` keeps the earliest mask for an ordinal and the later
one is silently dropped — it is neither applied nor surfaced in `unbound`, so
`allBound` stays true. Consistent with A6, whose mask-binding loop is itself
first-wins (`masks.none { it.ordinal == ordinal }`), so a duplicate should never
reach here in practice. ⚠️ **Untested on the Kotlin side**; the Go twin does
test it (`masking_test.go` "first duplicate ordinal wins"). §6 gap.

**Deps:** proto `ColumnMask`. **Go shape:** `engine.BindMasks` already exists —
import it.

### 4.2 SQL normalization — `probe/SqlNormalize.kt`, `probe/Dialect.kt`

> ⚠️ **F21 — this whole sub-area is production-dead.** Verified this session:
> `grep -rn 'sqlGrantHash\|normalizeSql' --include='*.kt'` across the repo
> returns **only** the definitions in `SqlNormalize.kt` and the calls in
> `engine/src/test/.../SqlNormalizeTest.kt`. No control-plane, goproxy, pmon or
> auditmon caller exists. The only production reference to `Dialect` is
> `val dialect = ds.engine.dialect` at `Query.kt:308`, **an unused local**
> (`grep -n dialect Query.kt` → that line only); its only effect is the
> `error("engine has no dialect: …")` throw in `Engines.kt:46` for a
> non-MySQL/Postgres engine. And the `sql_hash` actually persisted is a **raw
> SHA-256 of the SQL bytes** (`Access.kt:127-129` and `190-192`:
> `MessageDigest.getInstance("SHA-256").digest(sql.toByteArray(UTF_8))`), stored
> on `query_result` for durable audit and web preview
> (`QueryResultStore.kt:224`) and **never compared to anything**. So the
> canonical-token grant hash the file's own doc comment describes is not wired
> to any grant decision. **24 of this area's 56 test cases (43%) pin behaviour
> nothing consumes.**

#### `enum class Dialect { MYSQL, POSTGRES }` · enum

Kotlin: `Dialect.kt:3`. Two values, no properties. Mapped from `Engine` by
`Engines.kt:42-47` (A5), which `error(...)`s for `ENGINE_UNSPECIFIED`.

#### `fun normalizeSql(sql: String, dialect: Dialect): String?` · top-level fn

1. Map `MYSQL -> "mysql"`, `POSTGRES -> "postgres"`.
2. `Sqlglot.sqlNormalize(sql, dialectName)` (FFM → `probe.SqlNormalize`).
3. `catch (_: Throwable) -> null`.

**Contract** (`SqlNormalize.kt:8-16`, quoted): _"token-sequence equality with
byte-exact literals: equivalent statements may differ only in canonical
whitespace, comments, keyword case, and dialect-safe identifier case. Material
differences in tables, columns, operators, literals, numbers, or quoted
identifiers must remain distinct. … Invalid or unsupported input and every
native load, descriptor, encoding, or invocation failure return null so grant
decisions fail closed."_

🔒 **INV-A13-10 — every failure yields `null`, never a partially-normalized
string.** A salvaged canonicalization of unlexable input would let two
materially different statements hash equal, which on a grant-matching path is a
wrong-grant. Fail-closed = `null` = the caller refuses.

**INV-A13-11 — raw lexeme spellings are preserved byte-exactly.** The Go
implementation selects raw lexemes from the source
(`analyzer/probe/sqlnormalize.go:36-45` slices the original runes between
tokens), so decoded-equivalent literals stay distinct: `'a\'b'` ≠ `'a''b'`,
`E'a\nb'` ≠ `E'a\012b'`, `1` ≠ `01`, `0xAB` ≠ `0xab`, `"Name"` ≠ `"name"`.
`SqlNormalizeTest` case 19 is the whole matrix.

**Whose behaviour is this, actually?** Almost none of it is Kotlin's. The Kotlin
file is 34 lines of dialect string mapping + `try/catch` + SHA-256; every
assertion in the 24-case suite is a property of
`analyzer/probe/sqlnormalize.go`, which already has its own Go suite
(`analyzer/probe/sqlnormalize_test.go`). So the _port_ of this file is trivial;
the _test migration_ should check for duplication against the existing Go suite
rather than transcribing 24 cases twice.

#### `fun sqlGrantHash(sql: String, dialect: Dialect): String?` · top-level fn

`normalizeSql(...) ?: return null`, then SHA-256 of the UTF-8 bytes, hex-encoded
with `"%02x"`.

**INV-A13-12 — the hash is exactly 64 lowercase hex characters, or null.**
`SqlNormalizeTest` case 24 pins the shape; `null` propagates from `normalizeSql`
unchanged (never an empty string, never a hash of `""`).

**Go shape:** `probe.SqlNormalize(sql, dialect)` returns `(string, bool)`; `!ok`
⇒ null. Then `hex.EncodeToString(sha256.Sum256([]byte(norm))[:])` — note `%02x`
and Go's hex encoder both emit lowercase, so they agree. `⟦LIB⟧` none (SHA-256
is stdlib on both sides). **Disposition DEFER (F21, index F79) — resolve it
before porting, and do not resolve it inside the port.** The sub-area is
production-dead but its 260 LOC of test are live, so it is not an OMIT case on
its own; only an explicit "the one-time query grant is not being built" turns
dropping the file _and_ its suite into a legitimate OMIT. Until then it is
REPRODUCE, test surface included.

### 4.3 Analyzer facade — `probe/CatalogApi.kt`, `probe/Sqlglot.kt`

#### `object SqlglotProbe` · object

Kotlin:
`fun analyze(sql: String, namespace: PbNamespace, catalog: List<PbColumnSpec>, engineConfig: PbEngineConfig): StatementFacts`

**Behavior** (`Sqlglot.kt:34-51`):

1. Build
   `AnalyzeRequest { sql; namespace; catalog.addAll(catalog); engineConfig }`.
2. `StatementFacts.parseFrom(Sqlglot.analyzeStatement(request.toByteArray()))`.
3. `catch (e: Throwable)` ⇒
   `StatementFacts { resolved = false; failureClass = FAILURE_CLASS_UNANALYZABLE; failedStage = "LINEAGE"; detail = (e.message ?: e.javaClass.simpleName).take(150); statementClass = STATEMENT_CLASS_UNSPECIFIED }`.

🔒 **INV-A13-15 — `analyze` never throws; it always returns `StatementFacts`.**
The reason is in the file header (`Sqlglot.kt:22-24`), quoted: _"any
binding/parse error here also surfaces as an unresolved StatementFacts (→ DENY),
**never an escaped exception (which would bypass the decision/audit
contract)**."_ An exception escaping into A6's decision path would skip the
audit write for a statement that was in fact examined.

⚠️ **F28 — but "DENY" in that comment is not quite what happens.**
`FAILURE_CLASS_UNANALYZABLE` is the class A6 step 16 routes to Cedar
`sql.unanalyzable`: _"`failureClass != UNANALYZABLE` ⇒ `structuralDeny`. Else …
then Cedar `sql.unanalyzable`: Allow ⇒ ALLOW passthrough."_ So on a datasource
that permits the unanalyzable relay (a dev datasource with the shipped
`system:development` posture — see A2 INV-A2-1), **an FFM or protobuf failure
becomes a passthrough**, not a deny. Nothing in the failure class distinguishes
_"the analyzer says it cannot reason about this statement"_ from _"the analyzer
did not run"_. Deliberate per `AGENTS.md:136-139` ("fail-closed through Cedar,
not a hardcoded deny"), and moot in a Go port where the call is in-process — but
the Go port still has an error return from `probe.AnalyzeStatement` and must
decide the same question.

Two smaller fidelity details in the same branch: `.take(150)` truncates to 150
**UTF-16 code units** where `analyzer/probe/probe.go:652-658 truncateDetail`
truncates to 150 **runes**; and `detail` reaches `DecisionContext.detail` and
thus the wire as raw English exception text — which strengthens **F13**
(unlocalized deny prose).

**Two division-of-labour rules the `analyze` KDoc states and this doc previously
lost** (`Sqlglot.kt:30-33`, quoted; finding **F33**):

- _"**Go owns all engine-specific validation from `engineConfig` alone** (e.g.
  failing MySQL analysis closed without a parseable version)."_ The control
  plane must not pre-validate the engine version, the case mode, or the quoting
  mode before calling; the probe is the single place that decides those, and it
  fails closed at stage **`VALIDATE`** (`analyzer.proto:58-61`). Consequence for
  §7 Q2: `"VALIDATE"` is **already taken** by a real, distinguishable production
  condition, so labelling a _call/transport_ error `"VALIDATE"` in the Go port
  would merge two different faults into one `failed_stage` value. `"LINEAGE"`
  (what the Kotlin wrapper used) or a third label keeps them apart.
- _"Analyzer output identities are always `catalog.schema.table.column`."_ That
  is the same four-part rendering `validateUniqueness`/`columnKey` produce, and
  the reason the two must agree exactly (INV-A13-16, INV-A13-33): A6 joins facts
  back to catalog rows by that string.

**Deps:** `analyzer/jvm` FFM binding. **Go shape:** deleted; call
`probe.AnalyzeStatement` and map its `error` to the same fail-closed facts,
choosing `failedStage` deliberately (§7 Q2).

#### `class Analyzer` · class

Kotlin:
`class Analyzer internal constructor(internal val namespaceProto: Namespace, internal val catalogProto: List<ColumnSpec>, internal val engineConfigProto: EngineConfig, val piiColumns: Set<String>, val columnKeys: List<String>)`
· `fun analyze(sql: String): StatementFacts`

**Contract:** a validated, immutable per-request snapshot bound to one
datasource state. The constructor is `internal`, so outside the module only
`analyzerFor` can produce one.

**INV-A13-17 — the request snapshot is fixed for the lifetime of an `Analyzer`;
only `sql` varies per call.** Stated at `CatalogApi.kt:26-28`: _"held once and
reused by every `analyze` call (only `sql` varies per call; the engine
identity/version/settings never change mid-request)."_ The native probe is pure,
so an `Analyzer` is cheap to build per request — there is nothing to pool or
warm.

🔒 **INV-A13-34 — the scope of "fixed" is ONE STATEMENT, not one datasource: an
`Analyzer` must never be cached across statements.** "The engine settings never
change mid-request" is true only _within_ a request.
`EngineConfig.mysql_ansi_quotes` is a live per-session observation —
`analyzer.proto:70-71`: _"`sql_mode` is mutable per session, so this is observed
and forwarded per statement"_ — and A6 rebuilds the whole config from the live
value on every decision (`Query.kt:322-329`,
`if (liveAnsiQuotes) this.mysqlAnsiQuotes = true`, then `analyzerFor(...)` at
`Query.kt:343`). A Go port that memoizes an `Analyzer` per datasource (the
obvious "optimization", and cheap-looking because construction is pure) would
freeze a stale `ansi_quotes` and, when the client turns ANSI_QUOTES on
mid-session, parse `"masked_col"` as a **string literal instead of a column
read** — the masked column then leaks cleartext. The catalog snapshot has the
same problem in the other direction (a stale catalog misses a newly classified
column). Rebuild per statement; the invariant that makes that affordable is the
probe's purity, not a cache.

**INV-A13-14 — do NOT pre-clean the SQL before `analyze`.**
`CatalogApi.kt:41-43`, quoted: _"sqlglot parses a trailing terminator ';',
surrounding whitespace, and a ';' inside a string literal on its own, and
fail-closes a genuine multi-statement (>1 parsed statement) — so no pre-cleaning
is needed here."_ A port that strips trailing semicolons or trims whitespace "to
help" would, for the multi-statement case, help an attacker: the fail-close on
`>1` statement is the admission guard (`AnalyzerTest` case 3 pins
`select 1; select 2` ⇒ `FAILURE_CLASS_INADMISSIBLE`).

**`columnKeys`** — every input column's rendered key, in input order. Exposed so
callers needing a key per catalog row reuse construction's work rather than
walking the catalog twice (`CatalogApi.kt:30-32`); A6 consumes it at
`Query.kt:218-222` under a `require(catalog.size == analyzer.columnKeys.size)`.

**INV-A13-16 — `columnKeys[i]` corresponds to the _i_-th element of the list
passed to `analyzerFor`,** and equals what `columnKey` would render for it. A6's
index build zips the two lists positionally, so any reordering or filtering
breaks the catalog index silently.

⚠️ **`piiColumns` has no production consumer** — only `AnalyzerTest:46` reads it
(finding **F23**). Worse, the word means something different here than in A6:
`ColumnSpec.pii` is set from `col.classification != null` (`Query.kt:340`), i.e.
_"has any classification"_, while A6 step 28 computes the real PII set from
`classification.tags.contains("pii")` (`Query.kt:675`). Two meanings of "pii"
one function apart. (`piiColumns` is a `LinkedHashSet` built with
`mapTo(linkedSetOf())`, so it is insertion-ordered. **REPRODUCE (F23, index
F83)** — `AnalyzerTest:46` reads it, so this is a live _test_ fixture, not dead
code, and it is outside the OMIT boundary: Go needs an insertion-ordered,
test-visible equivalent, not a `map[string]struct{}`. The two colliding meanings
of "pii" are reproduced along with it; reconciling them is a separate decision,
not a port task.)

#### `fun analyzerFor(namespace: Namespace, columns: List<ColumnSpec>, engineConfig: EngineConfig): Analyzer` · top-level fn

1. `validateNamespace(namespace)`.
2. `renderedKeys = validateUniqueness(columns)` — throws
   `IllegalArgumentException` on any violation.
3. `piiColumns = columns.indices.filter { columns[it].pii }.mapTo(linkedSetOf()) { renderedKeys[it] }`.
4. Construct the `Analyzer`.

**Contract:** throws `IllegalArgumentException` (from `require`) rather than
returning a partial analyzer. A6 wraps the whole construction in
`try/catch (e: Exception)` and converts it to
`structuralDeny("$CATALOG_CONFIGURATION_DENY: ${e.message ?: e.javaClass.simpleName}", emptyList(), failedStage = "catalog").copy(catalogMiss = true)`
(`Query.kt:345-351` — note the message falls back to the **exception class
name** when `message` is null, and `catalogMiss` is set by `.copy`, not a
constructor argument) — so **the exception messages below are wire-visible deny
prose** carrying catalog identities. That is F13 territory and, separately, mild
structure disclosure; `sanitizeDiagnostics` (A6 step 31) redacts _backend_
diagnostics, not `denyReason`.

#### `private data class SchemaIdentity` / `TableIdentity` / `ColumnIdentity` · private data classes

Kotlin (`CatalogApi.kt:63-65`):
`SchemaIdentity(catalog: String, schema: String)` ·
`TableIdentity(schema: SchemaIdentity, table: String)` ·
`ColumnIdentity(table: TableIdentity, column: String)` — a nested triple, not a
flat one.

**Contract:** these three carry the _structural_ identity the collision checks
compare, as distinct from the dot-joined rendered key. Data-class `equals` gives
component-wise equality over the **unjoined** parts, which is exactly what makes
INV-A13-13 detectable: `("a.b","c","t","x")` and `("a","b.c","t","x")` render to
the identical key `a.b.c.t.x` but are _different_ `ColumnIdentity` values, so
`putIfAbsent` returns a non-equal previous value and the `require` fails. A Go
port that keys the collision maps on the joined string alone **cannot implement
INV-A13-13 at all** — it needs both the rendered key and the structured
identity.

⚠️ **Their `toString()` is wire-visible.** The two collision messages
interpolate the _data classes_, not the key, so the emitted prose is e.g.
`catalog table identities render to the same analyzer key 'a.b.c': TableIdentity(schema=SchemaIdentity(catalog=a, schema=b), table=c) and TableIdentity(schema=SchemaIdentity(catalog=a.b, schema=c), table=c)`
— Kotlin data-class rendering, reaching `denyReason` through A6's catch. A Go
port must pick a rendering deliberately (F13 again); byte-comparable deny prose
across the port is not achievable here without replicating Kotlin's `data class`
`toString` format on purpose.

#### `private fun validateNamespace(namespace: Namespace)`

`require(catalog.isNotBlank())` → `"analyzer namespace catalog is required"`;
`require(searchPathList.isNotEmpty())` →
`"analyzer namespace searchPath is required"`; each entry
`require(isNotBlank())` →
`"analyzer namespace searchPath entries are required"`.

#### `private fun validateColumn(column: ColumnSpec)`

Five `require`s, each with its own message: `catalog`, `identity.schema`,
`identity.table`, `identity.column`, **and `dataType`** must all be non-blank →
`"column catalog is required"` / `"column schema is required"` /
`"column table is required"` / `"column name is required"` /
`"column sqlType is required"`. Note the last message says `sqlType` (the
control-plane's field name) while the proto field is `data_type`.

#### `private fun validateUniqueness(columns: List<ColumnSpec>): List<String>`

Per column, in order:

1. `validateColumn(column)`.
2. Render the table key `"$catalog.$schema.$table"`;
   `renderedTables.putIfAbsent(renderedTable, table)`;
   `require(previous == null || previous == table)` →
   `"catalog table identities render to the same analyzer key '<key>': <a> and <b>"`.
3. `require(seenColumns.add(columnIdentity))` →
   `"catalog contains duplicate column identity: <rendered>"`.
4. `renderedColumns.putIfAbsent(rendered, columnIdentity)`;
   `require(previous == null || previous == columnIdentity)` →
   `"catalog column identities render to the same analyzer key '<rendered>': <a> and <b>"`.
5. Append `rendered` to the returned list.

🔒 **INV-A13-13 — the analyzer key must be INJECTIVE, and a collision is a hard
failure, not a warning.** The reason is spelled out at `CatalogApi.kt:81-87`,
quoted: _"Every column's identity already arrives canonical (goproxy normalizes
at introspection), so there is nothing here to fold … only two genuine risks
remain: an exact duplicate (schema, table, column) triple, and two DIFFERENT
identities whose dot-joined key happens to render identically (a dot embedded in
a raw identifier, e.g. catalog "a.b" + schema "c" vs. catalog "a" + schema
"b.c", both -> "a.b.c")."_ This is the **same delimiter-collision class as A2's
INV-A2-6** — `.` is legal inside a quoted SQL identifier, so without the guard
two distinct columns share one analyzer key and one column's grants apply to the
other. A2 guards it at the Cedar EUID; this guards it at the analyzer key.
**Both are required; neither substitutes for the other.**

**INV-A13-33 — no normalization or case folding happens here.**
`CatalogApi.kt:11-15`, quoted: _"goproxy normalizes every catalog column (its
bulk introspection push AND the per-connection schema-fragment refetch path both
call `analyzer/probe.NormalizeRelation` directly, in-process) before it ever
reaches the control plane. No normalization decision is made here — this is pure
concatenation of already-canonical parts."_ A Go port must not add folding: two
normalization sites disagreeing is how a masked column stops matching its
catalog row.

**Go shape:** a constructor returning `(*Analyzer, error)` over a flat
`[]*pb.ColumnSpec`; three ordered maps (`renderedTable → tableIdentity`,
`columnIdentity → seen`, `renderedColumn → columnIdentity`) plus the
rendered-key slice. Errors are _strings on the wire_ (see above), so preserve
the message text if A6's deny reasons are to stay comparable across the port.
`⟦LIB⟧` a protobuf runtime + generated Go stubs for
`analyzer.proto`/`controlplane.proto` — implied by §3.3 (the proto messages
_are_ this area's data classes, so there is no way to port it without one). Not
an open choice in practice: `goproxy` already generates Go stubs and
`00-INDEX.md:31` records `proto/`'s Kotlin codegen as _delete — replaced by buf
→ Go stubs_; the marker is here so the capability is not silently assumed.

#### `fun columnKey(namespace: Namespace, column: ColumnSpec): String` · top-level fn

Validates the namespace, validates the column, returns
`"${column.catalog}.${schema}.${table}.${column}"`.

⚠️ **F22 (index F82) — dead: OMIT.** No caller anywhere in the repo, main _or_
test (verified: `grep -rn 'columnKey('` matches only the definition and doc
references), so there is no observable behaviour and no test fixture to preserve
— unlike F23's `piiColumns` one section up. Its `namespace` parameter is
validated but contributes **nothing** to the returned key — the key is built
entirely from `column`. The rendering rule itself is **REPRODUCE**, and it
already lives in `validateUniqueness`; only the unreachable entry point is left
out.

### 4.4 System classification — `classification/`

#### `enum class SystemTag(val id: String)` · enum

`CRITICAL("system:critical")`, `DATA_LEAK("system:data-leak")`,
`ACTIVITY("system:activity")`, `CATALOG("system:catalog")` — **declared
strongest-first**. `companion`: `fun fromId(id: String): SystemTag?` (map
lookup, null for anything else);
`fun stronger(a, b): SystemTag = if (a.ordinal <= b.ordinal) a else b`.

🔒 **INV-A13-18 — the declaration order IS the strength order, and `ordinal` is
the comparison.** Reordering the enum silently inverts every precedence decision
and every boot validation. The reason for strongest-wins is at
`SystemManifest.kt:11-13`, quoted: _"when several rules match one object it
takes the STRONGEST tag, so a weaker exact rule can never downgrade a stronger
family rule. Over-classifying is safe; **under-classifying a credential/data
surface is the leak this guards**."_

**Go shape:** an `int`-backed enum with the same order plus an explicit
`strength` accessor, **not** a string comparison — and `fromId` returning
`(tag, ok)`. `⟦LIB⟧` none.

#### `class SystemManifestException(message: String) : Exception(message)` · class

`SystemClassifier.kt:4`, doc: _"A manifest that fails boot validation … —
fail-closed, aborts startup."_

#### `class SystemClassifier(val manifest: SystemManifest)` · class

**Contract:** classifies an _already schema-resolved_ `(catalog, schema, name)`
identity into exactly one `SystemTag`, or `null`. **Validates the manifest in
`init` and throws `SystemManifestException` on any violation.** Owns manifest
lookup only, never namespace resolution (`SystemClassifier.kt:12-14`).

**Compiled state** (all built in property initializers, i.e. _before_
`validate()` runs):

| Field                                                          | Built from                                                       | Key                                         |
| -------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------- |
| `systemSchemas: Set<String>`                                   | `manifest.systemSchemas.map { fold(it.schema) }`                 | folded schema                               |
| `logicalSchemas: Set<String>`                                  | `manifest.logicalFunctionSchemas.map { fold(it.schema) }`        | folded schema — ⚠️ **catalog dropped**, F30 |
| `relationExact: Map<Pair<String,String>, SystemTag>`           | `exactMap(manifest.relations, "relation")`                       | (folded schema, folded name)                |
| `functionExact`                                                | `exactMap(manifest.functions, "function")`                       | ditto                                       |
| `relationFamilies: Map<String, List<Pair<String, SystemTag>>>` | `familyMap(manifest.relationFamilies)`                           | folded schema → [(folded prefix, tag)]      |
| `functionFamilies`                                             | `familyMap(manifest.functionFamilies)`                           | ditto; a `"*"` schema keys under `"*"`      |
| `commandTags: Map<String, SystemTag>`                          | `manifest.commands.associate { it.id to requireTag(it.tag, …) }` | **raw `id`, NOT folded**                    |
| `functionAnySchema: Map<String, SystemTag>`                    | `manifest.functions.filter { it.schema == "*" }`                 | folded name                                 |

`private fun fold(s: String) = s.lowercase()` — a **full Kotlin `lowercase()`**,
i.e. locale-independent Unicode lowering, not an ASCII-only fold (despite the
doc's "case-insensitive ASCII fold" wording at `SystemClassifier.kt:11`). §7 Q3.

🔒 **INV-A13-25 — matching is case-insensitive and SCOPED to the manifest's own
schemas.** The reason (`SystemClassifier.kt:11-13`, and
`docs/system-classification.md:226-231`): system schemas and their objects are
conventionally lower-case and matching only happens inside the manifest's
schemas, so _folding cannot catch a user object_. That is what lets a manifest
store the canonical server spelling (`information_schema.USER_PRIVILEGES`) and
still match a lower-cased resolved identity.

⚠️ `commandTags` is keyed by the **raw** command id with no fold, unlike
everything else. Command ids are analyzer-emitted constants
(`SHOW_PROCESSLIST`), so this is consistent in practice — but it is an
inconsistency to replicate exactly, not to "unify".

🔒 **INV-A13-35 — a duplicate manifest rule with a conflicting tag must be
REJECTED, and two of the six compiled tag lookups do not reject it. Finding
F32.** `commandTags` and `functionAnySchema` are built with Kotlin `associate`
(`SystemClassifier.kt:33` and `:35-36`), whose documented behaviour is
_last-pair-wins_ for a repeated key — no conflict check, no strongest-first
combination. So:

- two `commands` entries with the same `id` and different tags load silently,
  and the **later** entry wins even when it is weaker:
  `[{id: SHOW_GRANTS, tag: system:critical}, {id: SHOW_GRANTS, tag: system:catalog}]`
  compiles to `CATALOG`. That is a **silent downgrade of a credential surface**
  — the exact failure mode INV-A13-18 and INV-A13-21 exist to prevent, arriving
  through the one map that has no guard.
- two cross-schema (`schema: "*"`) function rules with the same name and
  different tags behave the same way, and they get **no** duplicate check
  anywhere: `exactMap` explicitly `continue`s on `r.schema == "*"`
  (`SystemClassifier.kt:120`), so `"*"` rules are never keyed there either.

Contrast `exactMap`, which throws on a conflicting duplicate, and `familyMap`,
which appends (so duplicates combine strongest-first at match time and cannot
downgrade). Verified latent, not live-wrong: no shipped manifest has a duplicate
`commands[].id` or a duplicate `"*"` function name (checked all four JSON files
this session). But `docs/system-classification.md:196-203` lists _"duplicate
exact identities with different tags"_ as a boot-rejection class without
excluding commands, and the four-file curation loop is exactly where a
copy-paste duplicate would arrive. **REPRODUCE + PIN (F32, index F37).**
Last-pair-wins is observable at boot — it decides which tag a duplicated
`commands[].id` ends up carrying, and the losing direction silently downgrades a
credential surface — so this sits on a security path: port the `associate`
semantics as-is with a comment naming the finding, and **write the two tests
asserting last-pair-wins**, so a later fix has to change them deliberately.
"Behaviour-neutral for today's manifests" is exactly the argument that expires
the moment a fifth manifest lands; folding both into `exactMap`'s
reject-on-conflict path is the right change, taken separately.

##### `fun classifyRelation(catalog: String, schema: String, name: String): SystemTag?`

1. `if (!isSystemSchema(catalog, schema)) return null`.
2. `tag = CATALOG` (the floor).
3. `relationExact[(s, n)]` ⇒ `stronger`.
4. Every `relationFamilies[s]` entry whose prefix `n.startsWith(prefix)` ⇒
   `stronger`.
5. Return `tag` (never null past step 1).

🔒 **INV-A13-22 — outside an exposed system schema the answer is `null`, and
inside it the floor is `CATALOG`, never `null`.** The two are different signals
to A5/A6: `null` means "not a system object, apply ordinary user
classification"; `CATALOG` means "a system object that is open for browsing".
Collapsing them would either expose `pg_authid` as an ordinary user table or
deny `pg_class` to everyone. `docs/system-classification.md:249-257` records why
a **Column** is not independently defaulted to `system:catalog`: _"Otherwise a
column of `pg_authid` would inherit `system:critical` and carry a direct catalog
permit at once, and disabling or exempting the stronger guard would accidentally
create access without an ordinary grant."_ Relations are classified whole; a
Column inherits through its Cedar `Table` parent (A2).

##### `fun classifyFunction(catalog: String, schema: String, name: String): SystemTag?`

1. `tag = null`.
2. **Cross-schema first:** `functionAnySchema[n]` ⇒ combine; every
   `functionFamilies["*"]` prefix match ⇒ combine. These apply _in any schema_.
3. **If** `isSystemSchema(catalog, schema) || s in logicalSchemas`: combine
   `CATALOG`, then `functionExact[(s, n)]`, then `functionFamilies[s]` prefix
   matches.
4. Return `tag` (null iff nothing matched and the schema is neither system nor
   logical).

`private fun combine(cur: SystemTag?, new: SystemTag) = if (cur == null) new else SystemTag.stronger(cur, new)`.

🔒 **INV-A13-24 — a recognized cross-schema function is classified WHEREVER it
is installed, and over-classifying a same-named user function is accepted.**
`SystemClassifier.kt:58-61` and `66-68`, quoted: _"A recognized cross-schema
function (rule `schema: "*"`, e.g. an extension `dblink`) is classified in ANY
schema — over-classifying a same-named user function is safe (fail-closed)"_ …
_"cross-schema (`schema:"*"`) rules classify a dangerous extension function
wherever it is installed: exacts (e.g. `dblink`) AND families (e.g. pageinspect
`heap_page_`, `bt_page_`)."_ An extension can be installed into any schema, so
scoping the rule to one schema would let `CREATE EXTENSION dblink SCHEMA myapp`
evade the forbid.

##### `fun classifyBareFunction(name: String): SystemTag?`

1. `tag = null`.
2. `functionAnySchema[n]` ⇒ combine; `functionFamilies["*"]` prefix matches ⇒
   combine.
3. **For every schema in `systemSchemas + logicalSchemas`:**
   `functionExact[(s, n)]` ⇒ combine; `functionFamilies[s]` prefix matches ⇒
   combine.
4. Return `tag`. **Never adds the `CATALOG` default.**

🔒 **INV-A13-23 — `classifyBareFunction` must NOT add the `CATALOG` default,
unlike `classifyFunction`.** The reason is the most consequential comment in the
file (`SystemClassifier.kt:81-88`), quoted: _"sqlglot drops a function's schema
qualifier at parse time — `pg_catalog.pg_read_file`, `mysql.rds_kill`, and a
bare `pg_read_file` are indistinguishable post-parse — so the analyzer can only
emit the bare name. We resolve it against the cross-schema (`*`) rules AND every
system/logical schema the manifest governs, taking the strongest tag. **Unlike
`classifyFunction` this never adds the CATALOG default: a bare name that matches
no dangerous rule is an ordinary safe builtin (now/count/lower) and stays
UNCLASSIFIED (null), so the control-plane marshals a Cedar Function only for the
dangerous ones (never a forbid on every projection)**."_

This is the load-bearing half of A2's INV-A2-11 ("`authorizeFunctions`: the
caller passes **only** DANGEROUS-classified functions"). If the port ever
returned `CATALOG` here, every `now()` and `lower()` in every query would be
marshalled as a Cedar `Function` with no permit and deny-by-default would break
every query in the system. The function model is **enumerate-dangerous /
allow-safe** — the exact inverse of the utility model (enumerate-recognized /
deny-unclassified, A2 INV-A2-11 second half).

##### `fun classifyCommand(id: String): SystemTag?`

`commandTags[id]` — exact, unfolded, no default. **A null here does NOT mean
"safe"**: A5's `tagForCommand` doc and A6 step 13 make an unclassified
_recognized_ utility a hard deny, precisely because an untagged Cedar `Utility`
(Datasource parent only, no forbid) would be **PERMITTED** by a broad read grant
(A2 INV-A2-11). Opposite polarity to `classifyBareFunction`; do not unify them.

##### `private fun isSystemSchema(catalog: String, schema: String): Boolean`

1. `fold(schema) !in systemSchemas` ⇒ `false`.
2. Else
   `manifest.systemSchemas.any { fold(it.schema) == fold(schema) && (it.catalog == "*" || fold(it.catalog) == fold(catalog)) }`.

**INV-A13-26 — `catalog: "*"` matches any catalog; a pinned catalog must match
exactly (folded).** Reason at `SystemClassifier.kt:109-111`, quoted: _"The
manifest may pin a catalog ("def" for MySQL) or wildcard it ("_" for PostgreSQL,
since system schemas repeat in every database). A pinned catalog must match; "_"
matches any."_ Note step 2 is a **linear scan of the raw list**, so the folded
`systemSchemas` set in step 1 is only a fast reject. Note also
`it.catalog == "*"` is an **unfolded** literal compare.

⚠️ **F30 — `logicalFunctionSchemas` never consults `catalog`.**
`classifyFunction` step 3 tests `s in logicalSchemas` with no catalog check
(`SystemClassifier.kt:25,72`), so a MySQL manifest's `def` pin on
`def/__builtin__` is inert: a function in schema `__builtin__` under _any_
catalog takes the `CATALOG` default plus in-schema rules.
`docs/system-classification.md:241-243` independently notes the related gap:
_"Nothing validates the wildcard per engine: a `"*"` catalog in a MySQL manifest
would be accepted and would simply match every catalog."_ Direction is fail-safe
(over-classify), so replicate as-is.

##### `private fun requireTag(id: String, where: String): SystemTag`

`SystemTag.fromId(id) ?: throw SystemManifestException("<engine>/<series>: $where has non-system tag '$id'")`.
`where` strings: `"command <id>"`, `"function *.<name>"`,
`"<kind> <schema>.<name>"`, `"family <schema>.<prefix>*"`.

##### `private fun exactMap(rules: List<ObjectRule>, kind: String)`

Skips `r.schema == "*"` (_"cross-schema function handled separately; not a keyed
exact"_), calls `requireTag`, keys on `(fold(schema), fold(name))`, and
**throws** on a duplicate key with a different tag:
`"<id>: duplicate exact <kind> <schema>.<name> with conflicting tags <prev>/<tag>"`.
An identical duplicate is silently accepted.

⚠️ **F25 — stale comment.** `SystemClassifier.kt:27` says _"deduped
strongest-first so the exact-map value is already the winning tag"_. It is not:
conflicts are **rejected**, not resolved strongest-first. Do not carry the
comment.

##### `private fun familyMap(rules: List<FamilyRule>)`

`requireTag`, then
`getOrPut(fold(schema)) { mutableListOf() }.add(fold(prefix) to tag)`. No dedup,
no sort — list order is manifest order, and since matching combines
strongest-wins, order is not observable.

##### `private fun validate()` — the boot gate

1. **Wildcard-relation rejection:** the first `"*"` among
   `relations.map{schema} + relationFamilies.map{schema}` ⇒
   `"<id>: wildcard schema \"*\" is only valid on a function rule, not a relation"`.
2. **Family overlap:** for each `(schema, families)` in
   `relationFamilies + functionFamilies`, every ordered pair `i != j` with
   `pa.startsWith(pb) && ta != tb` ⇒
   `"<id>: overlapping families in <schema> ('<pa>' ⊂ '<pb>') with conflicting tags <ta>/<tb>"`.
3. `checkNoDowngrade(relationExact, relationFamilies, "relation")` and
   `checkNoDowngrade(functionExact, functionFamilies, "function")`.

🔒 **INV-A13-20 — the wildcard schema `"*"` is valid on a FUNCTION rule only.**
Reason quoted verbatim (`SystemClassifier.kt:142-143`): _"The wildcard schema
"_" is valid ONLY on a function rule (a cross-schema extension function), never
on a relation — **a "\*" relation would be silently un-keyed and classify
nothing (open)**."* This is a fail-open trap turned into a boot abort:
`exactMap` skips `"*"` rules, so a `"*"` relation rule would land nowhere and
`pg_authid` would classify as plain `CATALOG`. `SystemClassificationTest` case
18 pins it.

🔒 **INV-A13-21 — a manifest that merely LOOKS like it relies on match ordering
is rejected.** Reason quoted (`SystemClassifier.kt:157-161`): _"Category
downgrade by ordering: a WEAKER exact rule whose name matches a STRONGER family
prefix in the same schema would appear to downgrade the family. **The
strongest-first combinator already prevents the downgrade, but the doc requires
rejecting a manifest that even LOOKS like it relies on ordering** — so surface
it at boot rather than trust the runtime combinator."_ This is a
defence-in-depth rule against a _future_ refactor of the combinator, not against
today's runtime. A port that drops it because "the combinator already handles
it" removes the guard that makes the combinator safe to touch.
`checkNoDowngrade` compares `exactTag.ordinal > familyTag.ordinal` (exact
strictly **weaker** than the family it matches).

⚠️ **F29 — the family-overlap check has a live shadowing hole.**
`relationFamilies + functionFamilies` is a Kotlin **`Map.plus`**: for any schema
key present in both maps, the right operand (`functionFamilies`) wins and the
left operand's family list is **never validated**. Verified against the shipped
manifests: the overlap is present in **all four** — `pg_catalog` in
`postgres/16` and `postgres/17`; `mysql` in `mysql/8.0` and `mysql/8.4`. So
`pg_catalog`'s two relation families and `mysql`'s two relation families are
currently exempt from overlap validation. Also verified: **no shipped manifest
is presently ambiguous** (I checked every family pair in all four files for
`prefix-prefix` conflicts with differing tags — none), so the hole is **latent,
not live-wrong**, and the runtime combinator still prevents a wrong tag. But
`docs/system-classification.md:196-203` states the manifest must be rejected,
and it would not be. Fix in the port by iterating the two maps separately;
`checkNoDowngrade` is **unaffected** (it takes the two maps separately already).

##### `private fun checkNoDowngrade(exact: Map<Pair<String,String>, SystemTag>, families: Map<String, List<Pair<String, SystemTag>>>, kind: String)`

For every `(schema, name) → exactTag` in `exact`, for every `families[schema]`
entry `(prefix, familyTag)`: if
`name.startsWith(prefix) && exactTag.ordinal > familyTag.ordinal` ⇒ throw

```
<engine>/<series>: exact <kind> <schema>.<name> (tag <exactTag>) is weaker than the family '<prefix>*' (tag <familyTag>) it matches — would rely on match ordering
```

Called twice: `(relationExact, relationFamilies, "relation")` and
`(functionExact, functionFamilies, "function")` — **the two map pairs are passed
separately**, which is why F29's `Map.plus` shadowing does not affect it. The
comparison is strictly `>` on `ordinal`, so equal tags are fine and a _stronger_
exact over a weaker family is fine (that is the normal "raise one object out of
a family" pattern). Iteration order over a `HashMap` is unspecified, so
**which** violation is reported first is not contract; only the fact that one
is.

##### `private fun manifestId() = "${manifest.engine}/${manifest.series}"`

Every exception message is prefixed with it.

**Go shape for the classifier:** an immutable struct built by a
`NewSystemClassifier(manifest) (*Classifier, error)` constructor that returns
the validation error instead of panicking, plus
`Classify{Relation,Function, BareFunction,Command}` methods. Maps keyed by a
`struct{schema, name string}` value (Go's map key rules make `Pair`
unnecessary). Note the Kotlin build order — property initializers (which call
`requireTag`) run **before** `validate()` — so a non-system tag surfaces as a
tag error, not an overlap error; keep the order so error messages stay
comparable. `⟦LIB⟧` none.

#### `data class ResolvedClassification` · data class

`(classifier: SystemClassifier, requestedSeries: String, resolvedSeries: String, isFallback: Boolean)`.
Doc (`SystemClassificationStore.kt:9-10`): _"`isFallback` is true when no
manifest matched the version's major and the nearest supported major is being
used instead — the caller raises the high-severity
`classification_stale`/fallback health signal + audits
`resolvedSeries != requestedSeries`."_ ⚠️ That caller obligation is **not**
discharged in A5's `SystemClassificationService` (its known-limitations note at
`SystemClassificationService.kt:27-30` defers per-datasource fallback
observability). Not a new finding — the source already documents it as deferred
— but the Go port inherits the gap, not a feature.

#### `class SystemClassificationStore private constructor(byEngineSeries: Map<Pair<String,String>, SystemClassifier>, val checksum: String)`

##### `fun resolve(engine: String, serverVersion: String, allowFallback: Boolean): ResolvedClassification?`

1. `eng = engine.lowercase()`; `requested = seriesOf(eng, serverVersion)`.
2. Exact hit `byEngineSeries[eng to requested]` ⇒
   `ResolvedClassification(it, requested, requested, false)`.
3. `if (!allowFallback) return null`.
4. `nearest = nearestSeries(eng, requested) ?: return null`.
5. `ResolvedClassification(byEngineSeries.getValue(eng to nearest), requested, nearest, isFallback = true)`.

🔒 **INV-A13-27 — with fallback off (the default), an uncertified major returns
`null` and the datasource's system schemas stay unavailable.** Reason quoted
(`SystemClassificationStore.kt:39-41`): _"Returns null when there is no manifest
for the major and fallback is off — the caller then does NOT expose the
datasource's system schemas (fail-closed; user schemas keep ordinary
deny-by-default)."_ A5 turns this into A6's step-13 utility hard-deny and the
`tagForTable` null. The operator opt-in is a **widening**, so the default must
stay `false` in the port (A5 owns the flag).

##### `private fun nearestSeries(engine: String, requested: String): String?`

Candidates = supported series of that engine. Empty ⇒ null.
`notNewer = candidates.filter { seriesKey(it) <= seriesKey(requested) }`; if
non-empty ⇒ `maxBy(seriesKey)`, else ⇒ `candidates.minBy(seriesKey)`.

**INV-A13-28 — fallback picks the highest supported major ≤ requested; if the
datasource is older than every supported major, the LOWEST supported. Never
crosses engines** (candidates are filtered by engine first). Rationale
(`SystemClassificationStore.kt:73-76`): series compare component-wise as ints.

##### `fun seriesOf(engine: String, version: String): String` · companion

`"mysql"` ⇒ `version.split(".").take(2).joinToString(".")`; **anything else** ⇒
`version.substringBefore(".")`. So PostgreSQL `17.9` → `17`; MySQL `8.0.44` →
`8.0`, `8.4.7` → `8.4`. Note the `else` branch is the PostgreSQL rule _and_ the
rule for any unknown engine name.

##### `private fun seriesKey(series: String): Int` · companion

`(parts[0]?.toIntOrNull() ?: 0) * 1000 + (parts[1]?.toIntOrNull() ?: 0)`.
Comment (`SystemClassificationStore.kt:150-151`): _"A single comparable key for
ordering series WITHIN one engine (never compared cross-engine)."_

⚠️ Two observable edges neither test covers: a **non-numeric** series keys to
`0`, so with fallback on it resolves to the _lowest_ supported major (no
`notNewer` candidate); and MySQL `"8"` and `"8.0"` both key to `8000`, so a
single-component MySQL version misses the exact lookup and falls back to `8.0`.
In production A5 guards the input (`SystemClassificationService.classifierFor`
returns null when `parseServerVersion` yields null), so neither is reachable
today. §6 gap.

##### `fun supported(): Set<Pair<String,String>>` / `fun classifierFor(engine, series): SystemClassifier?`

Diagnostics/test accessors. `classifierFor` lowercases `engine` but **not**
`series`.

##### `fun classifiersForEngine(engine: String): List<SystemClassifier>`

All classifiers of one engine, in `byEngineSeries.entries` iteration order (a
`HashMap` — **unordered**). Order is not observable because the only consumer
takes the strongest tag across the list
(`SystemClassificationService.noManifestFunctionFloor`, A5).

**Purpose, quoted** (`SystemClassificationStore.kt:60-65`) because it is the
reason this method exists at all: _"Used to build the version-INDEPENDENT
dangerous-function floor for a datasource whose version resolves to NO manifest
(uncertified/absent major) — the union of these classifiers, strongest tag per
name, closes the no-manifest function leak (the manifest's
`table_to_xml*`/pageinspect/`lo_*`/replication families **a thin hand-curated
baseline missed**) without a hand-maintained duplicate that would drift from the
manifests."_

🔒 **INV-A13-29 — the no-manifest function floor is DERIVED from the shipped
manifests, never hand-listed.** The bug this fixed is named in the source: a
hand-curated baseline missed whole dangerous families, so any `pg ≠ 16/17` or
`mysql ≠ 8.0/8.4` datasource relayed them. A Go port that re-hand-lists the
floor reintroduces exactly that drift.

##### `fun load(): SystemClassificationStore` · companion

`BUNDLED = listOf("postgres/16", "postgres/17", "mysql/8.0", "mysql/8.4")`;
`RESOURCE_DIR = "/system-classification"`;
`JSON = Json { ignoreUnknownKeys = true }`.

For each stem in **`BUNDLED.sorted()`**:

1. Read `"/system-classification/$stem.json"` from the classpath; missing ⇒
   `SystemManifestException("bundled manifest missing from the classpath: $path")`.
2. `digest.update(text.toByteArray(UTF_8))` — the **raw file text**, before
   parsing.
3. Decode; any exception ⇒
   `SystemManifestException("malformed manifest $path: ${e.message}")`.
4. **Path ↔ declaration consistency:**
   `manifest.engine != dirEngine || manifest.series != fileSeries` ⇒
   `SystemManifestException("manifest $path declares engine/series X/Y but its path says A/B")`.
5. `SystemClassifier(manifest)` — validates; throws on any violation.
6. `map.put(engine.lowercase() to series, classifier) != null` ⇒
   `SystemManifestException("duplicate manifest for <engine>/<series>")`.

Then `checksum = SHA-256(concatenated texts).hex`.

⚠️ Two reachability facts about those steps, because they change what a port
needs to test:

- Step 4 compares `manifest.engine != dirEngine` **case-sensitively** against
  the path, so a manifest declaring `"Postgres"` is rejected outright. That
  makes step 6's `engine.lowercase()` inert _for `load`_ — the engine string is
  already pinned to the (lower-case) directory name. Only `of` (§below) relies
  on the fold.
- Step 6's duplicate guard is consequently **unreachable through the resource
  files**: step 4 forces `(engine, series)` to equal the stem, and the four
  `BUNDLED` stems are distinct. It can only fire if `BUNDLED` itself gains a
  repeated entry. It is a guard on the _constant_, not on the data — so "no
  suite constructs a bad classpath" is not the reason it is untested; the only
  way to test it is to inject the stem list. A Go `embed.FS` port should keep it
  that way (assert the embedded stem list is a set).

🔒 **INV-A13-19 — any manifest problem aborts startup.** Doc
(`SystemClassificationStore.kt:21-23`): _"Every manifest is validated at
construction — a malformed or conflicting manifest throws
`SystemManifestException` and **must abort startup, like a failed Flyway
migration**."_ **Seven** rejection classes, enumerated in
`docs/system-classification.md:196-203` (the doc's own list, verified this
session): path/declaration mismatch · duplicate engine/series · a tag outside
the four · a wildcard schema on a relation rule · duplicate exacts with
different tags · overlapping families with different tags · an exact weaker than
a family prefix it matches. **Coverage gaps here are security gaps**: a manifest
that loads half-validated silently downgrades a credential surface.

⚠️ Two of those seven are **not actually enforced as written**: overlapping
families are unchecked for any schema present in both family maps (F29), and
duplicate `commands`/`"*"`-function rules are not checked at all (F32,
INV-A13-35). The same doc section also records a deliberate non-goal that must
not be mistaken for a gap (`docs/system-classification.md:205-208`, quoted):
_"Validation does not check command ids against the analyzer: nothing verifies
that a manifest command id is one `analyzer/probe/facts.go` can actually emit,
or that every emitted id has a manifest entry. `ManifestCommandCoverageDbTest`
covers the second direction at test time."_

That suite is **not in this area** and is worth surfacing, because it is the
strongest guard the repo has over `classifyCommand` and the shipped `commands`
tables:
`control-plane/src/test/kotlin/com/ridi/oss/proxymonster/gocp/ManifestCommandCoverageDbTest.kt`
— 220 LOC, **2 cases** (`grep -rhoE '@Test\b' … | wc -l` = 2), and it
instantiates A5's `SystemClassificationService()` directly, so it belongs to
**A5's** inventory, not A13's. Its header states the bug it closes: _"The
hand-maintained subset kept leaking. This test closes the CLASS: it enumerates
EVERY `system:critical` / `system:data-leak` / `system:activity` command id in
EVERY shipped manifest and requires each to be either (a) DENIED through the
real `decideQuery` by a representative statement … or (b) on the explicit
`INTENTIONAL_PASSTHROUGH` allowlist with a documented reason. A NEW manifest
command id … with no sample and no passthrough entry FAILS this test — forcing a
deliberate decision instead of a silent relay."_ **Port consequence:** editing
the `commands` array of any manifest is gated by a test in a different module.
Whoever ports A5 must keep it, and whoever ports this area must not assume the
manifest JSON is free to edit.

**INV-A13-30 — the checksum is over `BUNDLED.sorted()` order and over the raw
file TEXT.** Both matter for reproducibility: the sort makes the digest
independent of the declaration order in `BUNDLED` (which is _not_ sorted as
written — `postgres/*` precedes `mysql/*`), and hashing the text rather than the
parsed model means a reformat changes the checksum. It is surfaced truncated to
12 chars in the boot log (`SystemClassificationService.kt:36`,
`store.checksum.take(12)`) so an operator can spot a drifted bundle. A Go port
must sort the same way or every deployment's logged checksum changes.

**Go shape:** `embed.FS` over the four JSON files (compile-time embedding
replaces the classpath, and keeps "missing from the classpath" a build error
rather than a runtime one — a _strengthening_, so keep the runtime check anyway
for the `of`-style path). `⟦LIB⟧` a compile-time-embedded read-only resource
bundle; `⟦LIB⟧` a JSON codec with per-call unknown-key strictness (lenient here,
strict for §1.3's table-detail payload).

##### `fun of(manifests: List<SystemManifest>): SystemClassificationStore` · companion

Test/diagnostic factory.
`map[engine.lowercase() to series] = SystemClassifier(m)`; `checksum = "test"`.

⚠️ **F26 — `of` is missing two of `load`'s guards**: no duplicate
`(engine, series)` check (a later manifest silently **overwrites** an earlier
one) and no path/declaration consistency check (there is no path). A test
manifest list with a duplicate passes silently where the same content on disk
would abort boot. Harmless for today's tests, but **REPRODUCE (F26, index F72)**
— the missing guards are observable (a duplicate `(engine, series)` silently
overwrites, where the on-disk path aborts boot), so the Go `of` keeps the
asymmetry with a comment naming the finding. Adding the guards is a separate
decision; the reason to take it is exactly the "loader it might later reuse"
risk, which is an argument for a follow-up PR, not for changing behaviour inside
an 18,000-line rewrite.

#### `object BaselineDangerousFunctions` · object

Kotlin: `fun classify(name: String): SystemTag?` = `byName[name.lowercase()]`.

**The complete table** (`BaselineDangerousFunctions.kt:35-55`) — 15 entries, and
the tags must match the manifests exactly:

| Bare name                                                                       | Tag            | Group                                   |
| ------------------------------------------------------------------------------- | -------------- | --------------------------------------- |
| `dblink`                                                                        | `DATA_LEAK`    | PostgreSQL dblink                       |
| `dblink_exec`                                                                   | **`CRITICAL`** | ditto                                   |
| `dblink_open`, `dblink_fetch`, `dblink_send_query`                              | `DATA_LEAK`    | ditto                                   |
| `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file`, `lo_import` | `DATA_LEAK`    | PostgreSQL file & large-object IO       |
| `lo_export`                                                                     | **`CRITICAL`** | ditto                                   |
| `query_to_xml`, `query_to_xml_and_xmlschema`, `xpath_table`                     | `DATA_LEAK`    | PostgreSQL arbitrary-SQL-string readers |
| `load_file`                                                                     | `DATA_LEAK`    | MySQL server-side file read             |

🔒 **INV-A13-31 — the baseline is a FLOOR that only ever RAISES (or matches) a
manifest classification, and it classifies no safe function.** Both halves
quoted (`BaselineDangerousFunctions.kt:20-27`): _"Each carries the SAME tag the
shipped manifests assign it, so the baseline **can never DISAGREE** with a
governing manifest — `SystemClassificationService` unions the two
strongest-first, so the baseline is a FLOOR that only ever RAISES (or matches)
the manifest classification, never lowers it."_ … _"It is deliberately NOT a
general denylist: a bare name absent here is untouched (an ordinary safe builtin
or a user UDF stays UNCLASSIFIED → not marshalled → not forbidden)."_ The
tag-equality property is asserted by `SystemClassificationTest` case 16
(`BaselineDangerousFunctions.kt:33-34` names that test as the verification).

Matching is a case-insensitive fold and **by bare name only** — same reason as
`classifyBareFunction`: sqlglot drops the schema qualifier, and over-classifying
a same-named user function is fail-closed.

**Relationship to the union floor, stated so the port does not delete one of the
two:** the _primary_ no-manifest mechanism is A5's derived union over
`classifiersForEngine`; this object is _"belt-and-suspenders … it still
classifies its curated set even for an engine with ZERO shipped manifests"_
(`BaselineDangerousFunctions.kt:14-16`). Both are consumed unconditionally, on
every call, by `SystemClassificationService.tagForFunction` (A5) — and
independently by A6 at `Query.kt:492` and `594` as
`?: BaselineDangerousFunctions.classify(name)?.id`.

**Go shape:** a package-level `map[string]SystemTag` and a
`Classify(name string) (SystemTag, bool)`. `⟦LIB⟧` none.

---

## 5. Cross-area dependency map

| Consumer                                      | What it uses                                                                                                                                                                                              | Where                                                                          |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **A5** `SystemClassificationService`          | `SystemClassificationStore.load/resolve/supported/checksum/classifiersForEngine`, `SystemClassifier.classify{Relation,BareFunction,Command}`, `SystemTag.stronger`, `BaselineDangerousFunctions.classify` | `SystemClassificationService.kt:22-110`                                        |
| **A5** `TableDetailService`                   | `TableDetail` (strict decode of the proxy payload)                                                                                                                                                        | `TableDetailExec.kt:70,138`                                                    |
| **A5** `DatasourceStore`                      | `Classification`                                                                                                                                                                                          | `Datasources.kt:560,598,619-643`                                               |
| **A6** `decideQueryDecision`                  | `analyzerFor`, `Analyzer.analyze`, `Analyzer.columnKeys`, `BaselineDangerousFunctions.classify`                                                                                                           | `Query.kt:343,218-222,492,594`                                                 |
| **A7** `decideResultView`                     | `bindMasks` (`binding.allBound`, `binding.byIndex`), `Masking.apply`                                                                                                                                      | `Approvals.kt:238-248`                                                         |
| **A9** `PolicyStore.listMaskFns`              | supplies the `kind` strings `Masking.apply` switches on                                                                                                                                                   | `Policies.kt:106-107`                                                          |
| **A11** `ManagementServices` / `McpServer`    | `TableDetail`, `Classification`                                                                                                                                                                           | `ManagementServices.kt:93,111-198`; `McpServer.kt:459,494,501`                 |
| `goproxy` (Go, stays)                         | `engine.BindMasks`, `applyMaskKind`, `spi.TableDetail`                                                                                                                                                    | `goproxy/engine/masking.go`, `goproxy/spi/spi.go`                              |
| **A5** (test) `ManifestCommandCoverageDbTest` | every `commands[].id`/`tag` in all four shipped manifests, via `SystemClassificationService` + real `decideQuery`                                                                                         | `control-plane/src/test/…/ManifestCommandCoverageDbTest.kt` (220 LOC, 2 cases) |
| **A5** (test) `EnginesTest`                   | `Engine.dialect` → `Dialect` (the only test of the F21 sub-area outside `engine/`)                                                                                                                        | `EnginesTest.kt:44-45`                                                         |

**Nothing in this module depends on any control-plane area.** It is a leaf: port
it **before** A5, A6, A7.

⚠️ But two of its guarantees are _tested_ from outside it (rows above). Neither
test is in this area's 56, and neither is in any already-counted area's
inventory — both fall to **A5**. Deleting or editing this module's manifests or
`Dialect` enum breaks tests in another module; a port that moves the manifests
to `embed.FS` must keep both suites pointed at the same data.

---

## 6. Test inventory — 5 files, 668 LOC, **56 cases**

Counted with `grep -rhoE '@Test\b' --include='*.kt' engine/src/test | wc -l` =
**56**. Re-counted per file independently (audit pass, same command per file):

| Suite                                        | LOC     | `@Test` count | enumerated names below |
| -------------------------------------------- | ------- | ------------- | ---------------------- |
| `classification/SystemClassificationTest.kt` | 289     | 19            | 19 ✔                   |
| `probe/SqlNormalizeTest.kt`                  | 226     | 24            | 24 ✔                   |
| `probe/AnalyzerTest.kt`                      | 72      | 3             | 3 ✔                    |
| `probe/BindMasksTest.kt`                     | 50      | 5             | 5 ✔                    |
| `probe/MaskingTest.kt`                       | 31      | 5             | 5 ✔                    |
| **total**                                    | **668** | **56**        | **56 ✔**               |

19 + 24 + 3 + 5 + 5 = 56, every enumerated name below matches a `fun` in the
source verbatim — **the counts agree**, and none of these five suites appears in
another area's inventory. This matches `00-INDEX.md:28` ("`engine/` | 804 | 668
(56 cases)") and `00-INDEX.md:61`.

All five suites are **unit** tests. **None needs a database or Testcontainers.**
Three of them (`AnalyzerTest`, `SqlNormalizeTest`, and — transitively — nothing
else) do need the **native probe** loaded: `engine/build.gradle.kts:31-34` notes
the `--enable-native-access` jvmArg and that `:analyzer:jvm`'s
`processResources` builds and bundles the c-shared library. In Go all five
become plain package tests.

### `classification/SystemClassificationTest.kt` — 289 LOC, 19 cases · unit

Header: _"Unit proof for the system-classification mechanism … Uses synthetic
manifests — the real curated Aurora manifests are proven separately."_ Four
sections: classifier · boot validation · version resolution · the real bundled
manifests.

1. a relation in a system schema defaults to catalog, exact and family raise it
   to the strongest (INV-A13-18, INV-A13-22)
2. case-insensitive within a system schema, catalog wildcard vs pinned
   (INV-A13-25, INV-A13-26)
3. a cross-schema function rule applies in any schema, catalog default only in a
   system schema (INV-A13-24)
4. a utility command maps to its resource tag
5. 🔒 a non-system tag aborts (INV-A13-19)
6. 🔒 a duplicate exact identity with conflicting tags aborts (INV-A13-19)
7. 🔒 an exact rule that would downgrade a stronger family aborts (INV-A13-21)
8. 🔒 overlapping families with conflicting tags abort (INV-A13-19) — ⚠️ uses a
   manifest with **only** `relationFamilies`, so it passes _through_ the F29
   shadowing hole rather than exposing it
9. an exact major and a newer minor both resolve to the series manifest, no
   fallback
10. 🔒 an unsupported major is unavailable without fallback, and falls back to
    the nearest lower with it (INV-A13-27, INV-A13-28)
11. a datasource older than every supported major falls back to the lowest
    (INV-A13-28)
12. mysql 8_4 falls back to 8_0 nearest-lower reasoning stays within engine
    (INV-A13-28)
13. all four bundled Aurora manifests load, validate, and index — **the boot
    check**; asserts
    `supported() == {postgres/16, postgres/17, mysql/8.0, mysql/8.4}` and
    `checksum.length == 64`
14. real PostgreSQL classifications (incl Aurora) are correct
15. real MySQL classifications (incl Aurora rds_) are correct
16. 🔒 the PostgreSQL manifest is a superset of the old dangerousFuncs (must
    hold before that map retires) — pins INV-A13-31's tag-equality property;
    named as the verification by `BaselineDangerousFunctions.kt:34`
17. 🔒 gate regressions - stat-getter, pageinspect, and aurora_stat functions
    are dangerous, not open
18. 🔒 a wildcard-schema relation rule is rejected at boot (INV-A13-20)
19. real version resolution + Aurora fallback

Cases 13–19 exercise the **real shipped manifests** and are the closest thing
the area has to a golden posture test (A2's `PolicyOriginDbTest` case 1
analogue). Case 17's comment records why each entry matters, e.g.
_"pg_stat_get_backend_activity(pid) returns another backend's query text — the
datum pg_stat_activity (activity) exposes; it must not classify as
CATALOG/open."_ Port these **with the manifest files unchanged**; they are the
regression net for any hand-edit of the JSON.

### `probe/SqlNormalizeTest.kt` — 226 LOC, 24 cases · unit (native probe required)

Header states the contract: _"same statement (up to whitespace / comments /
keyword-case, plus unquoted-identifier case on Postgres) → same hash; any
material difference … → different hash; unlexable → null."_ Helpers `eq(a,b,d)`
/ `ne(a,b,d)` assert on `sqlGrantHash`, echoing inputs in the message. Most
cases loop over both dialects.

_Hash-EQUAL classes_

1. whitespace, newlines and tabs are irrelevant
2. trailing semicolons are dropped
3. keyword case is folded in both dialects
4. Postgres folds unquoted identifier case
5. line comments are stripped — covers Postgres `--`, MySQL `-- ` and `#`, and
   `\r` terminators
6. block comments are stripped, including mid-statement and multiline
7. Postgres nested block comments are stripped

_Hash-DIFFERENT classes_ 8. a different table changes the hash 9. a different
column changes the hash 10. a different operator changes the hash 11. a
different string literal changes the hash 12. literal case and inner whitespace
are preserved 13. 🔒 a comment-lookalike inside a literal is preserved 14. MySQL
bare double-dash is arithmetic but Postgres is a comment — the
dialect-divergence case 15. 🔒 MySQL executable comments and optimizer hints
fail closed — _"Deliberate temporary posture until version-comment and hint
content can be preserved safely"_; also asserts the same markers **inside a
literal** still hash and stay distinct 16. Postgres quoted identifier case is
significant 17. MySQL preserves non-reserved identifier case (case-sensitive
tables) 18. Postgres dollar-quoted string body case is significant 19. 🔒 raw
lexeme spellings cannot collide (INV-A13-11) — the widest case: escaped-string
spellings, literal prefixes (`E'` vs `e'`, `X'` vs `x'`), leading-zero numbers,
hex case, quoted identifiers, dollar-quote delimiters, `!=` vs `<>`, non-ASCII
identifiers

_Fail-closed (null)_ 20. 🔒 unterminated constructs normalize to null
(INV-A13-10) 21. 🔒 empty and content-free inputs normalize to null — empty,
whitespace-only, `;`, `;;`, comment-only 22. 🔒 embedded NUL and unpaired
surrogates fail closed through the public API — asserts **both** `normalizeSql`
and `sqlGrantHash` 23. normalization is lexical and does not require parser
coverage — `SELECT (((1` normalizes 24. the hash is 64 lowercase hex chars
(INV-A13-12)

⚠️ **These 24 cases test `analyzer/probe/sqlnormalize.go` through a 34-line
Kotlin shim, for a function with no production caller (F21).** Before
transcribing them, diff against the existing
`analyzer/probe/sqlnormalize_test.go`; and settle F21 first — if the one-time
query grant is not being built, this suite retires with the file.

### `probe/AnalyzerTest.kt` — 72 LOC, 3 cases · unit (native probe required)

1. analyzer retains validated request snapshot and returns StatementFacts
   (INV-A13-17, INV-A13-16) — also the only assertion on `piiColumns` anywhere
   (F23)
2. 🔒 invalid catalog identity fails before native analysis (INV-A13-13) — a
   duplicate `(schema, table, column)` triple ⇒ `IllegalArgumentException`. ⚠️
   **The "before native analysis" part is in the test NAME only**: the body is a
   bare `assertFailsWith<IllegalArgumentException> { analyzerFor(...) }`
   (`AnalyzerTest.kt:52-58`) with no spy, no call counter, and nothing that
   would fail if validation moved after the probe call. The ordering is real
   (validation runs in `analyzerFor`, the probe only in `analyze`) but it is
   **unasserted** — a port that validated lazily inside `analyze` would still
   pass this test
3. 🔒 malformed and batched statements fail closed with explicit failure classes
   — `select 'unterminated` ⇒ `UNANALYZABLE`; `select 1; select 2` ⇒
   **`INADMISSIBLE`** (INV-A13-14's multi-statement fail-close)

Case 3 is the only place the two failure classes are distinguished at unit
level, and the `UNANALYZABLE`/`INADMISSIBLE` split is exactly what A6 step 16
branches on. Port it early.

### `probe/BindMasksTest.kt` — 50 LOC, 5 cases · unit

1. ordinal binds
2. 🔒 name is ignored (INV-A13-6) — uses `column = "EXPR$0"`
3. 🔒 out of range ordinal is unbound (INV-A13-8)
4. 🔒 absent ordinal is unbound - never binds to result column 0 (INV-A13-7) —
   the in-test comment restates the reason: _"that would mask the wrong column
   and leak the intended one"_
5. multiple ordinals bind

Case-for-case identical to `goproxy/engine/masking_test.go TestBindMasks`,
**except** the Go suite adds a sixth, `"first duplicate ordinal wins"`
(INV-A13-9). Migrate the Go superset, not the Kotlin subset.

### `probe/MaskingTest.kt` — 31 LOC, 5 cases · unit

Header: _"Deterministic masking shared by the control plane and the wire proxy —
must not drift."_

1. 🔒 last_n reveals only the final four — `"900101-1234567"` →
   `"**********4567"`
2. 🔒 last_n on short values masks entirely (INV-A13-3) — `"abc"` → `"***"`,
   `"1234"` → `"****"`
3. format_preserving keeps separators, masks alphanumerics — `"010-1234-5678"` →
   `"***-****-****"`
4. 🔒 fixed and null kinds (INV-A13-1) — `FIXED` → `"####"`, `NULL` → **null**
5. 🔒 null input stays null and unknown kind is fully masked (INV-A13-1,
   INV-A13-2) — `"secret"` + `"WHATEVER"` → `"****"`

`goproxy/engine/masking_test.go TestMasking` is a table test with **11 rows**
(`masking_test.go:21-31`), which is these 5 Kotlin methods' **8 assertions**
one-per-row plus **three** the Kotlin side lacks:
`"last_n counts UTF-16 code units"` (😀 → `"**1234"`),
`"format preserving keeps surrogate-pair letters"` (`"𐐀A1"` → `"𐐀**"`), and
`"format preserving masks Unicode 16 BMP letters"` (`"Ɤ-1"` → `"*-*"`) — plus a
separate `TestKotlinCharLetterOrDigitUnicode16Parity`. **The Go suite is the
authoritative one** for INV-A13-4/5. (Counting note: the Kotlin file has 5
`@Test` functions but 8 assertions, because cases 2, 4 and 5 each assert two
inputs; the 5 is what the area's 56 counts.)

### Coverage gaps in A13

**Masking / binding**

- **Duplicate-ordinal first-wins (INV-A13-9) is untested in Kotlin.** Covered in
  Go only.
- **UTF-16 code-unit semantics (INV-A13-4) are untested in Kotlin.** Covered in
  Go only — so the _definition_ of correct lives in the twin, not in the
  original. Migrate the Go cases.
- **INV-A13-5 (the two implementations agree) has no cross-language golden
  vector.** Compare with `AuditCanonical`, which _does_ have one
  (`atrail/canonical-golden.json`, F9). If the port keeps two implementations,
  add a shared golden file; if it collapses them (recommended, §1.1), the gap
  closes.
- `bindMasks` with `resultColumnCount == 0` (everything unbound) is untested.

**Classification**

- 🔒 **The F29 shadowing hole is untested and, by construction, unreachable by
  case 8** (which uses a manifest with only `relationFamilies`). A manifest with
  a conflicting relation-family pair in a schema that _also_ has function
  families would load. Add that manifest as a test in Step 3.
- 🔒 **Duplicate `commands[].id` and duplicate `"*"`-function rules are
  unvalidated and untested** (F32, INV-A13-35). `associate`'s last-wins can
  _downgrade_ a command's tag with no boot error. Add a manifest with a repeated
  command id carrying a weaker tag; it must abort.
- **Path ↔ declaration mismatch** (`load` step 4) is untested — no suite
  constructs a bad classpath. The **duplicate-manifest guard** (step 6) is
  untested _and unreachable through the files_: step 4 pins `(engine, series)`
  to the path, so only a repeated `BUNDLED` stem can trigger it. Test it by
  injecting the stem list, not by faking a classpath.
- **`missing from the classpath`** is untested.
- **`seriesKey` edges** are untested: a non-numeric series (keys to 0, falls
  back to the _lowest_ major) and MySQL `"8"` vs `"8.0"` (same key). Unreachable
  today only because A5 pre-validates the version string — which is a _different
  area's_ guard.
- **`SystemClassificationStore.of`'s missing duplicate check** (F26) is untested
  by construction.
- **`classifierFor` does not lowercase `series`** — untested asymmetry.
- **`CommandRule.resource`** (F31) is unread and therefore trivially untested.
- **`checksum` value** — only its _length_ is asserted (case 13). Nothing pins
  it to a byte-order-independent digest, so a port could reorder `BUNDLED` and
  change every operator's logged checksum without failing a test (INV-A13-30).

**Analyzer facade**

- **`validateNamespace`** (blank catalog, empty search path, blank entry) is
  untested.
- **`validateColumn`'s blank-`dataType` rejection** is untested.
- 🔒 **The dot-collision case (two DIFFERENT identities rendering to one key) is
  untested.** `AnalyzerTest` case 2 covers only the _exact duplicate_ branch.
  The collision branch is the security-relevant one — it is A2 INV-A2-6's
  analogue and A2 _does_ test its half (`ColumnAuthzTest` case 3). Add
  `catalog "a.b" + schema "c"` vs `catalog "a" + schema "b.c"` in Step 3.
- 🔒 **`SqlglotProbe`'s catch-all (INV-A13-15) is untested** — there is no way
  to make the FFM call throw from a test. It disappears in Go, but F28's
  question (what `failedStage`/failure class an analyzer _error_ gets) should be
  pinned by a new test on whatever mapping the port chooses.
- 🔒 **INV-A13-34 (an `Analyzer` is per-statement) is untested on both sides.**
  Nothing asserts that a changed `mysql_ansi_quotes` produces a different
  analysis, so a port that caches an `Analyzer` per datasource would pass every
  existing test while leaking a `"`-quoted masked column. The natural home is an
  A6 enforcement test (two decisions on one datasource with `liveAnsiQuotes`
  flipped), not a unit test here.
- **`Analyzer.analyze` is never called with a statement that needs
  `engineConfig` beyond the engine enum.** `AnalyzerTest` builds
  `engineConfig { engine = Engine.POSTGRES }` — no version, no case mode, no
  ansi_quotes — so the MySQL-specific fail-closed-without-a-parseable-version
  path (`analyzer.proto:58-61`) is not exercised from this module at all.
- **`Analyzer.piiColumns`** is asserted (case 1) but has no production consumer
  (F23) — an inverted gap: the test outlives the feature.

**Whole-area**

- No test exercises the **HTTP/strict serialization asymmetry** (INV-A13-32) for
  `TableDetail`: nothing asserts that a null field is omitted on the HTTP encode
  and required on the proxy decode. That contract is currently held only by the
  fact that both sides happen to be written consistently.

---

## 7. New findings raised by this area

Numbered **F21–F35** per the index's convention (F32–F35 added by the audit
pass). **I have not edited `00-INDEX.md`.** Two of the new ones are
security-relevant (F32 silent tag downgrade, F34 cleartext leak via a cached
`Analyzer`); F35 is an accounting item another area must absorb.

| #       | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Where                                                         | Kind                      |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------- |
| **F21** | `SqlNormalize.kt` (`normalizeSql`, `sqlGrantHash`) and `Dialect.kt` are **production-dead**: no caller in `control-plane/src/main`, `goproxy`, `pmon` or `auditmon`. The sole production `Dialect` reference is an **unused local** at `Query.kt:308`. The `query_result.sql_hash` actually persisted is a raw SHA-256 of the SQL bytes (`Access.kt:127-129`, `190-192`), never compared to anything. **24 of the area's 56 cases (43%) pin unconsumed behaviour.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `SqlNormalize.kt`, `Query.kt:308`, `Access.kt:127`            | dead code                 |
| **F22** | `columnKey(namespace, column)` has no caller anywhere in the repo; its `namespace` parameter is validated but contributes nothing to the returned key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `CatalogApi.kt:16`                                            | dead code                 |
| **F23** | `Analyzer.piiColumns` has no production consumer (only `AnalyzerTest:46`). Separately, `ColumnSpec.pii` is set from `col.classification != null` (`Query.kt:337`) — _"has any classification"_ — while A6's real PII set is `tags.contains("pii")` (`Query.kt:675`). Two meanings of "pii" one function apart.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `CatalogApi.kt:38`, `Query.kt:337`                            | dead code / inconsistency |
| **F24** | A **third** hand-maintained Kotlin↔Go DTO twin, absent from `00-INDEX.md`'s "Already twinned" table: `TableDetail` + 6 nested DTOs + `Classification`. The Kotlin side decodes the proxy's JSON **strictly** (`Json` defaults), so the pair is a live wire contract, and `table_detail.go:854`'s non-nil empty slices are load-bearing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `TableDetail.kt` ↔ `goproxy/spi/spi.go:101-177`               | duplication               |
| **F25** | Stale comment: _"deduped strongest-first so the exact-map value is already the winning tag"_. `exactMap` does not dedupe strongest-first — it **throws** on a conflicting duplicate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `SystemClassifier.kt:27`                                      | stale doc                 |
| **F26** | `SystemClassificationStore.of()` omits both of `load()`'s structural guards: no duplicate `(engine, series)` check (a later manifest silently overwrites) and no path/declaration consistency check.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `SystemClassificationStore.kt:138-142`                        | inconsistency             |
| **F27** | `Query.kt` imports `Masking` (line 40) and `bindMasks` (line 42); neither is used in that file. The build has no ktlint/detekt and no `allWarningsAsErrors`, so unused imports and the unused `val dialect` compile silently.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `Query.kt:40,42,308`                                          | dead code                 |
| **F28** | 🔒 An FFM/protobuf failure in `SqlglotProbe.analyze` is reported as `FAILURE_CLASS_UNANALYZABLE`, which A6 step 16 routes to Cedar `sql.unanalyzable` — so on a datasource permitting the relay, _"the analyzer did not run"_ becomes a **passthrough**, indistinguishable from _"the analyzer cannot reason about this statement"_. The wrapper also labels it `failedStage="LINEAGE"` while the Go probe uses `"VALIDATE"` for the analogous failure, and truncates `detail` by UTF-16 unit vs Go's rune.                                                                                                                                                                                                                                                                                                                                                                                                                              | `Sqlglot.kt:43-51`, `wire.go:43-48`                           | 🔒 possible gap           |
| **F29** | 🔒 `validate()`'s `relationFamilies + functionFamilies` is a Kotlin `Map.plus`: for any schema key in **both** maps, the relation families are never overlap-validated. Present in **all four shipped manifests** (`pg_catalog` in postgres/16 and /17; `mysql` in mysql/8.0 and /8.4). Verified **latent, not live-wrong** — no shipped manifest is currently ambiguous — but `docs/system-classification.md:196-203` says such a manifest must be rejected, and it would not be. `checkNoDowngrade` is unaffected.                                                                                                                                                                                                                                                                                                                                                                                                                     | `SystemClassifier.kt:147`                                     | 🔒 validation hole        |
| **F30** | `logicalFunctionSchemas` entries' `catalog` is never consulted (`SystemClassifier.kt:25,72`), unlike `systemSchemas` (line 111), so a MySQL manifest's `def` pin on `def/__builtin__` is inert — schema `__builtin__` under any catalog takes the CATALOG default. Direction is fail-safe (over-classify). Related, and independently documented: _"Nothing validates the wildcard per engine: a `"*"` catalog in a MySQL manifest would be accepted"_ (`docs/system-classification.md:241-243`).                                                                                                                                                                                                                                                                                                                                                                                                                                        | `SystemClassifier.kt:25,72`                                   | inconsistency             |
| **F31** | `CommandRule.resource` is decoded from every manifest and **never read by any code in the repo** (`commandTags` consumes only `id` and `tag`). Documentation inside a data file — keep it, but do not model it as behaviour.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `SystemManifest.kt:47`, `SystemClassifier.kt:33`              | dead field                |
| **F32** | 🔒 `commandTags` and `functionAnySchema` are built with Kotlin `associate`, i.e. **last-pair-wins on a duplicate key with no conflict check** — unlike `exactMap`, which throws. So a repeated `commands[].id` (or a repeated `schema:"*"` function name) silently keeps the LAST tag, which may be **weaker**: a duplicated `SHOW_GRANTS` ending in `system:catalog` downgrades a credential surface at boot with no error. `exactMap` explicitly skips `"*"` rules, so cross-schema function rules get no duplicate check anywhere. Verified latent — no shipped manifest has a duplicate command id or duplicate `"*"` name (all four files checked) — but `docs/system-classification.md:196-203` says duplicates with different tags must be rejected. Same class as F29. **REPRODUCE + PIN** — last-pair-wins is observable and sits on the classification path, so pin it with a test rather than quietly correcting it mid-port. | `SystemClassifier.kt:33`, `:35-36`, `:120`                    | 🔒 validation hole        |
| **F33** | The `analyze` KDoc's two division-of-labour rules were absent from the earlier draft of this doc: _"Go owns all engine-specific validation from `engineConfig` alone (e.g. failing MySQL analysis closed without a parseable version)"_ and _"Analyzer output identities are always `catalog.schema.table.column`"_. The first changes Q2's answer: `failedStage="VALIDATE"` is already a **live** probe signal for a missing/unparseable MySQL version (`analyzer.proto:58-61`), so reusing `"VALIDATE"` for a _call_ error would merge two distinct faults into one audited value.                                                                                                                                                                                                                                                                                                                                                     | `Sqlglot.kt:30-33`, `analyzer.proto:58-61`                    | stale doc / spec gap      |
| **F34** | 🔒 `EngineConfig.mysql_ansi_quotes` is an observation of the **live session** `sql_mode`, re-read per statement (`analyzer.proto:70-71`; A6 rebuilds it at `Query.kt:322-329` and calls `analyzerFor` at `:343`). INV-A13-17's "fixed for the lifetime of an `Analyzer`" therefore means _fixed for one statement_. A port that memoizes an `Analyzer` per datasource freezes `ansi_quotes` and parses `"masked_col"` as a string literal instead of a column read — cleartext leak. Untested on both sides.                                                                                                                                                                                                                                                                                                                                                                                                                             | `analyzer.proto:66-71`, `CatalogApi.kt:26-28`, `Query.kt:328` | 🔒 port hazard            |
| **F35** | `ManifestCommandCoverageDbTest` (`control-plane/src/test/…`, 220 LOC, **2 cases**) is the repo's strongest guard over this module's shipped `commands` tables and `classifyCommand`, and it lives in **A5**, outside this area's 56. `EnginesTest.kt:44-45` likewise is the only test of the F21 `Dialect` sub-area outside `engine/`. Neither appears in any already-counted area's inventory, so both must land in A5's when it is specified — and F21/Q4's "delete `Dialect`" has a test consequence in another module.                                                                                                                                                                                                                                                                                                                                                                                                               | `ManifestCommandCoverageDbTest.kt`, `EnginesTest.kt:44`       | cross-area accounting     |

---

## 8. Open questions

| #   | Question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | `masking.go`'s eight hardcoded Unicode-16 BMP letters exist to match JDK 24 `Character.isLetterOrDigit`. Once the JVM is gone, what defines correct? Freezing the current set is the conservative answer (stored results re-mask live on every view, INV-A7-3), but it should be a recorded decision, not an accident of when the file was written.                                                                                                                                                                                                                                                                                                                                                              |
| Q2  | `SqlglotProbe`'s catch-all sets `failedStage = "LINEAGE"`; the Go probe labels a decode/build failure `"VALIDATE"` (`wire.go:43,47`) and a recovered panic `"LINEAGE"` (`wire.go:38`). **Narrowed by F33:** `"VALIDATE"` is _already_ the live label for a missing/unparseable MySQL `engine_version`, so reusing it for a call error is lossy. Recommendation: keep `"LINEAGE"` for an unexpected error from `probe.AnalyzeStatement`, or introduce a third value — but decide it explicitly. Open sub-question unchanged: does anything (audit query, `web/`, F15's admission check) read `failed_stage` **by value**?                                                                                         |
| Q3  | `SystemClassifier.fold` is Kotlin `lowercase()` (full Unicode, locale-independent) while its own doc says "case-insensitive **ASCII** fold" (`SystemClassifier.kt:11`). Go's `strings.ToLower` also does full Unicode, so they agree today — but the doc and the code disagree, and a Turkish-İ-style identifier would expose it. Which is intended?                                                                                                                                                                                                                                                                                                                                                             |
| Q4  | F21 (index F79): is the one-time query grant still planned? If yes, `sqlGrantHash` needs wiring (and `query_result.sql_hash` is currently the _wrong_ hash for it). **Disposition DEFER** — this is a product question the port must not settle on its own, and until it is answered the sub-area is **REPRODUCE as a test-visible surface**, not OMIT: it is production-dead but carries a 24-case suite plus `EnginesTest.kt:44-45` in A5 (F35), and a suite that size is not "dead code with no observable behaviour". Only a deliberate "no" makes dropping `SqlNormalize.kt`, `Dialect.kt`, the `Engine.dialect` extension and those suites an OMIT. This decides ~43% of the area's test-migration budget. |
| Q5  | F24: should the Go control-plane import `goproxy/spi`'s `TableDetail` (and `goproxy/engine`'s masking) directly, or does a control-plane→data-plane package dependency violate the intended module boundary? Reusing them collapses two hand-maintained twins; a shared third package avoids the direction problem.                                                                                                                                                                                                                                                                                                                                                                                              |
| Q6  | F29 (index F38), the family-overlap shadowing. **Settled by the port policy: REPRODUCE.** The validation hole is observable at boot, and "behaviour-neutral for the four shipped manifests" (verified: none is currently ambiguous) stops being true at the fifth. The recommendation to add the overlap check and the missing test still stands — as a _post-cutover_ PR, where the change is ten reviewable lines instead of invisible inside the rewrite.                                                                                                                                                                                                                                                     |
| Q7  | `ResolvedClassification.isFallback` documents a caller obligation (raise `classification_stale`, audit `resolvedSeries != requestedSeries`) that A5 defers. Does the port carry the deferral forward, or is the fallback signal in scope?                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Q8  | Are `manifestVersion` and `curatedThrough` meant to be enforced (e.g. refuse a manifest whose `manifestVersion` the code does not understand)? Both are decoded and never read. (Values today, verified: all four manifests declare `manifestVersion: 1`; `curatedThrough` is `16.13` / `17.9` / `8.0.44` / `8.4.7`.)                                                                                                                                                                                                                                                                                                                                                                                            |
| Q9  | F32 (index F37): fold `commandTags`/`functionAnySchema` into `exactMap`'s reject-on-conflict path? **Not during the port — REPRODUCE + PIN.** The recommendation is still **yes** as a follow-up: behaviour-neutral for the four shipped manifests and it closes a silent-downgrade path. Secondary, and still open: should `commandTags` also fold case, or is the raw-id key deliberate because ids are analyzer constants?                                                                                                                                                                                                                                                                                    |
| Q10 | F34/INV-A13-34: does the Go port build an `Analyzer` per statement (matching Kotlin), and if a cache is wanted for the catalog half, what is the cache key that provably includes `mysql_ansi_quotes`, the case mode, the engine version **and** the catalog generation?                                                                                                                                                                                                                                                                                                                                                                                                                                         |
