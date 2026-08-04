# A8 — Audit (store, canonical bytes, read routes)

Files: `AuditStore.kt` (191) · `AuditCanonical.kt` (129) · `AuditRoutes.kt`
(67). Total 387 LOC. Fully read. Tables: `audit_event`, `audit_chain_head` (V4).

**Lowest-risk area** — `AuditCanonical` is already ported and cross-verified in
Go. See §2.

## Purpose

Tamper-evident append-only audit trail: one hash-chained row per decision, plus
the read surface. The `AuditEvent` DTO itself is specified in `01-bootstrap.md`
§3 (it is a shared type).

---

## 1. `AuditStore` — chain-linked insert

### `insert(rec): Long` / `insert(conn, rec): Long`

The single-argument form wraps `dataSource.inTx`. The connection overload lets
an audit event commit **atomically with its state change**; the caller owns
commit/rollback and failures propagate so the enclosing operation fails closed.

**Behavior of `insert(conn, rec)`:**

1. `SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE` —
   missing row ⇒ `check` fails `"audit chain head is missing"`; —
   `head_hash.size != 32` ⇒ `check` fails.
2. `newId = Math.addExact(lastId, 1)` — overflow throws rather than wrapping.
3. `instant = (rec.ts?.let(Instant::parse) ?: Instant.now()).truncatedTo(ChronoUnit.MICROS)`
4. `tsMicros = AuditCanonical.epochMicros(instant)`;
   `rowHash = AuditCanonical.rowHash(newId, rec, tsMicros, headHash)`
5. `INSERT INTO audit_event (…26 columns…)` — `check(executeUpdate() == 1)`
6. `UPDATE audit_chain_head SET last_id = ?, head_hash = ? WHERE id = 1` —
   `check(executeUpdate() == 1)`

🔒 **INV-A8-1 — the chain head row lock is what serializes appends.**
`FOR UPDATE` held until commit is the only thing preventing two concurrent
inserts from claiming the same `newId` or linking to the same `prev_hash`. Ids
are **application-allocated**, not a sequence — `AuditTrailSchemaDbTest` asserts
"a clean store has **no id sequence**". A Go port must keep the lock and must
not substitute a `BIGSERIAL`.

🔒 **INV-A8-2 — microsecond truncation before hashing.** The timestamp is
truncated to micros _before_ `epochMicros`, so the value hashed is exactly the
value stored (Postgres `timestamptz` is microsecond-precision). Hashing
nanoseconds and storing micros would make every row fail verification.

**INV-A8-3** — `rec.ts` is honoured when supplied (proxy ingest may set it) and
filled with `Instant.now()` when null.

**Column encoding:** five list fields (`roles`, `masked_columns`, `pii_touched`,
`effective_namespace`, `context_tags`) are stored as **`jsonb`** via `?::jsonb`
casts, serialized with `kotlinx.serialization`
`ListSerializer(String.serializer())`. `rows_returned` / `bytes_returned` /
`decision_id` use `setNull(…, Types.BIGINT)` when null. Note the DTO field
`authzAction`/`authzResource` map to columns **`action`/`resource`**.

### Reads

| Method                     | SQL                                            |
| -------------------------- | ---------------------------------------------- |
| `recent(limit)`            | `ORDER BY ts DESC LIMIT ?`                     |
| `recent(limit, principal)` | `WHERE principal = ? ORDER BY ts DESC LIMIT ?` |
| `get(id)`                  | `WHERE id = ?`                                 |

🔒 **INV-A8-4 — ownership filters before the limit.** `recent(limit, principal)`
puts `WHERE principal` in SQL, not a post-filter. Fetching `limit` rows then
filtering would return fewer than `limit` owned rows whenever other principals'
rows are newer. `AuditFeedDbTest` case 3 pins this.

`toRecord()` reads `ts` as `getTimestamp("ts")?.toInstant()?.toString()` — the
same Java `Instant.toString()` variable-precision formatting flagged in A2 §8.
Wire-visible.

`longOrNull(column)` = `getLong(column).let { if (wasNull()) null else it }` —
the JDBC idiom for a nullable bigint. Go's `sql.NullInt64` / `*int64` is the
direct equivalent.

---

## 2. `AuditCanonical` — **already ported; do not re-derive**

`auditmon/canon/canonical.go` is the Go implementation, and
`auditmon/canon/canonical_test.go:90` reads _this module's_ fixture
`control-plane/src/test/resources/atrail/canonical-golden.json`. The two
languages are already frozen against one shared golden-vector suite
(`canonical.go:1-9`).

**Port action: import `auditmon/canon`, delete the Kotlin.** Do not write a
third implementation.

Format, recorded here only so the contract is legible in one place:

- `canonical(event, tsMicros)` =
  `DOMAIN_SEP || u32be(CHAIN_VERSION) || fields(event)`
- row-hash preimage =
  `DOMAIN_SEP || u32be(CHAIN_VERSION) || u64be(id) || fields(event) || prevHash`
  (`prevHash` exactly 32 bytes); `row_hash = SHA-256(preimage)`
- `DOMAIN_SEP = "pm-audit-event"` (US-ASCII), `CHAIN_VERSION = 1`
- strings: `u32be(UTF-8 byte length) || UTF-8`; **null scalar = `0xFFFFFFFF`**
  (`writeInt(-1)`), no payload
- int64: `u32be(8) || i64be` signed
- arrays: `u32be(count)` then length-prefixed UTF-8 elements
- `fields` order (22): `kind`, `tsMicros`, `principal`, `roles`, `datasource`,
  `clientAddr`, `statement`, `decision.name`, `failedStage`,
  `effectiveNamespace`, `maskedColumns`, `piiTouched`, `latencyMs`, `detail`,
  `channel`, `contextTags`, `authzAction`, `authzResource`, `outcome`,
  `rowsReturned`, `bytesReturned`, `decisionId`
- never includes `id`, `prev_hash`, or `row_hash`

🔒 **INV-A8-5 — sorted vs insertion-order arrays.** `roles`, `maskedColumns`,
`piiTouched`, and `contextTags` sort **ascending by unsigned UTF-8 bytes and
preserve duplicates**; `effectiveNamespace` preserves input order. Getting
either wrong changes every hash.

The comparator compares bytes as **unsigned** (`b.toInt() and 0xff`) then by
length. Go's `bytes.Compare` is already unsigned, so `sort.Slice` with
`bytes.Compare` matches — but Kotlin's default `ByteArray` comparison would be
_signed_, which is why the explicit comparator exists.

`epochMicros` uses `Math.addExact`/`multiplyExact` — overflow throws. `rowHash`
requires `prevHash.size == 32`.

---

## 3. `AuditRoutes` — the visibility model

Two routes, both gated `requireApi(config)`.

| Method | Path              | Behavior                                                                                                                                                                                                     |
| ------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| GET    | `/api/audit`      | `limit` = query param or 100, **`coerceIn(1, 500)`**. `authDebug` ⇒ `recent(limit)`. Else `AUDIT_READ` on `AuthzResource.AuditLog`: Allow ⇒ `recent(limit)`, otherwise ⇒ `recent(limit, principal)`.         |
| GET    | `/api/audit/{id}` | bad id ⇒ `badId()`. Missing row ⇒ `notFound("audit record")`. `authDebug` ⇒ respond. Else `AUDIT_READ` on `AuthzResource.AuditRecord(record.principal)`: Allow ⇒ respond, Deny ⇒ `notFound("audit record")`. |

🔒 **INV-A8-6 — denied and missing are deliberately indistinguishable.** Both
respond `notFound("audit record")`. A caller must not be able to tell "exists
but you cannot see it" from "does not exist". `AuditReadRoutesDbTest` case 2
pins it.

🔒 **INV-A8-7 — a denied collection read degrades to own-rows, it does
not 403.** `/api/audit` falls back to `recent(limit, principal)` rather than
erroring. The two-tier model (own rows always, whole log by grant) is the
contract.

**INV-A8-8** — `authDebug` short-circuits **before any session resolution**,
mirroring `requireApi`. The `requireNotNull(call.userSession())` afterwards
carries the message _"audit list admitted a non-debug request without a
UserSession"_ — i.e. it asserts `requireApi`'s postcondition, and is not a
reachable user-facing error.

---

## 4. Test inventory — 5 files, 942 LOC, **18 cases**

### `AuditCanonicalGoldenTest.kt` — 122 LOC, 2 cases · unit

1. canonical bytes and row hashes match the cross-language golden vectors
2. row hash rejects a previous hash with the wrong length

**Port action:** the Go equivalent already exists
(`auditmon/canon/canonical_test.go`). Verify it still reads the fixture after
the Kotlin module is deleted — the fixture path
`control-plane/src/test/resources/atrail/canonical-golden.json` **moves**, and
that cross-repo relative path will break. Move the fixture to a language-neutral
location and update `canonical_test.go:90`. ⚠️ This is a concrete, easily-missed
cutover task.

### `AuditChainDbTest.kt` — 274 LOC, 5 cases · **DB**

1. single-argument inserts allocate contiguous ids and persist a recomputable
   chain (INV-A8-1)
2. 🔒 connection overload commits linked, and rollback leaves both event and
   head untouched
3. completion fields round-trip chain and reject a bogus decision id
4. 🔒 verify walk detects a historical event mutation — the tamper-evidence
   property
5. 🔒 concurrent appends serialize without duplicate ids and preserve the chain
   (INV-A8-1)

Case 5 is the one that fails if the `FOR UPDATE` lock is dropped. Case 2 is the
one that fails if the connection overload is reimplemented to open its own
transaction.

### `AuditTrailSchemaDbTest.kt` — 121 LOC, 1 case · **DB**

1. a clean store has no id sequence, a genesis head, and a live source-decision
   foreign key

Asserts the _absence_ of a sequence. A Go port that "modernises" to `BIGSERIAL`
fails here — correctly.

### `AuditFeedDbTest.kt` — 103 LOC, 3 cases · **DB**

1. lifecycle rows are visible in `recent` and `get`
2. effective namespace round-trips through `recent` and `get` (insertion order,
   INV-A8-5)
3. principal-scoped feed includes owned lifecycle rows before applying the limit
   (INV-A8-4)

### `AuditReadRoutesDbTest.kt` — 322 LOC, 7 cases · **DB + route**

1. 🔒 unauthenticated non-debug list is rejected without authorization
2. 🔒 ordinary principal sees only own rows, and denied detail is
   indistinguishable from missing (INV-A8-6, A8-7)
3. non-numeric audit id is a bad id, not a lookup
4. old decisions route is removed
5. auditor sees every row and can read details
6. auth debug returns all rows and details without authorization or a session
   (INV-A8-8)
7. `requester_ip` from a trusted edge gates the audit-collection read

Case 4 is a **negative route test** (a removed endpoint stays removed) — easy to
lose in a port and worth keeping. Case 7 depends on A12.

### Related suites owned by other areas

`ChannelDecideAuditDbTest` (7 cases) and `DiagnosticsRedactionTest` (5) /
`DiagnosticRedactionDecideDbTest` (2) write and read audit rows but test the
**query decision path** — counted in A6, not here.

### Coverage gaps in A8

- `insert`'s `Math.addExact` id overflow and the two
  `check(executeUpdate() == 1)` guards.
- The `head_hash.size != 32` guard on read (the genesis-corruption case).
- `limit` coercion bounds (`0`, `-1`, `501`, non-numeric) on `/api/audit`.
- `AuditStore.get` for a non-existent id at store level (only via the route).

---

## 5. Open questions

| #   | Question                                                                                                                                                                                                                                                                                 |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | **Where does `canonical-golden.json` live after cutover?** It is currently under `control-plane/src/test/resources/` and read by `auditmon` via a `../../` relative path. Needs a neutral home (e.g. `proto/` or a top-level `testdata/`) plus a one-line change in `canonical_test.go`. |
| Q2  | `AuditEvent.ts` round-trips through Java `Instant.toString()`. Confirm `web/` tolerates fixed-precision RFC3339 before changing it (same question as A2 Q3 — resolve once, apply to both).                                                                                               |
| Q3  | Does anything besides `auditmon` read `audit_event` directly? If so, the `jsonb` list encoding is a second wire contract, not just an internal detail.                                                                                                                                   |
