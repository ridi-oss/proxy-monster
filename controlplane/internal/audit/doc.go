// Package audit is the tamper-evident audit trail: the chain-linked append, the read surface, and the
// visibility model the two read routes are built on. It is the Go equivalent of AuditStore.kt (191
// LOC) plus the store half of AuditRoutes.kt (67 LOC).
//
// Area doc: plans/proxy-monster-go-port/08-audit.md.
//
// # The canonical bytes are NOT here
//
// AuditCanonical.kt is already ported, in Go, outside this module: auditmon/canon. That package and
// the Kotlin are frozen against ONE shared golden-vector suite
// (control-plane/src/test/resources/atrail/canonical-golden.json), so a third implementation here
// would be a third thing to keep in sync and the first one to drift. 08-audit.md §2's port action is
// literal: "import auditmon/canon, delete the Kotlin". This package imports it.
//
// What this package DOES own is the conversion: canon.AuditEvent is a storage-independent shape with
// TSMicros int64 and Decision string, while internal/types.AuditEvent is the WIRE shape with TS *string
// and a validated types.Decision. ToCanon is that adapter and TestGoldenVectorsThroughTypesAuditEvent
// runs the same fixture through it, so the conversion is pinned by the same bytes the Kotlin is.
//
// # The three invariants that make the chain a chain
//
// 🔒 INV-A8-1 — the `FOR UPDATE` lock on audit_chain_head is the ONLY thing serialising appends, and
// ids are APPLICATION-ALLOCATED. There is no sequence: V4__audit.sql declares `id BIGINT PRIMARY KEY`
// with no default, and TestCleanStoreHasNoIdSequence asserts its absence exactly as
// AuditTrailSchemaDbTest does. A port that "modernises" to BIGSERIAL fails that test, correctly — a
// sequence can hand out an id out of chain order, and then id order and chain order disagree.
//
// 🔒 INV-A8-2 — the timestamp is truncated to MICROSECONDS BEFORE it is hashed, because Postgres
// timestamptz is microsecond-precision and the value hashed has to be the value stored. Hashing
// nanoseconds and storing micros makes every row fail verification, which reads as tampering.
//
// 🔒 INV-A8-4 — recent(limit, principal) puts `WHERE principal` in SQL, BEFORE the limit. Fetching
// `limit` rows and filtering afterwards returns fewer than `limit` owned rows whenever another
// principal's rows are newer.
//
// # The visibility model (Reader)
//
// 🔒 INV-A8-6 — denied and missing are DELIBERATELY indistinguishable: both are "audit record not
// found". [Reader.Detail] returns (nil, nil) for both, so the HTTP layer physically cannot tell them
// apart and cannot leak "exists but you may not see it".
//
// 🔒 INV-A8-7 — a denied COLLECTION read degrades to own-rows; it does not 403. The two-tier model
// (own rows always, the whole log by grant) is the contract, not a fallback.
//
// # Increment status
//
// Landed: Store (Insert / InsertOn / Recent / RecentForPrincipal / Get), the canon conversion, and
// Reader — the store half of both read routes, including CoerceLimit.
//
// TODO(A1): the HTTP half of AuditRoutes.kt — requireApi, userSession(), idParam()/badId(),
// notFound("audit record"), and the response encoding through types.MarshalWire. Three
// AuditReadRoutesDbTest cases live entirely there and are NOT ported here: case 1 (unauthenticated
// non-debug list is 401 common.unauthenticated with zero role lookups), case 3 (a non-numeric id is
// common.bad_id, not a lookup) and case 4 (the old /api/decisions route stays removed).
//
// TODO(A1): /api/ingest/decision — the proxy's ingest route that calls Store.Insert. 01-bootstrap.md
// §3 owns its decode behaviour (a missing required field is a 500 common.fallback, not a 400).
//
// TODO(A6)/TODO(A7): decideQuery and the approval lifecycle are the two big callers of InsertOn, which
// exists precisely so an audit row commits atomically with the state change it describes.
package audit
