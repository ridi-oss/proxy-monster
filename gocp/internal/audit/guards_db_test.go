package audit

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// This file closes the four coverage gaps 08-audit.md §4 names explicitly:
//
//   - insert's Math.addExact id overflow;
//   - the two check(executeUpdate() == 1) guards;
//   - the head_hash.size != 32 guard on read (the genesis-corruption case).
//
// (The other two — limit coercion bounds and AuditStore.get for a nonexistent id — are in
// canon_test.go and feed_db_test.go.)
//
// None of these are reachable through the product's own writes, which is exactly why the Kotlin never
// covered them: every one is a "the database is not what we left it" case. They are still the
// difference between failing closed and appending a row onto a chain that no longer verifies, so each
// is provoked here by corrupting the store first.

// TestInsertRejectsAMissingChainHead is `check(rs.next()) { "audit chain head is missing" }`.
//
// Deleting the head is a plausible outcome of a bad restore or a well-meant "clean up the audit
// tables". The append must FAIL rather than treat the absence as "start again from nothing": a second
// chain rooted at a fresh genesis is indistinguishable, to a later verifier, from the first chain
// having been truncated.
func TestInsertRejectsAMissingChainHead(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DELETE FROM audit_chain_head`); err != nil {
		t.Fatalf("delete the chain head: %v", err)
	}
	_, err := s.Insert(ctx, types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow))
	if !errors.Is(err, ErrChainHeadMissing) {
		t.Fatalf("insert error = %v, want %v", err, ErrChainHeadMissing)
	}
}

// TestInsertRejectsAShortChainHeadHash is the `head_hash.size == SHA256_BYTES` guard.
//
// canon.RowHash would reject the short prev_hash anyway, so this looks redundant — it is not. The
// guard fires BEFORE the id is allocated and before anything is hashed, and it names the CHAIN HEAD as
// the corrupt thing. Without it the operator gets "prev_hash must be exactly 32 bytes" from a
// canonicalisation library and has to work backwards to the row that is actually wrong.
func TestInsertRejectsAShortChainHeadHash(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `UPDATE audit_chain_head SET head_hash = decode('00ff', 'hex') WHERE id = 1`); err != nil {
		t.Fatalf("corrupt the chain head hash: %v", err)
	}
	_, err := s.Insert(ctx, types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow))
	if !errors.Is(err, ErrChainHeadHashSize) {
		t.Fatalf("insert error = %v, want %v", err, ErrChainHeadHashSize)
	}

	// Nothing was appended: the guard fires before the INSERT.
	var count int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_event`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Errorf("a corrupt chain head still appended %d rows", count)
	}
}

// TestInsertRejectsAnIdOverflow is Math.addExact(lastId, 1L).
//
// Unreachable in practice — it needs 2^63 appends or a hand-edited head — but the alternative to
// throwing is WRAPPING to Long.MIN_VALUE, and a negative id both collides with nothing and sorts
// before every existing row, so the chain would verify per-row while its order silently inverted.
// Failing the append is the only safe answer.
func TestInsertRejectsAnIdOverflow(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`UPDATE audit_chain_head SET last_id = $1 WHERE id = 1`, int64(math.MaxInt64)); err != nil {
		t.Fatalf("set last_id to Long.MAX_VALUE: %v", err)
	}
	_, err := s.Insert(ctx, types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow))
	if !errors.Is(err, ErrIDOverflow) {
		t.Fatalf("insert error = %v, want %v", err, ErrIDOverflow)
	}
}

// TestInsertRejectsAnEventInsertThatAffectsNoRow is the first
// `check(ps.executeUpdate() == 1)`.
//
// Provoked with a Postgres RULE that swallows the INSERT — the only way to make a plain INSERT report
// zero affected rows. Contrived on purpose: the guard exists for the class of "something rewrote the
// statement" (a rule, an INSTEAD OF trigger on a view, a misconfigured partition route), and its value
// is that the chain head is NOT then advanced to point at a row that was never written.
func TestInsertRejectsAnEventInsertThatAffectsNoRow(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`CREATE RULE audit_event_swallow AS ON INSERT TO audit_event DO INSTEAD NOTHING`); err != nil {
		t.Fatalf("install the swallowing rule: %v", err)
	}
	beforeLastID, beforeHash := chainHead(t, pool)

	_, err := s.Insert(ctx, types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow))
	if !errors.Is(err, ErrInsertNotOneRow) {
		t.Fatalf("insert error = %v, want %v", err, ErrInsertNotOneRow)
	}

	// 🔒 The head must not have moved: Insert's transaction rolls the UPDATE back with the INSERT.
	afterLastID, afterHash := chainHead(t, pool)
	if afterLastID != beforeLastID || !bytes.Equal(beforeHash, afterHash) {
		t.Error("a swallowed INSERT still advanced the chain head")
	}
}

// TestInsertRejectsAChainHeadUpdateThatAffectsNoRow is the second `check(ps.executeUpdate() == 1)`.
//
// The guard that catches a chain head which stopped being writable between the lock and the write. The
// append must fail: an event row whose row_hash the head does not point at is a break in the chain,
// and every later append would link onto a head that never covered it.
func TestInsertRejectsAChainHeadUpdateThatAffectsNoRow(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`CREATE RULE audit_chain_head_swallow AS ON UPDATE TO audit_chain_head DO INSTEAD NOTHING`); err != nil {
		t.Fatalf("install the swallowing rule: %v", err)
	}

	_, err := s.Insert(ctx, types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow))
	if !errors.Is(err, ErrHeadUpdateNotOneRow) {
		t.Fatalf("insert error = %v, want %v", err, ErrHeadUpdateNotOneRow)
	}

	// The whole append rolled back, event row included.
	var count int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_event`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Errorf("a failed head update left %d event rows behind", count)
	}
}

// TestInsertRejectsAnUnparseableTs pins that a bad `ts` fails the append instead of being defaulted to
// now(). The timestamp is field 2 of the hash preimage, so silently substituting one would record a
// decision at an instant it did not happen and the row would still verify — the worst possible
// combination.
func TestInsertRejectsAnUnparseableTs(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	rec := types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow)
	rec.TS = types.Ptr("yesterday afternoon")
	if _, err := s.Insert(ctx, rec); err == nil {
		t.Fatal("an unparseable ts was accepted")
	}

	var count int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_event`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Errorf("an unparseable ts still appended %d rows", count)
	}
}

// TestInsertColumnMappingRoundTrips is the guard against the port's single biggest mechanical hazard:
// JDBC's positional `?` became pgx's `$n`, and a mis-numbered parameter is a SILENT wrong-value bug
// rather than a compile error (internal/store/doc.go).
//
// Every one of the 26 INSERT parameters is given a DISTINCT, type-appropriate value here, and every
// one of the 23 readable columns is compared after a round trip. Two pairs are specifically confusable
// and specifically covered:
//
//   - authzAction/authzResource ⇒ columns `action`/`resource`. The names do not match. Swapping them
//     compiles, stores, reads back, and quietly attributes every management decision to the wrong
//     Cedar action.
//   - the five jsonb lists, whose types are identical, so any permutation of them compiles.
//
// It also re-derives the row hash from the STORED columns, which is what proves the values that went
// into the hash are the values that went into the row.
func TestInsertColumnMappingRoundTrips(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	rec := types.AuditEvent{
		TS:                 types.Ptr("2026-07-01T01:02:03.123456Z"),
		Principal:          "col-principal",
		Roles:              []string{"role-one", "role-two"},
		Datasource:         "col-datasource",
		ClientAddr:         types.Ptr("10.1.2.3"),
		Statement:          "select col_statement",
		Decision:           types.DecisionMask,
		FailedStage:        types.Ptr("lineage"),
		EffectiveNamespace: []string{"ns-first", "ns-second"},
		MaskedColumns:      []string{"masked-col"},
		PIITouched:         []string{"pii-col"},
		LatencyMs:          4242,
		Detail:             types.Ptr("col-detail"),
		Channel:            types.Ptr("editor"),
		ContextTags:        []string{"tag-one"},
		AuthzAction:        types.Ptr("col-authz-action"),
		AuthzResource:      types.Ptr("col-authz-resource"),
		Outcome:            types.Ptr("col-outcome"),
		Kind:               "col-kind",
		RowsReturned:       types.Ptr(int64(11)),
		BytesReturned:      types.Ptr(int64(22)),
	}

	id, err := s.Insert(ctx, rec)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("get(%d) = %v, %v", id, got, err)
	}

	// The store fills id and normalises ts; everything else must come back byte-identical.
	want := rec
	want.ID = &id
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", *got, want)
	}

	// The confusable pair, asserted against the RAW columns as well, because DeepEqual over the DTO
	// would pass just as happily if BOTH the write and the read were swapped consistently.
	var action, resource string
	if err := pool.QueryRow(ctx, `SELECT action, resource FROM audit_event WHERE id = $1`, id).Scan(&action, &resource); err != nil {
		t.Fatalf("read action/resource: %v", err)
	}
	if action != "col-authz-action" {
		t.Errorf("column `action` = %q, want the DTO's authzAction", action)
	}
	if resource != "col-authz-resource" {
		t.Errorf("column `resource` = %q, want the DTO's authzResource", resource)
	}

	// And the hash covers exactly what was stored.
	mustVerifyWalk(t, pool)
}

// TestNullableBigintsAreStoredAsSqlNull is setNull(…, Types.BIGINT): an unset rowsReturned is SQL
// NULL, not 0. The distinction is on the wire (the field is absent, not `0`) and in the hash (0xFFFFFFFF
// versus an eight-byte zero), so a store that defaulted them would change every decision row's hash.
func TestNullableBigintsAreStoredAsSqlNull(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	id, err := s.Insert(ctx, types.NewAuditEvent("p", "d", "select 1", types.DecisionAllow))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	assertNullColumns(t, pool, id,
		"client_addr", "failed_stage", "detail", "channel", "action", "resource", "outcome",
		"rows_returned", "bytes_returned", "decision_id")

	got, err := s.Get(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.RowsReturned != nil || got.BytesReturned != nil || got.DecisionID != nil {
		t.Error("a nullable bigint read back as non-nil")
	}
	// The five list columns are the opposite case: never null, always [].
	for _, list := range [][]string{got.Roles, got.EffectiveNamespace, got.MaskedColumns, got.PIITouched, got.ContextTags} {
		if list == nil {
			t.Error("a list column read back as nil — it must be []")
		}
	}
}

func assertNullColumns(t *testing.T, pool *pgxpool.Pool, id int64, columns ...string) {
	t.Helper()
	for _, col := range columns {
		var isNull bool
		if err := pool.QueryRow(context.Background(),
			`SELECT `+col+` IS NULL FROM audit_event WHERE id = $1`, id).Scan(&isNull); err != nil {
			t.Fatalf("read %s: %v", col, err)
		}
		if !isNull {
			t.Errorf("column %s is not NULL for an unset field", col)
		}
	}
}
