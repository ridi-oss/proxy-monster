package verify_test

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
)

func event(principal, statement string) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:               "decision",
		TSMicros:           canon.EpochMicros(time.Now()),
		Principal:          principal,
		Roles:              []string{"analyst"},
		Datasource:         "warehouse",
		Statement:          statement,
		Decision:           "ALLOW",
		EffectiveNamespace: []string{"public"},
	}
}

func openReader(t *testing.T, ctx context.Context, dsn string) *store.Reader {
	t.Helper()
	r, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestVerifyTailIntact(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{event("a", "q1"), event("b", "q2"), event("c", "q3")})
	reader := openReader(t, ctx, dsn)

	// Verifying the whole trail against the genesis-based head (tail from 0) must be clean.
	events, err := reader.TailEvents(ctx, 0, 10000)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	f, err := verify.VerifyTail(store.ChainHead{LastID: 0, HeadHash: genesis}, events)
	if err != nil {
		t.Fatalf("verify tail: %v", err)
	}
	if f != nil {
		t.Fatalf("expected intact chain, got finding %+v", f)
	}
}

func TestVerifyFromGenesisIntact(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{event("a", "q1"), event("b", "q2")})
	reader := openReader(t, ctx, dsn)

	f, err := verify.VerifyFromGenesis(ctx, reader, genesis, nil)
	if err != nil {
		t.Fatalf("verify from genesis: %v", err)
	}
	if f != nil {
		t.Fatalf("expected intact chain, got finding %+v", f)
	}
}

// TestVerifyFromGenesisSkipsPreChainRows confirms the from-genesis walk begins at the first CHAINED row and
// ignores earlier pre-chain (chain_version NULL) historical rows, so a non-greenfield database does not
// false-wedge. Without the chain_version-IS-NOT-NULL filter, the walk would hit row 1 (a null-hash
// historical row) and report a spurious break.
func TestVerifyFromGenesisSkipsPreChainRows(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()

	// Pre-chain historical rows 1..3: no chain columns, as they existed before the hash chain was added.
	for id := int64(1); id <= 3; id++ {
		if _, err := pool.Exec(ctx, `
INSERT INTO audit_event (id, principal, datasource, statement, decision)
VALUES ($1, 'legacy', 'warehouse', 'q', 'ALLOW')`, id); err != nil {
			t.Fatalf("insert pre-chain row %d: %v", id, err)
		}
	}
	// Chained rows 4..6 build on the pinned genesis.
	dbtest.AppendChain(t, ctx, pool, 4, genesis, []canon.AuditEvent{event("a", "q4"), event("b", "q5"), event("c", "q6")})
	reader := openReader(t, ctx, dsn)

	f, err := verify.VerifyFromGenesis(ctx, reader, genesis, nil)
	if err != nil {
		t.Fatalf("verify from genesis: %v", err)
	}
	if f != nil {
		t.Fatalf("expected no finding with pre-chain rows present, got %+v", f)
	}
}

// TestVerifyFromGenesisAnchorHeadMismatch confirms the anchor cross-check catches an internally-consistent
// rewrite: the row-walk passes (every row_hash recomputes and links) but the head recomputed at the
// anchored up_to_id no longer equals the head the anchor witnessed.
func TestVerifyFromGenesisAnchorHeadMismatch(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{event("a", "q1"), event("b", "q2")})
	reader := openReader(t, ctx, dsn)

	// A signed anchor witnessed a DIFFERENT head at id 2 than the trail now recomputes.
	witnessed := []byte("this-is-not-the-real-head-hash!!")
	f, err := verify.VerifyFromGenesis(ctx, reader, genesis, []verify.AnchorCheck{{UpToID: 2, HeadHash: witnessed}})
	if err != nil {
		t.Fatalf("verify from genesis: %v", err)
	}
	if f == nil || f.DivergentID != 2 || f.Reason != verify.ReasonAnchorHeadMismatch {
		t.Fatalf("finding = %+v, want anchor_head_mismatch at id 2", f)
	}
}

// TestVerifyFromGenesisAnchorRowMissing confirms the cross-check catches deletion/truncation below a
// witnessed head: an anchor at an up_to_id the (shorter) chain never reaches.
func TestVerifyFromGenesisAnchorRowMissing(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{event("a", "q1"), event("b", "q2")})
	reader := openReader(t, ctx, dsn)

	// A signed anchor witnessed a head at id 5, but the chain only reaches id 2.
	f, err := verify.VerifyFromGenesis(ctx, reader, genesis, []verify.AnchorCheck{{UpToID: 5, HeadHash: genesis}})
	if err != nil {
		t.Fatalf("verify from genesis: %v", err)
	}
	if f == nil || f.DivergentID != 5 || f.Reason != verify.ReasonAnchorRowMissing {
		t.Fatalf("finding = %+v, want anchor_row_missing at id 5", f)
	}
}

func TestVerifyDetectsMutatedStatement(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{event("a", "q1"), event("b", "q2")})

	// Tamper: change the statement text of row 1 without recomputing its row_hash.
	if _, err := pool.Exec(ctx, "UPDATE audit_event SET statement = 'select secrets' WHERE id = 1"); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	reader := openReader(t, ctx, dsn)

	events, err := reader.TailEvents(ctx, 0, 10000)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	f, err := verify.VerifyTail(store.ChainHead{LastID: 0, HeadHash: genesis}, events)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if f == nil {
		t.Fatal("expected a finding for the mutated statement, got none")
	}
	if f.DivergentID != 1 || f.Reason != verify.ReasonRowHashMismatch {
		t.Fatalf("finding = %+v, want row_hash_mismatch at id 1", f)
	}
}

func TestVerifyDetectsMissingChainVersion(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	// One valid chained row, then a row that chains correctly (prev_hash matches the running head) but
	// carries a NULL chain_version — a pre-chain row surfacing after an anchored head, which must fail
	// closed rather than be silently skipped.
	_, head := dbtest.SeedChain(t, ctx, pool, genesis, []canon.AuditEvent{event("a", "q1")})
	if _, err := pool.Exec(ctx, `
INSERT INTO audit_event (id, principal, datasource, statement, decision, prev_hash, row_hash, chain_version)
VALUES (2, 'b', 'warehouse', 'q2', 'ALLOW', $1, $2, NULL)`,
		head, []byte("unchecked-row-hash")); err != nil {
		t.Fatalf("insert null-version row: %v", err)
	}
	reader := openReader(t, ctx, dsn)

	events, err := reader.TailEvents(ctx, 0, 10000)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	f, err := verify.VerifyTail(store.ChainHead{LastID: 0, HeadHash: genesis}, events)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if f == nil {
		t.Fatal("expected a finding for the null chain_version row, got none")
	}
	if f.DivergentID != 2 || f.Reason != verify.ReasonMissingChainVersion {
		t.Fatalf("finding = %+v, want missing_chain_version at id 2", f)
	}
}

func TestVerifyDetectsDeletedRow(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	genesis := canon.GenesisHash()
	dbtest.SeedChain(t, ctx, pool, genesis,
		[]canon.AuditEvent{event("a", "q1"), event("b", "q2"), event("c", "q3")})

	// Delete the middle row; its successor's stored prev_hash no longer matches the new predecessor.
	if _, err := pool.Exec(ctx, "DELETE FROM audit_event WHERE id = 2"); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	reader := openReader(t, ctx, dsn)

	events, err := reader.TailEvents(ctx, 0, 10000)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	f, err := verify.VerifyTail(store.ChainHead{LastID: 0, HeadHash: genesis}, events)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if f == nil {
		t.Fatal("expected a finding for the deleted row, got none")
	}
	if f.DivergentID != 3 || f.Reason != verify.ReasonPrevHashMismatch {
		t.Fatalf("finding = %+v, want prev_hash_mismatch at id 3", f)
	}
}
