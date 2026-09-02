package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
)

func ptrStr(s string) *string { return &s }
func ptrI64(v int64) *int64   { return &v }

func decisionEvent(principal, statement string) canon.AuditEvent {
	return canon.AuditEvent{
		Kind:               "decision",
		TSMicros:           canon.EpochMicros(time.Now()),
		Principal:          principal,
		Roles:              []string{"analyst", "on-call"},
		Datasource:         "warehouse",
		ClientAddr:         ptrStr("192.0.2.10"),
		Statement:          statement,
		Decision:           "ALLOW",
		EffectiveNamespace: []string{"public"},
		MaskedColumns:      []string{"users.email"},
		PIITouched:         []string{"pii:email"},
		LatencyMs:          12,
		Channel:            ptrStr("wire"),
		ContextTags:        []string{"in-office"},
	}
}

func completionEvent(decisionID int64) canon.AuditEvent {
	ev := decisionEvent("executor", "completion")
	ev.Kind = "completion"
	ev.RowsReturned = ptrI64(123)
	ev.BytesReturned = ptrI64(4096)
	ev.DecisionID = ptrI64(decisionID)
	return ev
}

func TestTailEventsReadsRowsAndChainColumns(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)

	events := []canon.AuditEvent{decisionEvent("alice", "select 1"), completionEvent(1)}
	lastID, head := dbtest.SeedChain(t, ctx, pool, canon.GenesisHash(), events)

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	got, err := reader.TailEvents(ctx, 0, 10000)
	if err != nil {
		t.Fatalf("tail events: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}

	first := got[0]
	if first.ID != 1 {
		t.Errorf("first id = %d, want 1", first.ID)
	}
	if first.Event.Principal != "alice" {
		t.Errorf("principal = %q, want alice", first.Event.Principal)
	}
	if first.Event.Decision != "ALLOW" || first.Event.Kind != "decision" {
		t.Errorf("decision/kind = %q/%q", first.Event.Decision, first.Event.Kind)
	}
	if first.Event.ClientAddr == nil || *first.Event.ClientAddr != "192.0.2.10" {
		t.Errorf("client_addr = %v", first.Event.ClientAddr)
	}
	if len(first.Event.Roles) != 2 || first.Event.Roles[0] != "analyst" {
		t.Errorf("roles = %v", first.Event.Roles)
	}
	if len(first.Event.PIITouched) != 1 || first.Event.PIITouched[0] != "pii:email" {
		t.Errorf("pii_touched = %v", first.Event.PIITouched)
	}
	if first.ChainVersion == nil || *first.ChainVersion != int32(canon.ChainVersion) {
		t.Errorf("chain_version = %v, want %d", first.ChainVersion, canon.ChainVersion)
	}

	// The stored row_hash must recompute from the read-back event: proof the columns round-tripped exactly.
	recomputed, err := canon.RowHash(first.ID, first.Event, uint32(*first.ChainVersion), first.PrevHash)
	if err != nil {
		t.Fatalf("recompute row hash: %v", err)
	}
	if !bytes.Equal(recomputed, first.RowHash) {
		t.Errorf("recomputed row hash != stored row hash for id 1")
	}

	second := got[1]
	if second.Event.Kind != "completion" {
		t.Errorf("second kind = %q, want completion", second.Event.Kind)
	}
	if second.Event.RowsReturned == nil || *second.Event.RowsReturned != 123 {
		t.Errorf("rows_returned = %v", second.Event.RowsReturned)
	}
	if second.Event.DecisionID == nil || *second.Event.DecisionID != 1 {
		t.Errorf("decision_id = %v", second.Event.DecisionID)
	}

	chainHead, err := reader.ReadChainHead(ctx)
	if err != nil {
		t.Fatalf("read chain head: %v", err)
	}
	if chainHead.LastID != lastID {
		t.Errorf("chain head last_id = %d, want %d", chainHead.LastID, lastID)
	}
	if !bytes.Equal(chainHead.HeadHash, head) {
		t.Errorf("chain head hash mismatch")
	}
}

func TestTailEventsRespectsCursor(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	dbtest.SeedChain(t, ctx, pool, canon.GenesisHash(),
		[]canon.AuditEvent{decisionEvent("a", "q1"), decisionEvent("b", "q2"), decisionEvent("c", "q3")})

	reader, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	got, err := reader.TailEvents(ctx, 2, 10000)
	if err != nil {
		t.Fatalf("tail after cursor: %v", err)
	}
	if len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("tail after id 2 = %+v, want just id 3", got)
	}
}
