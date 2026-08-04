package app_test

import (
	"context"
	"testing"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	amstore "github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/token"
)

// ---------------------------------------------------------------------------------------------
// CONSUMER CONFORMANCE — auditmon against the Go control-plane.
//
// 🔒 WHY THIS IS NOT COVERED BY THE CANONICAL-BYTES TESTS. Three suites already prove the Go CP and
// auditmon agree on canonicalisation (internal/audit/canon_test.go, internal/conformance/
// audit_canonical_test.go, auditmon/canon/canonical_test.go) — but all three replay a golden FIXTURE.
// None of them takes a chain the Go control-plane actually wrote and runs the REAL auditmon verifier
// over it. That gap is exactly where a port breaks: agreeing on how to hash one hand-authored event
// says nothing about whether the append path links rows in the order the verifier walks them, seeds
// genesis where the verifier expects it, or stores the columns the verifier reads.
//
// auditmon does NOT talk to the control-plane over HTTP or gRPC. It opens the control-plane's Postgres
// directly and walks `audit_event` + `audit_chain_head`, so the contract between them is the SCHEMA and
// the CHAIN, and this is what tests it: drive real decisions through the real gRPC surface, then point
// auditmon's own store.Reader and verify.VerifyFromGenesis at the same database.
//
// The tamper half is what makes the clean half worth anything: a verifier that accepted everything
// would also accept the untampered chain.
// ---------------------------------------------------------------------------------------------

// auditmonReader opens auditmon's OWN store against the control-plane database this app booted on.
// Deliberately auditmon's reader rather than internal/audit's — the point is to exercise the consumer's
// scan/decode of the columns the CP wrote, including its JSON array handling.
func auditmonReader(t *testing.T, b *bootedApp) *amstore.Reader {
	t.Helper()
	dsn := dbtest.Postgres(t).PostgresDSN(b.dbName)
	r, err := amstore.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("auditmon store.Open against the control-plane database: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

// driveAuditedDecisions produces a real audit trail: several wire decisions over a registered
// datasource, each of which the control-plane appends to the hash chain.
//
// It uses the DENY path deliberately — an ungranted principal — because a deny still writes a full
// audit row (INV: "a wire decision must be audited") and needs no policy seeding, so the trail is
// produced by the shortest honest path rather than by inserting rows behind the handler's back.
func driveAuditedDecisions(t *testing.T, f *decideFixture, n int) {
	t.Helper()
	connID := f.open(f.validToken)
	for i := 0; i < n; i++ {
		d, err := f.decide(&pb.DecisionRequest{
			Token: f.validToken, DatasourceName: f.ds.Name, ConnectionId: connID,
			Sql: "select id from t", ClientAddr: "10.9.8.7:5432",
		})
		if err != nil {
			t.Fatalf("Decide #%d: %v", i+1, err)
		}
		if d.GetVerdict() == nil || d.GetVerdict().GetDecisionId() <= 0 {
			t.Fatalf("Decide #%d produced no audited verdict; there would be no chain to verify", i+1)
		}
	}
}

// TestAuditmonVerifiesTheGoControlPlanesChainFromGenesis is the clean-path consumer proof.
func TestAuditmonVerifiesTheGoControlPlanesChainFromGenesis(t *testing.T) {
	f := newDecideFixture(t)
	driveAuditedDecisions(t, f, 5)

	reader := auditmonReader(t, f.b)
	ctx := context.Background()

	// The chain must be non-empty, or "no finding" would be vacuously true.
	events, err := reader.ChainedEventsAfter(ctx, 0)
	if err != nil {
		t.Fatalf("auditmon ChainedEventsAfter: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("auditmon read ZERO chained events from a control-plane that just decided 5 statements — " +
			"either the append path is not writing the chain columns auditmon reads, or its scan failed")
	}

	// 🔒 THE REAL VERIFIER, FROM THE PINNED GENESIS. canon.GenesisHash() is the same constant
	// auditmon's own main.go passes (cmd/auditmon/main.go:117), so this is the production walk.
	finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil)
	if err != nil {
		t.Fatalf("VerifyFromGenesis errored over a Go-CP-written chain: %v", err)
	}
	if finding != nil {
		t.Fatalf("auditmon rejected the Go control-plane's own audit chain: %+v\n"+
			"The CP writes it and auditmon verifies it; a finding here means the two disagree about "+
			"the chain the canonical-bytes fixtures said they agreed on.", *finding)
	}

	// The head the CP maintains must agree with the walk's endpoint.
	head, err := reader.ReadChainHead(ctx)
	if err != nil {
		t.Fatalf("auditmon ReadChainHead: %v", err)
	}
	last := events[len(events)-1]
	if head.LastID != last.ID {
		t.Errorf("audit_chain_head.last_id = %d, but the last chained event is %d — the coordination "+
			"row has drifted from the trail", head.LastID, last.ID)
	}

	// 🔒 THE INCREMENTAL PATH, which is how auditmon actually runs (a poll loop, not a genesis walk on
	// every tick — cmd/auditmon/main.go). VerifyTail starts from the head it snapshotted and walks only
	// the rows appended SINCE, so it is the check that would notice the CP linking a new row onto
	// anything other than the head it just advertised.
	driveAuditedDecisions(t, f, 3)
	appended, err := reader.ChainedEventsAfter(ctx, head.LastID)
	if err != nil {
		t.Fatalf("ChainedEventsAfter(%d): %v", head.LastID, err)
	}
	if len(appended) != 3 {
		t.Fatalf("rows appended after head %d = %d, want 3 — auditmon's incremental read is not "+
			"seeing the control-plane's new decisions", head.LastID, len(appended))
	}
	if tailFinding, err := verify.VerifyTail(head, appended); err != nil {
		t.Fatalf("VerifyTail: %v", err)
	} else if tailFinding != nil {
		t.Errorf("auditmon's incremental tail walk rejected rows the CP appended after the head it "+
			"published: %+v", *tailFinding)
	}
}

// TestAuditmonDetectsATamperedGoControlPlaneRow is the non-vacuity half.
//
// 🔒 WITHOUT THIS, THE TEST ABOVE PROVES NOTHING. A verifier that returned nil unconditionally — or one
// reading columns the CP never populated, so every row looked identically empty — would pass it. Here a
// single field of one already-written row is mutated WITHOUT recomputing its hash, which is exactly the
// shape of a database-level tamper, and auditmon must report it.
func TestAuditmonDetectsATamperedGoControlPlaneRow(t *testing.T) {
	f := newDecideFixture(t)
	driveAuditedDecisions(t, f, 5)

	reader := auditmonReader(t, f.b)
	ctx := context.Background()

	if finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil); err != nil || finding != nil {
		t.Fatalf("the chain must be clean BEFORE the tamper (finding=%v err=%v)", finding, err)
	}

	// Rewrite the principal on the middle row and leave row_hash alone.
	var target int64
	if err := f.b.app.Db.Pool.QueryRow(ctx,
		`SELECT id FROM audit_event ORDER BY id OFFSET 2 LIMIT 1`).Scan(&target); err != nil {
		t.Fatalf("pick a row to tamper: %v", err)
	}
	if _, err := f.b.app.Db.Pool.Exec(ctx,
		`UPDATE audit_event SET principal = 'attacker@example.com' WHERE id = $1`, target); err != nil {
		t.Fatalf("tamper row %d: %v", target, err)
	}

	finding, err := verify.VerifyFromGenesis(ctx, reader, canon.GenesisHash(), nil)
	if err != nil {
		t.Fatalf("VerifyFromGenesis errored after the tamper: %v", err)
	}
	if finding == nil {
		t.Fatal("auditmon did NOT detect a rewritten principal on a Go-CP-written audit row. The chain " +
			"is not protecting the field, or the row_hash preimage omits it — either way the audit " +
			"trail is forgeable.")
	}
	t.Logf("auditmon detected the tamper as expected: %+v", *finding)
}

// TestAuditmonReadsEveryFieldTheGoControlPlaneWrites guards the decode seam specifically.
//
// ⚠️ A verifier can pass while SILENTLY DROPPING fields: if auditmon's scan failed to decode, say, the
// roles JSON array and left it empty on every row, the recomputed hashes would still be internally
// consistent for rows the CP hashed the same way — and the walk would be green while the alerting rules
// downstream saw no roles at all. This asserts the consumer actually recovered the values the CP wrote.
func TestAuditmonReadsEveryFieldTheGoControlPlaneWrites(t *testing.T) {
	f := newDecideFixture(t)
	// A token whose principal is distinctive enough to find, with roles on the row.
	tok := f.issueKind(token.KindUser, "auditmon-fields@example.com", nil)
	connID := f.open(tok.Token)
	if _, err := f.decide(&pb.DecisionRequest{
		Token: tok.Token, DatasourceName: f.ds.Name, ConnectionId: connID,
		Sql: "select id from t", ClientAddr: "10.9.8.7:5432",
	}); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	reader := auditmonReader(t, f.b)
	events, err := reader.ChainedEventsAfter(context.Background(), 0)
	if err != nil {
		t.Fatalf("ChainedEventsAfter: %v", err)
	}

	var found *amstore.StoredEvent
	for i := range events {
		if events[i].Event.Principal == "auditmon-fields@example.com" {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatal("auditmon could not find the decision it should have read; the principal column did " +
			"not survive the CP write → auditmon read round-trip")
	}
	ev := found.Event
	if ev.Datasource != f.ds.Name {
		t.Errorf("datasource = %q, want %q", ev.Datasource, f.ds.Name)
	}
	if ev.Statement == "" {
		t.Error("statement is empty; auditmon's rules match on it")
	}
	if ev.Decision == "" {
		t.Error("decision is empty; every alerting rule keys on it")
	}
	if len(found.RowHash) == 0 {
		t.Error("row_hash did not decode; the chain walk would have nothing to compare")
	}
	if len(found.PrevHash) == 0 {
		t.Error("prev_hash did not decode; the chain would not be linked")
	}
	if found.ChainVersion == nil {
		t.Error("chain_version did not decode; auditmon uses it to pick the canonicalisation")
	}
}
