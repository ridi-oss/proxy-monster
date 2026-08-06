package audit

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// TestCleanStoreHasNoIdSequenceAGenesisHeadAndALiveSourceDecisionFK is AuditTrailSchemaDbTest's single
// case (docs/audit-trail-hardening.md).
//
// 🔒 INV-A8-1, asserted as an ABSENCE. `pg_get_serial_sequence('audit_event','id')` must be NULL and
// the column must have no default. This is the test a "modernising" port fails, and failing it is the
// correct outcome: a BIGSERIAL can hand out an id out of chain order, and then id order and chain
// order disagree while every row still verifies individually. The lock, not the database, allocates
// ids here.
//
// The rest of the case is the surrounding structure the chain depends on: the table and its ts index
// exist, the chain head is exactly one row at (1, 0, genesis), the FIRST append chains onto genesis
// and stamps chain_version, and access_request.source_decision_id is a REAL foreign key — a task may
// cite a recorded decision, never an imaginary one.
//
// KT: AuditTrailSchemaDbTest.kt#a clean store has no id sequence a genesis head and a live source-decision foreign key
func TestCleanStoreHasNoIdSequenceAGenesisHeadAndALiveSourceDecisionFK(t *testing.T) {
	db, _ := dbtest.MigratedStore(t)
	pool := db.Pool
	ctx := context.Background()

	var tableExists, indexExists bool
	if err := pool.QueryRow(ctx,
		`SELECT to_regclass('audit_event') IS NOT NULL, to_regclass('idx_audit_event_ts') IS NOT NULL`,
	).Scan(&tableExists, &indexExists); err != nil {
		t.Fatalf("check audit_event objects: %v", err)
	}
	if !tableExists {
		t.Error("audit_event does not exist")
	}
	if !indexExists {
		t.Error("idx_audit_event_ts does not exist")
	}

	// 🔒 No sequence and no default.
	var serialSequence *string
	if err := pool.QueryRow(ctx, `SELECT pg_get_serial_sequence('audit_event', 'id')`).Scan(&serialSequence); err != nil {
		t.Fatalf("check id sequence: %v", err)
	}
	if serialSequence != nil {
		t.Errorf("audit_event.id has sequence %q — ids must be application-allocated (INV-A8-1)", *serialSequence)
	}
	var columnDefault *string
	if err := pool.QueryRow(ctx,
		`SELECT column_default FROM information_schema.columns
		  WHERE table_schema = current_schema() AND table_name = 'audit_event' AND column_name = 'id'`,
	).Scan(&columnDefault); err != nil {
		t.Fatalf("check id default: %v", err)
	}
	if columnDefault != nil {
		t.Errorf("audit_event.id has default %q — ids must be application-allocated (INV-A8-1)", *columnDefault)
	}

	// The genesis head: exactly one row, last_id 0, head_hash = SHA-256("pm-audit-genesis").
	rows, err := pool.Query(ctx, `SELECT id, last_id, head_hash FROM audit_chain_head`)
	if err != nil {
		t.Fatalf("read chain head: %v", err)
	}
	count := 0
	for rows.Next() {
		count++
		var id int32
		var lastID int64
		var headHash []byte
		if err := rows.Scan(&id, &lastID, &headHash); err != nil {
			t.Fatalf("scan chain head: %v", err)
		}
		if id != 1 {
			t.Errorf("chain head id = %d, want 1", id)
		}
		if lastID != 0 {
			t.Errorf("chain head last_id = %d, want 0", lastID)
		}
		if !bytes.Equal(headHash, genesisHash()) {
			t.Error("chain head hash is not the genesis hash")
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read chain head: %v", err)
	}
	if count != 1 {
		t.Errorf("audit_chain_head has %d rows — the chain head is a single row", count)
	}

	// The first appended event chains onto genesis and gets id 1 (no sequence to skip ahead).
	s := New(pool)
	rec := types.NewAuditEvent("new-event", "audit-schema-ds", "select 3", types.DecisionAllow)
	rec.TS = types.Ptr("2026-07-01T00:00:00.123456Z")
	firstChained, err := s.Insert(ctx, rec)
	if err != nil {
		t.Fatalf("insert first chained event: %v", err)
	}
	if firstChained != 1 {
		t.Errorf("first chained id = %d, want 1", firstChained)
	}
	var chainVersion int32
	var prevHash []byte
	if err := pool.QueryRow(ctx,
		`SELECT chain_version, prev_hash FROM audit_event WHERE id = $1`, firstChained,
	).Scan(&chainVersion, &prevHash); err != nil {
		t.Fatalf("read the first chained row: %v", err)
	}
	if chainVersion != int32(ChainVersion) {
		t.Errorf("chain_version = %d, want %d", chainVersion, ChainVersion)
	}
	if !bytes.Equal(prevHash, genesisHash()) {
		t.Error("the first chained row does not link to genesis")
	}

	// source_decision_id is a real FK. A task may point at a RECORDED decision …
	var datasourceID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO datasource (name, engine, host, port, db_name)
		 VALUES ('audit-schema-ds', 'postgres', 'localhost', 5432, 'app') RETURNING id`,
	).Scan(&datasourceID); err != nil {
		t.Fatalf("seed datasource: %v", err)
	}
	requestID := seedAccessRequest(t, pool, datasourceID, firstChained)
	var storedDecisionID int64
	if err := pool.QueryRow(ctx,
		`SELECT source_decision_id FROM access_request WHERE id = $1`, requestID,
	).Scan(&storedDecisionID); err != nil {
		t.Fatalf("read source_decision_id: %v", err)
	}
	if storedDecisionID != firstChained {
		t.Errorf("source_decision_id = %d, want %d", storedDecisionID, firstChained)
	}

	// … and never at a nonexistent one.
	if _, err := pool.Exec(ctx,
		`INSERT INTO access_request (principal, kind, datasource_id, status, reason, source_decision_id)
		 VALUES ('requester', 'QUERY', $1, 'PENDING', 'need it', $2)`, datasourceID, int64(math.MaxInt64),
	); err == nil {
		t.Error("access_request accepted a nonexistent source_decision_id")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Errorf("want SQLSTATE 23503, got %v", err)
		}
	}
}

func seedAccessRequest(t *testing.T, pool *pgxpool.Pool, datasourceID, sourceDecisionID int64) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO access_request (principal, kind, datasource_id, status, reason, source_decision_id)
		 VALUES ('requester', 'QUERY', $1, 'PENDING', 'need it', $2) RETURNING id`,
		datasourceID, sourceDecisionID,
	).Scan(&id); err != nil {
		t.Fatalf("seed access_request: %v", err)
	}
	return id
}
