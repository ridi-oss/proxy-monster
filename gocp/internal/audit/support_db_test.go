package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// newStore is the Go twin of the Kotlin suites' four setup lines
// (`SharedPostgres.freshDatabase(...)` + Flyway + `AuditStore(dataSource)`), with one deliberate
// improvement recorded in dbtest's doc: the migrations run through the PRODUCTION runner, not Flyway.
//
// One fresh logical database per test, not one per suite. The Kotlin uses @TestInstance(PER_CLASS) and
// shares a database across a whole file's cases, which is why several of its cases have to reason
// about rows other cases left behind (see AuditChainDbTest's verifyWalk, which anchors on
// MIN(id) rather than on 1). Per-test isolation is strictly stronger and costs nothing here — the
// expensive thing is the container, and that is shared.
func newStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return New(db.Pool), db.Pool
}

// genesisHash is V4__audit.sql's seeded head — SHA-256("pm-audit-genesis"). Taken from canon rather
// than re-pasted as a hex literal, so the three places that need it (the migration, canon and these
// tests) cannot drift to two values.
func genesisHash() []byte { return canon.GenesisHash() }

// persistedRow is AuditChainDbTest's PersistedRow: everything needed to recompute a row's hash from
// storage alone, which is the whole point of the format.
type persistedRow struct {
	id       int64
	tsMicros int64
	event    types.AuditEvent
	version  int32
	prevHash []byte
	rowHash  []byte
}

// readRows reads the chained rows straight out of audit_event — deliberately NOT through Store.Recent.
//
// 🔒 A verification walk that reads through the code under test proves only that the code agrees with
// itself. This reads the raw columns, including the three the AUDIT_SELECT projection omits
// (chain_version, prev_hash, row_hash), and rebuilds the event from them.
func readRows(t *testing.T, pool *pgxpool.Pool, ids []int64) []persistedRow {
	t.Helper()
	ctx := context.Background()

	const cols = `SELECT id, ts, principal, roles, datasource, client_addr, statement, decision, failed_stage,
                      effective_namespace, masked_columns, pii_touched, latency_ms, detail, channel, context_tags,
                      action, resource, outcome, kind, rows_returned, bytes_returned, decision_id,
                      chain_version, prev_hash, row_hash
               FROM audit_event `
	sql := cols + `WHERE row_hash IS NOT NULL ORDER BY id`
	var args []any
	if ids != nil {
		sql = cols + `WHERE id = ANY($1) ORDER BY id`
		args = append(args, ids)
	}

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		t.Fatalf("read persisted rows: %v", err)
	}
	defer rows.Close()

	var out []persistedRow
	for rows.Next() {
		var (
			r                  persistedRow
			id                 int64
			ts                 time.Time
			principal          string
			roles              string
			datasource         string
			clientAddr         *string
			statement          string
			decision           string
			failedStage        *string
			effectiveNamespace string
			maskedColumns      string
			piiTouched         string
			latencyMs          int64
			detail             *string
			channel            *string
			contextTags        string
			authzAction        *string
			authzResource      *string
			outcome            *string
			kind               string
			rowsReturned       *int64
			bytesReturned      *int64
			decisionID         *int64
		)
		if err := rows.Scan(&id, &ts, &principal, &roles, &datasource, &clientAddr, &statement, &decision,
			&failedStage, &effectiveNamespace, &maskedColumns, &piiTouched, &latencyMs, &detail, &channel,
			&contextTags, &authzAction, &authzResource, &outcome, &kind, &rowsReturned, &bytesReturned,
			&decisionID, &r.version, &r.prevHash, &r.rowHash); err != nil {
			t.Fatalf("scan persisted row: %v", err)
		}
		d, err := types.ParseDecision(decision)
		if err != nil {
			t.Fatalf("row %d: %v", id, err)
		}
		r.id = id
		r.tsMicros = EpochMicros(ts)
		r.event = types.AuditEvent{
			ID:                 &id,
			TS:                 types.Ptr(FormatInstant(ts)),
			Principal:          principal,
			Roles:              mustDecodeList(t, roles),
			Datasource:         datasource,
			ClientAddr:         clientAddr,
			Statement:          statement,
			Decision:           d,
			FailedStage:        failedStage,
			EffectiveNamespace: mustDecodeList(t, effectiveNamespace),
			MaskedColumns:      mustDecodeList(t, maskedColumns),
			PIITouched:         mustDecodeList(t, piiTouched),
			LatencyMs:          latencyMs,
			Detail:             detail,
			Channel:            channel,
			ContextTags:        mustDecodeList(t, contextTags),
			AuthzAction:        authzAction,
			AuthzResource:      authzResource,
			Outcome:            outcome,
			Kind:               kind,
			RowsReturned:       rowsReturned,
			BytesReturned:      bytesReturned,
			DecisionID:         decisionID,
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read persisted rows: %v", err)
	}
	return out
}

func mustDecodeList(t *testing.T, raw string) []string {
	t.Helper()
	list, err := decodeList(&raw)
	if err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return list
}

func chainHead(t *testing.T, pool *pgxpool.Pool) (int64, []byte) {
	t.Helper()
	var lastID int64
	var headHash []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1`).Scan(&lastID, &headHash); err != nil {
		t.Fatalf("read chain head: %v", err)
	}
	return lastID, headHash
}

// verifyWalk is AuditChainDbTest's verifyWalk: walk every chained row in id order, assert each links
// to its predecessor (the first to genesis), assert each row's stored hash is REPRODUCIBLE from its
// stored columns, and assert the chain head matches the last row.
//
// It returns an error instead of failing the test, because case 4 asserts that it FAILS after a
// tamper — the Kotlin's `assertFailsWith<AssertionError> { verifyWalk() }`.
func verifyWalk(t *testing.T, pool *pgxpool.Pool) error {
	t.Helper()
	rows := readRows(t, pool, nil)

	var chainStartID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(MIN(id), 1) FROM audit_event WHERE row_hash IS NOT NULL`).Scan(&chainStartID); err != nil {
		t.Fatalf("read chain start: %v", err)
	}
	baseLastID := chainStartID - 1
	genesis := genesisHash()

	for i, row := range rows {
		expectedPrev := genesis
		if i > 0 {
			expectedPrev = rows[i-1].rowHash
		}
		if !bytes.Equal(expectedPrev, row.prevHash) {
			return failf("chain link at %d: prev_hash %s, want %s", row.id, hex.EncodeToString(row.prevHash), hex.EncodeToString(expectedPrev))
		}
		if row.version != int32(ChainVersion) {
			return failf("chain version at %d: %d, want %d", row.id, row.version, ChainVersion)
		}
		want, err := RowHash(row.id, row.event, row.tsMicros, row.prevHash)
		if err != nil {
			return failf("row hash at %d: %v", row.id, err)
		}
		if !bytes.Equal(want, row.rowHash) {
			return failf("row hash at %d: stored %s, recomputed %s", row.id, hex.EncodeToString(row.rowHash), hex.EncodeToString(want))
		}
	}

	lastID, headHash := chainHead(t, pool)
	wantLastID := baseLastID
	wantHead := genesis
	if len(rows) > 0 {
		wantLastID = rows[len(rows)-1].id
		wantHead = rows[len(rows)-1].rowHash
	}
	if lastID != wantLastID {
		return failf("chain head last_id = %d, want %d", lastID, wantLastID)
	}
	if !bytes.Equal(headHash, wantHead) {
		return failf("chain head hash = %s, want %s", hex.EncodeToString(headHash), hex.EncodeToString(wantHead))
	}
	return nil
}

func mustVerifyWalk(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := verifyWalk(t, pool); err != nil {
		t.Fatalf("verify walk: %v", err)
	}
}

// failf is the verification walk's "this chain does not verify" signal. It is a plain error, not a
// t.Fatalf, so case 4 can assert the walk fails after a tamper instead of the tamper crashing the run.
func failf(format string, args ...any) error { return fmt.Errorf(format, args...) }
