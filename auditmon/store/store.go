// Package store is the read-only reader over the committed audit trail. It issues SELECT only; the
// connection is opened with default_transaction_read_only = on as defense in depth, but the real guard is
// the monitor's DB role/IAM (SELECT-only on the audit tables). Nothing here ever writes.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
)

// StoredEvent is one audit_event row: the storage-independent event plus the chain columns needed to
// re-verify it.
type StoredEvent struct {
	ID           int64
	Event        canon.AuditEvent
	ChainVersion *int32
	PrevHash     []byte
	RowHash      []byte
}

// ChainHead is the singleton audit_chain_head row: the write path's append point (coordination only, never
// a trust anchor — verification recomputes from the events themselves).
type ChainHead struct {
	LastID   int64
	HeadHash []byte
}

// Reader reads the committed audit trail. Safe for concurrent use.
type Reader struct {
	pool *pgxpool.Pool
}

// Open connects a read-only pool to the audit database.
func Open(ctx context.Context, dsn string) (*Reader, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Defense in depth: every session refuses writes. SELECT still works; the DB role/IAM is the real guard.
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}
	return &Reader{pool: pool}, nil
}

// Close releases the pool.
func (r *Reader) Close() { r.pool.Close() }

// eventColumns is the fixed, ordered projection every audit_event read scans; TailEvents (the export/verify
// cursor) and EventsSince (the detection window) share it so both decode through the same scanEvents loop.
const eventColumns = `id, ts, principal, roles, datasource, client_addr, statement, decision, failed_stage,
       effective_namespace, masked_columns, pii_touched, latency_ms, detail, channel, context_tags,
       action, resource, outcome, kind, rows_returned, bytes_returned, decision_id,
       chain_version, prev_hash, row_hash`

const tailQuery = `SELECT ` + eventColumns + ` FROM audit_event WHERE id > $1 ORDER BY id LIMIT $2`

const chainedTailQuery = `SELECT ` + eventColumns + `
       FROM audit_event WHERE id > $1 AND chain_version IS NOT NULL ORDER BY id LIMIT $2`

const windowQuery = `SELECT ` + eventColumns + ` FROM audit_event WHERE ts >= $1 ORDER BY id`

// TailEvents returns up to limit audit_events with id greater than afterID, in id order — bounded so a
// long backlog is walked in batches instead of materialized at once. Because id is gap-free and
// commit-ordered, id > cursor cannot skip a late-committing row.
func (r *Reader) TailEvents(ctx context.Context, afterID int64, limit int) ([]StoredEvent, error) {
	rows, err := r.pool.Query(ctx, tailQuery, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: query tail: %w", err)
	}
	return scanEvents(rows)
}

// ChainedEventsAfter returns up to limit audit_events with id greater than afterID that carry a
// chain_version, in id order. It is the from-genesis full-verify read: pre-chain historical rows (chain_version NULL) are
// skipped so a non-greenfield database — where the earliest rows predate the hash chain — is not falsely
// flagged, and the walk begins at the first chained row (whose prev_hash is the pinned genesis).
func (r *Reader) ChainedEventsAfter(ctx context.Context, afterID int64, limit int) ([]StoredEvent, error) {
	rows, err := r.pool.Query(ctx, chainedTailQuery, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: query chained tail: %w", err)
	}
	return scanEvents(rows)
}

// EventsSince returns every audit_event with ts at or after since, in id order. It is the detection window
// read: rate rules recompute over a slice of the durable trail each poll rather than trusting in-memory
// counters, so a restart loses no state and nothing is double-counted. Read-only like the rest of the store.
func (r *Reader) EventsSince(ctx context.Context, since time.Time) ([]StoredEvent, error) {
	rows, err := r.pool.Query(ctx, windowQuery, since)
	if err != nil {
		return nil, fmt.Errorf("store: query window: %w", err)
	}
	return scanEvents(rows)
}

// scanEvents decodes eventColumns rows into StoredEvents and closes the rows. Timestamps collapse to the
// canonical epoch-micros the hash was computed over; the jsonb array columns decode to []string.
func scanEvents(rows pgx.Rows) ([]StoredEvent, error) {
	defer rows.Close()

	var out []StoredEvent
	for rows.Next() {
		var (
			ev     canon.AuditEvent
			ts     time.Time
			roles  []byte
			ns     []byte
			masked []byte
			pii    []byte
			tags   []byte
			se     StoredEvent
		)
		if err := rows.Scan(
			&se.ID,
			&ts,
			&ev.Principal,
			&roles,
			&ev.Datasource,
			&ev.ClientAddr,
			&ev.Statement,
			&ev.Decision,
			&ev.FailedStage,
			&ns,
			&masked,
			&pii,
			&ev.LatencyMs,
			&ev.Detail,
			&ev.Channel,
			&tags,
			&ev.AuthzAction,
			&ev.AuthzResource,
			&ev.Outcome,
			&ev.Kind,
			&ev.RowsReturned,
			&ev.BytesReturned,
			&ev.DecisionID,
			&se.ChainVersion,
			&se.PrevHash,
			&se.RowHash,
		); err != nil {
			return nil, fmt.Errorf("store: scan row: %w", err)
		}
		ev.TSMicros = canon.EpochMicros(ts)
		for _, a := range []struct {
			raw []byte
			dst *[]string
		}{
			{roles, &ev.Roles},
			{ns, &ev.EffectiveNamespace},
			{masked, &ev.MaskedColumns},
			{pii, &ev.PIITouched},
			{tags, &ev.ContextTags},
		} {
			if err := unmarshalStringArray(a.raw, a.dst); err != nil {
				return nil, fmt.Errorf("store: decode json array (row %d): %w", se.ID, err)
			}
		}
		se.Event = ev
		out = append(out, se)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate rows: %w", err)
	}
	return out, nil
}

// MaxEventID returns the highest audit_event id (0 when the table is empty). The tail walk pins it as its
// target before the first page: a walk that cannot reach the target it pinned means rows vanished between
// pages, which must surface as a finding rather than a short, clean-looking read.
func (r *Reader) MaxEventID(ctx context.Context) (int64, error) {
	var id int64
	if err := r.pool.QueryRow(ctx, `SELECT COALESCE(MAX(id), 0) FROM audit_event`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: max event id: %w", err)
	}
	return id, nil
}

// ReadChainHead returns the singleton audit_chain_head row.
func (r *Reader) ReadChainHead(ctx context.Context) (ChainHead, error) {
	var h ChainHead
	err := r.pool.QueryRow(ctx, `SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1`).
		Scan(&h.LastID, &h.HeadHash)
	if err != nil {
		return ChainHead{}, fmt.Errorf("store: read chain head: %w", err)
	}
	return h, nil
}

// unmarshalStringArray decodes a jsonb array of strings; an empty/absent value yields an empty slice.
func unmarshalStringArray(raw []byte, dst *[]string) error {
	if len(raw) == 0 {
		*dst = nil
		return nil
	}
	var vals []string
	if err := json.Unmarshal(raw, &vals); err != nil {
		return err
	}
	*dst = vals
	return nil
}
