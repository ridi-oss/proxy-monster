package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The five failure messages AuditStore.kt raises through Kotlin `check`/`Math.addExact`. They are
// exported and pre-built because an operator reads them out of a crash log and because the two
// executeUpdate guards are, per 08-audit.md §4, a named coverage gap this port closes with tests that
// match on exactly these values.
var (
	// ErrChainHeadMissing is `check(rs.next()) { "audit chain head is missing" }` — audit_chain_head
	// has no id = 1 row. Unreachable through the migrations (V4 seeds genesis); reachable if someone
	// deleted it, and then appending must FAIL rather than start a second chain from nothing.
	ErrChainHeadMissing = errors.New("audit chain head is missing")
	// ErrChainHeadHashSize is the head_hash width guard. A 31-byte head would produce a hash over a
	// short preimage that no verifier could reproduce, so it fails closed at read time.
	ErrChainHeadHashSize = fmt.Errorf("audit chain head hash must be exactly %d bytes", sha256Bytes)
	// ErrIDOverflow is Math.addExact(lastId, 1L)'s ArithmeticException. Java's message is exactly
	// "long overflow"; it is reproduced so a log line means the same thing in both runtimes.
	ErrIDOverflow = errors.New("long overflow")
	// ErrInsertNotOneRow is `check(ps.executeUpdate() == 1)` on the event INSERT.
	ErrInsertNotOneRow = errors.New("audit event insert did not affect exactly one row")
	// ErrHeadUpdateNotOneRow is `check(ps.executeUpdate() == 1)` on the chain-head UPDATE. It is the
	// guard that catches a chain head that vanished between the lock and the write.
	ErrHeadUpdateNotOneRow = errors.New("audit chain head update did not affect exactly one row")
)

// chainHeadLockSQL is AuditStore.kt's CHAIN_HEAD_LOCK_SQL, verbatim.
//
// 🔒 INV-A8-1 — `FOR UPDATE` is the whole serialisation mechanism. Held until the enclosing
// transaction commits, it is what stops two concurrent appends claiming the same newId or linking to
// the same prev_hash. Drop it and TestConcurrentAppendsSerialize fails; drop it in production and the
// chain silently forks. Ids are application-allocated: there is NO sequence to fall back on.
const chainHeadLockSQL = `SELECT last_id, head_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE`

// chainHeadUpdateSQL is CHAIN_HEAD_UPDATE_SQL with JDBC's positional `?` rewritten to pgx's `$n`.
const chainHeadUpdateSQL = `UPDATE audit_chain_head SET last_id = $1, head_hash = $2 WHERE id = 1`

// insertSQL is INSERT_SQL: 26 columns, 26 parameters, five of them cast `::jsonb`.
//
// F16: REPRODUCED. 00-INDEX.md:195 records that the Kotlin binds JSON columns two different ways —
// `PGobject(type="jsonb")` in QueryResultStore.completeRun and these `?::jsonb` casts here — and
// 00-INDEX.md:373 rules BOTH are REPRODUCE, unified only after cutover. So this keeps the casts and
// passes JSON text, rather than leaning on pgx's OID inference (which is the PGobject idiom's
// analogue and belongs to the OTHER call site).
//
// ⚠️ The `?`→`$n` rewrite is the single biggest mechanical hazard in the port (internal/store/doc.go):
// a mis-numbered parameter is a SILENT wrong-value bug, not a compile error. The ordinals below are
// the Kotlin's setter indices 1..26 in order, and TestInsertColumnMappingRoundTrips populates all 26
// with distinct values so a swap fails a test rather than shipping.
const insertSQL = `
            INSERT INTO audit_event
                (id, ts, principal, roles, datasource, client_addr, statement, decision,
                 failed_stage, masked_columns, pii_touched, latency_ms, detail, effective_namespace,
                 channel, context_tags, action, resource, outcome, kind, rows_returned, bytes_returned,
                 decision_id, chain_version, prev_hash, row_hash)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13, $14::jsonb,
                    $15, $16::jsonb, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
        `

// auditSelect is AUDIT_SELECT: the 23 business columns, in the order toRecord() reads them.
//
// ⚠️ Note columns `action`/`resource` carry the DTO fields authzAction/authzResource. The names do not
// match and the trap is real — 08-audit.md §1 calls it out explicitly.
const auditSelect = `SELECT id, ts, principal, roles, datasource, client_addr, statement, decision,
                      failed_stage, masked_columns, pii_touched, latency_ms, detail, effective_namespace,
                      channel, context_tags, action, resource, outcome, kind, rows_returned, bytes_returned,
                      decision_id
               FROM audit_event`

// Store is plain-pgx persistence for audit events — the port of `class AuditStore(dataSource)`.
//
// It holds a store.DB (the pool) rather than a connection: Recent/Get run on it directly, exactly as
// the Kotlin's `dataSource.connection.use { … }` does, and Insert wraps it in store.InTx.
type Store struct {
	db store.DB
}

// New builds an audit Store over the control-plane pool. `AuditStore(dataSource)`.
func New(db store.DB) *Store { return &Store{db: db} }

// Insert appends one audit event in its OWN transaction and returns its app-allocated id.
// `fun insert(rec: AuditEvent): Long = dataSource.inTx { insert(it, rec) }`.
//
// The transaction is not decoration: the chain-head row lock InsertOn takes is released at commit, so
// without one the lock would end at the first statement and two concurrent appends could claim the
// same id.
func (s *Store) Insert(ctx context.Context, rec types.AuditEvent) (int64, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (int64, error) {
		return s.InsertOn(ctx, tx, rec)
	})
}

// InsertOn appends on a CALLER-PROVIDED handle, so an audit event can commit atomically with the state
// change it describes. `fun insert(conn: Connection, rec: AuditEvent): Long`.
//
// The caller owns commit and rollback, and failures propagate so the enclosing operation fails closed.
// AuditChainDbTest case 2 pins both halves: a committed append is readable and linked; a rolled-back
// one leaves BOTH the event and the chain head untouched. That is only true because this method opens
// no transaction of its own — reimplementing it to do so breaks the atomicity its callers exist for.
//
// c is a store.Queryer, not a pgx.Tx, mirroring the Kotlin extension sitting on Connection. That
// carries the Kotlin's hazard across intact: handing it the pool runs each statement on its own
// implicit transaction, so the FOR UPDATE lock is released immediately and the append is no longer
// serialised — exactly what passing an autoCommit Connection does in the Kotlin. Callers who want the
// safe shape call Insert.
//
// The step order is AuditStore.kt:31-79 and is load-bearing:
//
//  1. lock the chain head, read (last_id, head_hash);
//  2. overflow-checked id increment;
//  3. resolve the instant and TRUNCATE TO MICROS (INV-A8-2) — before any hashing;
//  4. row hash over (newId, event, tsMicros, headHash);
//  5. INSERT the 26 columns, exactly one row;
//  6. UPDATE the chain head to (newId, rowHash), exactly one row.
func (s *Store) InsertOn(ctx context.Context, c store.Queryer, rec types.AuditEvent) (int64, error) {
	var lastID int64
	var headHash []byte
	if err := c.QueryRow(ctx, chainHeadLockSQL).Scan(&lastID, &headHash); err != nil {
		// `check(rs.next())` — an empty result set, not a query failure.
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrChainHeadMissing
		}
		return 0, err
	}
	if len(headHash) != sha256Bytes {
		return 0, ErrChainHeadHashSize
	}

	// Math.addExact(lastId, 1L): overflow THROWS rather than wrapping to a negative id that would
	// collide with the primary key and reorder the chain.
	if lastID == math.MaxInt64 {
		return 0, ErrIDOverflow
	}
	newID := lastID + 1

	// INV-A8-3: rec.ts is honoured when supplied (proxy ingest sets it) and filled with "now" when nil.
	instant := TruncateToMicros(time.Now())
	if rec.TS != nil {
		parsed, err := ParseInstant(*rec.TS)
		if err != nil {
			return 0, err
		}
		instant = TruncateToMicros(parsed)
	}
	tsMicros := EpochMicros(instant)

	rowHash, err := RowHash(newID, rec, tsMicros, headHash)
	if err != nil {
		return 0, err
	}

	tag, err := c.Exec(ctx, insertSQL,
		newID,                            // $1  id
		instant,                          // $2  ts            (the TRUNCATED instant, INV-A8-2)
		rec.Principal,                    // $3  principal
		jsonList(rec.Roles),              // $4  roles::jsonb
		rec.Datasource,                   // $5  datasource
		rec.ClientAddr,                   // $6  client_addr
		rec.Statement,                    // $7  statement
		string(rec.Decision),             // $8  decision      (Decision.name)
		rec.FailedStage,                  // $9  failed_stage
		jsonList(rec.MaskedColumns),      // $10 masked_columns::jsonb
		jsonList(rec.PIITouched),         // $11 pii_touched::jsonb
		rec.LatencyMs,                    // $12 latency_ms
		rec.Detail,                       // $13 detail
		jsonList(rec.EffectiveNamespace), // $14 effective_namespace::jsonb
		rec.Channel,                      // $15 channel
		jsonList(rec.ContextTags),        // $16 context_tags::jsonb
		rec.AuthzAction,                  // $17 action        ⚠️ authzAction, not "action" on the DTO
		rec.AuthzResource,                // $18 resource      ⚠️ authzResource
		rec.Outcome,                      // $19 outcome
		rec.Kind,                         // $20 kind
		rec.RowsReturned,                 // $21 rows_returned   (nil ⇒ SQL NULL, setNull(Types.BIGINT))
		rec.BytesReturned,                // $22 bytes_returned
		rec.DecisionID,                   // $23 decision_id
		int32(ChainVersion),              // $24 chain_version   (Kotlin setInt)
		headHash,                         // $25 prev_hash
		rowHash,                          // $26 row_hash
	)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() != 1 {
		return 0, ErrInsertNotOneRow
	}

	tag, err = c.Exec(ctx, chainHeadUpdateSQL, newID, rowHash)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() != 1 {
		return 0, ErrHeadUpdateNotOneRow
	}
	return newID, nil
}

// Recent returns the most recent events first, for a caller authorised to read the WHOLE log.
// `fun recent(limit: Int): List<AuditEvent>`.
func (s *Store) Recent(ctx context.Context, limit int) ([]types.AuditEvent, error) {
	const sql = auditSelect + `
            ORDER BY ts DESC
            LIMIT $1`
	// int32, not int: the Kotlin binds with setInt, and the limit is already clamped to [1, 500].
	return s.query(ctx, sql, int32(limit))
}

// RecentForPrincipal returns the most recent events OWNED BY principal.
// `fun recent(limit: Int, principal: String): List<AuditEvent>`.
//
// 🔒 INV-A8-4 — `WHERE principal = $1` is in the SQL, ahead of the LIMIT. Reading `limit` rows and
// filtering in Go would return fewer than `limit` owned rows whenever another principal's rows are
// newer, which is how an ordinary user's own audit feed silently goes empty on a busy system.
// TestPrincipalScopedFeedFiltersBeforeLimit pins it with a limit of 1 and a newer foreign row.
func (s *Store) RecentForPrincipal(ctx context.Context, limit int, principal string) ([]types.AuditEvent, error) {
	const sql = auditSelect + `
            WHERE principal = $1
            ORDER BY ts DESC
            LIMIT $2`
	return s.query(ctx, sql, principal, int32(limit))
}

// Get returns one event by id, or (nil, nil) when there is no such row. `fun get(id: Long): AuditEvent?`.
func (s *Store) Get(ctx context.Context, id int64) (*types.AuditEvent, error) {
	const sql = auditSelect + `
            WHERE id = $1`
	out, err := s.query(ctx, sql, id)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

// query runs one of the three AUDIT_SELECT shapes and materialises every row through toRecord.
func (s *Store) query(ctx context.Context, sql string, args ...any) ([]types.AuditEvent, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// ArrayList<AuditEvent>() — an empty, non-nil result, so a caller marshalling it gets [] and not
	// null (INV-A1-4 applies to the response body as much as to the record).
	out := []types.AuditEvent{}
	for rows.Next() {
		rec, err := toRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// toRecord is `private fun ResultSet.toRecord(): AuditEvent`.
//
// Two details are carried across deliberately:
//
//   - `ts` is rendered with FormatInstant, i.e. Java's variable-precision Instant.toString(). Wire-
//     visible; see FormatInstant.
//   - `longOrNull(column)` — the JDBC `getLong` + `wasNull()` idiom for a nullable bigint — is a *int64
//     here, which is the direct equivalent and needs no helper.
//
// Decision goes through types.ParseDecision, the analogue of Decision.valueOf: an unknown name in the
// column is an ERROR, not a silently-accepted verdict. The Kotlin throws IllegalArgumentException out
// of the read for the same reason.
func toRecord(rows pgx.Rows) (types.AuditEvent, error) {
	var (
		id                 int64
		ts                 *time.Time
		principal          string
		roles              *string
		datasource         string
		clientAddr         *string
		statement          string
		decision           string
		failedStage        *string
		maskedColumns      *string
		piiTouched         *string
		latencyMs          int64
		detail             *string
		effectiveNamespace *string
		channel            *string
		contextTags        *string
		authzAction        *string
		authzResource      *string
		outcome            *string
		kind               string
		rowsReturned       *int64
		bytesReturned      *int64
		decisionID         *int64
	)
	if err := rows.Scan(
		&id, &ts, &principal, &roles, &datasource, &clientAddr, &statement, &decision,
		&failedStage, &maskedColumns, &piiTouched, &latencyMs, &detail, &effectiveNamespace,
		&channel, &contextTags, &authzAction, &authzResource, &outcome, &kind, &rowsReturned,
		&bytesReturned, &decisionID,
	); err != nil {
		return types.AuditEvent{}, err
	}

	parsedDecision, err := types.ParseDecision(decision)
	if err != nil {
		return types.AuditEvent{}, fmt.Errorf("audit: row %d: %w", id, err)
	}

	rec := types.AuditEvent{
		ID:            &id,
		Principal:     principal,
		Datasource:    datasource,
		ClientAddr:    clientAddr,
		Statement:     statement,
		Decision:      parsedDecision,
		FailedStage:   failedStage,
		LatencyMs:     latencyMs,
		Detail:        detail,
		Channel:       channel,
		AuthzAction:   authzAction,
		AuthzResource: authzResource,
		Outcome:       outcome,
		Kind:          kind,
		RowsReturned:  rowsReturned,
		BytesReturned: bytesReturned,
		DecisionID:    decisionID,
	}
	if ts != nil {
		rec.TS = types.Ptr(FormatInstant(*ts))
	}
	for _, f := range []struct {
		raw *string
		dst *[]string
	}{
		{roles, &rec.Roles},
		{effectiveNamespace, &rec.EffectiveNamespace},
		{maskedColumns, &rec.MaskedColumns},
		{piiTouched, &rec.PIITouched},
		{contextTags, &rec.ContextTags},
	} {
		list, err := decodeList(f.raw)
		if err != nil {
			return types.AuditEvent{}, fmt.Errorf("audit: row %d: %w", id, err)
		}
		*f.dst = list
	}
	return rec, nil
}

// jsonList is `json.encodeToString(ListSerializer(String.serializer()), list)`.
//
// The result is bound to a `$n::jsonb` parameter as TEXT, so it must be a JSON array literal.
// json.Marshal cannot fail for a []string, and a Kotlin List<String> cannot be null — the nil guard
// exists because a Go nil slice marshals to `null`, which the column's
// `CHECK (jsonb_typeof(roles) = 'array')` would reject at 3am rather than here.
//
// HTML escaping is left ON (plain json.Marshal, not types.MarshalWire): the value is parsed into jsonb
// by Postgres, which normalises `<` and `<` to the same stored value, so the escaping is not
// observable on this path. types.MarshalWire's reason to exist is byte-identical RESPONSE bodies.
func jsonList(v []string) string {
	b, err := json.Marshal(orEmpty(v))
	if err != nil {
		// Unreachable for []string; a panic here beats storing a row whose hash covers a list the
		// column does not.
		panic(fmt.Sprintf("audit: encoding a string list cannot fail: %v", err))
	}
	return string(b)
}

// decodeList is `json.decodeFromString(stringList, getString(col) ?: "[]")` — including the `?: "[]"`
// fallback, which is dead against the current schema (all five columns are NOT NULL DEFAULT '[]') and
// is reproduced anyway. Inefficiency and dead defensiveness are REPRODUCE, not OMIT.
func decodeList(raw *string) ([]string, error) {
	text := "[]"
	if raw != nil {
		text = *raw
	}
	var out []string
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, fmt.Errorf("decode string list %q: %w", text, err)
	}
	return orEmpty(out), nil
}
