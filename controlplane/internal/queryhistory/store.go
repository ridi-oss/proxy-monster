package queryhistory

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// Entry is `@Serializable data class QueryHistoryEntry(sql, datasourceId, ranAt)`
// (07-tasks-approvals-results.md §1's DTO table).
//
// ⚠️ THERE IS NO `id` ON THE WIRE even though `query_history.id` is a BIGSERIAL primary key. The
// entry is not addressable — the only mutation is "clear mine", which takes no id — so exposing one
// would advertise an endpoint that does not exist.
//
// RanAt is a string for the same reason internal/types.AuditEvent.TS is: Java's variable-precision
// `Instant.toString()` is wire-visible, and Go's time.RFC3339Nano is a different function.
type Entry struct {
	SQL string `json:"sql"`
	// DatasourceID is `datasourceId: Long? = null` — NULL in the column, ABSENT on the wire
	// (INV-A1-4, explicitNulls = false). It is nullable because `query_history.datasource_id` has no
	// foreign key and no NOT NULL (V5__tasks.sql:108): a statement can be recorded before a
	// datasource is chosen.
	DatasourceID *int64 `json:"datasourceId,omitempty"`
	RanAt        string `json:"ranAt"`
}

// Store is `class QueryHistoryStore(dataSource)`.
//
// It holds the pool rather than a connection: all three methods are single statements the Kotlin
// runs through `dataSource.connection.use { … }`. There are no `…On` overloads because the Kotlin has
// none — nothing composes a history write into someone else's transaction, and INV-A7's best-effort
// `runCatching` at the A6 call site is the reason why (a write that must not fail the query must not
// share its transaction either).
type Store struct {
	db store.DB
}

// New builds the store over the shared control-plane handle (INV-A1-1).
func New(db store.DB) *Store { return &Store{db: db} }

// Add is `fun add(principal: String, datasourceId: Long?, sql: String)`.
//
// 🔒 A BLANK STATEMENT IS IGNORED — no row, no error. §9: "trims; blank is ignored (no row)." The
// editor sends whatever is in the buffer, and recording an empty statement would push a real one out
// of the deduplicated top-N for no information.
//
// ⚠️ The stored value is the TRIMMED string, so leading/trailing whitespace is not part of the row —
// which also means it is not part of `DISTINCT ON (sql)`'s identity: `"SELECT 1"` and `" SELECT 1 "`
// dedupe together. INTERIOR whitespace is untouched, so `"SELECT  1"` is a different entry.
//
// Kotlin's `isBlank()` is Character.isWhitespace; strings.TrimSpace's set is unicode.IsSpace. They
// differ on a handful of exotic code points (NBSP is whitespace to Go and not to Java), so a
// statement consisting solely of NBSP is dropped here and stored there. Recorded rather than
// hand-rolled: this is a UX list, the divergence is one row nobody sees, and internal/policy's
// managementRequired carries the same note for the same reason.
func (s *Store) Add(ctx context.Context, principal string, datasourceID *int64, sql string) error {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return nil
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO query_history (principal, datasource_id, sql) VALUES ($1, $2, $3)`,
		principal, datasourceID, trimmed)
	return err
}

// Recent is `fun recent(principal: String, limit: Int): List<QueryHistoryEntry>`.
//
// 🔒 THE DEDUPLICATION IS THE POINT AND IT IS TWO-LEVEL. The inner query is
// `DISTINCT ON (sql) … ORDER BY sql, created_at DESC`, which keeps the LATEST occurrence of each
// distinct statement; the outer re-sorts those survivors `ORDER BY created_at DESC` and applies the
// limit. Running the same statement ten times leaves ONE entry, at its most recent position — which
// is what makes a 50-entry history useful to someone who has been iterating on one query all
// afternoon.
//
// ⚠️ `DISTINCT ON` is PostgreSQL-only. §9: do NOT rewrite it to `GROUP BY` — that would need an
// aggregate over `created_at` plus a self-join to recover `datasource_id`, i.e. a different query
// with different behaviour on ties.
//
// ⚠️ Note the ORDER BY inside is `sql, created_at DESC` and the one outside is `created_at DESC`.
// The inner ordering is not cosmetic: `DISTINCT ON` keeps the FIRST row of each group as ordered, so
// dropping `created_at DESC` there would keep the OLDEST occurrence instead of the newest, and the
// list would silently show stale text for every repeated statement.
//
// limit must already be through [CoerceLimit].
func (s *Store) Recent(ctx context.Context, principal string, limit int) ([]Entry, error) {
	rows, err := s.db.Query(ctx, `
		SELECT sql, datasource_id, created_at
		FROM (
			SELECT DISTINCT ON (sql) sql, datasource_id, created_at
			FROM query_history
			WHERE principal = $1
			ORDER BY sql, created_at DESC
		) latest
		ORDER BY created_at DESC
		LIMIT $2`, principal, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// `[]`, never nil — INV-A1-4. Built empty here rather than normalised at the route, because the
	// store is also the MCP surface's input one day and an empty list is the answer in both.
	out := []Entry{}
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Clear is `fun clear(principal: String)` — every row for ONE principal.
//
// 🔒 There is no unscoped variant and there must not be one. The DELETE is the only mutation the API
// exposes on this table, and a `clearAll()` sitting next to it is how a route ends up wired to the
// wrong one.
func (s *Store) Clear(ctx context.Context, principal string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM query_history WHERE principal = $1`, principal)
	return err
}

func scanEntry(row pgx.Row) (Entry, error) {
	var e Entry
	var createdAt time.Time
	if err := row.Scan(&e.SQL, &e.DatasourceID, &createdAt); err != nil {
		return Entry{}, err
	}
	e.RanAt = instant.Format(createdAt)
	return e, nil
}

// ---- limit coercion ---------------------------------------------------------------------------

// The `GET /api/query-history` limit bounds — `(limit?.toIntOrNull() ?: 50).coerceIn(1, 200)`
// (07-tasks-approvals-results.md:630).
//
// ⚠️ DIFFERENT NUMBERS FROM audit.CoerceLimit's 100/[1,500], and deliberately so: this list is one
// user's editor history, not the security log. The two helpers are separate functions rather than one
// parameterised helper because the ONLY thing they share is the shape, and a shared helper is how the
// audit cap silently becomes 200.
const (
	// DefaultLimit is used when `limit` is absent OR unparseable.
	DefaultLimit = 50
	// MinLimit is coerceIn's floor: `?limit=0` and `?limit=-1` both read one row.
	MinLimit = 1
	// MaxLimit is coerceIn's ceiling.
	MaxLimit = 200
)

// CoerceLimit ports the rule exactly: absent or unparseable ⇒ 50, then clamped into [1, 200].
//
// present is "the query parameter was there at all". Kotlin's `queryParameters["limit"]` is null when
// absent, and null and "not a number" take the same branch, so the two are folded for the caller's
// convenience rather than modelled separately.
//
// The parse is 32-bit on purpose — see [parseKotlinInt]. `?limit=3000000000` is NOT a number to
// Kotlin and falls back to 50; a 64-bit parse would clamp it to 200 instead.
func CoerceLimit(raw string, present bool) int {
	limit := DefaultLimit
	if present {
		if v, ok := parseKotlinInt(raw); ok {
			limit = v
		}
	}
	if limit < MinLimit {
		return MinLimit
	}
	if limit > MaxLimit {
		return MaxLimit
	}
	return limit
}

// parseKotlinInt is Kotlin's String.toIntOrNull(): base 10, an optional leading sign, and — the part
// Go's strconv.Atoi does NOT reproduce on a 64-bit platform — a value outside the 32-bit Int range is
// NOT a number, it is null.
//
// ⚠️ A SECOND COPY of internal/audit's identical private helper. Deliberate: 09-policies.md:95-100
// dispositions the Kotlin's three copies of its JDBC helpers as REPRODUCE for the same reason, and
// exporting one of these would create a shared dependency between the audit read path and an editor
// convenience list that have no other relationship. Unify after cutover, as its own reviewable
// change, together with audit.CoerceLimit.
func parseKotlinInt(s string) (int, bool) {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return int(v), true
}
