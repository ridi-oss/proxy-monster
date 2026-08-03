package queryhistory

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/instant"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// ---------------------------------------------------------------------------------------------
// `QueryHistoryStore` — 07-tasks-approvals-results.md §9.
//
// 🔴 EVERY CASE HERE IS NEW. 00-INDEX.md F17: "`QueryHistoryStore` has no dedicated test file —
// `DISTINCT ON` dedup, `limit` coercion, and blank-SQL skipping are all unasserted. Second untested
// store after `PolicyStore` (F10)." So there is nothing to migrate and §9 is the sole specification;
// the three behaviours F17 names are the three this file leads with.
//
// ⚠️ doc.go already asserted that this file existed ("the three behaviours F17 names are the three the
// suite leads with") while the package carried NO test file at all. Recorded in the return as a
// finding; the sentence is now true.
// ---------------------------------------------------------------------------------------------

const (
	alice = "alice@example.com"
	bob   = "bob@example.com"
)

type storeFixture struct {
	t     *testing.T
	ctx   context.Context
	db    *store.Db
	store *Store
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &storeFixture{t: t, ctx: context.Background(), db: db, store: New(db.Pool)}
}

func (f *storeFixture) add(principal string, datasourceID *int64, sql string) {
	f.t.Helper()
	if err := f.store.Add(f.ctx, principal, datasourceID, sql); err != nil {
		f.t.Fatalf("add %q: %v", sql, err)
	}
}

func (f *storeFixture) recent(principal string, limit int) []Entry {
	f.t.Helper()
	out, err := f.store.Recent(f.ctx, principal, limit)
	if err != nil {
		f.t.Fatalf("recent %s: %v", principal, err)
	}
	return out
}

// rowCount reads the table directly. Recent DEDUPLICATES, so it cannot distinguish "one row" from
// "five identical rows", and the blank-SQL claim is precisely about whether a row exists.
func (f *storeFixture) rowCount(principal string) int64 {
	f.t.Helper()
	var n int64
	err := f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM query_history WHERE principal = $1`, principal).Scan(&n)
	if err != nil {
		f.t.Fatalf("count: %v", err)
	}
	return n
}

// ---- F17 #1: the DISTINCT ON dedup -------------------------------------------------------------

// 🔒 THE DEDUPLICATION IS THE POINT AND IT IS TWO-LEVEL. §9: the inner query is
// `DISTINCT ON (sql) … ORDER BY sql, created_at DESC`, keeping the LATEST occurrence of each distinct
// statement; the outer re-sorts the survivors `ORDER BY created_at DESC` and applies the limit.
//
// Running the same statement ten times must leave ONE entry, AT ITS MOST RECENT POSITION — which is
// what makes a 50-entry history useful to someone who has been iterating on one query all afternoon.
func TestRecentKeepsOneEntryPerStatementAtItsMostRecentPosition(t *testing.T) {
	f := newStoreFixture(t)

	f.add(alice, nil, "select 1")
	f.add(alice, nil, "select 2")
	f.add(alice, nil, "select 3")
	// `select 1` again — it must move to the FRONT and must not appear twice.
	f.add(alice, nil, "select 1")

	got := f.recent(alice, 50)

	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 distinct statements: %+v", len(got), got)
	}
	want := []string{"select 1", "select 3", "select 2"}
	for i, w := range want {
		if got[i].SQL != w {
			t.Errorf("entry %d: got %q, want %q (newest first, latest occurrence wins)", i, got[i].SQL, w)
		}
	}
	// Four rows were written; the dedup is a READ-side property, not a write-side one.
	if n := f.rowCount(alice); n != 4 {
		t.Errorf("the table holds %d rows, want 4 — Add must not deduplicate", n)
	}
}

// ⚠️ The inner `ORDER BY sql, created_at DESC` is not cosmetic: `DISTINCT ON` keeps the FIRST row of
// each group AS ORDERED, so dropping `created_at DESC` there would keep the OLDEST occurrence and the
// list would silently show stale text for every repeated statement.
//
// Here the two occurrences carry DIFFERENT datasource ids, which is the only way to see WHICH row
// survived — the sql text is identical by construction.
func TestTheSurvivingRowIsTheLatestOccurrenceNotTheEarliest(t *testing.T) {
	f := newStoreFixture(t)
	first := int64(1)
	second := int64(2)

	f.add(alice, &first, "select repeated")
	f.add(alice, &second, "select repeated")

	got := f.recent(alice, 50)

	if len(got) != 1 {
		t.Fatalf("want one deduplicated entry, got %d", len(got))
	}
	if got[0].DatasourceID == nil {
		t.Fatalf("datasourceId: got nil, want %d — DISTINCT ON must keep the LATEST occurrence", second)
	}
	if *got[0].DatasourceID != second {
		t.Errorf("datasourceId: got %d, want %d — DISTINCT ON must keep the LATEST occurrence",
			*got[0].DatasourceID, second)
	}
}

// ---- F17 #2: blank-SQL skipping ------------------------------------------------------------------

// 🔒 A BLANK STATEMENT IS IGNORED — no row, NO ERROR. §9: "trims; blank is ignored (no row)." The
// editor sends whatever is in the buffer, and recording an empty statement would push a real one out
// of the deduplicated top-N for no information.
//
// "No error" is half the contract: A6's queryRoutes calls Add inside `runCatching`, so an error would
// be swallowed there anyway — but a store that errored would make every empty-buffer run log a
// failure.
func TestABlankStatementIsIgnoredWithoutAnError(t *testing.T) {
	f := newStoreFixture(t)

	for _, blank := range []string{"", " ", "\t", "\n", "   \t\n  "} {
		if err := f.store.Add(f.ctx, alice, nil, blank); err != nil {
			t.Errorf("Add(%q) must not error: %v", blank, err)
		}
	}

	if n := f.rowCount(alice); n != 0 {
		t.Errorf("%d rows were written for blank statements, want 0", n)
	}
}

// The stored value is the TRIMMED string, so leading/trailing whitespace is not part of the row —
// which also means it is not part of `DISTINCT ON (sql)`'s identity. INTERIOR whitespace IS part of
// it.
func TestTrimmingFoldsOuterWhitespaceIntoOneEntryButNotInterior(t *testing.T) {
	f := newStoreFixture(t)

	f.add(alice, nil, "select 1")
	f.add(alice, nil, "   select 1   ")
	f.add(alice, nil, "select  1") // two spaces — a DIFFERENT statement

	got := f.recent(alice, 50)

	if len(got) != 2 {
		t.Fatalf("want 2 entries (outer whitespace folds, interior does not), got %d: %+v", len(got), got)
	}
	for _, e := range got {
		if e.SQL != "select 1" && e.SQL != "select  1" {
			t.Errorf("stored value %q is not trimmed", e.SQL)
		}
	}
}

// ---- F17 #3: the limit ---------------------------------------------------------------------------

// `(limit?.toIntOrNull() ?: 50).coerceIn(1, 200)` — 07-tasks-approvals-results.md:630.
//
// ⚠️ DIFFERENT NUMBERS FROM audit.CoerceLimit's 100/[1,500], deliberately: this list is one user's
// editor history, not the security log. The two helpers are separate functions rather than one
// parameterised helper because the ONLY thing they share is the shape, and a shared helper is how the
// audit cap silently becomes 200.
func TestCoerceLimit(t *testing.T) {
	for _, c := range []struct {
		raw     string
		present bool
		want    int
		why     string
	}{
		{"", false, 50, "absent ⇒ the default"},
		{"", true, 50, "present but empty is unparseable ⇒ the default"},
		{"abc", true, 50, "unparseable ⇒ the default"},
		{"1", true, 1, "in range"},
		{"200", true, 200, "the ceiling itself"},
		{"0", true, 1, "coerceIn's floor: 0 clamps UP to 1"},
		{"-1", true, 1, "the floor, from below"},
		{"201", true, 200, "the ceiling clamps DOWN"},
		{"3000000000", true, 50, "🔒 32-bit: Kotlin's toIntOrNull says NOT A NUMBER ⇒ the DEFAULT, not the 200 cap"},
		{"-3000000000", true, 50, "the same, negative"},
		{" 5", true, 50, "no whitespace tolerance in toIntOrNull ⇒ not a number"},
		{"+5", true, 5, "a leading + IS accepted by both toIntOrNull and ParseInt"},
	} {
		t.Run(c.raw+" "+c.why, func(t *testing.T) {
			if got := CoerceLimit(c.raw, c.present); got != c.want {
				t.Errorf("CoerceLimit(%q, %v) = %d, want %d — %s", c.raw, c.present, got, c.want, c.why)
			}
		})
	}
}

// The limit applies to the DEDUPLICATED list, not to the rows scanned: five distinct statements with
// limit 2 gives the two newest distinct ones.
func TestTheLimitAppliesAfterDeduplication(t *testing.T) {
	f := newStoreFixture(t)

	f.add(alice, nil, "select a")
	f.add(alice, nil, "select a")
	f.add(alice, nil, "select b")
	f.add(alice, nil, "select c")

	got := f.recent(alice, 2)

	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0].SQL != "select c" || got[1].SQL != "select b" {
		t.Errorf("got %q, %q; want the two NEWEST DISTINCT statements", got[0].SQL, got[1].SQL)
	}
}

// ---- principal scoping ----------------------------------------------------------------------------

// 🔒 There is no unscoped read and no unscoped clear, and there must not be one: the DELETE is the
// only mutation the API exposes on this table, and a `clearAll()` sitting next to it is how a route
// ends up wired to the wrong one.
func TestRecentAndClearAreBothScopedToOnePrincipal(t *testing.T) {
	f := newStoreFixture(t)

	f.add(alice, nil, "alice statement")
	f.add(bob, nil, "bob statement")

	if got := f.recent(alice, 50); len(got) != 1 || got[0].SQL != "alice statement" {
		t.Errorf("alice's history: %+v", got)
	}
	if got := f.recent(bob, 50); len(got) != 1 || got[0].SQL != "bob statement" {
		t.Errorf("bob's history: %+v", got)
	}

	if err := f.store.Clear(f.ctx, alice); err != nil {
		t.Fatalf("clear alice: %v", err)
	}
	if n := f.rowCount(alice); n != 0 {
		t.Errorf("alice still has %d rows after Clear", n)
	}
	if n := f.rowCount(bob); n != 1 {
		t.Errorf("Clear(alice) removed %d of bob's rows; it must touch only its own principal", 1-n)
	}
}

// ---- shape ----------------------------------------------------------------------------------------

// 🔒 INV-A1-4 — `[]`, never nil. Built empty in the store rather than normalised at the route,
// because an empty list is the answer on every consumer of this method.
func TestRecentReturnsAnEmptyNonNilSlice(t *testing.T) {
	f := newStoreFixture(t)

	got := f.recent("nobody@example.com", 50)

	if got == nil {
		t.Fatal("Recent must return [] and never nil — INV-A1-4")
	}
	if len(got) != 0 {
		t.Errorf("got %d entries for a principal with no history", len(got))
	}
}

// `datasourceId: Long? = null` — NULL in the column, ABSENT on the wire. It is nullable because
// `query_history.datasource_id` has no foreign key and no NOT NULL (V5__tasks.sql:108): a statement
// can be recorded before a datasource is chosen.
func TestDatasourceIdRoundTripsAsAnOptional(t *testing.T) {
	f := newStoreFixture(t)
	id := int64(77)

	f.add(alice, &id, "with a datasource")
	f.add(alice, nil, "without one")

	got := f.recent(alice, 50)
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	byStatement := map[string]Entry{}
	for _, e := range got {
		byStatement[e.SQL] = e
	}
	if e := byStatement["with a datasource"]; e.DatasourceID == nil || *e.DatasourceID != id {
		t.Errorf("datasourceId: got %v, want %d", e.DatasourceID, id)
	}
	if e := byStatement["without one"]; e.DatasourceID != nil {
		t.Errorf("datasourceId: got %d, want nil", *e.DatasourceID)
	}
}

// `ranAt` is rendered through [instant.Format] — Java's VARIABLE-PRECISION `Instant.toString()`, the
// same wire-visible formatting internal/audit uses for `ts`. Go's time.RFC3339Nano is a different
// function and would differ on any timestamp whose fractional part ends in a zero.
func TestRanAtIsRenderedWithTheJavaInstantFormatter(t *testing.T) {
	f := newStoreFixture(t)
	f.add(alice, nil, "select now")

	got := f.recent(alice, 50)
	if len(got) != 1 {
		t.Fatalf("want one entry, got %d", len(got))
	}
	if got[0].RanAt == "" {
		t.Fatal("ranAt must be rendered")
	}

	// Re-render the stored column through the same formatter and demand equality. That catches a swap
	// to RFC3339Nano without depending on which fractional digits today's clock happens to produce —
	// the two formatters agree on most instants and differ only when the fraction ends in a zero, so
	// a literal expectation here would be a flaky test rather than a strict one.
	createdAt := f.scanCreatedAt(alice)
	if want := instant.Format(createdAt); got[0].RanAt != want {
		t.Errorf("ranAt: got %q, want %q (instant.Format, not RFC3339Nano)", got[0].RanAt, want)
	}
}

// scanCreatedAt reads the raw `created_at` of a principal's single row.
func (f *storeFixture) scanCreatedAt(principal string) time.Time {
	f.t.Helper()
	var ts time.Time
	err := f.db.Pool.QueryRow(f.ctx,
		`SELECT created_at FROM query_history WHERE principal = $1`, principal).Scan(&ts)
	if err != nil {
		f.t.Fatalf("scan created_at: %v", err)
	}
	return ts
}
