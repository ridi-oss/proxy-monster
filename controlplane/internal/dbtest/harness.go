package dbtest

import (
	"database/sql"
	"fmt"
	"strings"
)

// QueryRows is the raw target result — the shape [ExecOnTarget] returns from a connection the TEST
// owns. Port of EnforcementHarness.kt:31.
//
// Test-only, and the Kotlin comment says why: the control plane does not dial the target; the proxy
// executes queries. Cells are strings because the Kotlin reads every column with rs.getString(i) and
// the mask functions are string transforms — a typed decoding here would change what the mask sees.
// A nil cell is SQL NULL, kept distinct from "" because a NULL-kind mask redacts TO nil and
// EnforcementHarness.kt:156-158 warns that conflating the two falls a redacted cell back to cleartext.
type QueryRows struct {
	Columns []string
	Rows    [][]*string
	// RowsAffected is set (non-nil) only for a statement that produced no result set, mirroring
	// Kotlin's `Int?` and its `st.updateCount`.
	RowsAffected *int64
}

// TargetQueryError is raised when the test-owned target query itself fails. Port of
// EnforcementHarness.kt:34's TargetQueryException.
//
// 🔒 It exists to stay DISTINCT from a policy DENY. A suite that collapsed the two would let a broken
// fixture — a typo'd table name — read as "the policy denied it", which is a green test proving
// nothing. Same reason types.DecisionError is distinct from types.DecisionDeny.
type TargetQueryError struct{ Err error }

func (e *TargetQueryError) Error() string { return "target query failed: " + e.Err.Error() }
func (e *TargetQueryError) Unwrap() error { return e.Err }

// ExecOnTarget runs query against a target over a handle the TEST owns, capped at maxRows.
//
// Port of EnforcementHarness.kt:83-98. It mirrors the deleted DatasourceStore.runQuery body so the
// enforcement suite can drive decide → execute → mask end-to-end against a real database without
// standing up a proxy. One body serves both engines, exactly as the Kotlin's DriverManager one does.
//
// Two deviations, both forced by database/sql and both invisible in the returned value:
//
//  1. JDBC's `Statement.execute()` reports AFTERWARDS whether a result set exists; database/sql makes
//     the caller pick Query or Exec BEFORE running, and re-running to find out is not an option on a
//     statement with side effects. [ProducesResultSet] makes the choice from the statement text. See
//     its doc for what that costs.
//  2. JDBC's `Statement.maxRows` has no database/sql equivalent, so the cap is applied while scanning.
//     The server may produce more rows than are read; the row set a caller sees is identical.
func ExecOnTarget(db *sql.DB, query string, maxRows int) (QueryRows, error) {
	if !ProducesResultSet(query) {
		res, err := db.Exec(query)
		if err != nil {
			return QueryRows{}, &TargetQueryError{Err: err}
		}
		n, err := res.RowsAffected()
		if err != nil {
			// Not every driver reports it. JDBC's updateCount is -1 in the same situation, so the
			// sentinel is carried rather than the error.
			n = -1
		}
		return QueryRows{RowsAffected: &n}, nil
	}

	rows, err := db.Query(query)
	if err != nil {
		return QueryRows{}, &TargetQueryError{Err: err}
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return QueryRows{}, &TargetQueryError{Err: err}
	}
	out := QueryRows{Columns: cols, Rows: [][]*string{}}
	for len(out.Rows) < maxRows && rows.Next() {
		cells := make([]*string, len(cols))
		dest := make([]any, len(cols))
		for i := range cells {
			dest[i] = &cells[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return QueryRows{}, &TargetQueryError{Err: err}
		}
		out.Rows = append(out.Rows, cells)
	}
	if err := rows.Err(); err != nil {
		return QueryRows{}, &TargetQueryError{Err: err}
	}
	return out, nil
}

// resultSetLeadingKeywords are the statement kinds that produce a result set on either engine.
var resultSetLeadingKeywords = map[string]bool{
	"SELECT": true, "WITH": true, "VALUES": true, "TABLE": true,
	"SHOW": true, "EXPLAIN": true, "ANALYZE": true, "DESC": true, "DESCRIBE": true,
}

// ProducesResultSet reports whether a statement returns rows, from its text alone.
//
// ⚠️ This is a HEURISTIC, and it exists only because database/sql has no analogue of JDBC's
// `execute(): Boolean` (see [ExecOnTarget] deviation 1). It is deliberately exported so a suite whose
// statement it gets wrong can say so at the call site rather than debugging an empty QueryRows.
//
// It handles the two shapes the enforcement suites actually use beyond a plain SELECT: a leading
// comment block (the analyzer's `SELECT *` rewrite can emit one), and PostgreSQL's
// `INSERT/UPDATE/DELETE … RETURNING`, which returns rows from a statement whose first keyword says it
// does not. It does NOT handle a `RETURNING` appearing inside a string literal — a false Query on a
// statement that produces no rows yields an empty result rather than a wrong one, so the failure mode
// is visible rather than silent.
func ProducesResultSet(query string) bool {
	s := stripLeadingComments(query)
	upper := strings.ToUpper(s)
	if strings.Contains(upper, " RETURNING ") || strings.HasSuffix(upper, " RETURNING") {
		return true
	}
	first, _, _ := strings.Cut(strings.TrimLeft(upper, "("), " ")
	first = strings.TrimRight(first, ";\t\r\n")
	return resultSetLeadingKeywords[first]
}

// stripLeadingComments removes leading whitespace, `-- line` comments and `/* block */` comments so
// the first keyword can be read.
func stripLeadingComments(s string) string {
	for {
		s = strings.TrimSpace(s)
		switch {
		case strings.HasPrefix(s, "--"):
			_, rest, found := strings.Cut(s, "\n")
			if !found {
				return ""
			}
			s = rest
		case strings.HasPrefix(s, "/*"):
			_, rest, found := strings.Cut(s[2:], "*/")
			if !found {
				return ""
			}
			s = rest
		default:
			return s
		}
	}
}

// Cell renders a cell for an assertion message, distinguishing SQL NULL from the empty string.
func Cell(v *string) string {
	if v == nil {
		return "<NULL>"
	}
	return fmt.Sprintf("%q", *v)
}

// Values flattens a QueryRows column into the values it holds, for the common "assert this column is
// masked" shape. A NULL cell becomes nil in the returned slice.
func (q QueryRows) Values(column string) ([]*string, bool) {
	idx := -1
	for i, c := range q.Columns {
		if c == column {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, false
	}
	out := make([]*string, 0, len(q.Rows))
	for _, row := range q.Rows {
		out = append(out, row[idx])
	}
	return out, true
}
