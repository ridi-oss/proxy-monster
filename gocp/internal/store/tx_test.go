package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// 🔒 INV-A3-4 — the lock key must stay hashtext(<principal>), computed BY POSTGRES. The Kotlin
// statement is `SELECT pg_advisory_xact_lock(hashtext(?))`; only JDBC's positional `?` becomes pgx's
// `$1`. ProvisionMergeDbTest cases 12-13 and DeprovisionDbTest case 8 take the lock from raw SQL with
// this exact expression, so the DB-backed tests pin the key too — but those need a container, and
// this one does not.
//
// A client-side hash passed as an integer would not serialize against a still-running Kotlin
// instance, and a rolling cutover would silently lose mutual exclusion for the whole deploy. That is
// why the SQL text is asserted literally rather than left to a code comment.
func TestAdvisoryLockSQLIsUnchangedFromKotlin(t *testing.T) {
	const want = `SELECT pg_advisory_xact_lock(hashtext($1))`
	if advisoryLockPrincipalSQL != want {
		t.Errorf("advisoryLockPrincipalSQL = %q, want %q", advisoryLockPrincipalSQL, want)
	}
}

// 03-identity-scim.md:878 — the predicate is `sqlState == "23505"` and nothing else. "Note 23503
// (foreign-key violation) is NOT matched — see F29." That is REPRODUCE: F29 records that a SCIM
// membership id which is numeric but nonexistent raises 23503, which this predicate does not match
// and which on POST is raised outside the try, so it surfaces differently from a non-numeric id that
// toLongOrNull silently drops. Two different wrong answers for one class of bad input — a defect the
// port carries, not fixes.
func TestIsUniqueViolation(t *testing.T) {
	unique := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
	if !IsUniqueViolation(unique) {
		t.Error("23505 must be a unique violation")
	}
	if !IsUniqueViolation(fmt.Errorf("insert app_user: %w", unique)) {
		t.Error("a wrapped 23505 must still match — errors.As, not a type assertion")
	}

	foreignKey := &pgconn.PgError{Code: "23503", Message: "violates foreign key constraint"}
	if IsUniqueViolation(foreignKey) {
		t.Error("23503 must NOT match: 03-identity-scim.md:878, F29 — reproduced deliberately")
	}

	for _, code := range []string{"23514", "23502", "40001", "42P01", "", "2350"} {
		if IsUniqueViolation(&pgconn.PgError{Code: code}) {
			t.Errorf("SQLSTATE %q must not match a unique violation", code)
		}
	}
	if IsUniqueViolation(nil) {
		t.Error("nil must not match")
	}
	if IsUniqueViolation(errors.New("connection reset")) {
		t.Error("a non-Postgres error must not match")
	}
}

// The port ships NO foreign-key predicate. If one is ever added, F29's observable behaviour changes
// and that must be a deliberate decision recorded against the finding, not a drive-by helper. This
// test exists to make the absence explicit; there is nothing to call.
func TestNoForeignKeyViolationHelperExists(t *testing.T) {
	t.Log("23503 has no predicate in this package by design — 03-identity-scim.md:878, F29")
}
