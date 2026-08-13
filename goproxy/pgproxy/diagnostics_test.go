package pgproxy

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
)

const diagSentinel = "010-1234-5678"

// A target DB ErrorResponse for an ordinary constraint violation: the stored value lands ONLY in Detail (the
// whole-row dump); the structural fields carry object names, not values, as PostgreSQL populates them for a
// real (non-RAISE) error.
func fullErrorResponse() *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity:            "ERROR",
		SeverityUnlocalized: "ERROR",
		Code:                "23514",
		Message:             `new row for relation "orders" violates check constraint "amount_positive"`,
		Detail:              "Failing row contains (1, x, " + diagSentinel + ", victim@example.com).",
		Hint:                "check the amount",
		Position:            42,
		InternalPosition:    7,
		InternalQuery:       "SELECT 1",
		Where:               "SQL statement in PL/pgSQL function f() line 3",
		SchemaName:          "public",
		TableName:           "orders",
		ColumnName:          "amount",
		DataTypeName:        "integer",
		ConstraintName:      "amount_positive",
		File:                "execMain.c",
		Line:                1234,
		Routine:             "ExecConstraints",
		UnknownFields:       map[byte]string{'z': diagSentinel},
	}
}

func TestSanitizeErrorRedactsMessageAndRowDump(t *testing.T) {
	in := fullErrorResponse()
	out := sanitizeError(in)

	// Kept: identity, the structural object names, context, positions, source location.
	if out.Severity != "ERROR" || out.SeverityUnlocalized != "ERROR" || out.Code != "23514" {
		t.Errorf("identity not preserved: %+v", out)
	}
	if out.TableName != "orders" || out.ColumnName != "amount" || out.ConstraintName != "amount_positive" ||
		out.DataTypeName != "integer" || out.SchemaName != "public" {
		t.Errorf("structural object names must be kept: %+v", out)
	}
	if out.Where == "" || out.Position == 0 || out.Hint == "" || out.File == "" {
		t.Errorf("context / position / hint / source must be kept: %+v", out)
	}

	// Message → the code's canonical condition name; the whole-row Detail dropped; unknown fields cleared.
	if out.Message != "check_violation" {
		t.Errorf("Message = %q, want the SQLSTATE condition name", out.Message)
	}
	if out.Detail != "" {
		t.Errorf("Detail (whole-row dump) must be dropped, got %q", out.Detail)
	}
	if out.UnknownFields != nil {
		t.Errorf("unknown fields must be dropped, got %v", out.UnknownFields)
	}

	// The stored value lived only in Detail + an unknown field — both stripped — so it is gone everywhere.
	blob := out.Severity + out.SeverityUnlocalized + out.Code + out.Message + out.Detail + out.Hint +
		out.InternalQuery + out.Where + out.SchemaName + out.TableName + out.ColumnName +
		out.DataTypeName + out.ConstraintName
	if strings.Contains(blob, diagSentinel) {
		t.Errorf("stored value survived redaction: %q", blob)
	}
}

func TestSanitizeErrorDoesNotMutateInput(t *testing.T) {
	in := fullErrorResponse()
	_ = sanitizeError(in)
	if in.Detail == "" || in.Message == "check_violation" || in.UnknownFields == nil {
		t.Error("sanitizeError mutated the target-DB frame instead of returning a copy")
	}
}

func TestPgDiagnosticMessage(t *testing.T) {
	cases := map[string]string{
		"23514": "check_violation",                // exact condition name
		"22P02": "invalid_text_representation",    // exact condition name
		"42P07": "duplicate_table",                // exact condition name (added by the full-catalog expansion)
		"23999": "integrity_constraint_violation", // unmapped exact code -> its class (23)
		"ZZZZZ": engine.RedactedDiagnosticMessage, // unknown class -> generic (guaranteed absent from the full table)
		"":      engine.RedactedDiagnosticMessage, // no code -> generic
	}
	for code, want := range cases {
		if got := pgDiagnosticMessage(code); got != want {
			t.Errorf("pgDiagnosticMessage(%q) = %q, want %q", code, got, want)
		}
	}
}
