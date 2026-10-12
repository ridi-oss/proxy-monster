package pgproxy

import (
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
)

const diagSentinel = "010-1234-5678"

// A target DB ErrorResponse for an ordinary constraint violation: the stored value lands in Detail (the
// whole-row dump) and Where; the structural fields carry object names, not values.
func fullErrorResponse() *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity:            "ERROR",
		SeverityUnlocalized: "ERROR",
		Code:                "23514",
		Message:             `new row for relation "orders" violates check constraint "amount_positive"`,
		Detail:              "Failing row contains (1, x, " + diagSentinel + ", victim@example.com).",
		Hint:                "check the amount",
		Position:            42,
		Where:               "JSON data, line 1: " + diagSentinel,
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

	// Kept: identity, the structural object names, hint, position, source location.
	if out.Severity != "ERROR" || out.SeverityUnlocalized != "ERROR" || out.Code != "23514" {
		t.Errorf("identity not preserved: %+v", out)
	}
	if out.TableName != "orders" || out.ColumnName != "amount" || out.ConstraintName != "amount_positive" ||
		out.DataTypeName != "integer" || out.SchemaName != "public" {
		t.Errorf("structural object names must be kept: %+v", out)
	}
	if out.Position == 0 || out.Hint == "" || out.File == "" {
		t.Errorf("position / hint / source must be kept: %+v", out)
	}

	// Message names only the relation and constraint, so it is kept; the whole-row Detail is dropped and
	// unknown fields cleared.
	if out.Message != in.Message {
		t.Errorf("Message = %q, want the schema-only message kept", out.Message)
	}
	if out.Detail != "" || out.Where != "" {
		t.Errorf("Detail and Where must be dropped, got %q / %q", out.Detail, out.Where)
	}
	if out.UnknownFields != nil {
		t.Errorf("unknown fields must be dropped, got %v", out.UnknownFields)
	}

	// The stored value lived only in Detail, Where, and an unknown field — all stripped — so it is gone everywhere.
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
	in.Code, in.Message = "22P02", `invalid input syntax for type integer: "`+diagSentinel+`"`
	if out := sanitizeError(in); out.Message != "invalid_text_representation" {
		t.Errorf("Message = %q, want the SQLSTATE condition name", out.Message)
	}
	if in.Detail == "" || in.Message == "invalid_text_representation" || in.UnknownFields == nil {
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

// Messages as PostgreSQL 16 and 17 send them.
func TestSanitizeErrorKeepsSchemaOnlyMessages(t *testing.T) {
	cases := []struct{ code, msg string }{
		{"42P01", `missing FROM-clause entry for table "o"`},
		{"42P01", `table "orders_tmp" does not exist`},
		{"42P01", `view "active_orders" does not exist`},
		{"42P01", `sequence "orders_id_seq" does not exist`},
		{"42P01", `materialized view "order_totals" does not exist`},
		{"42P07", `relation "orders" already exists`},
		{"42703", `column "shipped_at" does not exist`},
		{"42703", `column o.shipped_at does not exist`},
		{"42703", `column "customer_id" referenced in foreign key constraint does not exist`},
		{"42701", `column "email" specified more than once`},
		{"42701", `column "email" of relation "orders" already exists`},
		{"42702", `column reference "id" is ambiguous`},
		{"42704", `index "orders_email_idx" does not exist`},
		{"42704", `constraint "amount_positive" of relation "orders" does not exist`},
		{"42P06", `schema "acme" already exists`},
		{"42710", `constraint "orders_pkey" for relation "orders" already exists`},
		{"42710", `trigger "orders_audit" for relation "orders" already exists`},
		{"42710", `type "order_status" already exists`},
		{"42723", `function "mask_email" already exists with same argument types`},
		{"42804", `column "amount" is of type integer but expression is of type text`},
		{"42804", `column "tags" is of type character varying[] but expression is of type integer`},
		{"42501", `permission denied for table orders`},
		{"42501", `permission denied for schema acme`},
		{"23502", `null value in column "email" of relation "orders" violates not-null constraint`},
		{"23505", `duplicate key value violates unique constraint "orders_email_key"`},
		{"23503", `insert or update on table "order_items" violates foreign key constraint "order_items_order_id_fkey"`},
		{"23503", `update or delete on table "orders" violates foreign key constraint "order_items_order_id_fkey" on table "order_items"`},
		{"23514", `new row for relation "orders" violates check constraint "amount_positive"`},
		{"23514", `check constraint "amount_positive" of relation "orders" is violated by some row`},
		{"23P01", `conflicting key value violates exclusion constraint "bookings_room_during_excl"`},
	}
	for _, c := range cases {
		out := sanitizeError(&pgproto3.ErrorResponse{Severity: "ERROR", Code: c.code, Message: c.msg, Detail: "Key (email)=(" + diagSentinel + ") already exists."})
		if out.Message != c.msg {
			t.Errorf("[%s] %q was stripped to %q", c.code, c.msg, out.Message)
		}
		if out.Detail != "" {
			t.Errorf("[%s] Detail survived: %q", c.code, out.Detail)
		}
	}
}

func TestSanitizeErrorStripsValueMessages(t *testing.T) {
	cases := []struct{ code, msg string }{
		{"22P02", `invalid input syntax for type integer: "` + diagSentinel + `"`},
		{"22003", `value "` + diagSentinel + `" is out of range for type integer`},
		{"22007", `invalid input syntax for type date: "` + diagSentinel + `"`},
		{"22001", `value too long for type character varying(4)`},
		// An allowlisted SQLSTATE whose message does not match any of its templates.
		{"42P01", `relation "orders" does not exist: ` + diagSentinel},
		{"42703", `column "a"b" does not exist`},
		{"42701", `column "x" of relation "a" of relation "b" already exists`},
		{"42P01", diagSentinel},
		{"42P01", `column "shipped_at" does not exist`},
		{"42703", `column "shipped_at" does not exist` + "\n" + diagSentinel},
		{"42501", `permission denied for table 010-1234-5678`},
		{"23505", `duplicate key value violates unique constraint "orders_email_key" (` + diagSentinel + `)`},
		{"P0001", `relation "orders" does not exist`},
		// Codes whose template a run-time value can fill via a resolver (::regclass/::regtype/::regnamespace/
		// ::regoper/::regcollation, nextval, has_*_privilege, pg_relation_size): not allowlisted, so even a
		// clean schema-only message strips to the condition name.
		{"42P01", `relation "orders" does not exist`},
		{"42704", `type "order_status" does not exist`},
		{"42704", `collation "ko_KR" for encoding "UTF8" does not exist`},
		{"42883", `operator does not exist: integer = text`},
		{"3F000", `schema "acme" does not exist`},
		// has_column_privilege, pg_get_serial_sequence, and pg_get_object_address fill these from a string.
		{"42703", `column "shipped_at" of relation "orders" does not exist`},
		{"42704", `trigger "orders_audit" for table "orders" does not exist`},
		{"42883", `function mask_email(integer, unknown) does not exist`},
		{"42883", `function acme.mask_email(character varying) does not exist`},
		{"42883", `procedure refresh_totals() does not exist`},
	}
	for _, c := range cases {
		out := sanitizeError(&pgproto3.ErrorResponse{Severity: "ERROR", Code: c.code, Message: c.msg})
		if out.Message != pgDiagnosticMessage(c.code) {
			t.Errorf("[%s] %q = %q, want the condition name", c.code, c.msg, out.Message)
		}
	}
}

// query_to_xml and ts_stat run SQL text built from a value, so any template can carry it; InternalQuery marks that.
func TestSanitizeErrorStripsInternalQueryErrors(t *testing.T) {
	out := sanitizeError(&pgproto3.ErrorResponse{
		Severity: "ERROR", Code: "42703", Message: `column "topsecretword" does not exist`,
		InternalQuery: "SELECT topsecretword", InternalPosition: 8,
	})
	if out.Message != "undefined_column" || out.InternalQuery != "" || out.InternalPosition != 0 {
		t.Errorf("internal-query error not stripped: %+v", out)
	}
}

func TestEveryPgSchemaTemplateKeepsAFilledMessage(t *testing.T) {
	fill := strings.NewReplacer(`"%s"`, `"acme orders"`, "%i", "orders", "%t", "integer")
	for code, templates := range pgSchemaMessages {
		for _, tmpl := range templates {
			msg := fill.Replace(tmpl)
			if !isSchemaOnlyMessage(code, msg) {
				t.Errorf("[%s] %q is not kept", code, msg)
			}
			if isSchemaOnlyMessage(code, msg+" "+diagSentinel) && !regexp.MustCompile(`%t$`).MatchString(tmpl) {
				t.Errorf("[%s] %q with trailing text is kept", code, msg)
			}
		}
	}
}
