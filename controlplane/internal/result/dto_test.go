package result

import (
	"encoding/json"
	"testing"
)

// The DTO half of the wire contract (07-tasks-approvals-results.md §2), asserted as bytes for the
// same reason internal/types asserts AuditEvent's: INV-A1-4's two rules — optional ⇒ ABSENT, list ⇒
// always an array — are discipline, not a language feature, and a single wrong tag is invisible until
// a console table breaks.

func TestQueryResultMetaJSONContract(t *testing.T) {
	// An unset (not-yet-started) child: every optional field is absent, columns is [].
	got, err := json.Marshal(QueryResultMeta{TaskID: 7})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"taskId":7,"columns":[]}`; string(got) != want {
		t.Errorf("empty meta = %s, want %s", got, want)
	}

	full := QueryResultMeta{
		TaskID:     7,
		ExecutedBy: strPtr("bob@example.com"),
		ExecutedAt: strPtr("2026-08-01T03:04:05Z"),
		RowCount:   intPtr(2),
		ExpiresAt:  strPtr("2026-08-02T03:04:05Z"),
		Status:     strPtr("DONE"),
		ErrorCode:  nil,
		Columns:    []string{"id", "rrn"},
	}
	got, err = json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"taskId":7,"executedBy":"bob@example.com","executedAt":"2026-08-01T03:04:05Z",` +
		`"rowCount":2,"expiresAt":"2026-08-02T03:04:05Z","status":"DONE","columns":["id","rrn"]}`
	if string(got) != want {
		t.Errorf("full meta =\n%s\nwant\n%s", got, want)
	}
}

// The payload's bytes ARE the plaintext of the ciphertext, so this contract is a storage format, not
// just a wire format: a NULL cell must survive as null, and both lists must be arrays or a Kotlin
// instance reading a Go-written blob during cutover fails to decode it.
func TestDecryptedResultJSONContract(t *testing.T) {
	got, err := json.Marshal(DecryptedResult{
		Columns: []string{"id", "rrn"},
		Rows:    [][]*string{{strPtr("1"), nil}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"columns":["id","rrn"],"rows":[["1",null]]}`; string(got) != want {
		t.Errorf("payload = %s, want %s", got, want)
	}

	got, err = json.Marshal(DecryptedResult{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"columns":[],"rows":[]}`; string(got) != want {
		t.Errorf("empty payload = %s, want %s (never null — Kotlin's fields are non-nullable)", got, want)
	}

	// Round trip: a null cell decodes back to a nil pointer, not to "".
	var back DecryptedResult
	if err := json.Unmarshal([]byte(`{"columns":["a"],"rows":[["x",null]]}`), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Rows) != 1 || len(back.Rows[0]) != 2 || back.Rows[0][1] != nil {
		t.Errorf("round trip = %+v, want a nil second cell", back.Rows)
	}
}

// kotlinx does not HTML-escape; encoding/json does by default, and its outer compact pass re-escapes
// whatever a Marshaler returns — so a plain json.Marshal of this type DOES escape (that is stdlib
// behaviour, not a bug here). What matters is the encoder the store actually uses for the ciphertext
// plaintext and for a response body: marshalNoEscape, and types.MarshalWire above it.
func TestDecryptedResultPayloadEncoderDoesNotHTMLEscape(t *testing.T) {
	payload := DecryptedResult{Columns: []string{"a<b"}, Rows: [][]*string{{strPtr("x&y")}}}

	got, err := marshalNoEscape(payload) // what CompleteRun encrypts
	if err != nil {
		t.Fatalf("marshalNoEscape: %v", err)
	}
	if want := `{"columns":["a<b"],"rows":[["x&y"]]}`; string(got) != want {
		t.Errorf("stored payload = %s, want %s", got, want)
	}

	// And the escaped form still round-trips, which is why the choice is a byte-fidelity one rather
	// than a correctness one.
	escaped, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back DecryptedResult
	if err := json.Unmarshal(escaped, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Columns) != 1 || back.Columns[0] != "a<b" {
		t.Errorf("round trip = %+v, want columns [a<b]", back)
	}
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
