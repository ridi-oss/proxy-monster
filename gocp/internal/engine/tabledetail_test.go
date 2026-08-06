package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// probe/TableDetail.kt has NO Kotlin test of its own — it is a DTO file, and 13-engine.md §6 records the
// consequence as a whole-area gap: "No test exercises the HTTP/strict serialization asymmetry
// (INV-A13-32) for TableDetail: nothing asserts that a null field is omitted on the HTTP encode and
// required on the proxy decode. That contract is currently held only by the fact that both sides happen to
// be written consistently."
//
// These tests close it. They are new, not ported — the Kotlin has nothing to port here.

func strPtr(s string) *string { return &s }
func i64Ptr(v int64) *int64   { return &v }
func i32Ptr(v int32) *int32   { return &v }

// A complete proxy payload: every key present, nullable values explicitly null — the shape
// goproxy/spi/spi.go produces (no omitempty anywhere in spi.go:100-177, which is what makes the strict
// decode work at all).
const proxyTableDetailJSON = `{
  "schema": "public",
  "table": "users",
  "columns": [
    {
      "name": "id", "dataType": "bigint", "ordinal": 1, "nullable": false,
      "defaultValue": null, "characterMaximumLength": null, "numericPrecision": 64,
      "numericScale": 0, "partOfIndex": true, "autoIncrement": true,
      "comment": null, "charset": null, "collation": null, "classification": null
    }
  ],
  "indexes": [
    {"name": "users_pkey", "columns": [{"name": "id", "position": 1, "direction": "ASC"}], "unique": true, "type": "btree"}
  ],
  "foreignKeys": [],
  "referencedBy": [
    {
      "name": "orders_user_fk", "sourceSchema": "public", "sourceTable": "orders",
      "sourceColumns": ["user_id"], "targetSchema": "public", "targetTable": "users",
      "targetColumns": ["id"], "onUpdate": null, "onDelete": "CASCADE"
    }
  ],
  "metadata": {
    "engine": "postgres", "estimatedRows": 42, "rowFormat": null,
    "onDiskBytes": 8192, "collation": null, "comment": null
  }
}`

func TestUnmarshalTableDetailStrictAcceptsTheProxyPayload(t *testing.T) {
	detail, err := UnmarshalTableDetailStrict([]byte(proxyTableDetailJSON))
	if err != nil {
		t.Fatalf("the proxy's own payload shape must decode: %v", err)
	}
	if detail.Schema != "public" || detail.Table != "users" {
		t.Errorf("got %+v", detail)
	}
	if len(detail.Columns) != 1 || detail.Columns[0].Name != "id" {
		t.Fatalf("columns got %+v", detail.Columns)
	}
	col := detail.Columns[0]
	if col.DefaultValue != nil || col.Comment != nil || col.Charset != nil {
		t.Error("explicit nulls must decode as absent pointers")
	}
	if col.NumericPrecision == nil || *col.NumericPrecision != 64 {
		t.Errorf("numericPrecision got %v, want 64", col.NumericPrecision)
	}
	// Classification is ALWAYS null from the proxy; the control plane owns that overlay.
	if col.Classification != nil {
		t.Error("the proxy never populates classification")
	}
	// An empty list decodes to a non-nil empty slice, so a re-encode still emits [].
	if detail.ForeignKeys == nil || len(detail.ForeignKeys) != 0 {
		t.Errorf("foreignKeys got %v, want an empty non-nil slice", detail.ForeignKeys)
	}
	if len(detail.ReferencedBy) != 1 || detail.ReferencedBy[0].OnDelete == nil || *detail.ReferencedBy[0].OnDelete != "CASCADE" {
		t.Errorf("referencedBy got %+v", detail.ReferencedBy)
	}
	if detail.Metadata.EstimatedRows == nil || *detail.Metadata.EstimatedRows != 42 {
		t.Errorf("metadata.estimatedRows got %v, want 42", detail.Metadata.EstimatedRows)
	}
}

// 🔒 INV-A13-32, decode half: the proxy payload is decoded with kotlinx `Json` DEFAULTS — an UNKNOWN KEY
// THROWS. Go's encoding/json ignores unknown keys, so the strictness has to be asked for.
func TestUnmarshalTableDetailStrictRejectsAnUnknownKey(t *testing.T) {
	withExtra := strings.Replace(proxyTableDetailJSON, `"schema": "public",`, `"schema": "public", "surprise": 1,`, 1)
	if _, err := UnmarshalTableDetailStrict([]byte(withExtra)); err == nil {
		t.Fatal("an unknown key must be rejected — the proxy decode is strict")
	}
	// Contrast: plain encoding/json accepts it, which is exactly why the helper exists.
	var lenient TableDetail
	if err := json.Unmarshal([]byte(withExtra), &lenient); err != nil {
		t.Errorf("precondition: plain encoding/json is lenient, got %v", err)
	}
}

// 🔒 INV-A13-32, decode half: a NULLABLE-WITHOUT-DEFAULT property must be PRESENT (its value may be null).
// None of TableDetail's nullable fields carries a Kotlin default, so every key is mandatory.
func TestUnmarshalTableDetailStrictRequiresEveryNonDefaultedKey(t *testing.T) {
	for _, missing := range []string{
		`"defaultValue": null,`,
		`"comment": null, `,
		`"classification": null`,
		`"onUpdate": null, `,
		`"rowFormat": null,`,
	} {
		t.Run(strings.TrimSpace(missing), func(t *testing.T) {
			payload := strings.Replace(proxyTableDetailJSON, missing, "", 1)
			if payload == proxyTableDetailJSON {
				t.Fatalf("test bug: %q is not in the fixture", missing)
			}
			// Trim a trailing comma left behind when the LAST key of an object was removed.
			payload = strings.ReplaceAll(payload, ",\n  }", "\n  }")
			payload = strings.ReplaceAll(payload, ", }", " }")
			if _, err := UnmarshalTableDetailStrict([]byte(payload)); err == nil {
				t.Errorf("a nullable-without-default key must be PRESENT; removing %q was accepted", missing)
			}
		})
	}
	// The three properties that DO carry a Kotlin default are optional: Classification.tags/maskFnId/
	// maskFnName.
	overlaid := strings.Replace(
		proxyTableDetailJSON,
		`"classification": null`,
		`"classification": {"schema": "public", "table": "users", "column": "id"}`,
		1,
	)
	detail, err := UnmarshalTableDetailStrict([]byte(overlaid))
	if err != nil {
		t.Fatalf("tags/maskFnId/maskFnName carry Kotlin defaults, so their keys are optional: %v", err)
	}
	if detail.Columns[0].Classification == nil {
		t.Fatal("the overlay must decode")
	}
	if got := detail.Columns[0].Classification.Tags; got != nil && len(got) != 0 {
		t.Errorf("an absent tags key defaults to empty, got %v", got)
	}
}

// 🔒 INV-A13-32, encode half: explicitNulls=false means a NULL FIELD IS OMITTED, not emitted as null,
// while encodeDefaults=true means an EMPTY LIST IS EMITTED as []. Emitting "defaultValue": null where
// Kotlin omitted the key, or omitting "tags": [], are both wire changes web/ can observe.
func TestHTTPEncodeOmitsNullsButEmitsEmptyLists(t *testing.T) {
	detail := TableDetail{
		Schema: "public",
		Table:  "users",
		Columns: []TableDetailColumn{{
			Name: "id", DataType: "bigint", Ordinal: 1, Nullable: false,
			PartOfIndex: true, AutoIncrement: true,
			// Every nullable field left nil.
			Classification: &Classification{Schema: "public", Table: "users", Column: "id"},
		}},
		// Every list left nil.
		Metadata: TableMetadata{Engine: "postgres"},
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(encoded)

	// Nulls are OMITTED, never emitted.
	for _, key := range []string{
		`"defaultValue"`, `"characterMaximumLength"`, `"numericPrecision"`, `"numericScale"`,
		`"comment"`, `"charset"`, `"collation"`,
		`"estimatedRows"`, `"rowFormat"`, `"onDiskBytes"`,
		`"maskFnId"`, `"maskFnName"`,
	} {
		if strings.Contains(got, key) {
			t.Errorf("explicitNulls=false: %s must be OMITTED when null, got %s", key, got)
		}
	}
	// No null VALUE may appear. (Matching the bare word "null" would false-positive on the "nullable"
	// key, which is a required bool and stays.)
	if strings.Contains(got, ":null") {
		t.Errorf("no null value may appear on the HTTP encode, got %s", got)
	}

	// Empty lists ARE emitted, as [] — never null, never omitted. This is the half Go's nil slice would
	// otherwise get wrong.
	for _, key := range []string{
		`"columns":`, `"indexes":[]`, `"foreignKeys":[]`, `"referencedBy":[]`, `"tags":[]`,
	} {
		if !strings.Contains(got, key) {
			t.Errorf("encodeDefaults=true: expected %s in %s", key, got)
		}
	}

	// And a nested empty list, one level down: an index with no columns, a relation with no columns.
	nested, err := json.Marshal(TableDetail{
		Indexes:     []TableIndex{{Name: "i", Type: "btree"}},
		ForeignKeys: []TableRelation{{Name: "fk"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"columns":[]`, `"sourceColumns":[]`, `"targetColumns":[]`} {
		if !strings.Contains(string(nested), want) {
			t.Errorf("expected %s in %s", want, nested)
		}
	}
}

// The two configurations are a ROUND TRIP in one direction only, and that is contract: what the proxy
// sends decodes, and what the control plane re-encodes for web/ is a DIFFERENT (null-omitting) shape of
// the same data. Pinned so nobody "fixes" the asymmetry by making both ends agree.
func TestTheProxyDecodeAndHTTPEncodeShapesDifferDeliberately(t *testing.T) {
	detail, err := UnmarshalTableDetailStrict([]byte(proxyTableDetailJSON))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reencoded, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(reencoded), `"defaultValue"`) {
		t.Error("the HTTP encode drops the null keys the strict decode required")
	}
	// …so the re-encoded payload would NOT survive its own strict decoder. That is the asymmetry.
	if _, err := UnmarshalTableDetailStrict(reencoded); err == nil {
		t.Error("expected the HTTP shape to fail the strict proxy decode — the two configs are different " +
			"on purpose (INV-A13-32); if this now round-trips, one of the two halves was changed")
	}
}
