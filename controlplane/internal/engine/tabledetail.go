package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// The table-browser DTOs — probe/TableDetail.kt. The proxy produces this JSON and the control plane
// serves it through unchanged.
//
// F24 — these are a THIRD hand-maintained Kotlin↔Go twin, absent from 00-INDEX.md's "Already twinned"
// table: goproxy/spi/spi.go:101-177 declares the same seven types with JSON tags matching the Kotlin
// property names exactly. The JSON tags below are copied from spi.go so the pair stays a live wire
// contract. Once both ends are Go the hazard is gone, but while the Kotlin end exists do NOT "simplify"
// the non-nil empty-slice allocations on the producing side, and do NOT add omitempty to a slice field
// (see INV-A13-32 below).
//
// 🔒 INV-A13-32 — the two codec configurations are BOTH contract, and getting them crossed is the failure
// mode:
//
//   - HTTP responses → web/ use Json { ignoreUnknownKeys = true; encodeDefaults = true;
//     explicitNulls = false }. explicitNulls=false means a NULL FIELD IS OMITTED, not emitted as null;
//     encodeDefaults=true means an EMPTY LIST IS EMITTED as []. Reproduced by `omitempty` on every
//     POINTER field and NEVER on a slice field. Emitting "defaultValue": null where Kotlin omitted the
//     key, or omitting "tags": [], are both wire changes web/ can observe.
//   - The proxy → control-plane table-detail payload uses Json DEFAULTS — STRICT: unknown keys throw, and
//     a nullable-without-default property must be PRESENT. Go's encoding/json is lenient on both counts,
//     so UnmarshalTableDetailStrict below reproduces the strictness explicitly.
//
// ⚠️ A slice field must be non-nil to marshal as []; a nil slice marshals as null, which strict kotlinx
// then rejects for a non-nullable List. Seven Kotlin fields depend on this: TableDetail.{columns,indexes,
// foreignKeys,referencedBy}, TableIndex.columns and TableRelation.{sourceColumns,targetColumns}.

// Classification is the persisted column classification the control plane overlays onto live
// introspection.
//
// Tags, MaskFnID and MaskFnName are the ONLY three fields in this file with a Kotlin default
// (emptyList(), null, null), which is what makes them optional on the strict decode — every other field
// in every type here has no default and its key must therefore be present.
type Classification struct {
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Column     string   `json:"column"`
	Tags       []string `json:"tags" pmkotlin:"default"`
	MaskFnID   *int64   `json:"maskFnId,omitempty" pmkotlin:"default"`
	MaskFnName *string  `json:"maskFnName,omitempty" pmkotlin:"default"`
}

// TableDetail is live table-browser metadata. All seven fields are required, none nullable, no defaults.
type TableDetail struct {
	Schema       string              `json:"schema"`
	Table        string              `json:"table"`
	Columns      []TableDetailColumn `json:"columns"`
	Indexes      []TableIndex        `json:"indexes"`
	ForeignKeys  []TableRelation     `json:"foreignKeys"`
	ReferencedBy []TableRelation     `json:"referencedBy"`
	Metadata     TableMetadata       `json:"metadata"`
}

// TableDetailColumn describes one live target column.
//
// Classification is ALWAYS null from the proxy — spi.go:111-112 and :167 both say so ("Classification is
// always nil at the proxy; the control plane owns that overlay", "The proxy never populates it"). The
// control plane overlays it after decoding.
type TableDetailColumn struct {
	Name                   string          `json:"name"`
	DataType               string          `json:"dataType"`
	Ordinal                int32           `json:"ordinal"`
	Nullable               bool            `json:"nullable"`
	DefaultValue           *string         `json:"defaultValue,omitempty"`
	CharacterMaximumLength *int64          `json:"characterMaximumLength,omitempty"`
	NumericPrecision       *int32          `json:"numericPrecision,omitempty"`
	NumericScale           *int32          `json:"numericScale,omitempty"`
	PartOfIndex            bool            `json:"partOfIndex"`
	AutoIncrement          bool            `json:"autoIncrement"`
	Comment                *string         `json:"comment,omitempty"`
	Charset                *string         `json:"charset,omitempty"`
	Collation              *string         `json:"collation,omitempty"`
	Classification         *Classification `json:"classification,omitempty"`
}

// TableIndexColumn describes one column or expression in an index.
type TableIndexColumn struct {
	Name      string  `json:"name"`
	Position  int32   `json:"position"`
	Direction *string `json:"direction,omitempty"`
}

// TableIndex describes one live target index.
type TableIndex struct {
	Name    string             `json:"name"`
	Columns []TableIndexColumn `json:"columns"`
	Unique  bool               `json:"unique"`
	Type    string             `json:"type"`
}

// TableRelation describes one foreign-key relation.
type TableRelation struct {
	Name          string   `json:"name"`
	SourceSchema  string   `json:"sourceSchema"`
	SourceTable   string   `json:"sourceTable"`
	SourceColumns []string `json:"sourceColumns"`
	TargetSchema  string   `json:"targetSchema"`
	TargetTable   string   `json:"targetTable"`
	TargetColumns []string `json:"targetColumns"`
	OnUpdate      *string  `json:"onUpdate,omitempty"`
	OnDelete      *string  `json:"onDelete,omitempty"`
}

// TableMetadata contains engine-specific storage metadata for one table.
type TableMetadata struct {
	Engine        string  `json:"engine"`
	EstimatedRows *int64  `json:"estimatedRows,omitempty"`
	RowFormat     *string `json:"rowFormat,omitempty"`
	OnDiskBytes   *int64  `json:"onDiskBytes,omitempty"`
	Collation     *string `json:"collation,omitempty"`
	Comment       *string `json:"comment,omitempty"`
}

// The seven non-nullable List fields — TableDetail.{columns,indexes,foreignKeys,referencedBy},
// TableIndex.columns and TableRelation.{sourceColumns,targetColumns} — plus Classification.tags must
// ALWAYS encode as a JSON array, never as null. Kotlin gets that from its type system: a non-nullable
// List cannot be null, and encodeDefaults=true emits an empty one as []. Go's nil slice marshals to null,
// a shape the Kotlin end CANNOT produce and its strict decoder REJECTS.
//
// goproxy solves this by allocating every slice non-nil at the 14 build sites in
// goproxy/dialects/table_detail.go ("there is no nil-slice path at all", 13-engine.md §1.3). That is a
// discipline a caller can forget, so the marshallers below enforce the same shape at the type instead: a
// nil slice encodes as []. Language-forced mechanism, identical observable output.

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// MarshalJSON emits the four non-nullable list fields as [] rather than null when empty.
func (d TableDetail) MarshalJSON() ([]byte, error) {
	type alias TableDetail // sheds the method set, so this does not recurse
	out := alias(d)
	if out.Columns == nil {
		out.Columns = []TableDetailColumn{}
	}
	if out.Indexes == nil {
		out.Indexes = []TableIndex{}
	}
	if out.ForeignKeys == nil {
		out.ForeignKeys = []TableRelation{}
	}
	if out.ReferencedBy == nil {
		out.ReferencedBy = []TableRelation{}
	}
	// types.MarshalWire, NOT json.Marshal — kotlinx does not HTML-escape, and schema/table/column/
	// index names are user data. Found by the encoding/json/v2 differential.
	return types.MarshalWire(out)
}

// MarshalJSON emits columns as [] rather than null when empty (an index with no columns).
func (i TableIndex) MarshalJSON() ([]byte, error) {
	type alias TableIndex
	out := alias(i)
	if out.Columns == nil {
		out.Columns = []TableIndexColumn{}
	}
	// types.MarshalWire, NOT json.Marshal — kotlinx does not HTML-escape, and schema/table/column/
	// index names are user data. Found by the encoding/json/v2 differential.
	return types.MarshalWire(out)
}

// MarshalJSON emits both column lists as [] rather than null when empty.
func (r TableRelation) MarshalJSON() ([]byte, error) {
	type alias TableRelation
	out := alias(r)
	out.SourceColumns = nonNilStrings(out.SourceColumns)
	out.TargetColumns = nonNilStrings(out.TargetColumns)
	// types.MarshalWire, NOT json.Marshal — kotlinx does not HTML-escape, and schema/table/column/
	// index names are user data. Found by the encoding/json/v2 differential.
	return types.MarshalWire(out)
}

// MarshalJSON emits tags as [] rather than null when empty — Kotlin's `tags: List<String> = emptyList()`.
func (c Classification) MarshalJSON() ([]byte, error) {
	type alias Classification
	out := alias(c)
	out.Tags = nonNilStrings(out.Tags)
	// types.MarshalWire, NOT json.Marshal — kotlinx does not HTML-escape, and schema/table/column/
	// index names are user data. Found by the encoding/json/v2 differential.
	return types.MarshalWire(out)
}

// UnmarshalTableDetailStrict decodes the proxy's table-detail payload under the STRICT kotlinx
// configuration TableDetailExec.kt:68 uses: an unknown key is an error, and every property without a
// Kotlin default must be PRESENT (its value may be null). Go's encoding/json is lenient on both counts,
// so both halves are reproduced here rather than left to each call site to remember.
//
// The `pmkotlin:"default"` struct tag marks the three properties that DO carry a Kotlin default
// (Classification.tags/maskFnId/maskFnName) and are therefore optional on the wire.
func UnmarshalTableDetailStrict(data []byte) (*TableDetail, error) {
	var detail TableDetail
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // kotlinx default: an unknown key throws
	if err := dec.Decode(&detail); err != nil {
		return nil, fmt.Errorf("malformed table detail: %w", err)
	}

	// A nullable-without-default kotlinx property must be present even when null, which DisallowUnknownFields
	// cannot express — so walk the raw JSON alongside the struct type and require every non-defaulted key.
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("malformed table detail: %w", err)
	}
	if err := requireKotlinKeys(reflect.TypeOf(detail), raw, "$"); err != nil {
		return nil, err
	}
	return &detail, nil
}

// requireKotlinKeys asserts that every json-tagged field without `pmkotlin:"default"` has its key present
// in the decoded value, recursing through nested structs and slices. A null value is accepted — kotlinx
// requires PRESENCE, not non-nullness.
func requireKotlinKeys(t reflect.Type, value any, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := value.(map[string]any)
		if !ok {
			if value == nil {
				return nil // an absent/null nested object is the caller's presence problem, not ours
			}
			return fmt.Errorf("table detail %s: expected an object", path)
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			child, present := obj[name]
			if !present {
				if _, defaulted := field.Tag.Lookup("pmkotlin"); defaulted {
					continue
				}
				return fmt.Errorf("table detail %s.%s: required key is missing", path, name)
			}
			if err := requireKotlinKeys(field.Type, child, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return nil // null or absent: presence was already checked by the parent
		}
		for i, item := range items {
			if err := requireKotlinKeys(t.Elem(), item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
