package query

import (
	"encoding/json"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// QueryRequest is the POST /api/datasources/{id}/query body — Query.kt:91.
//
// ⚠️ Kotlin's `maxRows: Int = 500` default cannot be expressed by encoding/json, so decode through
// [DecodeQueryRequest], not json.Unmarshal — the same shape internal/datasource established for
// DatasourceInput's `engine = "postgres"` default.
type QueryRequest struct {
	SQL     string `json:"sql"`
	MaxRows int    `json:"maxRows"`
}

// DefaultQueryMaxRows is `maxRows: Int = 500` (Query.kt:91).
const DefaultQueryMaxRows = 500

// DecodeQueryRequest applies the maxRows default. An explicit `"maxRows": 0` is NOT the default in
// Kotlin (the field is present, so the default does not apply) but is indistinguishable from an
// absent field after json.Unmarshal into a plain Int — a divergence with no consequence, since the
// only consumer clamps into [1, 5000] anyway.
func DecodeQueryRequest(b []byte) (QueryRequest, error) {
	in := QueryRequest{MaxRows: DefaultQueryMaxRows}
	if err := json.Unmarshal(b, &in); err != nil {
		return QueryRequest{}, err
	}
	if in.MaxRows == 0 {
		in.MaxRows = DefaultQueryMaxRows
	}
	return in, nil
}

// QueryResponse is the query/editor HTTP response — Query.kt:94-106.
//
// ⚠️ `Rows` is `List<List<String?>>`: EVERY CELL IS A NULLABLE STRING, not a typed value, because the
// Kotlin reads every column with `rs.getString(i)` and the mask functions are string transforms. A
// typed decoding would change what the mask sees, and conflating nil with "" would fall a
// redacted-to-NULL cell back to cleartext.
//
// kotlinx `encodeDefaults = true` means `columns` and `rows` ALWAYS serialize, as `[]` when empty —
// hence [QueryResponse.MarshalJSON]'s nil→[] normalisation (internal/types D9's rule).
//
// ⚠️ F13 — DenyReason is English prose on a REST field. REPRODUCE.
type QueryResponse struct {
	// Decision goes through the fail-closed by-name codec — see [WireEnfAction] and INV-A6-3.
	Decision       WireEnfAction `json:"decision"`
	DecisionID     *int64        `json:"decisionId,omitempty"`
	DenyReason     *string       `json:"denyReason,omitempty"`
	MaskedColumns  []string      `json:"maskedColumns"`
	PIITouched     []string      `json:"piiTouched"`
	EffectiveRoles []string      `json:"effectiveRoles"`
	Columns        []string      `json:"columns"`
	Rows           [][]*string   `json:"rows"`
	RowsAffected   *int32        `json:"rowsAffected,omitempty"`
	LatencyMs      int64         `json:"latencyMs"`
}

type queryResponseJSON QueryResponse

// MarshalJSON normalises the five list fields to `[]` rather than `null` (encodeDefaults = true).
//
// 🔒 The encoder is types.MarshalWire, NOT json.Marshal. encoding/json rewrites '<', '>' and '&' as
// < / > / & by default and kotlinx.serialization does not, so a json.Marshal here puts
// escaped bytes on the wire for every result cell containing those characters — and `rows` carries
// the customer's own query output, which is the likeliest place in the whole API for them to appear.
//
// The escaping cannot be undone by the caller. encoding/json runs compact(escapeHTML) over whatever a
// Marshaler returns, and that pass can only ADD escapes — so a nested json.Marshal escapes even when
// the outer encoder has escaping OFF. The fix has to be here, at the Marshaler.
//
// Caught by internal/conformance's TestQueryResponseGoldenBytes/sql-metacharacters, which is exactly
// the drift 01-bootstrap.md:186 asks for a conformance fixture against.
func (r QueryResponse) MarshalJSON() ([]byte, error) {
	v := queryResponseJSON(r)
	if v.MaskedColumns == nil {
		v.MaskedColumns = []string{}
	}
	if v.PIITouched == nil {
		v.PIITouched = []string{}
	}
	if v.EffectiveRoles == nil {
		v.EffectiveRoles = []string{}
	}
	if v.Columns == nil {
		v.Columns = []string{}
	}
	if v.Rows == nil {
		v.Rows = [][]*string{}
	}
	return types.MarshalWire(v)
}
