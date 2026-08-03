package conformance

// ============================================================================================
// CONTRACT 3c — NO WIRE DTO MAY HTML-ESCAPE. INV-A1-4, the escaping half.
//
// This is the always-on guard. It has no build tag and needs no GOEXPERIMENT, so it runs in every CI
// leg and on every developer machine, unlike the encoding/json/v2 differential in
// wire_jsonv2_oracle_test.go (which is stronger — it also checks nil-normalisation — but only runs
// under GOEXPERIMENT=jsonv2).
//
// THE RULE. kotlinx.serialization does not escape '<' '>' '&'. Go's encoding/json escapes all three by
// default, and once escaped the bytes are permanent: httpapi.RespondJSON serialises every response
// through types.MarshalWire, whose compact(escapeHTML=false) pass will not UNDO a `<` that a
// DTO's own MarshalJSON already baked in. So a single `json.Marshal` inside any MarshalJSON silently
// changes the wire format for every field of that DTO.
//
// WHY IT IS A PROPERTY TEST AND NOT MORE GOLDENS. This bug has now been found three separate times, in
// query.QueryResponse and then in six more DTOs, and every time the golden fixtures passed — because a
// golden only pins the values its author thought to write down, and nobody writes `<` into a table
// name. The invariant is universal, so the test is universal: feed every wire DTO a value containing
// all three characters and assert none of them come back escaped.
//
// COVERAGE NOTE — this test is the ONLY check on datasource.Datasource. The v2 differential cannot
// cover it: Datasource projects onto the unexported datasourceWire (its `Engine` field is `json:"-"`
// and is injected by MarshalEngineJSON), so a method-stripped oracle would drop `engine` entirely and
// report a false positive. Here, escaping is checked on the OUTPUT bytes, so the projection is
// irrelevant and Datasource is covered like everything else. Same for httpapi.ScimError with a nil
// Schemas, whose default-substitution likewise defeats the differential.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/access"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/engine"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/policy"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/result"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/session"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// htmlProbe carries all three escapable characters. Shaped like a SQL predicate because that is how
// they actually arrive: in a statement, a deny reason, or a column name.
const htmlProbe = `a < b & c > d`

// escapeSequences maps what encoding/json EMITS for each character to the character itself.
//
// Keys are built with jsonUnicodeEscape rather than written as literals on purpose: the whole point is
// that the key must be the SIX BYTES `\`,`u`,`0`,`0`,`3`,`c` and not the single character `<`. Written
// inline, one accidental unescape silently inverts every assertion below into "the output must CONTAIN
// a less-than sign", which every correct encoder satisfies. jsonUnicodeEscape constructs the bytes
// explicitly, so that failure mode is unreachable.
var escapeSequences = map[string]string{
	jsonUnicodeEscape('<'): "<",
	jsonUnicodeEscape('>'): ">",
	jsonUnicodeEscape('&'): "&",
}

func strp(s string) *string { return &s }

// TestNoWireDTOHTMLEscapes feeds htmlProbe through every DTO that owns a MarshalJSON and asserts the
// bytes come back unescaped.
//
// Each case puts the probe in a field a user or an operator actually controls, so a failure names a
// real exposure rather than a synthetic one.
func TestNoWireDTOHTMLEscapes(t *testing.T) {
	cases := []struct {
		name string
		// field is where the probe was planted — quoted in the failure so the exposure is concrete.
		field string
		value any
	}{
		{"types.ApiError", "params value", types.ApiError{
			Code: "datasource.invalid_engine", Params: map[string]string{"engine": htmlProbe}}},

		{"types.AuditEvent", "statement", types.AuditEvent{
			Principal: "alice@example.com", Datasource: "prod", Statement: htmlProbe,
			Decision: types.Decision("DENY"), Kind: "query"}},

		{"query.QueryResponse", "rows cell (the original regression)", query.QueryResponse{
			Columns: []string{"c"}, Rows: [][]*string{{strp(htmlProbe)}}}},

		{"query.QueryResponse", "denyReason", query.QueryResponse{DenyReason: strp(htmlProbe)}},

		{"session.UserSession", "principal", session.UserSession{
			Principal: htmlProbe, Roles: []string{htmlProbe}}},

		{"access.AccessRequest", "reason", access.AccessRequest{
			ID: 1, Principal: "alice@example.com", Status: "PENDING",
			CreatedAt: "2026-08-01T00:00:00Z", Kind: "ACCESS", Reason: strp(htmlProbe)}},

		{"result.QueryResultMeta", "columns", result.QueryResultMeta{
			TaskID: 9, Columns: []string{htmlProbe}}},

		{"result.DecryptedResult", "rows cell", result.DecryptedResult{
			Columns: []string{"c"}, Rows: [][]*string{{strp(htmlProbe)}}}},

		{"datasource.Datasource", "name/host (differential cannot reach this DTO)", datasource.Datasource{
			ID: 1, Name: htmlProbe, Engine: datasource.EnginePostgres,
			Host: htmlProbe, Port: 5432, DBName: htmlProbe, Tags: []string{htmlProbe}}},

		{"datasource.Classification", "column name", datasource.Classification{
			Schema: "public", Table: "t", Column: htmlProbe, Tags: []string{htmlProbe}}},

		{"engine.Classification", "column name", engine.Classification{
			Schema: "public", Table: "t", Column: htmlProbe, Tags: []string{htmlProbe}}},

		{"engine.TableDetail", "table name", engine.TableDetail{
			Schema: "public", Table: htmlProbe,
			Columns: []engine.TableDetailColumn{{Name: htmlProbe, DataType: "text"}}}},

		{"engine.TableIndex", "index name", engine.TableIndex{
			Name: htmlProbe, Type: "BTREE",
			Columns: []engine.TableIndexColumn{{Name: htmlProbe, Position: 1}}}},

		{"engine.TableRelation", "constraint name", engine.TableRelation{
			Name: htmlProbe, SourceSchema: "public", SourceTable: "a",
			SourceColumns: []string{htmlProbe}, TargetSchema: "public", TargetTable: "b",
			TargetColumns: []string{htmlProbe}}},

		{"policy.CedarValidateResult", "errors (Cedar text is full of < and &)", policy.CedarValidateResult{
			Valid: false, Errors: []string{htmlProbe}}},

		{"policy.CedarPolicyErrors", "errors", policy.CedarPolicyErrors{Errors: []string{htmlProbe}}},

		{"httpapi.ScimError", "detail, with nil Schemas (differential cannot reach this shape)",
			httpapi.ScimError{Status: "400", Detail: strp(htmlProbe)}},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.field, func(t *testing.T) {
			// MarshalWire is exactly what httpapi.RespondJSON calls, so this is the real wire path.
			got, err := types.MarshalWire(tc.value)
			if err != nil {
				t.Fatalf("MarshalWire: %v", err)
			}
			for esc, ch := range escapeSequences {
				if strings.Contains(string(got), esc) {
					t.Errorf("%s HTML-escaped %q as %s on the wire — kotlinx does not.\n"+
						"  probe planted in : %s\n"+
						"  bytes            : %s\n"+
						"Its MarshalJSON almost certainly ends in json.Marshal / json.NewEncoder. Use\n"+
						"types.MarshalWire (or the package-local marshalNoEscape) instead. RespondJSON\n"+
						"cannot undo this downstream — the escape is already in the bytes.",
						tc.name, ch, esc, tc.field, got)
				}
			}
		})
	}
}

// TestHTMLProbeWouldBeEscapedByStdlib proves the probe can actually detect the bug — that these
// assertions pass because the encoders are correct, not because the probe is inert.
//
// Without this, deleting htmlProbe's metacharacters would leave 17 green tests asserting nothing.
func TestHTMLProbeWouldBeEscapedByStdlib(t *testing.T) {
	type plain struct {
		S string `json:"s"`
	}
	// The stdlib default path — what every one of the fixed DTOs used to do.
	raw, err := json.Marshal(plain{S: htmlProbe})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	escaped := string(raw)
	for esc := range escapeSequences {
		if !strings.Contains(escaped, esc) {
			t.Fatalf("the probe %q no longer triggers stdlib escaping (%s absent from %s), so\n"+
				"TestNoWireDTOHTMLEscapes proves nothing. Restore all three of < > & to htmlProbe.",
				htmlProbe, esc, escaped)
		}
	}
}
