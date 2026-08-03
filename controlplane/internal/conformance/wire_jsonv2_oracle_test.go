//go:build goexperiment.jsonv2

package conformance

// ============================================================================================
// CONTRACT 3b — encoding/json/v2 as an INDEPENDENT ORACLE for the hand-rolled wire encoder.
//
// WHY THIS EXISTS
//
// INV-A1-4: Kotlin's `Json { encodeDefaults = true; explicitNulls = false }` means ALWAYS emit [] for
// an empty list and ALWAYS OMIT an absent optional; kotlinx additionally does not escape '<' '>' '&'.
// encoding/json v1 gives the opposite of all three, so the port hand-rolls the semantics: a per-DTO
// MarshalJSON that nil-normalises every list and map, encoded through types.MarshalWire
// (escapeHTML=false).
//
// That hand-rolled layer is load-bearing and has already been wrong once in a way nothing else caught:
// query.QueryResponse.MarshalJSON called the ESCAPING encoder, so a result cell containing
// `a < b & c > d` reached the wire as `a < b & c > d` — in `rows`, the customer's own
// query output. 514 unit tests and a 14-mutation fail-open sweep both missed it; only golden BYTES
// caught it. A golden pins one value the author thought of. A SECOND IMPLEMENTATION checks every
// value, and is not written by the hand that wrote the encoder.
//
// encoding/json/v2 is that implementation, and it fits unusually well: measured on go1.26.4 it
// reproduces all three kotlinx behaviours BY DEFAULT, with no options set (nil slice -> [], nil map ->
// {}, nil pointer under omitempty -> omitted, no HTML escaping). TestJSONv2ReproducesKotlinDefaults
// pins that premise so it cannot silently drift.
//
// THE ORACLE MUST BYPASS THE MARSHALER — the subtlety this file turns on
//
// jsonv2.Marshal HONORS a v1 json.Marshaler. Measured: given a deliberately broken MarshalJSON,
//
//	hand-rolled                : {"roles":null,"statement":"a < b ..."}
//	jsonv2.Marshal(DTO)        : {"roles":null,"statement":"a < b ..."}     <- called the SAME broken code
//	jsonv2.Marshal(stripped)   : {"roles":[],  "statement":"a < b ..."}     <- independent
//
// so comparing against jsonv2.Marshal(dto) is close to vacuous: v2 re-emits the marshaler's output
// through its own writer, which launders escaping but passes SHAPE straight through. Mutation-measured
// on the two bugs that actually matter here:
//
//	mutation                        vs jsonv2.Marshal(dto)   vs method-stripped
//	nil-normalisation removed       SURVIVED                 CAUGHT
//	escapeHTML(false) removed       CAUGHT                   CAUGHT
//
// So every case below marshals the oracle side through a locally-declared `type raw X` — a defined
// type with the same underlying struct and NO method set — which forces v2 to encode from the STRUCT
// TAGS. That is what makes this a differential rather than a tautology.
//
// WHY IT IS BUILD-TAGGED AND NOT IN THE SHIPPING BINARY
//
// encoding/json/v2 is GOEXPERIMENT-gated in go1.26.4 (verified: importing it unflagged fails with
// "build constraints exclude all Go files"). A security product whose wire format IS its contract
// should not put an experimental package on the path that decides what bytes leave the process, and
// every CI leg and dev shell would need the flag. So v2 stays a TEST-ONLY oracle; production keeps
// types.MarshalWire.
//
//	go test ./internal/conformance                      # normal: this file is excluded
//	GOEXPERIMENT=jsonv2 go test ./internal/conformance   # oracle leg: this file runs
//
// When v2 ships unflagged this file doubles as the adoption proof: byte-identical agreement across
// every DTO, already demonstrated.
//
// SCOPE — and the three DTOs deliberately NOT here
//
// The differential is only valid for a MarshalJSON that PURELY nil-normalises, because only then is
// "the struct tags" the right answer. Three marshalers legitimately do more, and a struct-tag oracle
// would report a false positive on each:
//
//   - query.WireEnfAction — not a struct; `type WireEnfAction pb.EnfAction` over an int32 enum, whose
//     MarshalJSON encodes by NAME (fail-closed, INV-A6-3). Stripped, v2 would emit the integer. The
//     by-name codec is pinned by its own round-trip tests, not by shape.
//   - datasource.Datasource — projects onto a different wire struct: `Engine` is `json:"-"` on the
//     declared type and is injected by MarshalEngineJSON. Stripped, v2 would DROP `engine` entirely.
//   - httpapi.ScimError with a nil Schemas — substitutes a DEFAULT (`[ScimErrorSchema]`), not an empty
//     list. Stripped, v2 emits []. ScimError IS covered below, with Schemas populated, which exercises
//     the nil-normalising part of its behaviour without tripping the default substitution.
//
// FIXTURE RULES (two measured v1/v2 divergences that are NOT port bugs — do not construct these):
//   - never point a *string at "" — `,omitempty` keeps it in v1 and omits it in v2.
//   - never put `,omitempty` on a bare numeric — v1 omits 0, v2 emits it. Every optional number in
//     these DTOs is a POINTER, for which both agree, so this is a rule for future fields.

import (
	jsonv2 "encoding/json/v2"
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

// meta is the probe string. It carries all three HTML-escapable characters, and it is shaped like a
// SQL predicate because that is how it reaches the wire in the bug this file exists to prevent.
const meta = `a < b & c > d`

func sp(s string) *string { return &s }

// wireOracleCase is one DTO carried through both encoders.
type wireOracleCase struct {
	name string
	// why states what the case probes, so a failure reads as a contract violation, not a byte diff.
	why string
	// hand is the DTO itself; it dispatches to the port's MarshalJSON.
	hand any
	// oracle is the SAME value as a method-stripped defined type, so v2 encodes from struct tags.
	// Build it as `func() any { type raw X; return raw(v) }()`.
	oracle any
}

func wireOracleCases() []wireOracleCase {
	apiErr := types.ApiError{Code: "datasource.not_found", Params: nil}

	audit := types.AuditEvent{
		Principal: "alice@example.com", Datasource: "prod", Statement: "SELECT * FROM t WHERE " + meta,
		Decision: types.Decision("DENY"), Kind: "query", LatencyMs: 7,
		Roles: nil, EffectiveNamespace: nil, MaskedColumns: nil, PIITouched: nil, ContextTags: nil,
	}

	qr := query.QueryResponse{
		DenyReason: sp(meta), LatencyMs: 3,
		MaskedColumns: nil, PIITouched: nil, EffectiveRoles: nil, Columns: nil, Rows: nil,
	}

	usess := session.UserSession{Principal: meta, Roles: nil}

	areq := access.AccessRequest{
		ID: 1, Principal: "alice@example.com", RequestedDurationSec: 3600,
		Status: "PENDING", CreatedAt: "2026-08-01T00:00:00Z", Kind: "ACCESS",
		Reason: sp(meta), ExecuteAs: nil,
	}

	rmeta := result.QueryResultMeta{TaskID: 9, ErrorCode: sp(meta), Columns: nil}

	dres := result.DecryptedResult{Columns: nil, Rows: nil}

	dsClass := datasource.Classification{Schema: "public", Table: "t", Column: meta, Tags: nil}

	engClass := engine.Classification{Schema: "public", Table: "t", Column: meta, Tags: nil}

	tdetail := engine.TableDetail{
		Schema: "public", Table: meta,
		Columns: nil, Indexes: nil, ForeignKeys: nil, ReferencedBy: nil,
		Metadata: engine.TableMetadata{Engine: "InnoDB"},
	}

	tindex := engine.TableIndex{Name: meta, Columns: nil, Unique: true, Type: "BTREE"}

	trel := engine.TableRelation{
		Name: meta, SourceSchema: "public", SourceTable: "a", SourceColumns: nil,
		TargetSchema: "public", TargetTable: "b", TargetColumns: nil,
	}

	cvalid := policy.CedarValidateResult{Valid: false, Errors: nil}

	cerrs := policy.CedarPolicyErrors{Errors: nil}

	// Schemas is populated on purpose — see the ScimError note in the SCOPE block.
	scimErr := httpapi.ScimError{
		Schemas: []string{httpapi.ScimErrorSchema}, Status: "400", Detail: sp(meta),
	}

	return []wireOracleCase{
		{"types.ApiError", "nil Params map must be {}; code/params must not be escaped",
			apiErr, func() any { type raw types.ApiError; return raw(apiErr) }()},

		{"types.AuditEvent", "five nil lists must be []; the audited statement carries < & >",
			audit, func() any { type raw types.AuditEvent; return raw(audit) }()},

		{"query.QueryResponse", "the regression case — five nil lists, and denyReason carries < & >",
			qr, func() any { type raw query.QueryResponse; return raw(qr) }()},

		{"session.UserSession", "nil Roles must be []; principal carries < & >",
			usess, func() any { type raw session.UserSession; return raw(usess) }()},

		{"access.AccessRequest", "nil ExecuteAs must be []; user-supplied reason carries < & >",
			areq, func() any { type raw access.AccessRequest; return raw(areq) }()},

		{"result.QueryResultMeta", "nil Columns must be []; errorCode carries < & >",
			rmeta, func() any { type raw result.QueryResultMeta; return raw(rmeta) }()},

		{"result.DecryptedResult", "nil Columns and nil Rows must both be []",
			dres, func() any { type raw result.DecryptedResult; return raw(dres) }()},

		{"datasource.Classification", "nil Tags must be []; column name carries < & >",
			dsClass, func() any { type raw datasource.Classification; return raw(dsClass) }()},

		{"engine.Classification", "nil Tags must be []; column name carries < & >",
			engClass, func() any { type raw engine.Classification; return raw(engClass) }()},

		{"engine.TableDetail", "four nil lists must be []; table name carries < & >",
			tdetail, func() any { type raw engine.TableDetail; return raw(tdetail) }()},

		{"engine.TableIndex", "nil Columns must be []; index name carries < & >",
			tindex, func() any { type raw engine.TableIndex; return raw(tindex) }()},

		{"engine.TableRelation", "nil source/target column lists must be []; fk name carries < & >",
			trel, func() any { type raw engine.TableRelation; return raw(trel) }()},

		{"policy.CedarValidateResult", "nil Errors must be []",
			cvalid, func() any { type raw policy.CedarValidateResult; return raw(cvalid) }()},

		{"policy.CedarPolicyErrors", "nil Errors must be []",
			cerrs, func() any { type raw policy.CedarPolicyErrors; return raw(cerrs) }()},

		{"httpapi.ScimError", "populated Schemas passes through; detail carries < & >",
			scimErr, func() any { type raw httpapi.ScimError; return raw(scimErr) }()},
	}
}

// TestMarshalWireAgreesWithJSONv2 is the differential.
//
// It asserts no literal — wire_json*.go already pins those. It asserts that two independent
// implementations of INV-A1-4 produce the same bytes, a claim neither file can make alone.
func TestMarshalWireAgreesWithJSONv2(t *testing.T) {
	for _, tc := range wireOracleCases() {
		t.Run(tc.name, func(t *testing.T) {
			hand, err := types.MarshalWire(tc.hand)
			if err != nil {
				t.Fatalf("MarshalWire: %v", err)
			}
			oracle, err := jsonv2.Marshal(tc.oracle)
			if err != nil {
				t.Fatalf("jsonv2.Marshal: %v", err)
			}
			if string(hand) == string(oracle) {
				return
			}
			t.Errorf("the two encoders disagree on INV-A1-4.\n"+
				"  probing     : %s\n"+
				"  MarshalWire : %s\n"+
				"  jsonv2      : %s\n"+
				"  %s\n"+
				"One of them is wrong about kotlinx. Usual causes, in order of likelihood:\n"+
				"  1. the DTO's MarshalJSON ends in json.Marshal (ESCAPES < > &) instead of\n"+
				"     types.MarshalWire / marshalNoEscape — this is the query.QueryResponse bug;\n"+
				"  2. a list or map added to the struct without a matching nil-normalisation;\n"+
				"  3. the marshaler does more than nil-normalise, in which case it does not belong in\n"+
				"     this table — add it to the SCOPE exclusions with the reason.",
				tc.why, hand, oracle, firstDifference(hand, oracle))
		})
	}
}

// TestJSONv2ReproducesKotlinDefaults pins the PREMISE the differential rests on.
//
// If a future Go release changed any of these defaults, the differential would start producing false
// failures and someone would "fix" the port to match a moved oracle. This fails first, and says why.
func TestJSONv2ReproducesKotlinDefaults(t *testing.T) {
	type probe struct {
		Roles     []string          `json:"roles"`
		Params    map[string]string `json:"params"`
		Detail    *string           `json:"detail,omitempty"`
		Statement string            `json:"statement"`
	}

	got, err := jsonv2.Marshal(probe{Statement: meta})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"roles":[],"params":{},"statement":"a < b & c > d"}`
	if string(got) != want {
		t.Fatalf("encoding/json/v2 no longer reproduces kotlinx's defaults, so it is no longer a valid\n"+
			"oracle for INV-A1-4. Re-verify before trusting TestMarshalWireAgreesWithJSONv2.\n"+
			"  got  : %s\n  want : %s\n"+
			"Required: nil slice -> []; nil map -> {}; nil pointer under omitempty -> OMITTED;\n"+
			"and NO HTML escaping of < > &.", got, want)
	}
}

// TestJSONv2OracleIsNotVacuous guards the file's own method: it proves that comparing against
// jsonv2.Marshal(dto) — the obvious formulation — would NOT catch a missing nil-normalisation,
// which is why every case above strips the method set. If this ever starts failing, v2 has stopped
// honoring v1 marshalers and the `raw` indirection can be simplified away.
func TestJSONv2OracleIsNotVacuous(t *testing.T) {
	// A stand-in for a DTO whose MarshalJSON forgot to nil-normalise Roles.
	unnormalised := unnormalisedDTO{Roles: nil, Statement: meta}

	viaMarshaler, err := jsonv2.Marshal(unnormalised)
	if err != nil {
		t.Fatalf("Marshal(dto): %v", err)
	}
	type raw unnormalisedDTO
	viaStripped, err := jsonv2.Marshal(raw(unnormalised))
	if err != nil {
		t.Fatalf("Marshal(raw): %v", err)
	}

	if string(viaMarshaler) != `{"roles":null,"statement":"a < b & c > d"}` {
		t.Fatalf("jsonv2 no longer dispatches to a v1 MarshalJSON (got %s). The `raw` method-stripping\n"+
			"in wireOracleCases is now unnecessary — simplify it.", viaMarshaler)
	}
	if string(viaStripped) == string(viaMarshaler) {
		t.Fatalf("method-stripping no longer produces an independent encoding, so the differential is\n"+
			"vacuous and this whole file proves nothing. Both gave %s.", viaStripped)
	}
}

type unnormalisedDTO struct {
	Roles     []string `json:"roles"`
	Statement string   `json:"statement"`
}

// MarshalJSON deliberately omits the nil-normalisation, mimicking the mutation.
func (d unnormalisedDTO) MarshalJSON() ([]byte, error) {
	type alias unnormalisedDTO
	return types.MarshalWire(alias(d))
}
