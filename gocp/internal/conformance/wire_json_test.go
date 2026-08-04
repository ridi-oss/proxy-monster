package conformance

import (
	"bytes"
	"embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
	"github.com/ridi-oss/proxy-monster/gocp/internal/query"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ============================================================================================
// CONTRACT 3 — JSON wire shapes. INV-A1-4.
//
// ORACLE: the wire-contract tables in the spec, cited per DTO in the table below, plus the Kotlin
// sources they were derived from (read this session where quoted). There is no golden JSON fixture
// checked into the Kotlin module the way there is for the audit hash, so the expectation is the
// SPEC'S SHAPE, expressed as literal bytes.
//
// 01-bootstrap.md:175-186 states INV-A1-4 and then says exactly what this file is for:
//
//	"For a Go port this reduces to: omit optional fields entirely, always emit empty slices as [].
//	 Naive encoding/json gives the opposite of both by default (omitempty drops empty slices; absent
//	 pointers marshal as null). Every DTO needs deliberate tags, and this needs a conformance fixture."
//
// This is that fixture. internal/types already defends the rule inside MarshalJSON and has
// mutation-verified unit tests for it; what a GOLDEN BYTES layer adds is drift the unit tests cannot
// see — a field renamed on both sides at once, a field REORDERED (kotlinx emits in declaration order
// and so does encoding/json, so the order IS part of the contract), a new field appended in the wrong
// place, or an encoder swapped for one with different escaping. Each of those keeps every unit test
// green and changes the bytes on the wire.
//
// 🔴 WHAT THIS LAYER CAUGHT, and why it is written as literal files rather than as
// json.Marshal-then-compare: QueryResponse.MarshalJSON was calling json.Marshal, which HTML-escapes
// '<', '>' and '&' — so a result cell containing `a < b` went on the wire as `a < b` where
// kotlinx emits it raw. `rows` carries the customer's own query output, which is the single most
// likely place in the product for those characters to appear. See
// TestQueryResponseGoldenBytes/sql-metacharacters and the finding recorded in the return.
// ============================================================================================

//go:embed testdata/wire
var wireGolden embed.FS

// htmlEscapes maps each character encoding/json rewrites BY DEFAULT to the escape it produces.
// kotlinx.serialization rewrites none of them, so every value on the right must be absent from any
// body this port writes, and every key must survive verbatim.
//
// Unverified: kotlinx's non-escaping of these three is reasoned from its escape table, not measured —
// there is no JVM/kotlinx toolchain on this box. types.MarshalWire's own doc carries the same caveat
// and a TODO(A1) to confirm against a running Kotlin control plane during cutover.
var htmlEscapes = map[string]string{
	"<": jsonUnicodeEscape('<'),
	">": jsonUnicodeEscape('>'),
	"&": jsonUnicodeEscape('&'),
}

// jsonUnicodeEscape renders one ASCII byte the way encoding/json's HTML escaper does: the six
// characters backslash, 'u', and four lowercase hex digits.
//
// It is BUILT rather than written as a literal on purpose. A literal escape sequence in this source
// file is itself subject to being interpreted somewhere between an editor, a template and a diff,
// and this test's whole job is to be exact about those six characters.
func jsonUnicodeEscape(c byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{'\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0x0F]})
}

// goldenBytes reads a golden wire fixture. The file carries a trailing newline so it is editable and
// diffable; the newline is NOT part of the contract (a response body has none — see MarshalWire) and
// is trimmed here.
func goldenBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := wireGolden.ReadFile("testdata/wire/" + name)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return bytes.TrimRight(b, "\n")
}

// assertWireBytes is the assertion every case below runs: marshal through types.MarshalWire — the
// port's analogue of App.kt:340's application-wide Json instance — and demand the EXACT bytes.
//
// It deliberately does not normalise, re-indent or semantically compare. A semantic comparison would
// pass on `{"roles":null}` vs `{"roles":[]}` in some libraries and would certainly pass on reordered
// keys, and both of those are the failures this file exists to catch.
func assertWireBytes(t *testing.T, v any, goldenName string) {
	t.Helper()
	got, err := types.MarshalWire(v)
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	want := goldenBytes(t, goldenName)
	if !bytes.Equal(got, want) {
		t.Errorf("wire bytes differ from testdata/wire/%s\n got  %s\n want %s\n%s",
			goldenName, got, want, firstDifference(got, want))
	}
	// A golden that is not valid JSON would be a broken fixture rather than a caught drift, so the
	// bytes are parsed once as a sanity check on the FIXTURE, not on the DTO.
	if !json.Valid(want) {
		t.Fatalf("golden testdata/wire/%s is not valid JSON", goldenName)
	}
}

// firstDifference points at the byte offset where two encodings diverge. Wire bodies are long and a
// one-character difference (`[]` vs `null`, `<` vs `<`) is otherwise invisible in a diff.
func firstDifference(got, want []byte) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			lo := i - 30
			if lo < 0 {
				lo = 0
			}
			return "  first difference at byte " + itoa(i) + ":\n" +
				"   got  ..." + string(got[lo:min(len(got), i+30)]) + "...\n" +
				"   want ..." + string(want[lo:min(len(want), i+30)]) + "..."
		}
	}
	if len(got) != len(want) {
		return "  identical for " + itoa(n) + " bytes, then lengths differ (" +
			itoa(len(got)) + " vs " + itoa(len(want)) + ")"
	}
	return ""
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ---- types.AuditEvent ----------------------------------------------------------------------
//
// SPEC: 01-bootstrap.md §3 "`AuditEvent` · data class" (the 23-row field table at :323-347). The
// table order IS the emission order; the five List<String> fields default to `[]`; `latencyMs`
// defaults to 0 and `kind` to "decision"; every `T?` defaults to null and is therefore ABSENT.

func TestAuditEventGoldenBytes(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		// NewAuditEvent materialises the Kotlin primary constructor's defaults. Everything optional is
		// ABSENT (not null), every list is `[]` (not null), latencyMs is 0 and kind is "decision" —
		// both emitted because encodeDefaults = true.
		assertWireBytes(t,
			types.NewAuditEvent("alice", "acme-prod", "select 1", types.DecisionAllow),
			"audit_event_minimal.json")
	})

	t.Run("fully-populated", func(t *testing.T) {
		// Every one of the 23 fields set, so the golden pins the complete FIELD ORDER. A reordered
		// struct — the single easiest silent break, since Go emits in declaration order — moves bytes
		// here and nowhere else in the suite.
		ev := types.AuditEvent{
			ID:                 types.Ptr(int64(42)),
			TS:                 types.Ptr("2026-07-01T01:02:03.123456Z"),
			Principal:          "alice",
			Roles:              []string{"analyst", "auditor"},
			Datasource:         "acme-prod",
			ClientAddr:         types.Ptr("192.0.2.10"),
			Statement:          "select rrn from users",
			Decision:           types.DecisionMask,
			FailedStage:        types.Ptr("lineage"),
			EffectiveNamespace: []string{"catalog", "public"},
			MaskedColumns:      []string{"users.rrn"},
			PIITouched:         []string{"users.rrn"},
			LatencyMs:          12,
			Detail:             types.Ptr("masked output"),
			Channel:            types.Ptr("editor"),
			ContextTags:        []string{"trusted-network"},
			AuthzAction:        types.Ptr("sql.select"),
			AuthzResource:      types.Ptr("Column::users/rrn"),
			Outcome:            types.Ptr("MASK"),
			Kind:               "decision",
			RowsReturned:       types.Ptr(int64(3)),
			BytesReturned:      types.Ptr(int64(128)),
			DecisionID:         types.Ptr(int64(7)),
		}
		assertWireBytes(t, ev, "audit_event_full.json")
	})

	t.Run("nil-slices-become-empty-arrays", func(t *testing.T) {
		// 🔒 INV-A1-4, the half Go gets backwards. A bare struct literal has NIL slices, which
		// encoding/json renders as `null`; Kotlin's List<String> is non-null so `[]` is the only empty
		// it can hold, and the UI relies on the arrays being PRESENT.
		//
		// This case also pins the deliberate NON-normalisation of `kind`: Kotlin can legitimately
		// construct AuditEvent(kind = ""), so MarshalJSON must NOT default it — the default belongs in
		// NewAuditEvent. The golden therefore carries `"kind":""`, and a well-meaning "fix" that forces
		// "decision" at the marshal boundary fails here.
		ev := types.AuditEvent{
			Principal:  "alice",
			Datasource: "acme-prod",
			Statement:  "select 1",
			Decision:   types.DecisionDeny,
		}
		assertWireBytes(t, ev, "audit_event_nil_slices.json")
	})

	t.Run("sql-metacharacters", func(t *testing.T) {
		// `statement` is raw SQL, so '<', '>' and '&' appear on essentially every comparison predicate
		// the product exists to inspect. encoding/json escapes all three by default; kotlinx does not.
		// MarshalWire turns the escaping off, and this golden is what proves it stayed off.
		ev := types.NewAuditEvent("alice", "acme-prod",
			"select * from t where a < 5 and b > 3 and c = 'x&y'", types.DecisionAllow)
		assertWireBytes(t, ev, "audit_event_sql_metacharacters.json")

		// Stated as a rule as well as a golden, because the golden alone would not say WHY: the raw
		// characters must survive, and the \u00xx escapes must not appear.
		got, err := types.MarshalWire(ev)
		if err != nil {
			t.Fatal(err)
		}
		for raw, esc := range htmlEscapes {
			if bytes.Contains(got, []byte(esc)) {
				t.Errorf("MarshalWire emitted %s for %q; kotlinx emits the raw character", esc, raw)
			}
			if !bytes.Contains(got, []byte(raw)) {
				t.Errorf("the raw character %q did not survive into the wire bytes", raw)
			}
		}
	})
}

// TestAuditEventJsonKeepsInsertionOrderWhileTheHashSorts is the trap that costs an afternoon.
//
// The SAME five list fields have TWO different orderings depending on which contract is in play:
//
//   - on the JSON wire, they are emitted in the order they were built (there is no sort anywhere in
//     types.AuditEvent.MarshalJSON), and
//   - in the canonical hash preimage, four of them are sorted by unsigned UTF-8 bytes (INV-A8-5) while
//     effectiveNamespace is not.
//
// Someone reconciling the two will be tempted to make them agree. They must not: sorting the JSON
// changes the wire, and not sorting the hash makes the chain unverifiable. This test pins the JSON
// half against exactly that edit, and audit_canonical_test.go pins the hash half.
func TestAuditEventJsonKeepsInsertionOrderWhileTheHashSorts(t *testing.T) {
	ev := types.NewAuditEvent("alice", "acme-prod", "select 1", types.DecisionAllow)
	ev.Roles = []string{"zeta", "alpha"} // deliberately NOT sorted
	got, err := types.MarshalWire(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"roles":["zeta","alpha"]`)) {
		t.Errorf("JSON must keep insertion order, got: %s", got)
	}
}

// ---- types.ApiError ------------------------------------------------------------------------
//
// SPEC: 01-bootstrap.md §3 "`ApiError` · data class" (:354-374) — `{code: String, params:
// Map<String,String> = {}}`, plus the eight shared common.* codes and their statuses.
// KOTLIN: control-plane/src/main/kotlin/.../ApiErrors.kt (read this session).

func TestApiErrorGoldenBytes(t *testing.T) {
	t.Run("bare", func(t *testing.T) {
		// `params` is a DEFAULTED NON-NULL field, so encodeDefaults = true means it is ALWAYS present,
		// as `{}` at minimum. Go's nil map renders as `null`; MarshalJSON normalises it.
		assertWireBytes(t, types.BadID().Body, "api_error_bare.json")
	})

	t.Run("one-param", func(t *testing.T) {
		// The separator in `fields` is ", " — comma AND space (ApiErrors.kt's
		// `fields.joinToString(", ")`). The area-doc table says only "comma-joined", and the web
		// interpolates this straight into a sentence, so the space is user-visible.
		assertWireBytes(t, types.FieldRequired("name", "engine").Body, "api_error_one_param.json")
	})

	t.Run("two-params-key-order-is-a-known-divergence", func(t *testing.T) {
		// ⚠️ CROSS-LANGUAGE DIVERGENCE, recorded rather than papered over.
		//
		// alreadyExists is the ONLY helper with two params. The Kotlin builds them with
		// `buildMap { put("resource", resource); name?.let { put("name", it) } }` — insertion-ordered,
		// resource FIRST (ApiErrors.kt, read this session). Go's encoding/json sorts map keys, so the
		// bytes come out name-first.
		//
		// Unverified: that kotlinx emits a Map in its iteration order — reasoned from buildMap
		// returning a LinkedHashMap, not measured, because there is no JVM on this machine. What IS
		// verified is the Go side, which this golden freezes.
		//
		// Severity is low — JSON object key order carries no meaning and every consumer indexes by key
		// — but MarshalWire's stated goal is byte-identical output so a Kotlin↔Go diff stays readable
		// during cutover, and this is the one DTO where that goal is not met. Fixing it would mean
		// giving ApiError an ordered params representation, which is a bigger change than the problem.
		assertWireBytes(t, types.AlreadyExists("datasource", types.Ptr("acme")).Body,
			"api_error_two_params.json")
	})
}

// TestApiErrorHelperStatusesAndCodes pins the 01-bootstrap.md §3 status/code table itself, since a
// wrong STATUS on a right BODY is invisible to a bytes assertion.
func TestApiErrorHelperStatusesAndCodes(t *testing.T) {
	cases := []struct {
		what   string
		got    types.ErrorResponse
		status int
		code   string
		params map[string]string
	}{
		{"badId", types.BadID(), 400, "common.bad_id", nil},
		{"notFound", types.NotFound("datasource"), 404, "common.not_found", map[string]string{"resource": "datasource"}},
		{"fieldRequired", types.FieldRequired("name", "engine"), 400, "common.field_required", map[string]string{"fields": "name, engine"}},
		{"alreadyExists(name)", types.AlreadyExists("datasource", types.Ptr("acme")), 409, "common.already_exists", map[string]string{"resource": "datasource", "name": "acme"}},
		{"alreadyExists(nil)", types.AlreadyExists("datasource", nil), 409, "common.already_exists", map[string]string{"resource": "datasource"}},
		{"unauthenticated", types.Unauthenticated(), 401, "common.unauthenticated", nil},
		{"invalidToken(kind)", types.InvalidToken(types.Ptr("wire")), 401, "common.invalid_token", map[string]string{"kind": "wire"}},
		{"invalidToken(nil)", types.InvalidToken(nil), 401, "common.invalid_token", nil},
		{"fallback", types.Fallback(), 500, "common.fallback", nil},
		{"forbidden(detail)", types.Forbidden(types.Ptr("denied by policy: policy-1")), 403, "common.forbidden", map[string]string{"detail": "denied by policy: policy-1"}},
		{"forbidden(nil)", types.Forbidden(nil), 403, "common.forbidden", nil},
	}
	for _, c := range cases {
		if c.got.Status != c.status {
			t.Errorf("%s: status = %d, want %d", c.what, c.got.Status, c.status)
		}
		if c.got.Body.Code != c.code {
			t.Errorf("%s: code = %q, want %q", c.what, c.got.Body.Code, c.code)
		}
		if len(c.got.Body.Params) != len(c.params) {
			t.Errorf("%s: params = %v, want %v", c.what, c.got.Body.Params, c.params)
			continue
		}
		for k, v := range c.params {
			if c.got.Body.Params[k] != v {
				t.Errorf("%s: params[%q] = %q, want %q", c.what, k, c.got.Body.Params[k], v)
			}
		}
		// 🔒 INV-A1-13 — no English prose on the wire. Every code is a dot-namespaced i18n key, and the
		// only prose-shaped param is `detail`, which carries Cedar's own reason string by design
		// (requireAuthz / the MCP tool gate pass decision.reason).
		if !strings.Contains(c.got.Body.Code, ".") || strings.Contains(c.got.Body.Code, " ") {
			t.Errorf("%s: code %q does not look like a dot-namespaced i18n key", c.what, c.got.Body.Code)
		}
	}
}

// ---- query.QueryResponse -------------------------------------------------------------------
//
// SPEC: 06-query-decision.md §2 "`QueryRequest` / `QueryResponse`" (:105-113) —
// `QueryResponse{decision (custom serializer), decisionId: Long? = null, denyReason: String? = null,
// maskedColumns: [], piiTouched: [], effectiveRoles: [], columns: [], rows: List<List<String?>> = [],
// rowsAffected: Int? = null, latencyMs: Long = 0}`, with the note "`rows` is `List<List<String?>>` —
// every cell is a nullable string ... Go: [][]*string, and encodeDefaults means rows/columns must
// always serialize as []".
// KOTLIN: control-plane/src/main/kotlin/.../Query.kt:92-106 (read this session).

func TestQueryResponseGoldenBytes(t *testing.T) {
	t.Run("all-defaults", func(t *testing.T) {
		// The zero value. FIVE list fields must appear as `[]` and the three optionals must be ABSENT.
		//
		// ⚠️ `decision` reads ENF_ACTION_UNSPECIFIED because the proto zero value is not one of the
		// three verdicts. Kotlin has no such state (EnfAction is always set by the time a response is
		// built), so this string is a Go-only artifact of the zero value and is NOT a wire contract —
		// it is pinned so that a reader who sees it in a log knows it means "nobody set the decision",
		// and so that a change to the serialize half is visible. INV-A6-3 governs the DESERIALIZE
		// direction, and it collapses this string to DENY.
		assertWireBytes(t, query.QueryResponse{}, "query_response_zero.json")
	})

	t.Run("fully-populated", func(t *testing.T) {
		// Note the NULL CELL. `rows` is List<List<String?>> and a nil cell must serialize as JSON null,
		// NOT as "" — conflating the two would fall a redacted-to-NULL cell back to cleartext in the
		// consumer, which is the reason the type is [][]*string in the first place.
		r := query.QueryResponse{
			Decision:       query.WireEnfAction(pb.EnfAction_MASK),
			DecisionID:     types.Ptr(int64(7)),
			MaskedColumns:  []string{"users.rrn"},
			PIITouched:     []string{"users.rrn"},
			EffectiveRoles: []string{"analyst"},
			Columns:        []string{"id", "rrn"},
			Rows:           [][]*string{{types.Ptr("1"), nil}, {types.Ptr("2"), types.Ptr("***")}},
			LatencyMs:      12,
		}
		assertWireBytes(t, r, "query_response_full.json")
	})

	t.Run("deny", func(t *testing.T) {
		// ⚠️ F13 — `denyReason` is ENGLISH PROSE on a REST field, which sits uneasily with INV-A1-13.
		// 06-query-decision.md §8 Q3 leaves it OPEN; the PORT POLICY says REPRODUCE, so the golden
		// carries the prose verbatim (including its non-ASCII em dash, which also proves the encoder is
		// not escaping non-ASCII).
		//
		// `rowsAffected` is a POINTER to 0, and the golden shows it PRESENT. `omitempty` on a pointer
		// tests only for nil, so an explicit zero survives — which is the correct reading of Kotlin's
		// `Int? = null`, where 0 and null are different values.
		r := query.QueryResponse{
			Decision:       query.WireEnfAction(pb.EnfAction_DENY),
			DenyReason:     types.Ptr("cannot EXPLAIN a query whose columns are masked — request full access or run the query directly"),
			EffectiveRoles: []string{"analyst"},
			RowsAffected:   types.Ptr(int32(0)),
			LatencyMs:      3,
		}
		assertWireBytes(t, r, "query_response_deny.json")
	})

	t.Run("sql-metacharacters", func(t *testing.T) {
		// 🔴 THE CATCH. `rows` carries the customer's own query output and `columns` their identifiers,
		// so '<', '>' and '&' are ordinary content here — more so than anywhere else in the API.
		// QueryResponse.MarshalJSON must not HTML-escape them, for the same reason AuditEvent's must
		// not: kotlinx does not, and MarshalWire's contract is byte-identical output.
		r := query.QueryResponse{
			Decision: query.WireEnfAction(pb.EnfAction_ALLOW),
			Columns:  []string{"expr"},
			Rows:     [][]*string{{types.Ptr("a < b & c > d")}},
		}
		assertWireBytes(t, r, "query_response_sql_metacharacters.json")

		got, err := types.MarshalWire(r)
		if err != nil {
			t.Fatal(err)
		}
		for raw, esc := range htmlEscapes {
			if bytes.Contains(got, []byte(esc)) {
				t.Errorf("QueryResponse emitted %s for %q in a result cell; kotlinx emits the raw "+
					"character. A nested MarshalJSON that calls json.Marshal escapes even when the "+
					"outer encoder has escaping OFF — encoding/json only re-compacts a Marshaler's "+
					"output, it never un-escapes it.", esc, raw)
			}
		}
	})
}

// TestWireEnfActionSerializesByName pins the three real verdicts, which is the whole point of Kotlin's
// EnfActionSerializer: the proto enum is not kotlinx-@Serializable, so REST JSON is kept at exactly
// "ALLOW" / "MASK" / "DENY" rather than at an ordinal.
func TestWireEnfActionSerializesByName(t *testing.T) {
	for _, c := range []struct {
		in   pb.EnfAction
		want string
	}{
		{pb.EnfAction_ALLOW, `"ALLOW"`},
		{pb.EnfAction_MASK, `"MASK"`},
		{pb.EnfAction_DENY, `"DENY"`},
	} {
		got, err := types.MarshalWire(query.WireEnfAction(c.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("WireEnfAction(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

// ---- query.DecisionContext -------------------------------------------------------------------

// TestDecisionContextHasNoJsonWireShape records — and then GUARDS — a correction to the task framing.
//
// DecisionContext was named alongside QueryResponse as a "ported DTO" needing golden JSON. It is not
// one. Query.kt:123-164 declares `data class DecisionContext(...)` with NO `@Serializable` annotation
// (read this session; QueryRequest at :91 and QueryResponse at :93 both carry one, three lines
// apart), so kotlinx cannot encode it and it has NO JSON wire representation to be conformant with.
// It reaches the outside world in exactly two projected forms, neither of them this struct:
//
//	QueryResponse         over REST      — goldened above.
//	pb.WireDecision       over gRPC      — protobuf, mapped by grpcsvc.toWireDecision; the wire
//	                                       contract there is the .proto, not a JSON shape.
//
// So the useful assertion is the inverse one: that nobody GIVES it a JSON shape. A `json:"..."` tag
// appearing on this struct would mean the Go port invented a wire contract the Kotlin does not have —
// and, worse, one whose field names nothing on the other side agrees with. That is a silent
// divergence a golden-bytes file could never catch, because there would be no Kotlin bytes to compare
// against.
func TestDecisionContextHasNoJsonWireShape(t *testing.T) {
	rt := reflect.TypeOf(query.DecisionContext{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if tag, ok := f.Tag.Lookup("json"); ok {
			t.Errorf("DecisionContext.%s carries a json tag %q. Query.kt:123-164 has no @Serializable, "+
				"so this struct has no JSON wire contract; if one is genuinely needed, it must be "+
				"specified in 06-query-decision.md first and goldened here.", f.Name, tag)
		}
	}
	// Guard the premise too: if the struct ever loses its fields the loop above passes vacuously.
	if rt.NumField() != 18 {
		t.Errorf("DecisionContext has %d fields, want 18 (06-query-decision.md §2 — "+
			"\"`DecisionContext` · data class — 18 fields\")", rt.NumField())
	}
}
