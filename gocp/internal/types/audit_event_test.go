package types

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// jsonEscaped returns the six-character \uXXXX form encoding/json uses for the HTML-sensitive
// characters. The leading backslash is built from its code point (92) rather than typed as a literal
// escape, because a fixture whose whole point is "these exact bytes" must not itself depend on an
// escape sequence surviving every editor and tool that touches this file — the first draft of this
// test lost them.
func jsonEscaped(r rune) string { return string(rune(92)) + fmt.Sprintf("u%04x", r) }

// fullyPopulated returns an AuditEvent with all 23 fields set, so a marshal assertion covers every
// name, every nullable and the field ORDER in one string.
//
// The statement deliberately contains '<', '>' and '&' — the three characters encoding/json escapes
// and kotlinx does not. SQL predicates carry them constantly, so this is not a synthetic edge case.
func fullyPopulated() AuditEvent {
	return AuditEvent{
		ID:                 Ptr(int64(7)),
		TS:                 Ptr("2026-08-01T09:15:04.123456Z"),
		Principal:          "alice@ridi.com",
		Roles:              []string{"analyst", "oncall"},
		Datasource:         "warehouse",
		ClientAddr:         Ptr("10.0.0.7:51234"),
		Statement:          "SELECT id FROM users WHERE age < 30 & tier > 1",
		Decision:           DecisionMask,
		FailedStage:        Ptr("lineage"),
		EffectiveNamespace: []string{"prod", "public"},
		MaskedColumns:      []string{"users.email"},
		PIITouched:         []string{"users.email", "users.phone"},
		LatencyMs:          42,
		Detail:             Ptr("masked 1 column"),
		Channel:            Ptr("editor"),
		ContextTags:        []string{"business-hours"},
		AuthzAction:        Ptr("task.approve"),
		AuthzResource:      Ptr("ApprovalRequest:31"),
		Outcome:            Ptr("applied"),
		Kind:               "decision",
		RowsReturned:       Ptr(int64(12)),
		BytesReturned:      Ptr(int64(2048)),
		DecisionID:         Ptr(int64(99)),
	}
}

// The fully-populated event as MarshalWire emits it — the bytes that actually go on the wire, and the
// ones a Kotlin control plane emits for the same event.
//
// 🔒 This is the wire contract shared by the proxy, the UI and auditmon, asserted byte-for-byte: it
// fails on a renamed field, a reordered field, a dropped default and an unexpected null alike.
// 01-bootstrap.md §3 field order: id, ts, principal, roles, datasource, clientAddr, statement,
// decision, failedStage, effectiveNamespace, maskedColumns, piiTouched, latencyMs, detail, channel,
// contextTags, authzAction, authzResource, outcome, kind, rowsReturned, bytesReturned, decisionId.
const fullyPopulatedWireJSON = `{"id":7,"ts":"2026-08-01T09:15:04.123456Z","principal":"alice@ridi.com",` +
	`"roles":["analyst","oncall"],"datasource":"warehouse","clientAddr":"10.0.0.7:51234",` +
	`"statement":"SELECT id FROM users WHERE age < 30 & tier > 1","decision":"MASK",` +
	`"failedStage":"lineage","effectiveNamespace":["prod","public"],` +
	`"maskedColumns":["users.email"],"piiTouched":["users.email","users.phone"],` +
	`"latencyMs":42,"detail":"masked 1 column","channel":"editor",` +
	`"contextTags":["business-hours"],"authzAction":"task.approve",` +
	`"authzResource":"ApprovalRequest:31","outcome":"applied","kind":"decision",` +
	`"rowsReturned":12,"bytesReturned":2048,"decisionId":99}`

func TestAuditEventMarshalFullyPopulated(t *testing.T) {
	got, err := MarshalWire(fullyPopulated())
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if string(got) != fullyPopulatedWireJSON {
		t.Errorf("wire shape drifted.\n got: %s\nwant: %s", got, fullyPopulatedWireJSON)
	}

	// Field count: 23 keys, no more and no fewer, on a fully-populated event.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(got, &keys); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if len(keys) != 23 {
		t.Errorf("fully-populated AuditEvent emitted %d keys, want 23", len(keys))
	}

	// No trailing newline — Encoder.Encode adds one, a response body has none.
	if strings.HasSuffix(string(got), "\n") {
		t.Error("MarshalWire left the encoder's trailing newline on the body")
	}
}

// The escaping divergence, pinned in BOTH directions.
//
// A plain json.Marshal escapes '<', '>' and '&'; kotlinx does not. This is why MarshalWire exists and
// why the HTTP layer must use it for every response body. It also demonstrates the constraint noted
// on MarshalWire: AuditEvent.MarshalJSON emits the characters raw, and the OUTER encoder still
// re-escapes them — a Marshaler cannot opt itself out, because encoding/json runs
// compact(escapeHTML) over whatever it returns.
//
// SQL predicates carry these three characters constantly, so `statement` is escaped on essentially
// every comparison the product exists to inspect. The two encodings parse to the same string, so this
// is a byte-level divergence only — but it is the difference between a readable and an unreadable
// Kotlin/Go diff during cutover.
func TestAuditEventEscapingDivergesBetweenStdlibAndWire(t *testing.T) {
	const rawStatement = `"statement":"SELECT id FROM users WHERE age < 30 & tier > 1"`
	escapedStatement := `"statement":"SELECT id FROM users WHERE age ` + jsonEscaped('<') +
		` 30 ` + jsonEscaped('&') + ` tier ` + jsonEscaped('>') + ` 1"`

	wire, err := MarshalWire(fullyPopulated())
	if err != nil {
		t.Fatalf("MarshalWire: %v", err)
	}
	if !strings.Contains(string(wire), rawStatement) {
		t.Errorf("MarshalWire escaped HTML characters.\n got: %s\nwant to contain: %s", wire, rawStatement)
	}
	for _, r := range []rune{'<', '>', '&'} {
		if strings.Contains(string(wire), jsonEscaped(r)) {
			t.Errorf("MarshalWire output still contains an escaped %q: %s", r, wire)
		}
	}

	stdlib, err := json.Marshal(fullyPopulated())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(stdlib), escapedStatement) {
		t.Errorf("json.Marshal stopped escaping — if the stdlib changed, MarshalWire's contract needs "+
			"re-checking.\n got: %s\nwant to contain: %s", stdlib, escapedStatement)
	}

	// Both decode to the identical event, so the divergence is bytes and not meaning.
	var fromWire, fromStdlib AuditEvent
	if err := json.Unmarshal(wire, &fromWire); err != nil {
		t.Fatalf("decode wire: %v", err)
	}
	if err := json.Unmarshal(stdlib, &fromStdlib); err != nil {
		t.Fatalf("decode stdlib: %v", err)
	}
	if !reflect.DeepEqual(fromWire, fromStdlib) {
		t.Error("the two encodings decoded to different events")
	}
}

// 🔒 INV-A1-4, the empty-slice half. Go's zero value has nil slices, which marshal as null; Kotlin's
// emptyList() marshals as []. The UI relies on the arrays being PRESENT, so this must hold even for a
// struct nobody initialised properly.
//
// Note what this shape is NOT: `decision` and `kind` come out empty because Go has no required-field
// constructor and no property defaults. No Kotlin AuditEvent can look like this. NewAuditEvent is the
// constructor that gives Kotlin's actual defaults — see TestNewAuditEventMarshalsKotlinDefaults.
func TestAuditEventMarshalZeroValue(t *testing.T) {
	const want = `{"principal":"","roles":[],"datasource":"","statement":"","decision":"",` +
		`"effectiveNamespace":[],"maskedColumns":[],"piiTouched":[],"latencyMs":0,` +
		`"contextTags":[],"kind":""}`

	got, err := json.Marshal(AuditEvent{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("zero-value shape drifted.\n got: %s\nwant: %s", got, want)
	}
	// Belt and braces: no optional field may appear as an explicit null (explicitNulls = false), and
	// no list may appear as null.
	if strings.Contains(string(got), "null") {
		t.Errorf("zero-value AuditEvent emitted a null: %s", got)
	}
	// 11 keys: 3 required strings + decision + 5 lists + latencyMs + kind. The 11 optional fields are
	// absent, not null.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(got, &keys); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if len(keys) != 11 {
		t.Errorf("zero-value AuditEvent emitted %d keys, want 11", len(keys))
	}
}

// NewAuditEvent materialises Kotlin's declared defaults, so this is the shape a Kotlin
// AuditEvent(principal, datasource, statement, decision) serializes to under
// {encodeDefaults = true; explicitNulls = false}.
func TestNewAuditEventMarshalsKotlinDefaults(t *testing.T) {
	const want = `{"principal":"alice@ridi.com","roles":[],"datasource":"warehouse",` +
		`"statement":"SELECT 1","decision":"ALLOW","effectiveNamespace":[],"maskedColumns":[],` +
		`"piiTouched":[],"latencyMs":0,"contextTags":[],"kind":"decision"}`

	got, err := json.Marshal(NewAuditEvent("alice@ridi.com", "warehouse", "SELECT 1", DecisionAllow))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("default shape drifted.\n got: %s\nwant: %s", got, want)
	}
}

// A nil slice assigned after construction must still marshal as [] — the guarantee lives in
// MarshalJSON, not in the constructor, precisely so a later mutation cannot break the UI.
func TestAuditEventNilSlicesMarshalAsEmptyArrays(t *testing.T) {
	ev := NewAuditEvent("p", "d", "s", DecisionDeny)
	ev.Roles = nil
	ev.EffectiveNamespace = nil
	ev.MaskedColumns = nil
	ev.PIITouched = nil
	ev.ContextTags = nil

	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, field := range []string{"roles", "effectiveNamespace", "maskedColumns", "piiTouched", "contextTags"} {
		if !strings.Contains(string(got), `"`+field+`":[]`) {
			t.Errorf("%s did not marshal as []: %s", field, got)
		}
	}
	// MarshalJSON must not mutate the receiver's slices back into the caller's struct.
	if ev.Roles != nil {
		t.Error("MarshalJSON mutated the receiver's Roles")
	}
}

// kotlinx raises MissingFieldException for a property with no default, and the ingest route answers
// 400. Go would silently zero-fill, storing an event attributed to principal "".
func TestAuditEventUnmarshalRequiresFields(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		missing []string
	}{
		{"all absent", `{}`, []string{"principal", "datasource", "statement", "decision"}},
		{"principal absent", `{"datasource":"d","statement":"s","decision":"ALLOW"}`, []string{"principal"}},
		{"datasource absent", `{"principal":"p","statement":"s","decision":"ALLOW"}`, []string{"datasource"}},
		{"statement absent", `{"principal":"p","datasource":"d","decision":"ALLOW"}`, []string{"statement"}},
		{"decision absent", `{"principal":"p","datasource":"d","statement":"s"}`, []string{"decision"}},
		// An explicit null for a non-nullable Kotlin property is a decode failure there too.
		{"decision null", `{"principal":"p","datasource":"d","statement":"s","decision":null}`, []string{"decision"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ev AuditEvent
			err := json.Unmarshal([]byte(tc.body), &ev)
			if err == nil {
				t.Fatalf("Unmarshal(%s) succeeded, want a missing-field error", tc.body)
			}
			for _, field := range tc.missing {
				if !strings.Contains(err.Error(), field) {
					t.Errorf("error %q does not name the missing field %q", err, field)
				}
			}
		})
	}
}

// An unknown decision name is rejected at the field level, so it surfaces as a decode failure on the
// whole event rather than an unenforceable verdict reaching the store.
func TestAuditEventUnmarshalRejectsUnknownDecision(t *testing.T) {
	var ev AuditEvent
	body := `{"principal":"p","datasource":"d","statement":"s","decision":"PERMIT"}`
	if err := json.Unmarshal([]byte(body), &ev); err == nil {
		t.Fatal("Unmarshal accepted decision \"PERMIT\", want an error")
	}
}

// Decoding applies Kotlin's property defaults: kind "decision", the five lists emptyList().
//
// 🔒 kind is field 1 of the canonical hash preimage (08-audit.md §2), so a proxy that omits it must
// still produce kind "decision" or every such row fails auditmon's chain verification.
func TestAuditEventUnmarshalAppliesDefaults(t *testing.T) {
	var ev AuditEvent
	body := `{"principal":"p","datasource":"d","statement":"s","decision":"DENY"}`
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Asserted against the literal, not against DefaultAuditKind — comparing the constant to itself
	// would pass no matter what the constant said, which a mutation run caught.
	if ev.Kind != "decision" {
		t.Errorf("Kind = %q, want \"decision\"", ev.Kind)
	}
	if DefaultAuditKind != "decision" {
		t.Errorf("DefaultAuditKind = %q, want \"decision\" — it is field 1 of the canonical hash "+
			"preimage (08-audit.md §2)", DefaultAuditKind)
	}
	if ev.LatencyMs != 0 {
		t.Errorf("LatencyMs = %d, want 0", ev.LatencyMs)
	}
	for name, got := range map[string][]string{
		"Roles":              ev.Roles,
		"EffectiveNamespace": ev.EffectiveNamespace,
		"MaskedColumns":      ev.MaskedColumns,
		"PIITouched":         ev.PIITouched,
		"ContextTags":        ev.ContextTags,
	} {
		if got == nil {
			t.Errorf("%s decoded as nil, want an empty slice (Kotlin emptyList())", name)
		}
		if len(got) != 0 {
			t.Errorf("%s = %v, want empty", name, got)
		}
	}
	// Every optional stays nil — absent means absent, not "".
	if ev.TS != nil || ev.ClientAddr != nil || ev.Detail != nil || ev.ID != nil || ev.DecisionID != nil {
		t.Errorf("an absent optional decoded as non-nil: %+v", ev)
	}
	// An explicitly supplied kind wins over the default.
	body = `{"principal":"p","datasource":"d","statement":"s","decision":"DENY","kind":"lifecycle"}`
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ev.Kind != "lifecycle" {
		t.Errorf("Kind = %q, want \"lifecycle\"", ev.Kind)
	}
}

// ignoreUnknownKeys = true (INV-A1-4). This is already Go's default; the test exists so nobody
// "hardens" it with DisallowUnknownFields, which would be a behaviour change.
func TestAuditEventUnmarshalIgnoresUnknownKeys(t *testing.T) {
	var ev AuditEvent
	body := `{"principal":"p","datasource":"d","statement":"s","decision":"ALLOW",` +
		`"somethingTheProxyAddedLater":42,"nested":{"a":[1,2]}}`
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatalf("Unmarshal rejected an unknown key: %v", err)
	}
	if ev.Principal != "p" {
		t.Errorf("Principal = %q", ev.Principal)
	}
}

func TestAuditEventRoundTrip(t *testing.T) {
	original := fullyPopulated()
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded AuditEvent
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("round trip lost data.\noriginal: %+v\n decoded: %+v", original, decoded)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if string(reencoded) != string(encoded) {
		t.Errorf("re-encode drifted.\nfirst: %s\n then: %s", encoded, reencoded)
	}
}

// The JSON names are frozen; this enumerates them independently of the marshal fixture so a rename
// fails with a message naming the field rather than a diff of two long strings.
func TestAuditEventJSONNamesAreFrozen(t *testing.T) {
	want := []struct{ field, jsonName string }{
		{"ID", "id"},
		{"TS", "ts"},
		{"Principal", "principal"},
		{"Roles", "roles"},
		{"Datasource", "datasource"},
		{"ClientAddr", "clientAddr"},
		{"Statement", "statement"},
		{"Decision", "decision"},
		{"FailedStage", "failedStage"},
		{"EffectiveNamespace", "effectiveNamespace"},
		{"MaskedColumns", "maskedColumns"},
		{"PIITouched", "piiTouched"},
		{"LatencyMs", "latencyMs"},
		{"Detail", "detail"},
		{"Channel", "channel"},
		{"ContextTags", "contextTags"},
		{"AuthzAction", "authzAction"},
		{"AuthzResource", "authzResource"},
		{"Outcome", "outcome"},
		{"Kind", "kind"},
		{"RowsReturned", "rowsReturned"},
		{"BytesReturned", "bytesReturned"},
		{"DecisionID", "decisionId"},
	}
	typ := reflect.TypeOf(AuditEvent{})
	if typ.NumField() != len(want) {
		t.Fatalf("AuditEvent has %d fields, want %d — the wire contract is frozen", typ.NumField(), len(want))
	}
	for i, w := range want {
		f := typ.Field(i)
		if f.Name != w.field {
			t.Errorf("field %d is %s, want %s (order is frozen)", i, f.Name, w.field)
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != w.jsonName {
			t.Errorf("%s json name = %q, want %q", f.Name, name, w.jsonName)
		}
	}
}

// INV-A1-4 spelled out as a tag rule, so the reason a tag is the way it is survives a refactor:
// optional (pointer) fields carry omitempty; required scalars, the defaulted scalars and every slice
// do NOT.
func TestAuditEventOmitemptyPolicy(t *testing.T) {
	wantOmitempty := map[string]bool{
		"id": true, "ts": true, "clientAddr": true, "failedStage": true, "detail": true,
		"channel": true, "authzAction": true, "authzResource": true, "outcome": true,
		"rowsReturned": true, "bytesReturned": true, "decisionId": true,
	}
	typ := reflect.TypeOf(AuditEvent{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		hasOmit := strings.Contains(opts, "omitempty")
		if hasOmit != wantOmitempty[name] {
			t.Errorf("%s (json %q): omitempty = %v, want %v", f.Name, name, hasOmit, wantOmitempty[name])
		}
		if hasOmit && f.Type.Kind() != reflect.Pointer {
			t.Errorf("%s carries omitempty but is %s, not a pointer — omitempty on a non-pointer "+
				"drops zero values Kotlin would emit", f.Name, f.Type.Kind())
		}
		if f.Type.Kind() == reflect.Slice && hasOmit {
			t.Errorf("%s is a slice with omitempty — an empty list must marshal as [], not vanish", f.Name)
		}
	}
}
