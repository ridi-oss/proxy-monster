package query

import (
	"encoding/json"
	"testing"

	pb "github.com/ridi-oss/proxy-monster/gocp/internal/pb"
)

// The EnfAction wire contract — 06-query-decision.md §2.
//
// 🔒 INV-A6-3 — a verdict NEVER falls open. Both halves are asserted here, and the DESERIALIZE half
// is one 06-query-decision.md §7 records as a COVERAGE GAP in the Kotlin suite ("EnfActionSerializer's
// deserialize path — only serialize is exercised"). It is the fail-closed half, so it is the one that
// matters: the serializer's job is to make sure a client cannot talk the control plane into an ALLOW.

// KnownOrDeny: ALLOW / MASK / DENY pass through; everything else collapses to DENY.
func TestKnownOrDenyCollapsesEverythingUnknownToDeny(t *testing.T) {
	for _, a := range []pb.EnfAction{pb.EnfAction_ALLOW, pb.EnfAction_MASK, pb.EnfAction_DENY} {
		if got := KnownOrDeny(a); got != a {
			t.Errorf("KnownOrDeny(%v) = %v, want %v", a, got, a)
		}
	}
	// The proto3 zero value.
	if got := KnownOrDeny(pb.EnfAction_ENF_ACTION_UNSPECIFIED); got != pb.EnfAction_DENY {
		t.Errorf("KnownOrDeny(UNSPECIFIED) = %v, want DENY", got)
	}
	// 🔒 The Go-specific half. protobuf-go has NO UNRECOGNIZED sentinel — an unknown enum arrives as a
	// raw int32 — so an exhaustiveness check over the generated constants would silently accept this.
	if got := KnownOrDeny(pb.EnfAction(7)); got != pb.EnfAction_DENY {
		t.Errorf("KnownOrDeny(EnfAction(7)) = %v, want DENY", got)
	}
	if got := KnownOrDeny(pb.EnfAction(-1)); got != pb.EnfAction_DENY {
		t.Errorf("KnownOrDeny(EnfAction(-1)) = %v, want DENY", got)
	}
}

// The serialize half: REST JSON stays at exactly "ALLOW" / "MASK" / "DENY".
func TestWireEnfActionSerializesByName(t *testing.T) {
	for _, tc := range []struct {
		in   pb.EnfAction
		want string
	}{
		{pb.EnfAction_ALLOW, `"ALLOW"`},
		{pb.EnfAction_MASK, `"MASK"`},
		{pb.EnfAction_DENY, `"DENY"`},
		{pb.EnfAction_ENF_ACTION_UNSPECIFIED, `"ENF_ACTION_UNSPECIFIED"`},
	} {
		b, err := json.Marshal(WireEnfAction(tc.in))
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.in, err)
		}
		if string(b) != tc.want {
			t.Errorf("marshal(%v) = %s, want %s", tc.in, b, tc.want)
		}
	}
}

// 🔒 The deserialize half — the fail-closed one. Anything that is not the literal "ALLOW" or "MASK"
// becomes DENY, INCLUDING lower-case spellings, the unspecified name, and the Kotlin sentinel name.
func TestWireEnfActionDeserializesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want pb.EnfAction
	}{
		{`"ALLOW"`, pb.EnfAction_ALLOW},
		{`"MASK"`, pb.EnfAction_MASK},
		{`"DENY"`, pb.EnfAction_DENY},
		{`"ENF_ACTION_UNSPECIFIED"`, pb.EnfAction_DENY},
		{`"UNRECOGNIZED"`, pb.EnfAction_DENY},
		{`"allow"`, pb.EnfAction_DENY},
		{`"Allow"`, pb.EnfAction_DENY},
		{`""`, pb.EnfAction_DENY},
		{`"anything at all"`, pb.EnfAction_DENY},
	} {
		var got WireEnfAction
		if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.in, err)
		}
		if pb.EnfAction(got) != tc.want {
			t.Errorf("unmarshal(%s) = %v, want %v", tc.in, pb.EnfAction(got), tc.want)
		}
	}
}

// QueryResponse's list fields always serialize, as [] rather than null (encodeDefaults = true).
func TestQueryResponseAlwaysEmitsItsListFields(t *testing.T) {
	b, err := json.Marshal(QueryResponse{Decision: WireEnfAction(pb.EnfAction_DENY)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"decision":"DENY","maskedColumns":[],"piiTouched":[],"effectiveRoles":[],` +
		`"columns":[],"rows":[],"latencyMs":0}`
	if string(b) != want {
		t.Errorf("QueryResponse JSON =\n  %s\nwant\n  %s", b, want)
	}
}

// The maxRows default (Query.kt:91) that encoding/json cannot express on its own.
func TestDecodeQueryRequestAppliesTheMaxRowsDefault(t *testing.T) {
	got, err := DecodeQueryRequest([]byte(`{"sql":"select 1"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.MaxRows != 500 {
		t.Errorf("maxRows = %d, want 500", got.MaxRows)
	}
	got, err = DecodeQueryRequest([]byte(`{"sql":"select 1","maxRows":10}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.MaxRows != 10 {
		t.Errorf("maxRows = %d, want 10", got.MaxRows)
	}
}
