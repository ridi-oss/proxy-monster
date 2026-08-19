package types

import (
	"encoding/json"
	"testing"
)

// 01-bootstrap.md §3: ALLOW | MASK | DENY | ERROR, in that order (Kotlin declaration order, which
// auditmon/canon's golden vectors also depend on because the name is what gets hashed).
func TestDecisionValues(t *testing.T) {
	got := DecisionValues()
	want := []Decision{"ALLOW", "MASK", "DENY", "ERROR"}
	if len(got) != len(want) {
		t.Fatalf("DecisionValues() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DecisionValues()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// The named constants must be the same strings, since those are the wire/hash names.
	for i, d := range []Decision{DecisionAllow, DecisionMask, DecisionDeny, DecisionError} {
		if d != want[i] {
			t.Errorf("constant %d = %q, want %q", i, d, want[i])
		}
	}
}

// 🔒 ERROR is the internal-failure case and is DISTINCT from the fail-closed DENY (01-bootstrap.md
// §3). This pins the distinction against a future "simplification" that folds one into the other.
func TestDecisionErrorIsNotDeny(t *testing.T) {
	if DecisionError == DecisionDeny {
		t.Fatal("DecisionError must not equal DecisionDeny — ERROR is 'no verdict reached', DENY is a verdict")
	}
	if DecisionError.String() != "ERROR" || DecisionDeny.String() != "DENY" {
		t.Fatalf("names drifted: error=%q deny=%q", DecisionError, DecisionDeny)
	}
}

func TestDecisionIsValid(t *testing.T) {
	for _, d := range DecisionValues() {
		if !d.IsValid() {
			t.Errorf("%q.IsValid() = false, want true", d)
		}
	}
	// The Go zero value has no Kotlin counterpart; it must not pass for a decision. See the type doc
	// on why the zero value is "" and not ALLOW.
	for _, bad := range []Decision{"", "allow", "Allow", "PERMIT", " ALLOW", "ALLOW "} {
		if bad.IsValid() {
			t.Errorf("%q.IsValid() = true, want false", bad)
		}
	}
}

func TestParseDecision(t *testing.T) {
	for _, name := range []string{"ALLOW", "MASK", "DENY", "ERROR"} {
		got, err := ParseDecision(name)
		if err != nil {
			t.Errorf("ParseDecision(%q) errored: %v", name, err)
			continue
		}
		if string(got) != name {
			t.Errorf("ParseDecision(%q) = %q", name, got)
		}
	}
	// Decision.valueOf is case-sensitive and throws on anything else; so is this.
	for _, name := range []string{"allow", "Deny", "PERMIT", ""} {
		if _, err := ParseDecision(name); err == nil {
			t.Errorf("ParseDecision(%q) succeeded, want an error", name)
		}
	}
}

func TestDecisionMarshalJSON(t *testing.T) {
	b, err := json.Marshal(DecisionMask)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"MASK"` {
		t.Fatalf("Marshal(DecisionMask) = %s, want \"MASK\"", b)
	}
}

// kotlinx's enum decoder throws on an unknown name and the ingest route turns that into a 400. A
// bare `type Decision string` would accept anything, which is a behaviour change on a security path.
func TestDecisionUnmarshalJSONRejectsUnknown(t *testing.T) {
	var d Decision
	for _, body := range []string{`"PERMIT"`, `"allow"`, `""`, `"BLOCK"`} {
		if err := json.Unmarshal([]byte(body), &d); err == nil {
			t.Errorf("Unmarshal(%s) succeeded, want an error", body)
		}
	}
	// A non-string is rejected too — the Kotlin enum decoder never sees a number here.
	if err := json.Unmarshal([]byte(`3`), &d); err == nil {
		t.Error("Unmarshal(3) succeeded, want an error")
	}
	for _, body := range []string{`"ALLOW"`, `"MASK"`, `"DENY"`, `"ERROR"`} {
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Errorf("Unmarshal(%s) errored: %v", body, err)
		}
	}
}
