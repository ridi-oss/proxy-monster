package differential

import "testing"

// TestNormaliserDoesNotHideARealDifference is the harness's own non-vacuity check.
//
// 🔒 THE NORMALISER IS THE ONE PLACE A DIVERGENCE CAN VANISH, and a too-aggressive rule makes the whole
// run a green light that proves nothing. These pairs MUST still compare unequal after normalisation.
func TestNormaliserDoesNotHideARealDifference(t *testing.T) {
	mustDiffer := []struct{ name, a, b string }{
		{"a different error code", `{"code":"common.bad_id","params":{}}`, `{"code":"common.not_found","params":{}}`},
		{"an omitted params map", `{"code":"x","params":{}}`, `{"code":"x"}`},
		{"a flipped boolean", `{"isAdmin":true}`, `{"isAdmin":false}`},
		{"a renamed field", `{"advertiseWireTls":true}`, `{"advertiseWireTLS":true}`},
		{"a shorter array", `[{"name":"a"},{"name":"b"}]`, `[{"name":"a"}]`},
		{"null vs a volatile value", `{"expiresAt":null}`, `{"expiresAt":"2026-01-01T00:00:00Z"}`},
		{"a different string value", `{"principal":"a@example.com"}`, `{"principal":"b@example.com"}`},
		{"a missing nested key", `{"session":{"heartbeatMs":90000}}`, `{"session":{}}`},
	}
	for _, tc := range mustDiffer {
		t.Run(tc.name, func(t *testing.T) {
			if Normalize(tc.a) == Normalize(tc.b) {
				t.Errorf("the normaliser collapsed a REAL difference:\n  %s\n  %s\nnormalised both to: %s",
					tc.a, tc.b, Normalize(tc.a))
			}
		})
	}

	// And the converse: the three admissible classes MUST normalise equal, or the run drowns in noise.
	mustAgree := []struct{ name, a, b string }{
		{"differing ids", `{"id":1,"name":"r"}`, `{"id":97,"name":"r"}`},
		{"differing timestamps", `{"createdAt":"2026-01-01T00:00:00Z"}`, `{"createdAt":"2027-06-02T11:22:33.44Z"}`},
		{"differing secrets", `{"token":"pmr_aaa"}`, `{"token":"pmr_zzz"}`},
		{"differing key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`},
	}
	for _, tc := range mustAgree {
		t.Run(tc.name, func(t *testing.T) {
			if Normalize(tc.a) != Normalize(tc.b) {
				t.Errorf("the normaliser reported noise as a difference:\n  %s → %s\n  %s → %s",
					tc.a, Normalize(tc.a), tc.b, Normalize(tc.b))
			}
		})
	}
}
