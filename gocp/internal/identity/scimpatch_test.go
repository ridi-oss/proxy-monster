package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `ScimPatchValidatorTest.kt` — 117 LOC, 14 cases, unit (no DB).
//
// The suite asserts the exact `scimType` on every rejection, because that is the field an IdP
// branches on: `invalidPath` tells Okta "you asked for something I do not implement" while
// `invalidValue` tells it "the shape was right, the payload was not". Getting the two the wrong way
// round is a wire-contract bug no status code would reveal.
// ---------------------------------------------------------------------------------------------

// op builds one operation. value is raw JSON text so a case can express "absent", "wrong type" and
// "right type" without the decoder normalising the difference away.
func op(name string, path *string, value string) ScimPatchOperation {
	return ScimPatchOperation{Op: name, Path: path, Value: json.RawMessage(value)}
}

// assertInvalid checks that validation failed with this scimType, and returns the detail.
func assertInvalid(t *testing.T, err error, wantType, what string) string {
	t.Helper()
	var invalid *ScimPatchInvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("%s: got %v, want a ScimPatchInvalidError", what, err)
	}
	if invalid.ScimType != wantType {
		t.Errorf("%s: scimType %q, want %q (detail: %s)", what, invalid.ScimType, wantType, invalid.Detail)
	}
	return invalid.Detail
}

// Cases 1 and 2 — `accepts replace active true` / `false`.
// KT: ScimPatchValidatorTest.kt#accepts replace active false — the same table drives both values
// KT: ScimPatchValidatorTest.kt#accepts replace active true
func TestScimPatchAcceptsReplaceActive(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{{"true", true}, {"false", false}} {
		action, err := ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("active"), tc.value)})
		if err != nil {
			t.Fatalf("replace active %s: %v", tc.value, err)
		}
		if action.SetActive == nil || *action.SetActive != tc.want {
			t.Errorf("replace active %s: got %v, want SetActive(%v)", tc.value, action.SetActive, tc.want)
		}
		if action.MemberOp != nil {
			t.Errorf("replace active %s also produced a MemberOp: %+v", tc.value, action.MemberOp)
		}
	}
}

// Case 3 — `op is case-insensitive for replace active`. The Kotlin uses `equals(…, ignoreCase =
// true)` on `op.op` — but NOT on the path, which is compared with `==` after a trim.
// KT: ScimPatchValidatorTest.kt#op is case-insensitive for replace active
func TestScimPatchOpIsCaseInsensitiveButThePathIsNot(t *testing.T) {
	action, err := ValidateScimPatch([]ScimPatchOperation{op("REPLACE", types.Ptr("active"), "true")})
	if err != nil || action.SetActive == nil || !*action.SetActive {
		t.Errorf(`op "REPLACE" must match: got %+v, %v`, action, err)
	}

	// The path is NOT case-folded — "Active" falls through to the unsupported branch.
	_, err = ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("Active"), "true")})
	assertInvalid(t, err, "invalidPath", `path "Active"`)

	// It IS trimmed, though.
	action, err = ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("  active  "), "false")})
	if err != nil || action.SetActive == nil || *action.SetActive {
		t.Errorf("a padded path must be trimmed for matching: got %+v, %v", action, err)
	}
}

// Cases 4 and 5 — `accepts add|remove members with a value array`, and the op is LOWERCASED into the
// action so the routes can compare against the literal "add".
// KT: ScimPatchValidatorTest.kt#accepts add members with a value array
// KT: ScimPatchValidatorTest.kt#accepts remove members with a value array
func TestScimPatchAcceptsAddAndRemoveMembers(t *testing.T) {
	const value = `[{"value":"1"},{"value":"2"}]`
	for _, name := range []string{"add", "remove", "ADD", "Remove"} {
		action, err := ValidateScimPatch([]ScimPatchOperation{op(name, types.Ptr("members"), value)})
		if err != nil {
			t.Fatalf("%s members: %v", name, err)
		}
		if action.MemberOp == nil {
			t.Fatalf("%s members: got no MemberOp", name)
		}
		wantOp := "add"
		if name == "remove" || name == "Remove" {
			wantOp = "remove"
		}
		if action.MemberOp.Op != wantOp {
			t.Errorf("%s members: op %q, want the lowercased %q", name, action.MemberOp.Op, wantOp)
		}
		if len(action.MemberOp.Values) != 2 ||
			action.MemberOp.Values[0] != "1" || action.MemberOp.Values[1] != "2" {
			t.Errorf("%s members: values %v, want [1 2]", name, action.MemberOp.Values)
		}
	}
}

// Case 6 — `rejects an unsupported path`, and the message interpolates BOTH tokens.
// KT: ScimPatchValidatorTest.kt#rejects an unsupported path
func TestScimPatchRejectsAnUnsupportedPath(t *testing.T) {
	_, err := ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("userName"), `"bob"`)})
	detail := assertInvalid(t, err, "invalidPath", "replace:userName")
	const want = "unsupported PATCH op/path 'replace'/'userName' — " +
		"only replace:active (Users) and add|remove:members (Groups) are supported"
	if detail != want {
		t.Errorf("detail:\n got %q\nwant %q", detail, want)
	}
}

// Case 7 — `rejects a non-boolean active value`.
// KT: ScimPatchValidatorTest.kt#rejects a non-boolean active value
func TestScimPatchRejectsANonBooleanActiveValue(t *testing.T) {
	_, err := ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("active"), `"yes"`)})
	detail := assertInvalid(t, err, "invalidValue", `active "yes"`)
	if detail != "path 'active' requires a boolean value" {
		t.Errorf("detail %q", detail)
	}

	// A number, an object, an array and an absent value all take the same branch.
	for _, value := range []string{`1`, `0`, `{}`, `[]`, `null`, ``} {
		_, err := ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("active"), value)})
		assertInvalid(t, err, "invalidValue", "active value "+value)
	}
}

// 🔴 THE ONE UNVERIFIED SUB-BEHAVIOUR IN THIS FILE. 03-identity-scim.md:1024 states that
// `booleanOrNull` "only accepts an unquoted literal", so a JSON STRING "true" is rejected — that is
// what jsonBooleanLiteral implements and what this pins. kotlinx's own `booleanOrNull` is documented
// as `content.toBooleanStrictOrNull()`, which does not consult `isString` and would ACCEPT it. No
// Kotlin test covers a quoted boolean in either direction, so the spec doc decides.
//
//	TODO(A3): confirm at cutover by sending {"op":"replace","path":"active","value":"false"} at a
//	          running Kotlin control plane. If it answers 200, flip jsonBooleanLiteral and this test.
func TestScimPatchRejectsAQuotedBooleanPerTheSpec(t *testing.T) {
	for _, value := range []string{`"true"`, `"false"`} {
		_, err := ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("active"), value)})
		assertInvalid(t, err, "invalidValue", "quoted boolean "+value)
	}
}

// 🔒 Case 8 — `rejects filter-path grammar on members`. INV-A3-42: the filter grammar
// (`members[value eq "..."]`) was DELIBERATELY not implemented, and it must be REJECTED rather than
// partially honoured — a partial parse would let an IdP believe it removed a member when it did not.
// **Never guess at an unsupported path.**
// KT: ScimPatchValidatorTest.kt#rejects filter-path grammar on members
func TestScimPatchRejectsFilterPathGrammarOnMembers(t *testing.T) {
	_, err := ValidateScimPatch([]ScimPatchOperation{
		op("remove", types.Ptr(`members[value eq "2"]`), ``),
	})
	assertInvalid(t, err, "invalidPath", "filter-path grammar")
}

// Cases 9 and 10 — INV-A3-43: op/path PAIRING is enforced, not just the path. Each token below is
// individually valid and every combination is still invalidPath.
// KT: ScimPatchValidatorTest.kt#rejects replace on members (wrong op for that path)
// KT: ScimPatchValidatorTest.kt#rejects add on active (wrong op for that path)
func TestScimPatchEnforcesOpPathPairing(t *testing.T) {
	_, err := ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("members"), `[{"value":"1"}]`)})
	assertInvalid(t, err, "invalidPath", "replace:members")

	_, err = ValidateScimPatch([]ScimPatchOperation{op("add", types.Ptr("active"), "true")})
	assertInvalid(t, err, "invalidPath", "add:active")

	_, err = ValidateScimPatch([]ScimPatchOperation{op("remove", types.Ptr("active"), "false")})
	assertInvalid(t, err, "invalidPath", "remove:active")
}

// Case 11 — `rejects a members value that is not an array of objects`.
//
// ⚠️ Only the whole value NOT being an array is an error. INV-A3-46: within an array, a non-object
// entry, an entry with no `value` key, and a `value` that is itself an object are all SILENTLY
// DROPPED — asserted below, because a port that rejected them would answer 400 where the Kotlin
// answers 200 with a shorter list.
// KT: ScimPatchValidatorTest.kt#rejects a members value that is not an array of objects
func TestScimPatchRejectsANonArrayMembersValueButSilentlyDropsBadEntries(t *testing.T) {
	for _, value := range []string{`{"value":"1"}`, `"1"`, `1`, `null`, ``} {
		_, err := ValidateScimPatch([]ScimPatchOperation{op("add", types.Ptr("members"), value)})
		detail := assertInvalid(t, err, "invalidValue", "members value "+value)
		if detail != "path 'members' requires a value array of {value}" {
			t.Errorf("detail %q", detail)
		}
	}

	// The silent-drop half.
	action, err := ValidateScimPatch([]ScimPatchOperation{
		op("add", types.Ptr("members"), `["bare",{"nope":"1"},{"value":{"nested":1}},{"value":null},{"value":"7"}]`),
	})
	if err != nil {
		t.Fatalf("mixed array: %v", err)
	}
	if len(action.MemberOp.Values) != 1 || action.MemberOp.Values[0] != "7" {
		t.Errorf("values %v, want only [7] — the other four entries are silently dropped",
			action.MemberOp.Values)
	}

	// `contentOrNull` yields a NUMBER's literal text, so a numeric id survives as a string — which is
	// how a numeric-but-nonexistent id reaches the foreign key and raises 23503 (F29).
	action, err = ValidateScimPatch([]ScimPatchOperation{op("add", types.Ptr("members"), `[{"value":7},{"value":true}]`)})
	if err != nil {
		t.Fatalf("numeric member value: %v", err)
	}
	if len(action.MemberOp.Values) != 2 || action.MemberOp.Values[0] != "7" || action.MemberOp.Values[1] != "true" {
		t.Errorf("values %v, want [7 true] — contentOrNull keeps the literal text", action.MemberOp.Values)
	}

	// An empty array is a legal no-op, not an error.
	action, err = ValidateScimPatch([]ScimPatchOperation{op("remove", types.Ptr("members"), `[]`)})
	if err != nil || action.MemberOp == nil || len(action.MemberOp.Values) != 0 {
		t.Errorf("an empty members array is a no-op: got %+v, %v", action, err)
	}
}

// Cases 12 and 13 — `rejects multiple operations` / `rejects an empty Operations list`. One check
// covers both, and it runs FIRST, before any op/path inspection.
// KT: ScimPatchValidatorTest.kt#rejects an empty Operations list
// KT: ScimPatchValidatorTest.kt#rejects multiple operations
func TestScimPatchRejectsAnythingOtherThanExactlyOneOperation(t *testing.T) {
	valid := op("replace", types.Ptr("active"), "true")

	_, err := ValidateScimPatch(nil)
	detail := assertInvalid(t, err, "invalidPath", "nil operations")
	if detail != "exactly one Operations entry is supported" {
		t.Errorf("detail %q", detail)
	}
	_, err = ValidateScimPatch([]ScimPatchOperation{})
	assertInvalid(t, err, "invalidPath", "empty operations")

	// Two VALID operations are still rejected — the count check precedes everything.
	_, err = ValidateScimPatch([]ScimPatchOperation{valid, valid})
	assertInvalid(t, err, "invalidPath", "two operations")
}

// Case 14 — `rejects a missing path`.
//
// ⚠️ The message interpolates the UNTRIMMED `op.path`, and Kotlin renders a null as the four
// characters `null`. So a body with no path at all reports `.../'null'`. Reproduced literally.
// KT: ScimPatchValidatorTest.kt#rejects a missing path
func TestScimPatchRejectsAMissingPathAndReportsItAsNull(t *testing.T) {
	_, err := ValidateScimPatch([]ScimPatchOperation{op("replace", nil, "true")})
	detail := assertInvalid(t, err, "invalidPath", "missing path")
	const want = "unsupported PATCH op/path 'replace'/'null' — " +
		"only replace:active (Users) and add|remove:members (Groups) are supported"
	if detail != want {
		t.Errorf("detail:\n got %q\nwant %q", detail, want)
	}

	// And the UNTRIMMED path is what appears, even though the trimmed one drove the matching.
	_, err = ValidateScimPatch([]ScimPatchOperation{op("replace", types.Ptr("  nope  "), "true")})
	detail = assertInvalid(t, err, "invalidPath", "untrimmed path in the message")
	if detail != "unsupported PATCH op/path 'replace'/'  nope  ' — "+
		"only replace:active (Users) and add|remove:members (Groups) are supported" {
		t.Errorf("the message must carry the UNTRIMMED path, got %q", detail)
	}
}

// The ScimPatchOp envelope itself: `schemas` is read but NEVER validated, and `Operations` is
// capital-O on the wire.
func TestScimPatchOpEnvelopeIsDecodedWithoutValidatingSchemas(t *testing.T) {
	var body ScimPatchOp
	raw := `{"schemas":["urn:totally:made:up"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Operations) != 1 {
		t.Fatalf("Operations must decode from the CAPITALISED key, got %+v", body)
	}
	action, err := ValidateScimPatch(body.Operations)
	if err != nil || action.SetActive == nil || *action.SetActive {
		t.Errorf("a made-up schemas urn must be accepted: got %+v, %v", action, err)
	}

	// A body with no `schemas` at all is equally fine.
	body = ScimPatchOp{}
	if err := json.Unmarshal([]byte(`{"Operations":[]}`), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Schemas != nil {
		t.Errorf("schemas %v, want none", body.Schemas)
	}
}
