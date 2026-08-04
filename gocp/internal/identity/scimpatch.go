package identity

import (
	"encoding/json"
	"strings"
)

// ---------------------------------------------------------------------------------------------
// `object ScimPatchValidator` and its output types — Scim.kt:98-137.
// ---------------------------------------------------------------------------------------------

// ScimPatchInvalidError is
// `class ScimPatchInvalidException(val scimType: String, val detailMessage: String)` (Scim.kt:99) —
// it carries the SCIM `scimType` the route echoes into the 400 body.
type ScimPatchInvalidError struct {
	ScimType string
	Detail   string
}

func (e *ScimPatchInvalidError) Error() string { return e.Detail }

// ScimPatchAction is `sealed interface ScimPatchAction` (Scim.kt:101) as a tagged union: exactly one
// of the two variants is set.
//
// 🔒 INV-A3-44 — THE VALIDATOR IS RESOURCE-AGNOSTIC AND THE ROUTES DECIDE. `SetActive` on Groups is
// 400 `invalidPath` "path 'active' is only valid on Users"; `MemberOp` on Users is 400 `invalidPath`
// "path 'members' is only valid on Groups". Keeping the validator neutral is what lets ONE
// implementation serve both routes; the cost is those two extra route branches, which must not be
// dropped.
type ScimPatchAction struct {
	// SetActive is `data class SetActive(val active: Boolean)`.
	SetActive *bool
	// MemberOp is `data class MemberOp(val op: String, val values: List<String>)` — op is ALWAYS the
	// lowercased "add" or "remove"; values are the target resources' SCIM ids as strings.
	MemberOp *ScimMemberOp
}

// ScimMemberOp is the MemberOp variant's payload.
type ScimMemberOp struct {
	Op     string
	Values []string
}

// ValidateScimPatch is `fun validate(operations: List<ScimPatchOperation>): ScimPatchAction`
// (Scim.kt:113) — a PURE function: no I/O, no store access. The routes apply the returned action.
//
// 🔒 INV-A3-42 — THE SUBSET IS EXACTLY TWO SHAPES AND EVERYTHING ELSE IS A SCIM 400, NEVER A SILENT
// ACCEPT. docs/auth-model.md:147-150 gives the reason the subset is small ("near-identical across
// IdPs, so it is cheap and portable") and records that a filter-path grammar
// (`members[value eq "..."]`) was DECLINED. ScimPatchValidatorTest case 8 pins that filter-path syntax
// is REJECTED, not partially honoured — a partial parse would let an IdP believe it removed a member
// when it did not. **Never guess at an unsupported path.**
//
// INV-A3-43 — op/path PAIRING is enforced, not just the path: `replace:members` and `add:active` are
// both `invalidPath` even though each token is individually valid.
func ValidateScimPatch(operations []ScimPatchOperation) (ScimPatchAction, error) {
	// Step 1 — covers both an empty and a multi-op body.
	if len(operations) != 1 {
		return ScimPatchAction{}, &ScimPatchInvalidError{
			ScimType: "invalidPath", Detail: "exactly one Operations entry is supported",
		}
	}
	op := operations[0]

	// Step 2 — the path is TRIMMED for matching, and `op.op` is matched case-insensitively.
	path := ""
	hasPath := op.Path != nil
	if hasPath {
		path = strings.TrimSpace(*op.Path)
	}

	// Step 3 — replace:active.
	if strings.EqualFold(op.Op, "replace") && hasPath && path == "active" {
		active, ok := jsonBooleanLiteral(op.Value)
		if !ok {
			return ScimPatchAction{}, &ScimPatchInvalidError{
				ScimType: "invalidValue", Detail: "path 'active' requires a boolean value",
			}
		}
		return ScimPatchAction{SetActive: &active}, nil
	}

	// Step 4 — add|remove:members.
	if (strings.EqualFold(op.Op, "add") || strings.EqualFold(op.Op, "remove")) && hasPath && path == "members" {
		values, ok := memberValues(op.Value)
		if !ok {
			return ScimPatchAction{}, &ScimPatchInvalidError{
				ScimType: "invalidValue", Detail: "path 'members' requires a value array of {value}",
			}
		}
		return ScimPatchAction{MemberOp: &ScimMemberOp{Op: strings.ToLower(op.Op), Values: values}}, nil
	}

	// Step 5 — everything else.
	//
	// ⚠️ The message interpolates the UNTRIMMED `op.path`, and a Kotlin string template renders a null
	// as the four characters `null`. So a body with no `path` at all reports
	// `unsupported PATCH op/path 'replace'/'null'`. Reproduced literally, including that `null`.
	rawPath := "null"
	if op.Path != nil {
		rawPath = *op.Path
	}
	return ScimPatchAction{}, &ScimPatchInvalidError{
		ScimType: "invalidPath",
		Detail: "unsupported PATCH op/path '" + op.Op + "'/'" + rawPath +
			"' — only replace:active (Users) and add|remove:members (Groups) are supported",
	}
}

// jsonBooleanLiteral is `(op.value as? JsonPrimitive)?.booleanOrNull`.
//
// ⚠️ UNVERIFIED SUB-BEHAVIOUR, and the ONE place this file departs from a literal reading of the
// kotlinx API. 03-identity-scim.md:1024 states the contract as "booleanOrNull only accepts an
// unquoted literal", so a JSON STRING `"true"` is rejected — that is what is implemented here.
// kotlinx's own `booleanOrNull` is documented as `content.toBooleanStrictOrNull()`, which does NOT
// consult `isString` and would therefore ALSO accept the quoted `"true"`. The two readings differ
// only for a quoted boolean, which no Kotlin test covers in either direction.
//
// The spec doc is the port's stated source of truth, so its reading is the one implemented and
// TestScimPatchRejectsAQuotedBooleanPerTheSpec pins it. Flipping it is a one-line change here plus
// that one test.
//
//	TODO(A3): confirm against a running Kotlin control plane at cutover — send
//	          {"op":"replace","path":"active","value":"false"} and record which answer it gives.
//
// Certain in both readings, and all reproduced: a non-primitive (object/array) is rejected, `"yes"`
// is rejected (ScimPatchValidatorTest case 7), an absent value is rejected, and JSON `null` is
// rejected.
func jsonBooleanLiteral(raw json.RawMessage) (bool, bool) {
	switch strings.TrimSpace(string(raw)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// memberValues is
// `(op.value as? JsonArray)?.mapNotNull { (it as? JsonObject)?.get("value")?.let { (it as? JsonPrimitive)?.contentOrNull } }`.
//
// ⚠️ INV-A3-46 / the silent-drop half of F29 — NON-OBJECT ENTRIES AND ENTRIES WITHOUT A `value` KEY
// ARE SILENTLY DROPPED, not rejected, and so is a `value` that is a nested object or array. Only the
// whole `value` NOT being an array is an error. Two different answers for one class of bad input;
// REPRODUCE.
//
// `contentOrNull` returns a JsonPrimitive's CONTENT, so a NUMBER is accepted and stringified
// (`{"value": 7}` ⇒ "7") and a JSON `null` is dropped. That matters downstream: the routes then run
// `toLongOrNull()` over these strings, so a numeric-but-nonexistent id survives to the foreign key and
// raises SQLSTATE 23503 — which `isUniqueViolation()` does not match (F29).
//
// The bool reports "was the value a JSON array at all"; false ⇒ the invalidValue branch.
func memberValues(raw json.RawMessage) ([]string, bool) {
	// `as? JsonArray` matches ONLY an array. A JSON `null` decodes into a nil Go slice without error,
	// so it has to be excluded explicitly — it is a JsonNull in Kotlin, i.e. a JsonPrimitive, and the
	// cast fails.
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || !strings.HasPrefix(trimmed, "[") {
		return nil, false
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	// `mapNotNull` over an empty array yields an empty list, not an error.
	values := []string{}
	for _, entry := range entries {
		var object map[string]json.RawMessage
		if json.Unmarshal(entry, &object) != nil {
			// Not a JsonObject ⇒ dropped.
			continue
		}
		value, present := object["value"]
		if !present {
			continue
		}
		content, ok := jsonPrimitiveContent(value)
		if !ok {
			continue
		}
		values = append(values, content)
	}
	return values, true
}

// jsonPrimitiveContent is `(it as? JsonPrimitive)?.contentOrNull`: the unquoted content of a string,
// the literal text of a number or boolean, and NOTHING for JSON null, an object or an array.
func jsonPrimitiveContent(raw json.RawMessage) (string, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", false
	}
	switch trimmed[0] {
	case '{', '[':
		return "", false
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	default:
		// A number or a boolean literal — kotlinx keeps the source text as `content`.
		return trimmed, true
	}
}
