package mcp

import (
	"unicode/utf16"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A11 §5 — `schemaFor(tool)` and `validateArguments`.
//
// 🔒 INV-A11-16 — STRICT UNKNOWN-KEY REJECTION, ENFORCED AGAINST schemaFor's OWN PROPERTY LIST. The
// tool surface is closed: a client cannot smuggle an extra argument past the schema. Because the
// validator reads the very list the advertiser publishes, THE TWO CANNOT DRIFT — which is the actual
// invariant, and the reason `schemaFor` is called from `validateArguments` on every request rather
// than a precomputed set being kept beside it. Reproduced literally, recomputation included.
// ---------------------------------------------------------------------------------------------

// orderedObject is `kotlinx.serialization.json.buildJsonObject`'s result: a JSON object whose keys
// serialize in INSERTION order, not sorted order.
//
// Go's `map[string]any` marshals with keys sorted, which would reorder every advertised `properties`
// block relative to the Kotlin. The content is semantically identical either way — JSON Schema does
// not care — but `tools/list` output is what a client caches and what a cutover diff compares, so the
// order is kept.
//
// 🔒 `put` on an EXISTING key overwrites the value and KEEPS THE ORIGINAL POSITION, which is
// LinkedHashMap's contract and therefore `putJsonObject`'s. That is load-bearing for §11 Q6: most
// WRITE tools declare `idempotencyKey` twice — once inside the `when`, once in the trailing
// `if (classification == WRITE)` — and the second put must not move it to the end.
type orderedObject struct {
	keys   []string
	values map[string]any
}

func newOrderedObject() *orderedObject {
	return &orderedObject{values: map[string]any{}}
}

func (o *orderedObject) put(key string, value any) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *orderedObject) has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// MarshalJSON emits `{}` for an empty object rather than `null` — INV-A1-4's "always emit empty
// collections" rule, which matters here because a READ tool with no arguments advertises
// `"properties": {}`.
func (o *orderedObject) MarshalJSON() ([]byte, error) {
	out := []byte{'{'}
	for i, k := range o.keys {
		if i > 0 {
			out = append(out, ',')
		}
		encoded, err := types.MarshalWire(k)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
		out = append(out, ':')
		encoded, err = types.MarshalWire(o.values[k])
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	return append(out, '}'), nil
}

// toolSchema is the Kotlin SDK's `ToolSchema(properties, required)` as it reaches the wire.
//
// `type: "object"` is mandated by the MCP spec for a tool input schema and is the Kotlin SDK type's
// own default; the two collections are always emitted, `{}` and `[]` when empty, per INV-A1-4.
type toolSchema struct {
	Type       string         `json:"type"`
	Properties *orderedObject `json:"properties"`
	Required   []string       `json:"required"`
}

// schemaFor is `private fun schemaFor(tool: String): ToolSchema` — the per-tool JSON Schema, built by
// hand in a `when`, exactly as the Kotlin does.
//
// 🔴 IT IS THE AUTHORITY FOR BOTH ADVERTISING AND VALIDATING (INV-A11-16). Adding a property here
// widens what a client may send; removing one narrows it. There is no second list.
//
// ⚠️ §11 Q6 — `idempotencyKey` is declared TWICE for most WRITE tools: once in the `when` arm and
// again by the trailing `if`. Harmless (the second put overwrites an identical value in place) and
// REPRODUCED rather than tidied, both arms included, because "harmless duplication" is exactly the
// PORT POLICY's REPRODUCE case.
//
// ⚠️ Several tools have a property with NO corresponding `required` entry and vice versa is
// impossible-by-inspection but unenforced: `update_policy` requires `name` and `cedarSrc` yet
// declares `newName` and `enabled` too, while `set_column_classification` requires
// `datasource, table, column, tags` and NOT `schema` (a nil schema means "resolve the default" —
// INV-A11-29). The asymmetries are the Kotlin's.
func schemaFor(tool string) toolSchema {
	properties := newOrderedObject()
	str := func(name string) { properties.put(name, map[string]any{"type": "string"}) }
	boolean := func(name string) { properties.put(name, map[string]any{"type": "boolean"}) }
	strings := func(name string) {
		properties.put(name, map[string]any{"type": "array", "items": map[string]any{"type": "string"}})
	}

	switch tool {
	case "get_datasource_liveness", "browse_catalog", "list_column_tags":
		str("datasource")
	case "get_table_detail":
		str("datasource")
		str("schema")
		str("table")
	case "get_policy", "enable_policy", "disable_policy", "delete_policy", "delete_role", "delete_group", "delete_mask_fn":
		str("name")
	case "validate_policy":
		str("cedarSrc")
	case "list_role_assignments":
		str("principal")
		str("roleName")
	case "set_column_classification":
		str("datasource")
		str("schema")
		str("table")
		str("column")
		strings("tags")
		str("maskFnName")
		str("idempotencyKey")
	case "clear_column_classification":
		str("datasource")
		str("schema")
		str("table")
		str("column")
		str("idempotencyKey")
	case "create_policy":
		str("name")
		str("cedarSrc")
		boolean("enabled")
		str("idempotencyKey")
	case "update_policy":
		str("name")
		str("newName")
		str("cedarSrc")
		boolean("enabled")
		str("idempotencyKey")
	case "create_role":
		str("name")
		str("description")
		str("idempotencyKey")
	case "update_role":
		str("name")
		str("newName")
		str("description")
		str("idempotencyKey")
	case "assign_role", "unassign_role":
		str("principal")
		str("roleName")
		str("idempotencyKey")
	case "create_user":
		str("principal")
		str("displayName")
		str("email")
		boolean("active")
		str("idempotencyKey")
	case "update_user":
		str("principal")
		str("newPrincipal")
		str("displayName")
		str("email")
		boolean("active")
		str("idempotencyKey")
	case "deprovision_user":
		str("principal")
		str("idempotencyKey")
	case "create_group":
		str("name")
		str("description")
		str("idempotencyKey")
	case "update_group":
		str("name")
		str("newName")
		str("description")
		str("idempotencyKey")
	case "add_group_member", "remove_group_member":
		str("groupName")
		str("principal")
		str("idempotencyKey")
	case "set_group_roles":
		str("groupName")
		strings("roleNames")
		str("idempotencyKey")
	case "create_mask_fn":
		str("name")
		str("kind")
		str("idempotencyKey")
	case "update_mask_fn":
		str("name")
		str("newName")
		str("kind")
		str("idempotencyKey")
	}

	// The trailing `if` — see Q6 above. It fires for tools whose `when` arm already declared the key
	// (a no-op that keeps the position) AND for the four WRITE tools with no `when` arm at all
	// (`enable_policy`, `disable_policy`, `delete_policy`, `delete_role`, `delete_group`,
	// `delete_mask_fn`), for which it is the ONLY declaration and therefore not redundant at all.
	if c, ok := ByName[tool]; ok && c.Classification == ClassificationWrite {
		str("idempotencyKey")
	}

	required := requiredFor(tool)
	return toolSchema{Type: "object", Properties: properties, Required: required}
}

// requiredFor is `schemaFor`'s second `when`. Split out only so the two tables read side by side;
// nothing else calls it.
//
// ⚠️ `else -> emptyList()` covers every READ tool with no arguments AND every WRITE tool whose
// arguments are all optional — so an unlisted tool advertises no required argument rather than
// failing. Reproduced, including the fact that it is a silent default.
func requiredFor(tool string) []string {
	switch tool {
	case "get_datasource_liveness", "browse_catalog", "list_column_tags":
		return []string{"datasource"}
	case "get_table_detail":
		return []string{"datasource", "schema", "table"}
	case "get_policy", "enable_policy", "disable_policy", "delete_policy", "delete_role", "delete_group", "delete_mask_fn":
		return []string{"name"}
	case "validate_policy":
		return []string{"cedarSrc"}
	case "set_column_classification":
		return []string{"datasource", "table", "column", "tags"}
	case "clear_column_classification":
		return []string{"datasource", "table", "column"}
	case "create_policy":
		return []string{"name", "cedarSrc"}
	case "update_policy":
		return []string{"name", "cedarSrc"}
	case "create_role", "create_group":
		return []string{"name"}
	case "update_role", "update_group":
		return []string{"name"}
	case "assign_role", "unassign_role":
		return []string{"principal", "roleName"}
	case "create_user", "update_user", "deprovision_user":
		return []string{"principal"}
	case "add_group_member", "remove_group_member":
		return []string{"groupName", "principal"}
	case "set_group_roles":
		return []string{"groupName", "roleNames"}
	case "create_mask_fn", "update_mask_fn":
		return []string{"name", "kind"}
	default:
		return []string{}
	}
}

// maxIdempotencyKeyLength is the Kotlin's `key.length > 128`.
const maxIdempotencyKeyLength = 128

// validateArguments is `private fun validateArguments(capability, arguments)`.
//
//  1. 🔒 INV-A11-16 — `(arguments.keys - allowed).isNotEmpty()` ⇒ McpInputException. Note the
//     direction: an argument the schema does not declare is REFUSED; a declared argument the client
//     omitted is not this function's business (the accessors decide that), and neither is a `required`
//     entry — nothing here checks `required` at all, so a missing required argument surfaces later as
//     `common.field_required` from `requiredString`, not as `mcp.invalid_request`. That difference is
//     visible in the audit trail's `outcome` column.
//  2. `idempotencyKey`, when the key is PRESENT, must be a string primitive, non-blank, ≤ 128.
//
// ⚠️ `arguments["idempotencyKey"]?.let { … }` runs for an EXPLICIT NULL, because kotlinx's `JsonNull`
// is a non-null JsonElement. `JsonNull` IS a `JsonPrimitive` but has `isString == false`, so
// `{"idempotencyKey": null}` is `mcp.invalid_request` — NOT "no idempotency key". Reproduced.
//
// ⚠️ `key.length` is Kotlin's UTF-16 length, not a byte count. A 128-character Korean key is 128 to
// Kotlin and 384 to `len()`, so the cap is measured in UTF-16 code units here too.
func validateArguments(capability Capability, arguments argValue) error {
	allowed := schemaFor(capability.ToolName).Properties
	for _, k := range arguments.keys() {
		if !allowed.has(k) {
			return errInvalidInput
		}
	}
	raw, present := arguments.obj["idempotencyKey"]
	if !present {
		return nil
	}
	if raw.kind != argString {
		return errInvalidInput
	}
	if isBlank(raw.str) || len(utf16.Encode([]rune(raw.str))) > maxIdempotencyKeyLength {
		return errInvalidInput
	}
	return nil
}
