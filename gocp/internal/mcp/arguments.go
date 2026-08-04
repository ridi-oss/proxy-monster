package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
)

// ---------------------------------------------------------------------------------------------
// A11 §5 — the JSON argument model and the five accessor helpers.
//
// Kotlin passes `kotlinx.serialization.json.JsonObject` around. Go's SDK hands the handler a
// `json.RawMessage`, so the port needs a tree type, and the tree type is NOT `map[string]any`:
//
//  1. 🔒 INV-A11-17 — `has(name)` vs `string(name)` must distinguish ABSENT from EXPLICITLY NULL,
//     because every update tool is written `if (args.has("x")) args.string("x") else current.x`. A
//     client CLEARS a field by passing null and PRESERVES it by omitting the key. `map[string]any`
//     with a comma-ok lookup does give this — but see (2).
//  2. `canonicalJson` is a HASH INPUT (INV-A11-11) and therefore a stored-row compatibility contract,
//     and it renders numbers by their RAW SOURCE TEXT (`JsonPrimitive.toString()` returns the literal
//     as parsed). `map[string]any` decodes a number to float64 and loses `1.50` / `1e5` / `-0`
//     irrecoverably. json.Number preserves the token, which is why [argValue] keeps a `lit` field.
//  3. The accessors need to tell a STRING primitive from a non-string primitive with the same content
//     (`"true"` vs `true`), which `any` can express but only via repeated type switches at every call
//     site.
// ---------------------------------------------------------------------------------------------

// argKind is which of kotlinx's four JsonElement shapes a value is. JsonNull collapses into
// [argLiteral] with `lit == "null"`, exactly as kotlinx's `JsonNull.toString()` does.
type argKind uint8

const (
	// argLiteral is a non-string primitive: a number, `true`, `false` or `null`. `lit` holds the RAW
	// source token, which is what `JsonPrimitive.toString()` emits for a non-string literal.
	argLiteral argKind = iota
	// argString is a string primitive — `isString == true`. `str` holds the DECODED content.
	argString
	argArray
	argObject
)

// argValue is one kotlinx `JsonElement`.
type argValue struct {
	kind argKind
	lit  string
	str  string
	arr  []argValue
	obj  map[string]argValue
}

func (v argValue) isNull() bool { return v.kind == argLiteral && v.lit == "null" }

// emptyArguments is `JsonObject(emptyMap())` — what `request.arguments ?: JsonObject(emptyMap())`
// falls back to when the client sends no `arguments` at all.
func emptyArguments() argValue { return argValue{kind: argObject, obj: map[string]argValue{}} }

// errNotAnObject is what a `tools/call` whose `arguments` is present but not a JSON object produces.
//
// The Kotlin never sees this case: `CallToolRequest.arguments` is typed `JsonObject?` in the Kotlin
// SDK, so a non-object fails DESERIALIZATION and the SDK answers a JSON-RPC protocol error before any
// handler runs. Go's SDK hands over the raw bytes instead, so the same outcome has to be produced
// here — returning an error from the handler, which the Go SDK likewise turns into a protocol error.
var errNotAnObject = errors.New("mcp: tool arguments must be a JSON object")

// parseArguments decodes the SDK's raw `arguments` into the tree.
func parseArguments(raw json.RawMessage) (argValue, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return emptyArguments(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber is load-bearing, not a style choice: it is what keeps a number's SOURCE TEXT for
	// canonicalJson. Without it 1.50 hashes as 1.5 and every pre-existing idempotency row minted by
	// the Kotlin becomes a spurious conflict.
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return argValue{}, err
	}
	v, err := fromDecoded(decoded)
	if err != nil {
		return argValue{}, err
	}
	if v.kind != argObject {
		return argValue{}, errNotAnObject
	}
	return v, nil
}

func fromDecoded(v any) (argValue, error) {
	switch t := v.(type) {
	case nil:
		return argValue{kind: argLiteral, lit: "null"}, nil
	case bool:
		if t {
			return argValue{kind: argLiteral, lit: "true"}, nil
		}
		return argValue{kind: argLiteral, lit: "false"}, nil
	case json.Number:
		return argValue{kind: argLiteral, lit: t.String()}, nil
	case string:
		return argValue{kind: argString, str: t}, nil
	case []any:
		out := make([]argValue, 0, len(t))
		for _, e := range t {
			c, err := fromDecoded(e)
			if err != nil {
				return argValue{}, err
			}
			out = append(out, c)
		}
		return argValue{kind: argArray, arr: out}, nil
	case map[string]any:
		out := make(map[string]argValue, len(t))
		for k, e := range t {
			c, err := fromDecoded(e)
			if err != nil {
				return argValue{}, err
			}
			out[k] = c
		}
		return argValue{kind: argObject, obj: out}, nil
	default:
		return argValue{}, fmt.Errorf("mcp: unsupported JSON value %T", v)
	}
}

// ---------------------------------------------------------------------------------------------
// The five accessors — McpServer.kt:723-742. Their FAILURE TYPES differ and the difference is
// audited: `requiredString` and `stringSet` raise a ManagementException (audit outcome =
// `common.field_required`), while `string`, `boolean` and a bad element inside `stringSet` raise
// McpInputException (audit outcome = `mcp.invalid_request`). Do not unify them.
// ---------------------------------------------------------------------------------------------

// inputError is `private class McpInputException : RuntimeException()` — a bare marker with no
// payload. It becomes `mcp.invalid_request` at both the audit and the error-body layer.
type inputError struct{}

func (inputError) Error() string { return "mcp.invalid_request" }

var errInvalidInput error = inputError{}

// has is `JsonObject.has(name)` = `containsKey(name)`.
//
// 🔒 INV-A11-17 — this is the ABSENT/NULL discriminator. `has("email") && string("email") == nil` is a
// client CLEARING the email; `!has("email")` is a client leaving it alone. Every update tool depends
// on the pair, and collapsing them would silently make omission mean deletion.
func (v argValue) has(name string) bool {
	_, ok := v.obj[name]
	return ok
}

// str is `JsonObject.string(name): String?`:
//
//	val value = get(name) ?: return null
//	if (value is JsonNull) return null
//	return (value as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: throw McpInputException()
//
// Absent ⇒ nil. Explicit null ⇒ nil. A string ⇒ its content, INCLUDING the empty string (blankness is
// `requiredString`'s business, not this one's). Anything else — a number, a boolean, an object, an
// array — ⇒ mcp.invalid_request.
func (v argValue) optString(name string) (*string, error) {
	value, ok := v.obj[name]
	if !ok || value.isNull() {
		return nil, nil
	}
	if value.kind != argString {
		return nil, errInvalidInput
	}
	s := value.str
	return &s, nil
}

// requiredString is `JsonObject.requiredString(name)`:
//
//	string(name)?.takeIf(String::isNotBlank) ?: throw ManagementException(common.field_required{fields: name})
//
// ⚠️ Note it delegates to `string`, so a NON-STRING value still fails as `mcp.invalid_request` rather
// than `common.field_required` — the type error is reported before the presence error. Only absent,
// null and blank reach the field_required arm.
//
// ⚠️ The param key is `fields`, PLURAL, carrying exactly one field name. That is
// management.Required's own reproduced quirk and it is wire-visible.
func (v argValue) requiredString(name string) (string, error) {
	s, err := v.optString(name)
	if err != nil {
		return "", err
	}
	if s == nil || isBlank(*s) {
		return "", management.Fail("common.field_required", map[string]string{"fields": name})
	}
	return *s, nil
}

// boolean is `JsonObject.boolean(name): Boolean?`:
//
//	(value as? JsonPrimitive)?.booleanOrNull ?: throw McpInputException()
//
// ⚠️ 🔴 `booleanOrNull` IS `content.toBooleanStrictOrNull()` AND DOES NOT CHECK `isString`, so the
// JSON STRING `"true"` IS ACCEPTED AS `true`. That is kotlinx behaviour, it is reachable from any
// client, and it is REPRODUCED: `{"enabled": "true"}` enables a policy here exactly as it does on the
// Kotlin. `toBooleanStrictOrNull` is case-SENSITIVE, so `"True"` is still mcp.invalid_request.
//
// TestBooleanAcceptsTheStringTrueBecauseKotlinxDoes pins it, deliberately, as the buggy behaviour.
func (v argValue) boolean(name string) (*bool, error) {
	value, ok := v.obj[name]
	if !ok || value.isNull() {
		return nil, nil
	}
	var content string
	switch value.kind {
	case argString:
		content = value.str
	case argLiteral:
		content = value.lit
	default:
		// An object or an array is not a JsonPrimitive at all: `as?` yields null.
		return nil, errInvalidInput
	}
	switch content {
	case "true":
		t := true
		return &t, nil
	case "false":
		f := false
		return &f, nil
	default:
		return nil, errInvalidInput
	}
}

// stringSet is `JsonObject.stringSet(name): Set<String>`:
//
//	val array = get(name) as? JsonArray ?: throw ManagementException(common.field_required{fields: name})
//	return array.map { (it as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: throw McpInputException() }.toSet()
//
// ⚠️ Absent, null, and "present but not an array" ALL land on `common.field_required` — the `as?`
// swallows the type distinction. A non-string ELEMENT, by contrast, is `mcp.invalid_request`.
//
// 🔒 The result is a `Set`, and Kotlin's `toSet()` on a List builds a LinkedHashSet: duplicates
// collapse and FIRST-OCCURRENCE ORDER is preserved. That order is observable — `tags.toList()` is
// written to `classification.tags` in it, and the column's tag list is read back by the console. So
// this dedups in place rather than sorting.
func (v argValue) stringSet(name string) ([]string, error) {
	value, ok := v.obj[name]
	if !ok || value.kind != argArray {
		return nil, management.Fail("common.field_required", map[string]string{"fields": name})
	}
	seen := make(map[string]struct{}, len(value.arr))
	out := make([]string, 0, len(value.arr))
	for _, e := range value.arr {
		if e.kind != argString {
			return nil, errInvalidInput
		}
		if _, dup := seen[e.str]; dup {
			continue
		}
		seen[e.str] = struct{}{}
		out = append(out, e.str)
	}
	return out, nil
}

// stringPrimitive is the shared shape of `mutationDetail`'s and `safeDatasource`'s reads:
// `(args[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull`. It NEVER throws — a
// non-string is simply skipped — which is why a malformed `datasource` argument audits as
// "control-plane" rather than failing the audit row.
func (v argValue) stringPrimitive(name string) (string, bool) {
	value, ok := v.obj[name]
	if !ok || value.kind != argString {
		return "", false
	}
	return value.str, true
}

// keys returns the object's keys. Only ever consumed as a SET (the unknown-key difference in
// validateArguments), so the order is irrelevant; it is sorted anyway so a failure message is stable.
func (v argValue) keys() []string {
	out := make([]string, 0, len(v.obj))
	for k := range v.obj {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// without returns a copy of the object with one key removed — `JsonObject(arguments.filterKeys { it
// != "idempotencyKey" })`, the exact expression canonicalJson is applied to.
func (v argValue) without(name string) argValue {
	out := make(map[string]argValue, len(v.obj))
	for k, e := range v.obj {
		if k == name {
			continue
		}
		out[k] = e
	}
	return argValue{kind: argObject, obj: out}
}

// isBlank is Kotlin's `String.isBlank()`: empty, or every character is whitespace.
//
// Kotlin tests `Character.isWhitespace`, Go's unicode.IsSpace differs on a handful of exotic code
// points (NBSP is whitespace to Go and not to Java). Unreachable for the fields this guards — a
// principal or a role name made only of NBSP is refused a line later by the store — and narrower in
// the rejecting direction, matching internal/management's own note on the same helper.
func isBlank(s string) bool {
	for _, r := range s {
		if !isJavaWhitespace(r) {
			return false
		}
	}
	return true
}

// isJavaWhitespace is `Character.isWhitespace`, reproduced for the ASCII and separator range that can
// reach an MCP argument. It deliberately EXCLUDES the three non-breaking spaces (U+00A0, U+2007,
// U+202F), which Java also excludes and unicode.IsSpace includes.
func isJavaWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1C, 0x1D, 0x1E, 0x1F:
		return true
	case 0x00A0, 0x2007, 0x202F:
		return false // non-breaking: whitespace to Go, NOT to Java.
	}
	switch {
	case r >= 0x2000 && r <= 0x200A, // EN QUAD .. HAIR SPACE
		r == 0x1680, // OGHAM SPACE MARK
		r == 0x2028, // LINE SEPARATOR
		r == 0x2029, // PARAGRAPH SEPARATOR
		r == 0x205F, // MEDIUM MATHEMATICAL SPACE
		r == 0x3000: // IDEOGRAPHIC SPACE
		return true
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
