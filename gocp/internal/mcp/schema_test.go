package mcp

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/management"
)

// ---------------------------------------------------------------------------------------------
// A11 §5 — `schemaFor` and `validateArguments`. All NEW: `McpServerDbTest` touches this surface only
// through case 5's single "unexpected" argument, and 00-INDEX.md F19 is exactly the observation that
// 8 cases for 38 tools leaves most of the schema unasserted.
// ---------------------------------------------------------------------------------------------

// TestSchemaForEveryToolMatchesTheKotlin pins the properties AND their declaration order AND the
// required list, for all 38 tools.
//
// 🔒 This is the INV-A11-16 table: `schemaFor` is the authority for what a client may SEND as well as
// what it is TOLD it may send, so a property missing here is an argument the server will reject with
// `mcp.invalid_request` no matter what the tool body expects.
func TestSchemaForEveryToolMatchesTheKotlin(t *testing.T) {
	type want struct {
		props    []string
		required []string
	}
	table := map[string]want{
		// READ tools with no arguments — empty properties, empty required.
		"list_datasources":  {nil, nil},
		"list_policies":     {nil, nil},
		"get_policy_schema": {nil, nil},
		"list_roles":        {nil, nil},
		"list_users":        {nil, nil},
		"list_groups":       {nil, nil},
		"list_mask_fns":     {nil, nil},

		"get_datasource_liveness": {[]string{"datasource"}, []string{"datasource"}},
		"browse_catalog":          {[]string{"datasource"}, []string{"datasource"}},
		"list_column_tags":        {[]string{"datasource"}, []string{"datasource"}},
		"get_table_detail": {
			[]string{"datasource", "schema", "table"},
			[]string{"datasource", "schema", "table"},
		},
		"get_policy":            {[]string{"name"}, []string{"name"}},
		"validate_policy":       {[]string{"cedarSrc"}, []string{"cedarSrc"}},
		"list_role_assignments": {[]string{"principal", "roleName"}, nil},

		// WRITE tools. Every one carries idempotencyKey, and for six of them the trailing `if` is its
		// ONLY declaration (they have no `when` arm at all).
		"set_column_classification": {
			[]string{"datasource", "schema", "table", "column", "tags", "maskFnName", "idempotencyKey"},
			[]string{"datasource", "table", "column", "tags"},
		},
		"clear_column_classification": {
			[]string{"datasource", "schema", "table", "column", "idempotencyKey"},
			[]string{"datasource", "table", "column"},
		},
		"create_policy": {
			[]string{"name", "cedarSrc", "enabled", "idempotencyKey"},
			[]string{"name", "cedarSrc"},
		},
		"update_policy": {
			[]string{"name", "newName", "cedarSrc", "enabled", "idempotencyKey"},
			[]string{"name", "cedarSrc"},
		},
		"enable_policy":  {[]string{"name", "idempotencyKey"}, []string{"name"}},
		"disable_policy": {[]string{"name", "idempotencyKey"}, []string{"name"}},
		"delete_policy":  {[]string{"name", "idempotencyKey"}, []string{"name"}},
		"create_role":    {[]string{"name", "description", "idempotencyKey"}, []string{"name"}},
		"update_role":    {[]string{"name", "newName", "description", "idempotencyKey"}, []string{"name"}},
		"delete_role":    {[]string{"name", "idempotencyKey"}, []string{"name"}},
		"assign_role": {
			[]string{"principal", "roleName", "idempotencyKey"},
			[]string{"principal", "roleName"},
		},
		"unassign_role": {
			[]string{"principal", "roleName", "idempotencyKey"},
			[]string{"principal", "roleName"},
		},
		"create_user": {
			[]string{"principal", "displayName", "email", "active", "idempotencyKey"},
			[]string{"principal"},
		},
		"update_user": {
			[]string{"principal", "newPrincipal", "displayName", "email", "active", "idempotencyKey"},
			[]string{"principal"},
		},
		"deprovision_user": {[]string{"principal", "idempotencyKey"}, []string{"principal"}},
		"create_group":     {[]string{"name", "description", "idempotencyKey"}, []string{"name"}},
		"update_group":     {[]string{"name", "newName", "description", "idempotencyKey"}, []string{"name"}},
		"delete_group":     {[]string{"name", "idempotencyKey"}, []string{"name"}},
		"add_group_member": {
			[]string{"groupName", "principal", "idempotencyKey"},
			[]string{"groupName", "principal"},
		},
		"remove_group_member": {
			[]string{"groupName", "principal", "idempotencyKey"},
			[]string{"groupName", "principal"},
		},
		"set_group_roles": {
			[]string{"groupName", "roleNames", "idempotencyKey"},
			[]string{"groupName", "roleNames"},
		},
		"create_mask_fn": {[]string{"name", "kind", "idempotencyKey"}, []string{"name", "kind"}},
		"update_mask_fn": {
			[]string{"name", "newName", "kind", "idempotencyKey"},
			[]string{"name", "kind"},
		},
		"delete_mask_fn": {[]string{"name", "idempotencyKey"}, []string{"name"}},
	}
	if len(table) != len(Entries) {
		t.Fatalf("expectation table has %d rows, catalog has %d", len(table), len(Entries))
	}
	for _, c := range Entries {
		w := table[c.ToolName]
		schema := schemaFor(c.ToolName)
		if schema.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", c.ToolName, schema.Type)
		}
		wantProps := w.props
		if wantProps == nil {
			wantProps = []string{}
		}
		if !slices.Equal(schema.Properties.keys, wantProps) {
			t.Errorf("%s: properties = %v, want %v (ORDER matters — it is advertised)",
				c.ToolName, schema.Properties.keys, wantProps)
		}
		wantRequired := w.required
		if wantRequired == nil {
			wantRequired = []string{}
		}
		if !slices.Equal(schema.Required, wantRequired) {
			t.Errorf("%s: required = %v, want %v", c.ToolName, schema.Required, wantRequired)
		}
	}
}

// TestEveryWriteToolAdvertisesIdempotencyKeyAndNoReadToolDoes is the structural half of INV-A11-11:
// a WRITE tool without the key cannot be made idempotent by any client, and a READ tool WITH one would
// accept an argument the executor never reads.
func TestEveryWriteToolAdvertisesIdempotencyKeyAndNoReadToolDoes(t *testing.T) {
	for _, c := range Entries {
		has := schemaFor(c.ToolName).Properties.has("idempotencyKey")
		want := c.Classification == ClassificationWrite
		if has != want {
			t.Errorf("%s (%s): idempotencyKey advertised = %v, want %v", c.ToolName, c.Classification, has, want)
		}
	}
}

// TestTheDoubleIdempotencyKeyPutKeepsItsPosition is §11 Q6 pinned.
//
// ⚠️ Most WRITE tools declare `idempotencyKey` twice — once inside the `when` arm, once by the trailing
// `if (classification == WRITE)`. Kotlin's `putJsonObject` on an existing key overwrites the VALUE and
// keeps the LinkedHashMap POSITION, so the second put is invisible. A Go implementation that appended
// on every put would move the key to the end for the 18 tools that declare it inline, changing the
// advertised order.
func TestTheDoubleIdempotencyKeyPutKeepsItsPosition(t *testing.T) {
	// create_policy declares it LAST in its `when` arm, so a positional bug is invisible there. Use
	// set_column_classification, where it is declared inline before nothing... and update_mask_fn,
	// where the inline declaration is also last. The real discriminator is a tool whose `when` arm
	// declares it and then the trailing `if` re-declares it: EVERY inline tool. Assert the count.
	o := newOrderedObject()
	o.put("a", 1)
	o.put("b", 2)
	o.put("a", 3)
	if !slices.Equal(o.keys, []string{"a", "b"}) {
		t.Fatalf("re-put moved the key: %v, want [a b]", o.keys)
	}
	if o.values["a"] != 3 {
		t.Errorf("re-put did not overwrite the value: %v", o.values["a"])
	}
	// And end to end: the key appears exactly once in the advertised property list.
	for _, c := range Entries {
		if c.Classification != ClassificationWrite {
			continue
		}
		count := 0
		for _, k := range schemaFor(c.ToolName).Properties.keys {
			if k == "idempotencyKey" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s advertises idempotencyKey %d times", c.ToolName, count)
		}
	}
}

// TestTheAdvertisedSchemaSerialisesAsJSONSchema pins the bytes one tool's schema reaches the wire as —
// `properties` in declaration order, `required` as an array, `{}`/`[]` rather than null.
func TestTheAdvertisedSchemaSerialisesAsJSONSchema(t *testing.T) {
	got, err := json.Marshal(schemaFor("create_role"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"type":"object","properties":{"name":{"type":"string"},` +
		`"description":{"type":"string"},"idempotencyKey":{"type":"string"}},"required":["name"]}`
	if string(got) != want {
		t.Errorf("schema =\n  %s\nwant\n  %s", got, want)
	}

	// A no-argument READ tool: empty object and empty array, never null (INV-A1-4).
	got, err = json.Marshal(schemaFor("list_roles"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != `{"type":"object","properties":{},"required":[]}` {
		t.Errorf("list_roles schema = %s", got)
	}

	// An array-typed property.
	got, err = json.Marshal(schemaFor("set_group_roles"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(got), `"roleNames":{"items":{"type":"string"},"type":"array"}`) &&
		!strings.Contains(string(got), `"roleNames":{"type":"array","items":{"type":"string"}}`) {
		t.Errorf("set_group_roles schema does not declare roleNames as an array of strings: %s", got)
	}
}

// ---------------------------------------------------------------------------------------------
// validateArguments
// ---------------------------------------------------------------------------------------------

// TestUnknownKeysAreRejectedAgainstSchemaForsOwnList is 🔒 INV-A11-16.
func TestUnknownKeysAreRejectedAgainstSchemaForsOwnList(t *testing.T) {
	c := ByName["create_role"]
	if err := validateArguments(c, mustArgs(t, `{"name":"r"}`)); err != nil {
		t.Fatalf("a declared argument was rejected: %v", err)
	}
	if err := validateArguments(c, mustArgs(t, `{"name":"r","unexpected":true}`)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("an undeclared argument was accepted (err = %v)", err)
	}
	// 🔒 The no-drift property: the allowed set IS the advertised set, for every tool. A test that
	// hard-coded the allowed names would pass even after the two lists diverged.
	for _, cap := range Entries {
		for _, prop := range schemaFor(cap.ToolName).Properties.keys {
			args := argValue{kind: argObject, obj: map[string]argValue{prop: {kind: argString, str: "x"}}}
			if err := validateArguments(cap, args); errors.Is(err, errInvalidInput) {
				t.Errorf("%s advertises %q but validateArguments rejects it", cap.ToolName, prop)
			}
		}
	}
}

// TestMissingRequiredArgumentsAreNotThisFunctionsBusiness pins the split that shows up in the audit
// trail: a missing required argument is `common.field_required` (raised later, by requiredString),
// NOT `mcp.invalid_request`.
func TestMissingRequiredArgumentsAreNotThisFunctionsBusiness(t *testing.T) {
	c := ByName["create_role"]
	if err := validateArguments(c, mustArgs(t, `{}`)); err != nil {
		t.Fatalf("validateArguments rejected a missing REQUIRED argument (%v); "+
			"that check belongs to requiredString and audits differently", err)
	}
}

func TestTheIdempotencyKeyMustBeANonBlankStringOfAtMost128CodeUnits(t *testing.T) {
	c := ByName["create_role"]
	cases := []struct {
		name  string
		args  string
		valid bool
	}{
		{"absent", `{"name":"r"}`, true},
		{"a plain key", `{"name":"r","idempotencyKey":"k"}`, true},
		{"exactly 128 characters", `{"name":"r","idempotencyKey":"` + strings.Repeat("k", 128) + `"}`, true},
		{"129 characters", `{"name":"r","idempotencyKey":"` + strings.Repeat("k", 129) + `"}`, false},
		{"blank", `{"name":"r","idempotencyKey":"   "}`, false},
		{"empty", `{"name":"r","idempotencyKey":""}`, false},
		// ⚠️ An EXPLICIT NULL is invalid, not "absent": kotlinx's JsonNull is a non-null JsonElement,
		// so `?.let` runs and `takeIf { it.isString }` fails.
		{"explicit null", `{"name":"r","idempotencyKey":null}`, false},
		{"a number", `{"name":"r","idempotencyKey":7}`, false},
		{"a boolean", `{"name":"r","idempotencyKey":true}`, false},
		{"an object", `{"name":"r","idempotencyKey":{}}`, false},
		// ⚠️ The cap is UTF-16 CODE UNITS, Kotlin's String.length. 128 Korean characters are 128 code
		// units and 384 bytes; a byte-based cap would reject this.
		{"128 Korean characters", `{"name":"r","idempotencyKey":"` + strings.Repeat("가", 128) + `"}`, true},
		{"129 Korean characters", `{"name":"r","idempotencyKey":"` + strings.Repeat("가", 129) + `"}`, false},
		// An emoji is TWO UTF-16 code units, so 64 of them are exactly at the cap and 65 are over.
		{"64 emoji is 128 code units", `{"name":"r","idempotencyKey":"` + strings.Repeat("😀", 64) + `"}`, true},
		{"65 emoji is 130 code units", `{"name":"r","idempotencyKey":"` + strings.Repeat("😀", 65) + `"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateArguments(c, mustArgs(t, tc.args))
			if tc.valid && err != nil {
				t.Errorf("rejected: %v", err)
			}
			if !tc.valid && !errors.Is(err, errInvalidInput) {
				t.Errorf("accepted (err = %v), want mcp.invalid_request", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// The accessors — A11 §5's "JSON accessor helpers", including INV-A11-17.
// ---------------------------------------------------------------------------------------------

// TestHasVersusStringDistinguishesAbsentFromExplicitlyNull is 🔒 INV-A11-17.
//
// It is the mechanism by which a client CLEARS a field (pass null) versus PRESERVES it (omit the key).
// A port that collapsed the two would make every omitted optional field a deletion on every update.
func TestHasVersusStringDistinguishesAbsentFromExplicitlyNull(t *testing.T) {
	absent := mustArgs(t, `{"principal":"p"}`)
	explicit := mustArgs(t, `{"principal":"p","email":null}`)
	set := mustArgs(t, `{"principal":"p","email":"a@b.c"}`)

	if absent.has("email") {
		t.Error("has() said an omitted key was present")
	}
	if !explicit.has("email") {
		t.Error("has() said an explicit null was absent — that is the whole distinction")
	}
	if !set.has("email") {
		t.Error("has() said a set key was absent")
	}
	for _, tc := range []struct {
		name string
		args argValue
		want *string
	}{
		{"absent", absent, nil},
		{"explicit null", explicit, nil},
		{"set", set, strp("a@b.c")},
	} {
		got, err := tc.args.optString("email")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: optString = %v, want %v", tc.name, deref(got), deref(tc.want))
		}
	}
}

func TestStringAccessorRejectsANonStringButAcceptsTheEmptyString(t *testing.T) {
	args := mustArgs(t, `{"a":"","n":1,"b":true,"o":{},"arr":[]}`)
	got, err := args.optString("a")
	if err != nil || got == nil || *got != "" {
		t.Errorf(`optString("") = %v, %v; the empty string is a valid string here`, deref(got), err)
	}
	for _, key := range []string{"n", "b", "o", "arr"} {
		if _, err := args.optString(key); !errors.Is(err, errInvalidInput) {
			t.Errorf("optString(%q) = %v, want mcp.invalid_request", key, err)
		}
	}
}

func TestRequiredStringReportsFieldRequiredForAbsentNullAndBlank(t *testing.T) {
	for _, raw := range []string{`{}`, `{"name":null}`, `{"name":""}`, `{"name":"   "}`} {
		_, err := mustArgs(t, raw).requiredString("name")
		var me *management.Error
		if !errors.As(err, &me) || me.Err.Code != "common.field_required" {
			t.Errorf("requiredString(%s) = %v, want common.field_required", raw, err)
			continue
		}
		// ⚠️ The param key is `fields`, PLURAL, carrying one field name. Wire-visible.
		if me.Err.Params["fields"] != "name" {
			t.Errorf("requiredString(%s) params = %v, want fields=name", raw, me.Err.Params)
		}
	}
	// ⚠️ A NON-STRING is mcp.invalid_request, not common.field_required — the type error is reported
	// before the presence error, because requiredString delegates to string().
	if _, err := mustArgs(t, `{"name":7}`).requiredString("name"); !errors.Is(err, errInvalidInput) {
		t.Errorf("requiredString(number) = %v, want mcp.invalid_request", err)
	}
}

// TestBooleanAcceptsTheStringTrueBecauseKotlinxDoes is 🔴 REPRODUCE + PIN of a real kotlinx quirk.
//
// `JsonPrimitive.booleanOrNull` is `content.toBooleanStrictOrNull()` and does NOT check `isString`, so
// the JSON STRING `"true"` is accepted as the boolean `true`. `{"enabled": "true"}` therefore ENABLES a
// policy, on the Kotlin and here. This test asserts the BUGGY behaviour deliberately: a later fix must
// change it on purpose.
func TestBooleanAcceptsTheStringTrueBecauseKotlinxDoes(t *testing.T) {
	args := mustArgs(t, `{"t":true,"f":false,"st":"true","sf":"false","cap":"True","n":1,"o":{}}`)
	for _, tc := range []struct {
		key  string
		want *bool
		err  bool
	}{
		{"t", boolp(true), false},
		{"f", boolp(false), false},
		{"st", boolp(true), false},  // 🔴 the quirk
		{"sf", boolp(false), false}, // 🔴 the quirk
		{"cap", nil, true},          // toBooleanStrictOrNull is case-SENSITIVE
		{"n", nil, true},
		{"o", nil, true},
		{"missing", nil, false},
	} {
		got, err := args.boolean(tc.key)
		if tc.err {
			if !errors.Is(err, errInvalidInput) {
				t.Errorf("boolean(%q) = %v, %v; want mcp.invalid_request", tc.key, got, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("boolean(%q): %v", tc.key, err)
			continue
		}
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("boolean(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// TestStringSetDedupsInFirstOccurrenceOrderAndRejectsNonArrays pins both halves of `stringSet`'s split
// failure behaviour and the LinkedHashSet ordering.
func TestStringSetDedupsInFirstOccurrenceOrderAndRejectsNonArrays(t *testing.T) {
	got, err := mustArgs(t, `{"tags":["c","a","c","b","a"]}`).stringSet("tags")
	if err != nil {
		t.Fatalf("stringSet: %v", err)
	}
	// 🔒 First-occurrence order, NOT sorted: the order is written to classification.tags and read back
	// by the console.
	if !slices.Equal(got, []string{"c", "a", "b"}) {
		t.Errorf("stringSet = %v, want [c a b]", got)
	}

	// ⚠️ Absent, null and "present but not an array" ALL land on common.field_required — the Kotlin's
	// `as? JsonArray` swallows the type distinction.
	for _, raw := range []string{`{}`, `{"tags":null}`, `{"tags":"pii"}`, `{"tags":{}}`} {
		_, err := mustArgs(t, raw).stringSet("tags")
		var me *management.Error
		if !errors.As(err, &me) || me.Err.Code != "common.field_required" {
			t.Errorf("stringSet(%s) = %v, want common.field_required", raw, err)
		}
	}
	// ⚠️ A non-string ELEMENT is mcp.invalid_request, a different audit outcome.
	if _, err := mustArgs(t, `{"tags":["ok",7]}`).stringSet("tags"); !errors.Is(err, errInvalidInput) {
		t.Errorf("stringSet with a numeric element = %v, want mcp.invalid_request", err)
	}
	// An empty array is a valid empty set, not a missing field.
	empty, err := mustArgs(t, `{"tags":[]}`).stringSet("tags")
	if err != nil || len(empty) != 0 {
		t.Errorf("stringSet([]) = %v, %v; want an empty set", empty, err)
	}
}

func TestAbsentArgumentsAreAnEmptyObjectNotAnError(t *testing.T) {
	v, err := parseArguments(nil)
	if err != nil {
		t.Fatalf("parseArguments(nil): %v", err)
	}
	if v.kind != argObject || len(v.obj) != 0 {
		t.Errorf("parseArguments(nil) = %+v, want an empty object", v)
	}
	if _, err := parseArguments(json.RawMessage(`[1,2]`)); !errors.Is(err, errNotAnObject) {
		t.Errorf("parseArguments(array) = %v, want errNotAnObject", err)
	}
}

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }
func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
