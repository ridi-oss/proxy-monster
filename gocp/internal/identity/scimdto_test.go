package identity

import (
	"encoding/json"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// 🔴 NEW. No Kotlin suite asserts a single SCIM response BYTE — 03-identity-scim.md's coverage gap 6
// records that "every route-level branch in Scim.kt:320-594 … the `Resources` envelope — is
// unasserted", and the DTO defaults are only implicit in kotlinx's `encodeDefaults = true` +
// `explicitNulls = false`.
//
// That combination is the single easiest way to break `web/` and Okta at once, and Go's
// encoding/json defaults are the OPPOSITE of it on BOTH halves. These cases are the pin.
// ---------------------------------------------------------------------------------------------

func assertWire(t *testing.T, value any, want, what string) {
	t.Helper()
	raw, err := types.MarshalWire(value)
	if err != nil {
		t.Fatalf("%s: marshal: %v", what, err)
	}
	if string(raw) != want {
		t.Errorf("%s:\n got %s\nwant %s", what, raw, want)
	}
}

// 🔒 INV-A1-4 on ScimUser: `schemas` is the ONE-ELEMENT default (not `[]`), `emails` and `groups` are
// `[]` (not `null`), `active` is always emitted, and the three nullable fields are OMITTED.
func TestScimUserEmitsKotlinDefaultsAndOmitsAbsentOptionals(t *testing.T) {
	// The barest possible value — every default in play at once.
	assertWire(t, ScimUser{},
		`{"schemas":["`+ScimUserSchema+`"],"userName":"","emails":[],"active":false,"groups":[]}`,
		"a zero ScimUser")

	// A real user, mapped.
	user := AppUser{
		ID: 7, Principal: "alice@example.com",
		DisplayName: types.Ptr("Alice"), Email: types.Ptr("alice@example.com"),
		Source: "SCIM", ExternalID: types.Ptr("okta-1"), Active: true,
		Groups: []GroupRef{{ID: 3, Name: "engineering"}},
	}
	assertWire(t, user.ToScim(),
		`{"schemas":["`+ScimUserSchema+`"],"id":"7","externalId":"okta-1",`+
			`"userName":"alice@example.com","name":{"formatted":"Alice"},`+
			`"emails":[{"value":"alice@example.com","primary":true}],"active":true,`+
			`"groups":[{"value":"3","display":"engineering"}]}`,
		"a fully-populated user")

	// No displayName ⇒ no `name` key at all (explicitNulls=false), and no email ⇒ `emails: []`.
	bare := AppUser{ID: 8, Principal: "bob@example.com", Source: "LOCAL", Active: false}
	assertWire(t, bare.ToScim(),
		`{"schemas":["`+ScimUserSchema+`"],"id":"8","userName":"bob@example.com",`+
			`"emails":[],"active":false,"groups":[]}`,
		"a user with nothing optional set")
}

// 🔒 F22 — `active` DEFAULTS TO TRUE ON DECODE. Go's zero value is false, so leaving the custom
// unmarshaller out would silently FIX F22 and turn every Okta PUT that omits `active` into a
// deprovision. This is the unit half; the route half is
// TestScimPutOmittingActiveSilentlyReactivatesADeprovisionedUser.
func TestScimUserActiveDefaultsToTrueOnDecode(t *testing.T) {
	var body ScimUser
	if err := json.Unmarshal([]byte(`{"userName":"alice@example.com","externalId":"okta-1"}`), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Active {
		t.Errorf("active=%v for a body that omits it, want TRUE — the Kotlin default (F22)", body.Active)
	}

	// An explicit false still decodes as false.
	body = ScimUser{}
	if err := json.Unmarshal([]byte(`{"userName":"a","active":false}`), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Active {
		t.Errorf("an explicit active=false must survive, got %v", body.Active)
	}

	// `ignoreUnknownKeys = true` is encoding/json's own default — an IdP sending attributes this
	// server does not model must not 400.
	body = ScimUser{}
	err := json.Unmarshal([]byte(`{"userName":"a","nickName":"z","x509Certificates":[{"value":"…"}]}`), &body)
	if err != nil {
		t.Errorf("unknown SCIM attributes must be ignored, got %v", err)
	}
}

// `primaryEmail()`: the first entry with `primary == true`, else the FIRST entry's value.
//
// ⚠️ `it.primary == true` is a null-safe comparison on `Boolean?`, so an entry with no `primary` key
// does not match the first arm but is still eligible for the second.
func TestScimUserPrimaryEmailPrefersPrimaryThenFallsBackToTheFirst(t *testing.T) {
	none := ScimUser{}
	if none.PrimaryEmail() != nil {
		t.Errorf("no emails ⇒ nil, got %v", none.PrimaryEmail())
	}

	unmarked := ScimUser{Emails: []ScimEmail{{Value: types.Ptr("first@x")}, {Value: types.Ptr("second@x")}}}
	if got := unmarked.PrimaryEmail(); got == nil || *got != "first@x" {
		t.Errorf("no primary flag ⇒ the first entry, got %v", got)
	}

	marked := ScimUser{Emails: []ScimEmail{
		{Value: types.Ptr("first@x")},
		{Value: types.Ptr("second@x"), Primary: types.Ptr(true)},
	}}
	if got := marked.PrimaryEmail(); got == nil || *got != "second@x" {
		t.Errorf("primary=true wins wherever it sits, got %v", got)
	}

	// primary=false explicitly is NOT a match for the first arm.
	notPrimary := ScimUser{Emails: []ScimEmail{{Value: types.Ptr("only@x"), Primary: types.Ptr(false)}}}
	if got := notPrimary.PrimaryEmail(); got == nil || *got != "only@x" {
		t.Errorf("primary=false still falls back to the first entry, got %v", got)
	}
}

// ScimGroup and the list envelope. ⚠️ `Resources` is CAPITALISED — RFC 7644 §3.4.2's spelling, and
// the only capitalised key on the surface.
func TestScimGroupAndListEnvelopeShape(t *testing.T) {
	assertWire(t, ScimGroup{},
		`{"schemas":["`+ScimGroupSchema+`"],"displayName":"","members":[]}`,
		"a zero ScimGroup")

	group := AppGroup{ID: 3, Name: "engineering", Source: "SCIM", ExternalID: types.Ptr("okta-g1")}
	assertWire(t, GroupToScim(group, []GroupMemberEntry{{UserID: 7, Principal: "alice@example.com"}}),
		`{"schemas":["`+ScimGroupSchema+`"],"id":"3","externalId":"okta-g1",`+
			`"displayName":"engineering","members":[{"value":"7","display":"alice@example.com"}]}`,
		"a group with one member")

	// A group with no members is `[]`, never null.
	assertWire(t, GroupToScim(AppGroup{ID: 4, Name: "empty", Source: "LOCAL"}, nil),
		`{"schemas":["`+ScimGroupSchema+`"],"id":"4","displayName":"empty","members":[]}`,
		"a member-less group")

	// The envelope carries NO startIndex / itemsPerPage.
	assertWire(t, NewScimListResponse(nil),
		`{"schemas":["`+ScimListResponseSchema+`"],"totalResults":0,"Resources":[]}`,
		"an empty ListResponse")
	assertWire(t, NewScimListResponse([]any{GroupToScim(AppGroup{ID: 4, Name: "e"}, nil)}),
		`{"schemas":["`+ScimListResponseSchema+`"],"totalResults":1,"Resources":`+
			`[{"schemas":["`+ScimGroupSchema+`"],"id":"4","displayName":"e","members":[]}]}`,
		"a one-element ListResponse")
}

// The three static discovery documents are served BYTE FOR BYTE, so they are asserted as bytes. They
// are also checked to be valid JSON, because a typo inside a Go string concatenation is otherwise
// invisible until an IdP chokes on it.
//
// ⚠️ F33's three deviations live here and are asserted POSITIVELY: /ResourceTypes and /Schemas are
// BARE ARRAYS (not ListResponse), each ResourceTypes entry has a `schemas` key while the two Schemas
// entries do NOT, and ServiceProviderConfig has no `meta` and no `documentationUri`.
func TestDiscoveryDocumentsAreTheShippedBytes(t *testing.T) {
	for name, doc := range map[string]string{
		"ServiceProviderConfig": ServiceProviderConfigJSON,
		"ResourceTypes":         ResourceTypesJSON,
		"Schemas":               SchemasJSON,
	} {
		if !json.Valid([]byte(doc)) {
			t.Errorf("%s is not valid JSON: %s", name, doc)
		}
	}

	var spc map[string]any
	if err := json.Unmarshal([]byte(ServiceProviderConfigJSON), &spc); err != nil {
		t.Fatalf("ServiceProviderConfig: %v", err)
	}
	for _, absent := range []string{"meta", "documentationUri"} {
		if _, present := spc[absent]; present {
			t.Errorf("ServiceProviderConfig must NOT carry %q — replicate the omission", absent)
		}
	}
	if patch, _ := spc["patch"].(map[string]any); patch["supported"] != true {
		t.Errorf("patch.supported must be true, got %v", spc["patch"])
	}
	if filter, _ := spc["filter"].(map[string]any); filter["supported"] != false {
		t.Errorf("filter.supported must be false — the list routes take no filter, got %v", spc["filter"])
	}

	// Bare arrays, not ListResponse envelopes.
	var resourceTypes []map[string]any
	if err := json.Unmarshal([]byte(ResourceTypesJSON), &resourceTypes); err != nil {
		t.Fatalf("ResourceTypes is not a bare array: %v", err)
	}
	if len(resourceTypes) != 2 {
		t.Fatalf("ResourceTypes: %d entries, want 2", len(resourceTypes))
	}
	for _, entry := range resourceTypes {
		if _, present := entry["schemas"]; !present {
			t.Errorf("every ResourceTypes entry carries a schemas key, %v does not", entry)
		}
	}

	var schemas []map[string]any
	if err := json.Unmarshal([]byte(SchemasJSON), &schemas); err != nil {
		t.Fatalf("Schemas is not a bare array: %v", err)
	}
	if len(schemas) != 2 {
		t.Fatalf("Schemas: %d entries, want 2", len(schemas))
	}
	for _, entry := range schemas {
		// ⚠️ The asymmetry: these entries have ONLY id, name, attributes.
		if _, present := entry["schemas"]; present {
			t.Errorf("a Schemas entry must NOT carry a schemas key, %v does", entry["id"])
		}
		if _, present := entry["meta"]; present {
			t.Errorf("a Schemas entry must NOT carry meta, %v does", entry["id"])
		}
		if len(entry) != 3 {
			t.Errorf("a Schemas entry has exactly id/name/attributes, %v has %d keys", entry["id"], len(entry))
		}
	}
	// `groups` is the only readOnly attribute — which is what makes ScimUser.groups response-only.
	userAttrs, _ := schemas[0]["attributes"].([]any)
	readOnly := 0
	for _, a := range userAttrs {
		attr, _ := a.(map[string]any)
		if attr["mutability"] == "readOnly" {
			readOnly++
			if attr["name"] != "groups" {
				t.Errorf("the only readOnly User attribute is `groups`, found %v", attr["name"])
			}
		}
	}
	if readOnly != 1 {
		t.Errorf("%d readOnly User attributes, want exactly 1", readOnly)
	}
}
