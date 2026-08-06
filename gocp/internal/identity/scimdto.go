package identity

import (
	"encoding/json"
	"strconv"

	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `Scim.kt`'s DTOs — Scim.kt:35-105, and the static discovery documents at :235-304.
//
// 🔒 INV-A1-4 GOVERNS EVERY FIELD HERE AND GO'S DEFAULTS ARE THE OPPOSITE ON BOTH HALVES:
//
//   - `explicitNulls = false` ⇒ a null optional is ABSENT, never `"field": null` ⇒ `*T` + omitempty.
//   - `encodeDefaults = true` ⇒ a defaulted NON-null property is ALWAYS emitted, so `schemas`,
//     `userName`, `emails: []`, `active`, `groups: []`, `members: []` all appear even when they carry
//     their default. Go marshals a nil slice as `null`, which is why every list-bearing DTO here has
//     a MarshalJSON that normalises nil to the Kotlin's default value — `[]` for the collections and
//     the ONE-ELEMENT urn list for `schemas`.
//
// An IdP that receives `"schemas": null` or a response missing `active` is looking at a different
// contract from the one Okta already accepts.
//
// [httpapi.ScimError] is NOT redeclared here: the gate emits it too, and 03-identity-scim.md is
// explicit that a second declaration is how the gate and the routes drift apart on the body an IdP
// parses. [scimError] below builds it.
// ---------------------------------------------------------------------------------------------

// The schema URNs, emitted verbatim (Scim.kt:35-39).
const (
	ScimUserSchema                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	ScimGroupSchema                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ScimListResponseSchema          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ScimServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// ScimName is `data class ScimName(val formatted: String? = null)` (Scim.kt:41).
//
// ⚠️ It models ONLY `formatted`. An IdP pushing `givenName`/`familyName` and no `formatted` yields
// `displayName = null` silently, because `ignoreUnknownKeys = true` drops the other two without
// complaint. Okta sends `formatted`; other IdPs may not (03-identity-scim.md Q5).
type ScimName struct {
	Formatted *string `json:"formatted,omitempty"`
}

// ScimEmail is `data class ScimEmail(value, primary, type)` (Scim.kt:42). `type` is accepted and
// IGNORED — it round-trips nowhere.
type ScimEmail struct {
	Value   *string `json:"value,omitempty"`
	Primary *bool   `json:"primary,omitempty"`
	Type    *string `json:"type,omitempty"`
}

// ScimUserGroupRef is `data class ScimUserGroupRef(value, display)` (Scim.kt:43) — `value` is the
// group's id as a DECIMAL STRING, per RFC 7643's opaque-id rule.
type ScimUserGroupRef struct {
	Value   string  `json:"value"`
	Display *string `json:"display,omitempty"`
}

// ScimMemberRef is `data class ScimMemberRef(value, display)` (Scim.kt:44).
type ScimMemberRef struct {
	Value   string  `json:"value"`
	Display *string `json:"display,omitempty"`
}

// ScimUser is `data class ScimUser(...)` (Scim.kt:47).
//
// 🔒 F22 — `active` DEFAULTS TO TRUE, and that default is what makes a `PUT /Users/{id}` body which
// OMITS `active` silently REACTIVATE a deprovisioned user (the PUT passes `body.active` verbatim, and
// the deactivate branch then never fires, so no credential teardown re-runs). REPRODUCED here in
// [ScimUser.UnmarshalJSON]; PINNED by TestScimPutOmittingActiveSilentlyReactivatesADeprovisionedUser.
// Go's zero value for bool is FALSE, i.e. the opposite, so leaving the custom unmarshaller out would
// have silently FIXED F22 — and turned every Okta PUT that omits `active` into a deprovision.
type ScimUser struct {
	Schemas    []string           `json:"schemas"`
	ID         *string            `json:"id,omitempty"`
	ExternalID *string            `json:"externalId,omitempty"`
	UserName   string             `json:"userName"`
	Name       *ScimName          `json:"name,omitempty"`
	Emails     []ScimEmail        `json:"emails"`
	Active     bool               `json:"active"`
	Groups     []ScimUserGroupRef `json:"groups"`
}

type scimUserJSON ScimUser

// MarshalJSON applies the three encodeDefaults normalisations: the one-element `schemas`, and `[]`
// for `emails` and `groups`.
func (u ScimUser) MarshalJSON() ([]byte, error) {
	v := scimUserJSON(u)
	if v.Schemas == nil {
		v.Schemas = []string{ScimUserSchema}
	}
	if v.Emails == nil {
		v.Emails = []ScimEmail{}
	}
	if v.Groups == nil {
		v.Groups = []ScimUserGroupRef{}
	}
	return types.MarshalWire(v)
}

// UnmarshalJSON decodes with `active` defaulting to TRUE — see the type's own 🔒 F22 note.
func (u *ScimUser) UnmarshalJSON(b []byte) error {
	v := scimUserJSON{Active: true}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*u = ScimUser(v)
	return nil
}

// PrimaryEmail is `fun primaryEmail(): String?` (Scim.kt:57): the first entry with `primary == true`,
// else the FIRST entry's value; may be nil.
//
// ⚠️ Note `it.primary == true` in Kotlin is a NULL-SAFE comparison on `Boolean?`, so an entry with no
// `primary` key does not match the first arm but is still eligible for the second. Reproduced.
func (u ScimUser) PrimaryEmail() *string {
	for _, e := range u.Emails {
		if e.Primary != nil && *e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return nil
}

// ScimGroup is `data class ScimGroup(...)` (Scim.kt:61).
type ScimGroup struct {
	Schemas     []string        `json:"schemas"`
	ID          *string         `json:"id,omitempty"`
	ExternalID  *string         `json:"externalId,omitempty"`
	DisplayName string          `json:"displayName"`
	Members     []ScimMemberRef `json:"members"`
}

type scimGroupJSON ScimGroup

// MarshalJSON normalises `schemas` to the one-element default and `members` to `[]`.
func (g ScimGroup) MarshalJSON() ([]byte, error) {
	v := scimGroupJSON(g)
	if v.Schemas == nil {
		v.Schemas = []string{ScimGroupSchema}
	}
	if v.Members == nil {
		v.Members = []ScimMemberRef{}
	}
	return types.MarshalWire(v)
}

// ScimListResponse is `data class ScimListResponse<T>(schemas, totalResults, @SerialName("Resources")
// resources)` (Scim.kt:70).
//
// ⚠️ `Resources` is CAPITALISED on the wire — RFC 7644 §3.4.2's spelling — while every other key in
// the file is camelCase. And there is NO `startIndex` / `itemsPerPage`: the list endpoints take no
// `startIndex`/`count`/`filter`, `ServiceProviderConfig` honestly advertises `filter.supported =
// false`, and `GET /Users` and `GET /Groups` return the ENTIRE directory in one unbounded response
// (03-identity-scim.md Q9). REPRODUCE — adding pagination would make Okta start sending
// `startIndex`/`count` the routes ignore.
//
// Go has no generic-with-methods that would let one type serve both users and groups while keeping a
// MarshalJSON, so Resources is []any and the two routes pass their own slice. The wire shape is
// identical; the type parameter was never observable.
type ScimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	Resources    []any    `json:"Resources"`
}

type scimListResponseJSON ScimListResponse

// MarshalJSON normalises `schemas` and emits `[]` for an empty directory — `resources` has NO Kotlin
// default (it is a required constructor argument), but it is a non-null List, so an empty one is `[]`
// either way.
func (l ScimListResponse) MarshalJSON() ([]byte, error) {
	v := scimListResponseJSON(l)
	if v.Schemas == nil {
		v.Schemas = []string{ScimListResponseSchema}
	}
	if v.Resources == nil {
		v.Resources = []any{}
	}
	return types.MarshalWire(v)
}

// NewScimListResponse builds the envelope with `totalResults` taken from the slice, which is what
// both call sites do (`totalResults = users.size`).
func NewScimListResponse(resources []any) ScimListResponse {
	if resources == nil {
		resources = []any{}
	}
	return ScimListResponse{
		Schemas:      []string{ScimListResponseSchema},
		TotalResults: len(resources),
		Resources:    resources,
	}
}

// ScimPatchOperation is `data class ScimPatchOperation(op, path, value)` (Scim.kt:90).
//
// 🔒 `value` stays a RAW JSON value rather than a pre-decoded bool/array: the validator must
// distinguish "wrong JSON type" (⇒ `invalidValue`) from "absent" (⇒ `invalidPath`), and a decoded
// `any` would collapse `false` and absent into the same nil-ish shape.
type ScimPatchOperation struct {
	Op    string          `json:"op"`
	Path  *string         `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ScimPatchOp is `data class ScimPatchOp(schemas, @SerialName("Operations") operations)`
// (Scim.kt:93).
//
// ⚠️ `schemas` defaults to the EMPTY list here, not to a urn — and it is READ BUT NEVER VALIDATED. An
// IdP sending the wrong PATCH schema urn, or none, is accepted. REPRODUCE.
type ScimPatchOp struct {
	Schemas    []string             `json:"schemas"`
	Operations []ScimPatchOperation `json:"Operations"`
}

// ---- mappers (Scim.kt:212-227) --------------------------------------------------------------------

// ToScim is `private fun AppUser.toScim()` (Scim.kt:212).
//
// `id` is the row id as a DECIMAL STRING; `userName` is the principal; `name` is present only when
// displayName is; `emails` is a ONE-ELEMENT `primary: true` list, or empty.
//
// ⚠️ `AppUser.email` therefore round-trips as a single primary address: a multi-valued push is lossy,
// only PrimaryEmail survives, and a subsequent GET shows one address. Deliberate — there is one
// `email` column.
func (u AppUser) ToScim() ScimUser {
	out := ScimUser{
		Schemas:    []string{ScimUserSchema},
		ID:         types.Ptr(strconv.FormatInt(u.ID, 10)),
		ExternalID: u.ExternalID,
		UserName:   u.Principal,
		Emails:     []ScimEmail{},
		Active:     u.Active,
		Groups:     []ScimUserGroupRef{},
	}
	if u.DisplayName != nil {
		out.Name = &ScimName{Formatted: u.DisplayName}
	}
	if u.Email != nil {
		out.Emails = []ScimEmail{{Value: u.Email, Primary: types.Ptr(true)}}
	}
	for _, g := range u.Groups {
		out.Groups = append(out.Groups, ScimUserGroupRef{
			Value: strconv.FormatInt(g.ID, 10), Display: types.Ptr(g.Name),
		})
	}
	return out
}

// GroupToScim is `private fun AppGroup.toScim(members: List<GroupMemberEntry>)` (Scim.kt:222).
//
// The members are passed in rather than read here, which is what lets the routes answer with a
// FRESHLY re-read member list over a STALE group row — see the PATCH and POST notes in scimroutes.go.
func GroupToScim(g AppGroup, members []GroupMemberEntry) ScimGroup {
	out := ScimGroup{
		Schemas:     []string{ScimGroupSchema},
		ID:          types.Ptr(strconv.FormatInt(g.ID, 10)),
		ExternalID:  g.ExternalID,
		DisplayName: g.Name,
		Members:     []ScimMemberRef{},
	}
	for _, m := range members {
		out.Members = append(out.Members, ScimMemberRef{
			Value: strconv.FormatInt(m.UserID, 10), Display: types.Ptr(m.Principal),
		})
	}
	return out
}

// scimError is `private suspend fun respondScimError(status, scimType, detail)` (Scim.kt:229) as a
// VALUE — `ScimError(status = status.value.toString(), scimType = scimType, detail = detail)`.
//
// 🔒 INV-A3-2 / INV-A1-13 — this is the ONE documented exemption from the ApiError envelope, and the
// `detail` strings are deliberately English prose: the consumer is an IdP with no locale to look a
// code up in, and an operator reads these out of Okta's provisioning log. scimType is nil on several
// paths and that nil is load-bearing (F26 — DELETE /Groups answers 409 with NO scimType where every
// sibling sets "mutability").
func scimError(status int, scimType *string, detail string) httpapi.ScimError {
	return httpapi.ScimError{
		Schemas:  []string{httpapi.ScimErrorSchema},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   types.Ptr(detail),
	}
}

// ---- static discovery documents (Scim.kt:235-304) --------------------------------------------------
//
// The Kotlin builds these once as `JsonObject`/`JsonArray` literals and serves them VERBATIM through
// ContentNegotiation, which emits kotlinx's compact form (no spaces) in insertion order. They are
// therefore reproduced as literal JSON text rather than as Go structs: a struct would re-derive the
// key order from field order and silently re-encode, and these bytes are what Okta already accepts.
//
// ⚠️ F33 — three deliberate RFC deviations live in these three documents and are REPRODUCED:
//
//  1. `/ResourceTypes` and `/Schemas` return BARE ARRAYS. RFC 7644 §4 wants each wrapped in a
//     ListResponse. Okta tolerates it today.
//  2. Each RESOURCE_TYPES entry carries a `schemas` key, but the two SCHEMAS entries carry ONLY `id`,
//     `name` and `attributes` — no `schemas`, no `meta`, and no per-attribute
//     `required`/`caseExact`/`returned`/`uniqueness`. The asymmetry is inside the shipped bytes.
//  3. `SERVICE_PROVIDER_CONFIG` has no `meta` and no `documentationUri`.

// ServiceProviderConfigJSON is `SERVICE_PROVIDER_CONFIG` (Scim.kt:235).
//
// Note what it advertises, honestly: `patch.supported = true` (the two-shape core subset only),
// `filter.supported = false`, `sort`/`etag`/`bulk`/`changePassword` all false. The single
// authenticationSchemes entry names the standing PM_SCIM_TOKEN credential.
const ServiceProviderConfigJSON = `{"schemas":["` + ScimServiceProviderConfigSchema + `"],` +
	`"patch":{"supported":true},` +
	`"bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},` +
	`"filter":{"supported":false,"maxResults":0},` +
	`"changePassword":{"supported":false},` +
	`"sort":{"supported":false},` +
	`"etag":{"supported":false},` +
	`"authenticationSchemes":[{"type":"oauthbearertoken","name":"OAuth Bearer Token",` +
	`"description":"Authentication via a standing PM_SCIM_TOKEN bearer credential, TLS-only",` +
	`"primary":true}]}`

// ResourceTypesJSON is `RESOURCE_TYPES` (Scim.kt:257) — a BARE array of two objects.
const ResourceTypesJSON = `[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],` +
	`"id":"User","name":"User","endpoint":"/Users","schema":"` + ScimUserSchema + `"},` +
	`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],` +
	`"id":"Group","name":"Group","endpoint":"/Groups","schema":"` + ScimGroupSchema + `"}]`

// SchemasJSON is `SCHEMAS` (Scim.kt:278) — a BARE array of two schema objects. `groups` is the only
// readOnly attribute, which is what makes `ScimUser.groups` response-only and ignored on input.
const SchemasJSON = `[{"id":"` + ScimUserSchema + `","name":"User","attributes":[` +
	`{"name":"userName","type":"string","mutability":"readWrite"},` +
	`{"name":"externalId","type":"string","mutability":"readWrite"},` +
	`{"name":"name","type":"complex","mutability":"readWrite"},` +
	`{"name":"emails","type":"complex","multiValued":true,"mutability":"readWrite"},` +
	`{"name":"active","type":"boolean","mutability":"readWrite"},` +
	`{"name":"groups","type":"complex","multiValued":true,"mutability":"readOnly"}]},` +
	`{"id":"` + ScimGroupSchema + `","name":"Group","attributes":[` +
	`{"name":"displayName","type":"string","mutability":"readWrite"},` +
	`{"name":"externalId","type":"string","mutability":"readWrite"},` +
	`{"name":"members","type":"complex","multiValued":true,"mutability":"readWrite"}]}]`
