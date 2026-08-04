package httpapi

import "github.com/ridi-oss/proxy-monster/gocp/internal/types"

// ---------------------------------------------------------------------------------------------
// A1's session-challenge DTO — 01-bootstrap.md §3 "App-local DTOs"
// ---------------------------------------------------------------------------------------------

// SessionStatusError is the body of the Authentication plugin's challenge:
// `@Serializable data class SessionStatusError(val reason: String)` (App.kt:224), written by
// `respondSessionUnauthorized` (App.kt:242-253).
//
// 🔒 INV-A4-3 — `reason` is a CLOSED four-value vocabulary — `none` | `displaced` | `bind_mismatch` |
// `expired` — collapsed from the six stored `ENDED_*` reasons. The three surfaced values are the
// three the console must explain differently: "someone signed in elsewhere", "this browser is not the
// one that signed in", "your session ran out". DEACTIVATED is deliberately NOT surfaced, so an
// unauthenticated caller is never told that a specific account was deprovisioned. See
// session.WireReason for the mapping and [Sessions.RespondSessionUnauthorized] for the one arm that
// mapping cannot express.
//
// A plain non-null String with no default, so there is nothing for encodeDefaults/explicitNulls to
// change: one required key, always present.
type SessionStatusError struct {
	Reason string `json:"reason"`
}

// ---------------------------------------------------------------------------------------------
// SCIM's error envelope — 03-identity-scim.md §"Scim.kt"
// ---------------------------------------------------------------------------------------------

// ScimErrorSchema is `SCIM_ERROR_SCHEMA` (Scim.kt:38) — the RFC 7644 §3.12 error URN.
const ScimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// ScimError is `@Serializable data class ScimError(schemas, status, scimType, detail)` (Scim.kt:77).
//
// 🔒 INV-A1-13's ONE EXEMPTION. Every other error body on the wire is [types.ApiError] — a
// dot-namespaced i18n key with no English prose. SCIM is exempt because its consumer is an IdP, not
// the console: the IdP parses the SCIM 2.0 shape and there is no locale to look anything up in.
// `detail` is therefore deliberately English prose, and reproducing the exact strings matters —
// "SCIM provisioning is not configured", "SCIM requires TLS", "invalid bearer token" are what an
// operator reads out of Okta's or Entra's provisioning log when they are debugging a 501.
//
// `status` is a STRING, not a number, per the SCIM spec. `schemas` is a defaulted non-null list, so
// encodeDefaults=true always emits it (INV-A1-4) — hence the normalisation in [ScimError.MarshalJSON]
// rather than a nil slice reaching the wire as `null`. `scimType` and `detail` are nullable with null
// defaults, so explicitNulls=false OMITS them when absent.
//
// It lives in this package rather than in internal/identity because all three of its emissions are
// [Gates.RequireScimAuth]'s. A3's `respondScimError` (Scim.kt:229) must REUSE this type; a second
// declaration is how the gate and the routes drift apart on the body an IdP parses.
//
//	TODO(A3): the rest of the SCIM DTOs (ScimUser, ScimGroup, ScimListResponse, ScimPatchOp) —
//	          03-identity-scim.md §"Scim.kt".
type ScimError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType *string  `json:"scimType,omitempty"`
	Detail   *string  `json:"detail,omitempty"`
}

// scimErrorJSON strips ScimError's own methods so the reflection codec can be reused inside them.
type scimErrorJSON ScimError

// MarshalJSON emits `schemas: [ScimErrorSchema]` when the slice is nil.
//
// The Kotlin default is `listOf(SCIM_ERROR_SCHEMA)`, not `emptyList()`, so a nil slice here must
// become the ONE-ELEMENT default — not `[]`. An IdP that receives `"schemas": []` cannot tell what it
// is holding, and every construction site in the port writes `ScimError{Status: …}` without it.
func (e ScimError) MarshalJSON() ([]byte, error) {
	v := scimErrorJSON(e)
	if v.Schemas == nil {
		v.Schemas = []string{ScimErrorSchema}
	}
	// No HTML escaping — the same reason types.MarshalWire gives. Calling it on the alias type is
	// what keeps this from recursing back into MarshalJSON.
	return types.MarshalWire(v)
}

// NewScimError builds the gate's three bodies: schemas defaulted, no scimType, an English detail.
func NewScimError(status, detail string) ScimError {
	return ScimError{Schemas: []string{ScimErrorSchema}, Status: status, Detail: &detail}
}
