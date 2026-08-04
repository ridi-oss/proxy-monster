package policy

import (
	"encoding/json"
	"fmt"
	"github.com/ridi-oss/proxy-monster/gocp/internal/session"

	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// A2's five Cedar-policy wire DTOs, 02-authz.md §8 "Wire DTOs". Each is a `@Serializable data class`
// in `CedarPolicyStore.kt`, and kotlinx serializes by PROPERTY NAME — so `cedarSrc`, `systemKey`,
// `updatedBy` and `updatedAt` are camelCase on the wire and NOT the snake_case column names.

// CedarPolicy is one `policy` row as the API returns it.
//
// 🔒 `origin` and `systemKey` are EXPOSED but never accepted: `CedarPolicyRoutesTest` case 1 is
// literally "list exposes system provenance without accepting it in input", which is why the input
// DTO below has neither field. A port that reused one struct for both directions would let a POST
// body claim `origin: "SYSTEM"`, and the CHECK constraints in V3__policy.sql:32-41 would then reject
// the insert with a 500 instead of ignoring it.
//
// UpdatedAt is a STRING, not a time.Time, for the reason internal/types.AuditEvent.TS is: the Kotlin
// renders it with `getTimestamp(...).toInstant().toString()`, i.e. Java's VARIABLE-PRECISION
// ISO_INSTANT printer, and that formatting is wire-visible (02-authz.md:450-452, Q3). Go's
// time.RFC3339Nano is a different function. [instantString] is the shared renderer.
type CedarPolicy struct {
	ID     int64  `json:"id"`
	Origin string `json:"origin"`
	// SystemKey is `system_key`, non-null exactly for SYSTEM rows (V3__policy.sql:34-35).
	SystemKey *string `json:"systemKey,omitempty"`
	Name      string  `json:"name"`
	CedarSrc  string  `json:"cedarSrc"`
	Enabled   bool    `json:"enabled"`
	// UpdatedBy is the principal that last wrote the row; NULL for migration-owned rows.
	UpdatedBy *string `json:"updatedBy,omitempty"`
	UpdatedAt string  `json:"updatedAt"`
}

// CedarPolicyInput is the POST/PUT body.
//
// 🔒 `enabled: Boolean = true` IS THE TRAP IN THIS FILE. kotlinx applies a declared default when the
// key is ABSENT, so `{"name":"x","cedarSrc":"…"}` decodes to enabled=TRUE. Go's zero value is FALSE,
// so a naive `json.Decode` into this struct silently creates every policy DISABLED — a change nothing
// would notice until a grant stopped applying, because the row is there and reads back fine. The
// UnmarshalJSON below is the fix and it is not optional.
type CedarPolicyInput struct {
	Name     string `json:"name"`
	CedarSrc string `json:"cedarSrc"`
	Enabled  bool   `json:"enabled"`
}

// NewCedarPolicyInput is the Kotlin's default-argument constructor: enabled defaults to true.
func NewCedarPolicyInput(name, cedarSrc string) CedarPolicyInput {
	return CedarPolicyInput{Name: name, CedarSrc: cedarSrc, Enabled: true}
}

// cedarPolicyInputJSON strips the method set so the reflection codec can be reused inside it.
type cedarPolicyInputJSON CedarPolicyInput

// UnmarshalJSON reproduces kotlinx's defaulting: an ABSENT `enabled` reads as true, an explicit
// `false` reads as false.
//
// It decodes into a shadow struct whose Enabled is a *bool purely to tell those two apart — the one
// thing encoding/json cannot express with a value field. `ignoreUnknownKeys = true` is already
// encoding/json's default, so nothing is needed for it, and `name`/`cedarSrc` have NO defaults in the
// Kotlin, which means kotlinx throws MissingFieldException when either is absent. That throw becomes
// a 500 common.fallback through StatusPages, not a 400.
//
// ⚠️ AN EARLIER NOTE HERE SAID THAT WAS "reproduced by the route rather than here". It was not: the
// route answered 400. Measured against the running Kotlin — r3-policy-missing-name,
// r3-policy-missing-src and r3-policy-null-src all returned 500 while Go returned 400 — so the presence
// check lives HERE, where the decode is, and the 500 follows from session.ErrMissingField reaching
// StatusPages exactly as MissingFieldException does.
func (in *CedarPolicyInput) UnmarshalJSON(data []byte) error {
	var raw struct {
		cedarPolicyInputJSON
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Presence, before defaulting: absent and explicit-null are the same for a non-nullable field, and a
	// present-but-BLANK value is deliberately not rejected here (that is `required(…)`'s 400 further in).
	var probe struct {
		Name     *string `json:"name"`
		CedarSrc *string `json:"cedarSrc"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if probe.Name == nil {
		return fmt.Errorf("%w: name (CedarPolicyInput)", session.ErrMissingField)
	}
	if probe.CedarSrc == nil {
		return fmt.Errorf("%w: cedarSrc (CedarPolicyInput)", session.ErrMissingField)
	}

	v := CedarPolicyInput(raw.cedarPolicyInputJSON)
	v.Enabled = raw.Enabled == nil || *raw.Enabled
	*in = v
	return nil
}

// CedarValidateInput is `POST /api/policies/validate`'s body — the editor asking "would this compile"
// without writing anything.
type CedarValidateInput struct {
	CedarSrc string `json:"cedarSrc"`
}

// CedarValidateResult is that route's 200 body.
//
// 🔒 INV-A1-4 — `errors: List<String> = []` is a defaulted non-null list, so encodeDefaults=true
// ALWAYS emits it, as `[]` for the valid case. Go's nil slice marshals as `null`; the MarshalJSON
// below normalises it, so a `CedarValidateResult{Valid: true}` literal cannot produce the wrong shape.
// The editor renders `errors.length` without a null check.
type CedarValidateResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
}

type cedarValidateResultJSON CedarValidateResult

// MarshalJSON emits `errors: []` when the slice is nil.
func (r CedarValidateResult) MarshalJSON() ([]byte, error) {
	v := cedarValidateResultJSON(r)
	if v.Errors == nil {
		v.Errors = []string{}
	}
	return types.MarshalWire(v)
}

// CedarSchemaResult is `GET /api/policies/schema`'s 200 body: the bundled schema text, served to the
// editor for schema-aware linting.
//
// 02-authz.md:447 states the disclosure decision outright — "the schema is the authz model, not
// secret". It is still behind requireAdmin(ADMIN_POLICIES) like every other route in the group.
type CedarSchemaResult struct {
	Schema string `json:"schema"`
}

// CedarPolicyErrors is the body of the 400 a failed validate-on-write produces:
// `call.respond(HttpStatusCode.BadRequest, mapOf("errors" to e.errors))`.
//
// ⚠️ 02-authz.md:511 — "a **bare map**, not `ApiError`. An exception to INV-A1-13; the messages are
// Cedar's own compiler output. Preserve the shape." So this is deliberately NOT
// types.ApiError{Code: "policy.invalid"} with a joined detail: the policy editor renders one line per
// message, and Cedar's compiler prose has no i18n key to hide behind. A one-field struct is the
// faithful Go rendering of a one-key map — the bytes are identical and the shape is checked at
// compile time.
//
// 🔒 It is the SECOND documented exemption from INV-A1-13, after httpapi.ScimError. Any third one
// should be argued from a spec line, not from convenience.
type CedarPolicyErrors struct {
	Errors []string `json:"errors"`
}

type cedarPolicyErrorsJSON CedarPolicyErrors

// MarshalJSON emits `errors: []` for a nil slice, matching kotlinx over a `List<String>`.
//
// The empty case should be unreachable — the exception only exists because validation FAILED — but a
// `{"errors":null}` reaching the editor would render as a crash rather than as "no messages", and the
// normalisation costs nothing.
func (e CedarPolicyErrors) MarshalJSON() ([]byte, error) {
	v := cedarPolicyErrorsJSON(e)
	if v.Errors == nil {
		v.Errors = []string{}
	}
	return types.MarshalWire(v)
}
