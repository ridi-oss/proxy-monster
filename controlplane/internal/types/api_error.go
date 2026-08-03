package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// ApiError is the user-facing API error envelope (docs/l10n.md): a stable, dot-namespaced Code the
// web UI looks up directly as an i18n message key, plus the Params it interpolates into that message.
//
// 🔒 INV-A1-13 — no English prose on the wire. Unlike an ad-hoc {"error": "<English sentence>"}, this
// keeps prose out of the wire contract so messages can be localized and deduplicated across routes.
// Code is either a shared common.* code (the helpers below, reused across many routes for the same
// KIND of failure) or a route-specific <feature>.* code for a message genuinely unique to one
// workflow. Scim.kt is the only exempt file — its error body follows the SCIM 2.0 spec for the IdP,
// not this envelope.
//
// Every code must exist in every locale under web/messages/<locale>/. 00-INDEX.md contract #11
// records that no automated completeness check exists today, so adding a code here is only half the
// change.
//
// The Go name keeps Kotlin's ApiError spelling rather than the Go-idiomatic APIError, because it is
// the name used throughout the 14 area docs and in web/'s own types; a reader grepping for ApiError
// across the port and the spec should find both.
type ApiError struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params"`
}

// apiErrorJSON strips ApiError's own methods so the reflection codec can be reused inside them.
type apiErrorJSON ApiError

// MarshalJSON emits params as {} when the map is nil.
//
// Kotlin's `params: Map<String,String> = emptyMap()` is a defaulted non-null field, so with
// encodeDefaults = true it is ALWAYS present, as {} at minimum (INV-A1-4). Go's nil map marshals as
// null, which is a different shape. Normalising here rather than at each construction site means a
// bare ApiError{Code: "..."} literal — which the port will write in dozens of places — cannot produce
// the wrong wire shape.
func (e ApiError) MarshalJSON() ([]byte, error) {
	v := apiErrorJSON(e)
	if v.Params == nil {
		v.Params = map[string]string{}
	}
	// No HTML escaping, for the reason given on MarshalWire; a plain json.Marshal caller re-escapes.
	return marshalJSON(v, false)
}

// UnmarshalJSON mirrors kotlinx: code is required (no default), params defaults to an empty map.
func (e *ApiError) UnmarshalJSON(data []byte) error {
	var raw struct {
		apiErrorJSON
		Code *string `json:"code"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Code == nil {
		return errors.New(`types: ApiError is missing required field(s) [code]`)
	}
	v := ApiError(raw.apiErrorJSON)
	v.Code = *raw.Code
	if v.Params == nil {
		v.Params = map[string]string{}
	}
	*e = v
	return nil
}

// ErrorResponse pairs an HTTP status with the ApiError body, which is what Kotlin's
// `ApplicationCall.respondError(status, code, params)` does at its call sites. The Kotlin helpers are
// suspend extensions on ApplicationCall that write the response as a side effect; in Go they are
// pure functions returning this value, so a handler can build an error, hand it up through a call
// chain and let one place write it. That also lets them be unit-tested without an HTTP server, which
// the Kotlin ones cannot be.
type ErrorResponse struct {
	Status int
	Body   ApiError
}

// Error lets an ErrorResponse travel as a plain Go error through a handler's call chain (Kotlin uses
// exceptions for the same job — see McpAuthorizationException, which wraps an ApiError).
//
// The text is deliberately status + code + params and no prose. INV-A1-13 governs the WIRE, and this
// string never reaches it — but writing an English sentence here is how prose leaks into a log, a
// gRPC status message or an MCP error payload later, so there is none to leak.
func (e ErrorResponse) Error() string {
	if len(e.Body.Params) == 0 {
		return fmt.Sprintf("%d %s", e.Status, e.Body.Code)
	}
	// Sorted so the string is stable regardless of Go's map iteration order.
	keys := make([]string, 0, len(e.Body.Params))
	for k := range e.Body.Params {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+e.Body.Params[k])
	}
	return fmt.Sprintf("%d %s {%s}", e.Status, e.Body.Code, strings.Join(parts, ", "))
}

// Respond writes the error as the Kotlin `respond(status, ApiError(...))` would: the status line plus
// the JSON envelope, through MarshalWire so the bytes match kotlinx's.
//
// TODO(A1): pin the exact Content-Type against a running Kotlin control plane. Ktor's
// ContentNegotiation may emit `application/json; charset=UTF-8` rather than the bare media type;
// 01-bootstrap.md does not say, and this is the wrong increment to guess in front of a browser.
func (e ErrorResponse) Respond(w http.ResponseWriter) error {
	body, err := MarshalWire(e.Body)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_, err = w.Write(body)
	return err
}

// RespondError is the direct analogue of Kotlin's `ApplicationCall.respondError(status, code, params)`
// for the route-specific <feature>.* codes that have no helper of their own.
func RespondError(w http.ResponseWriter, status int, code string, params map[string]string) error {
	return ErrorResponse{Status: status, Body: ApiError{Code: code, Params: params}}.Respond(w)
}

// ---- Common, cross-cutting codes -----------------------------------------------------------
//
// 01-bootstrap.md §3 lists eight. The de-duplication is the point (docs/l10n.md): "bad id" /
// "not found" / "X required" / "already exists" were each repeated near-verbatim across a dozen-plus
// routes, so there is one shared code per KIND of failure, parameterized with which resource or field
// it was about, instead of a bespoke English sentence (and a bespoke i18n key) per call site.

// BadID — 400 common.bad_id. A path param that failed to parse as an id (blank or non-numeric).
func BadID() ErrorResponse {
	return ErrorResponse{Status: http.StatusBadRequest, Body: ApiError{Code: "common.bad_id"}}
}

// NotFound — 404 common.not_found {resource}. No row matching the given id/name for resource
// (e.g. "datasource", "group", "role").
func NotFound(resource string) ErrorResponse {
	return ErrorResponse{
		Status: http.StatusNotFound,
		Body:   ApiError{Code: "common.not_found", Params: map[string]string{"resource": resource}},
	}
}

// FieldRequired — 400 common.field_required {fields}. One or more required body fields were missing
// or blank.
//
// The separator is ", " — comma AND space. The area-doc table says only "comma-joined"; the Kotlin is
// explicit (`fields.joinToString(", ")`, ApiErrors.kt), and since the web interpolates this straight
// into a sentence the space is user-visible.
func FieldRequired(fields ...string) ErrorResponse {
	return ErrorResponse{
		Status: http.StatusBadRequest,
		Body: ApiError{
			Code:   "common.field_required",
			Params: map[string]string{"fields": strings.Join(fields, ", ")},
		},
	}
}

// AlreadyExists — 409 common.already_exists {resource, name?}. A create or rename would collide with
// an existing resource, optionally naming which one.
//
// name is *string, not an optional/variadic argument, because the null case is not "no argument" but
// "the name key is ABSENT from params" — Kotlin's buildMap only puts it when non-null, and the web's
// message picks a different phrasing depending on whether the key is there. Pass nil explicitly.
func AlreadyExists(resource string, name *string) ErrorResponse {
	params := map[string]string{"resource": resource}
	if name != nil {
		params["name"] = *name
	}
	return ErrorResponse{Status: http.StatusConflict, Body: ApiError{Code: "common.already_exists", Params: params}}
}

// Unauthenticated — 401 common.unauthenticated. No session and PM_AUTH_DEBUG is off: the request
// carries no usable identity at all.
func Unauthenticated() ErrorResponse {
	return ErrorResponse{Status: http.StatusUnauthorized, Body: ApiError{Code: "common.unauthenticated"}}
}

// InvalidToken — 401 common.invalid_token {kind?}. A bearer/wire/ingest credential was missing,
// malformed or expired; kind names which one.
//
// Note the Kotlin passes emptyMap() when kind is null rather than a map with an absent key — the same
// observable result, since MarshalJSON emits {} for a nil map either way.
func InvalidToken(kind *string) ErrorResponse {
	var params map[string]string
	if kind != nil {
		params = map[string]string{"kind": *kind}
	}
	return ErrorResponse{Status: http.StatusUnauthorized, Body: ApiError{Code: "common.invalid_token", Params: params}}
}

// Fallback — 500 common.fallback. The StatusPages catch-all (App.kt:460), the body for ANY uncaught
// exception.
//
// ⚠️ F30/F41 (03-identity-scim.md:1477, 99-reconciliation-report.md:245): the catch-all also fires on
// /api/scim/v2/**, so an uncaught exception breaks the documented SCIM error-body exemption exactly
// where an IdP is least able to parse it. That is a defect, and the PORT POLICY says REPRODUCE it —
// whoever wires StatusPages must NOT carve out a SCIM branch.
func Fallback() ErrorResponse {
	return ErrorResponse{Status: http.StatusInternalServerError, Body: ApiError{Code: "common.fallback"}}
}

// Forbidden — 403 common.forbidden {detail?}. An authenticated caller whose authorization was
// refused.
//
// Two call-site families exist in the Kotlin and both are reachable, hence the pointer:
//   - WITH detail — requireAuthz (Authz.kt:911) and the MCP tool gate (McpServer.kt:213) pass
//     mapOf("detail" to decision.reason), i.e. Cedar's own reason string.
//   - WITHOUT — Query.kt:956,971 and Approvals.kt:435,466 respond a bare ApiError("common.forbidden").
//
// The area-doc table lists only the first. Reproducing both is required: McpServer.kt:663 branches on
// code == "common.forbidden" alone, so the two must keep the same code and differ only in params.
func Forbidden(detail *string) ErrorResponse {
	var params map[string]string
	if detail != nil {
		params = map[string]string{"detail": *detail}
	}
	return ErrorResponse{Status: http.StatusForbidden, Body: ApiError{Code: "common.forbidden", Params: params}}
}
