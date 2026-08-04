package types

import "net/http"

// OAuthError is the RFC 6749 §5.2 error body — `internal data class OAuthError(val error: String,
// val error_description: String? = null)` (oauth/OAuthRoutes.kt:64).
//
// # Why it lives here and not in an oauth package
//
// The Kotlin declares it `internal` inside `oauth/OAuthRoutes.kt`, but A1's StatusPages catch-all
// answers with it (App.kt:456) for every `/oauth/**` path and for
// `/.well-known/oauth-authorization-server` — so the type is already shared between A1 and A11 in the
// Kotlin, and A11 does not exist in the port yet. Hoisting it next to [ApiError], the port's other
// error envelope, is a FILE-PLACEMENT decision of exactly the kind 05-datasources-catalog.md:619
// blesses for `requireApi` ("a Go port should hoist it somewhere neutral — a file-placement decision,
// not a behaviour one").
//
//	TODO(A11): the OAuth routes must REUSE this type, never redeclare one. Two declarations is how
//	the two surfaces drift apart on a body an MCP client parses.
//
// 🔒 The field name is `error_description`, snake_case, because RFC 6749 says so and kotlinx emits
// the Kotlin property name verbatim (there is no @SerialName on it). It is NOT `errorDescription`;
// the rest of the port's DTOs are camelCase and this one deliberately is not.
//
// explicitNulls=false (INV-A1-4) means an absent description is an ABSENT KEY, never `null` — hence
// *string. The StatusPages path always leaves it absent.
type OAuthError struct {
	Error            string  `json:"error"`
	ErrorDescription *string `json:"error_description,omitempty"`
}

// OAuthServerError is the StatusPages catch-all's body for the OAuth surface: `OAuthError("server_error")`
// with no description (App.kt:456).
//
// 🔒 The reason the catch-all branches at all: an OAuth/MCP client parses `{"error": ...}` and has no
// schema for `{"code": ...}`. Answering an ApiError there gives the client an unparseable body at the
// exact moment it most needs to distinguish a retryable server fault from a protocol error.
func OAuthServerError() OAuthErrorResponse {
	return OAuthErrorResponse{Status: http.StatusInternalServerError, Body: OAuthError{Error: "server_error"}}
}

// OAuthErrorResponse pairs a status with an [OAuthError] body, the same shape [ErrorResponse] has for
// the ApiError envelope.
type OAuthErrorResponse struct {
	Status int
	Body   OAuthError
}

// Error lets an OAuthErrorResponse travel as a plain Go error. Status + code, no prose — same reason
// as [ErrorResponse.Error].
func (e OAuthErrorResponse) Error() string {
	if e.Body.ErrorDescription == nil {
		return itoaStatus(e.Status) + " " + e.Body.Error
	}
	return itoaStatus(e.Status) + " " + e.Body.Error + " (" + *e.Body.ErrorDescription + ")"
}

// Respond writes the status line plus the JSON envelope through MarshalWire, so the bytes match
// kotlinx's (INV-A1-4).
func (e OAuthErrorResponse) Respond(w http.ResponseWriter) error {
	body, err := MarshalWire(e.Body)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_, err = w.Write(body)
	return err
}

// itoaStatus avoids a fmt dependency for the one place a status becomes text.
func itoaStatus(status int) string {
	if status < 100 || status > 999 {
		return "???"
	}
	return string([]byte{byte('0' + status/100), byte('0' + (status/10)%10), byte('0' + status%10)})
}
