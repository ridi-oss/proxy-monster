package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// ContentTypeJSON is what Ktor's ContentNegotiation writes for a kotlinx-serialized body.
//
// Ktor's `withCharsetIfNeeded` appends `; charset=UTF-8` only when the content type's TYPE is `text`,
// so `application/json` goes out bare. Unverified: reasoned from Ktor's serialization path, not
// measured — there is no JVM on this machine (see types.MarshalWire's identical caveat).
//
//	TODO(A1): confirm against a running Kotlin control plane during cutover. If Ktor does append a
//	charset, this constant is the ONE place to change it.
const ContentTypeJSON = "application/json"

// RespondJSON is the ContentNegotiation plugin, reduced to the one thing it does here:
// `install(ContentNegotiation) { json(appJson) }` (App.kt:452).
//
// There is no negotiation to reproduce — one converter, one media type, and the Kotlin never varies
// on Accept — so the plugin collapses into the responder. What survives is the appJson CONFIG, and
// that is load-bearing:
//
// 🔒 INV-A1-4 — `encodeDefaults = true` + `explicitNulls = false`, application-wide. In Go that
// becomes: ALWAYS emit `[]` for an empty slice, ALWAYS OMIT an absent optional, and never HTML-escape
// `<`/`>`/`&`. encoding/json gives the opposite of all three, so every body goes through
// types.MarshalWire — never json.Marshal and never json.NewEncoder(w).Encode, both of which re-escape
// whatever a nested MarshalJSON returned.
//
// A marshalling failure cannot be reported to the client (the status is already chosen and,
// depending on the caller, may already be written), so it is returned for the caller to log. Every
// caller in this package logs it.
func RespondJSON(w http.ResponseWriter, status int, body any) error {
	raw, err := types.MarshalWire(body)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	_, err = w.Write(raw)
	return err
}

// RespondAPIError writes one of types' shared ApiError envelopes — the Go form of Kotlin's
// `call.respondError(status, code, params)` / `call.badId()` / `call.notFound(resource)` / …
//
// The helpers themselves live in internal/types (they are pure values there, so they can be built,
// passed up a call chain and unit-tested without an HTTP server — which the Kotlin suspend extensions
// cannot). This is the one place that turns one into bytes.
//
//	httpapi.RespondAPIError(w, types.NotFound("datasource"))
//	httpapi.RespondAPIError(w, types.Forbidden(&reason))
func RespondAPIError(w http.ResponseWriter, e types.ErrorResponse) error {
	return e.Respond(w)
}

// RespondOAuthError writes an RFC 6749 error body — the StatusPages OAuth branch, and A11's routes.
func RespondOAuthError(w http.ResponseWriter, e types.OAuthErrorResponse) error {
	return e.Respond(w)
}

// RespondManagementError is `internal suspend fun ApplicationCall.respondManagementError(exception)`
// (Datasources.kt:709-717) — the ONE place a transport-neutral management failure becomes an HTTP
// status.
//
// It takes the [types.ApiError] rather than the error value, because that is literally what the
// Kotlin switches on (`exception.error.code`) and it keeps this package free of any dependency on
// the management services themselves. A caller unwraps first:
//
//	var me *policy.ManagementError
//	if errors.As(err, &me) { httpapi.RespondManagementError(w, me.Err); return }
//
// 🔒 THE DEFAULT ARM IS 400, NOT 500. A management service raises a code precisely when it has
// decided the REQUEST is at fault; falling back to 500 would relabel every unlisted validation
// failure as a server bug and send the console looking at logs for something the caller sent. The
// four arms are reproduced verbatim, including the `datasource.table_introspection_failed` 502 —
// which is A5's, listed here because it lives in this switch and a partial copy is how the switch
// drifts between areas.
//
// It lives in this package for the same reason [Gates.RequireAPI] and [IDParam] do: it is declared
// in Datasources.kt but called from six route files (Datasources.kt, Policies.kt, Users.kt,
// Access.kt, App.kt and the Cedar policy routes), so it is plumbing, not A5 behaviour.
func RespondManagementError(w http.ResponseWriter, e types.ApiError) error {
	status := http.StatusBadRequest
	switch e.Code {
	case "common.not_found":
		status = http.StatusNotFound
	case "datasource.table_introspection_failed":
		status = http.StatusBadGateway
	case "group.system_immutable", "role.system_immutable", "policy.system_immutable":
		status = http.StatusConflict
	}
	return RespondJSON(w, status, e)
}

// RespondScimError writes a SCIM 2.0 error body. 🔒 INV-A1-13's one exemption — see [ScimError].
func RespondScimError(w http.ResponseWriter, status int, body ScimError) error {
	return RespondJSON(w, status, body)
}

// Receive is the request half of ContentNegotiation: `call.receive<T>()` with appJson.
//
// `ignoreUnknownKeys = true` is encoding/json's default, so nothing is needed for it. What IS needed
// is the size cap: Ktor's ApplicationCall.receive has no bound of its own, but the Netty engine caps
// a request body long before a control-plane handler sees it, and a Go handler reading an unbounded
// body from a JSON decoder will happily buffer a hostile gigabyte. [MaxRequestBodyBytes] is the port
// making that implicit bound explicit.
//
// A decode failure is returned, never responded to: the CALLER chooses the code, because the Kotlin's
// choice differs per route (400 common.field_required, 400 <feature>.invalid_request, and in a few
// places a bare 400) and collapsing them here would flatten a distinction the web depends on.
func Receive(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxRequestBodyBytes))
	return dec.Decode(dst)
}

// MaxRequestBodyBytes bounds a decoded request body at 8 MiB.
//
// Chosen to sit above every legitimate body the control plane accepts — the largest by far is a
// policy source or a pushed catalog fragment, both kilobytes — and far below anything that threatens
// the process. It is a PORT ADDITION, not a Kotlin behaviour: the JVM's engine-level cap has no
// equivalent in net/http, so leaving it out would be a silent widening rather than a faithful port.
const MaxRequestBodyBytes = 8 << 20
