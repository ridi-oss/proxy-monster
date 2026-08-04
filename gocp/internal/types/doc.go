// Package types holds the three types used across every other area of the control plane:
// Decision, AuditEvent and ApiError, plus the ApiError construction helpers.
//
// Area doc: plans/proxy-monster-go-port/01-bootstrap.md §3 ("Wire contract — shared DTOs").
// Kotlin sources: Decision.kt (46 LOC), ApiErrors.kt (58 LOC).
//
// Three constraints from the area doc govern everything in here.
//
// Decision is ALLOW | MASK | DENY | ERROR. ERROR is the internal-failure case — the proxy could not
// reach a verdict — and is DISTINCT from the fail-closed DENY. Do not collapse them.
//
// AuditEvent's field names and order are FROZEN (INV, 01-bootstrap.md §3). It is the wire contract
// shared by the proxy (emitting to /api/ingest/decision), the web UI (reading it back) and auditmon
// (re-verifying the hash chain) — auditmon/canon encodes 22 business columns in a fixed order, so a
// reordering or a rename here silently breaks chain verification rather than failing a build.
//
// ApiError is {code, params} and INV-A1-13 forbids English prose on the wire: code is a stable
// dot-namespaced i18n key the web looks up directly (docs/l10n.md). Scim.kt is the only exempt file —
// its error body follows the SCIM 2.0 spec. Every code must exist in every locale under
// web/messages/<locale>/; 00-INDEX.md contract #11 records that no automated completeness check
// exists today.
//
// # JSON encoding (D9)
//
// The Kotlin's application-wide Json config is
// {ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false} and INV-A1-4 marks all
// three flags load-bearing. For Go that reduces to two rules, which are the inverse of encoding/json's
// defaults on both axes:
//
//   - an OPTIONAL field is *T with omitempty, so an unset field is ABSENT — never null. The co-hosted
//     MCP surface is consumed by the MCP TypeScript SDK's Zod schemas, which model optional protocol
//     fields as .optional() (key absent) and never .nullable(); with explicit nulls every
//     `claude mcp login` failed with a bare client-side invalid_union and zero server-side signal.
//   - a SLICE field NEVER carries omitempty and is initialised to []T{} rather than left nil, so it
//     marshals as [] and not null. The UI relies on effectiveRoles[]/rows[]/columns[] being present
//     arrays.
//
// Deliberate asymmetry to REPRODUCE: cookie payloads use the BARE Kotlin Json default, so
// explicitNulls is TRUE inside cookies and INV-A1-4 does not apply there
// (04-auth-session-tokens.md:397).
//
// A third rule the D9 summary does not spell out, added here because it bit this package: a nil MAP
// marshals as null too, and ApiError.params is a defaulted non-null Map<String,String>. It is
// normalised the same way the slices are.
//
// Neither normalisation can be left to the caller's discipline, so both AuditEvent and ApiError carry
// a MarshalJSON. What a custom MarshalJSON CANNOT fix is HTML escaping — encoding/json runs
// compact(escapeHTML) over a Marshaler's output, so the outer encoder always wins. MarshalWire in
// json.go is the seam that turns it off; the HTTP layer must use it for every response body.
//
// # Implemented in this increment
//
// Decision (decision.go) · AuditEvent (audit_event.go) · ApiError, ErrorResponse, RespondError and
// the eight helpers BadID/NotFound/FieldRequired/AlreadyExists/Unauthenticated/InvalidToken/Fallback/
// Forbidden (api_error.go) · MarshalWire and Ptr (json.go).
//
// TODO(A1): the app-local DTOs (MePermissions, SessionStatus, AuthConfigResponse, …) stay with their
// owning area, not here — see 01-bootstrap.md §3 "App-local DTOs".
// TODO(A8): the AuditEvent -> auditmon/canon.AuditEvent mapping (kind, tsMicros, then the 22 business
// fields) belongs with the audit store, not here — see 08-audit.md §2. Do NOT write a third canonical
// implementation; import auditmon/canon.
// TODO(A1): ErrorResponse.Respond's Content-Type is an unpinned guess — see the note on the method.
package types
