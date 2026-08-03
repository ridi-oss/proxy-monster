package policy

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// CedarPolicyRoutes is `Route.cedarPolicyRoutes(config, authz, management)` — A2 §8's eight
// `/api/policies` endpoints.
//
// 🔒 EVERY ROUTE IS `requireAdmin(config, authz, ADMIN_POLICIES)`, including the two read-only ones.
// That is not over-gating: `GET /api/policies` returns `cedarSrc` for every policy, which is the
// deployment's whole authorization model in source form — every grant, every forbid, every
// datasource name and role name it mentions. A reader who cannot administer policies has no reason
// to hold the map of what is permitted to whom, and A9's deliberately-loose `GET /api/roles`
// (INV-A9-3) is the contrast that shows the difference is considered rather than accidental.
//
// `GET /api/policies/schema` is behind the same gate even though 02-authz.md:447 says outright that
// "the schema is the authz model, not secret" — the disclosure judgment is about what the SCHEMA
// reveals, not a decision to open the route.
//
// The routes delegate to [PolicyManagement] and catch exactly two failures, which is the whole of
// 02-authz.md:497-498: `CedarValidationManagementException ⇒ 400 {errors: [...]}` and
// `ManagementException ⇒ respondManagementError`. Anything else reaches StatusPages as
// 500 common.fallback.
type CedarPolicyRoutes struct {
	gates      *httpapi.Gates
	management *PolicyManagement
	log        *slog.Logger
}

// NewCedarPolicyRoutes builds the group. A nil logger defaults to slog.Default().
func NewCedarPolicyRoutes(gates *httpapi.Gates, management *PolicyManagement, log *slog.Logger) *CedarPolicyRoutes {
	if log == nil {
		log = slog.Default()
	}
	return &CedarPolicyRoutes{gates: gates, management: management, log: log}
}

var _ httpapi.RouteGroup = (*CedarPolicyRoutes)(nil)

// Register mounts the eight patterns.
//
// ⚠️ NO PATTERN ENDS IN `/`. httpapi.Router's divergence 1: a trailing-slash pattern makes ServeMux
// create a subtree match AND a redirect from the bare path, which Ktor does not do (App.kt installs
// no IgnoreTrailingSlash). Every group in the port owes this and Router.Mount cannot enforce it.
//
// The literal segments `/validate` and `/schema` sit alongside the `{id}` wildcard. Go 1.22+
// patterns resolve that by SPECIFICITY, not by registration order — a literal beats a wildcard — so
// `POST /api/policies/validate` reaches the validate handler and never `{id}`. That is also why
// there is no `GET /api/policies/{id}`: adding one later would be safe, but its absence today means
// `GET /api/policies/schema` has no wildcard to be shadowed by at all.
func (rt *CedarPolicyRoutes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/policies", rt.list)
	mux.HandleFunc("POST /api/policies", rt.create)
	mux.HandleFunc("PUT /api/policies/{id}", rt.update)
	mux.HandleFunc("DELETE /api/policies/{id}", rt.delete)
	mux.HandleFunc("POST /api/policies/validate", rt.validate)
	mux.HandleFunc("GET /api/policies/schema", rt.schema)
	mux.HandleFunc("POST /api/policies/{id}/enable", rt.enable)
	mux.HandleFunc("POST /api/policies/{id}/disable", rt.disable)
}

// admin is the shared first line of all eight handlers: `if (!call.requireAdmin(config, authz,
// ADMIN_POLICIES)) return@get`.
func (rt *CedarPolicyRoutes) admin(w http.ResponseWriter, r *http.Request) bool {
	return rt.gates.RequireAdmin(w, r, authz.ActionAdminPolicies)
}

// GET /api/policies — 200, the whole list including SYSTEM rows.
func (rt *CedarPolicyRoutes) list(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	policies, err := rt.management.ListPolicies(r.Context())
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, policies)
}

// POST /api/policies — **201**, not 200.
func (rt *CedarPolicyRoutes) create(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	input, ok := rt.receiveInput(w, r)
	if !ok {
		return
	}
	updatedBy, ok := rt.updatedBy(w, r)
	if !ok {
		return
	}
	created, err := rt.management.CreatePolicy(r.Context(), input, updatedBy)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// PUT /api/policies/{id} — 200; 400 common.bad_id on an unparseable id; 409 policy.system_immutable
// for a SYSTEM row (`CedarPolicyRoutesTest` case 3).
func (rt *CedarPolicyRoutes) update(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	input, ok := rt.receiveInput(w, r)
	if !ok {
		return
	}
	updatedBy, ok := rt.updatedBy(w, r)
	if !ok {
		return
	}
	updated, err := rt.management.UpdatePolicy(r.Context(), id, input, updatedBy)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, updated)
}

// DELETE /api/policies/{id} — **204** with NO body.
func (rt *CedarPolicyRoutes) delete(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if err := rt.management.DeletePolicy(r.Context(), id); err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/policies/validate — 200 [CedarValidateResult], for BOTH outcomes.
//
// 🔒 An invalid source is `{"valid":false,"errors":[…]}` at 200, never a 400. The route asked "would
// this compile"; "no" is a successful answer. Only validate-on-WRITE turns the same list into the
// 400 `{errors: […]}` body — see [CedarPolicyRoutes.fail].
func (rt *CedarPolicyRoutes) validate(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	var input CedarValidateInput
	if err := httpapi.Receive(r, &input); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	rt.respond(w, r, http.StatusOK, rt.management.ValidatePolicy(input.CedarSrc))
}

// GET /api/policies/schema — 200 [CedarSchemaResult].
func (rt *CedarPolicyRoutes) schema(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	rt.respond(w, r, http.StatusOK, rt.management.PolicySchema())
}

// POST /api/policies/{id}/enable — 200. 🔒 INV-A2-21 revalidates here; a stored-malformed row is
// rejected with the `{errors: […]}` 400 and STAYS disabled.
func (rt *CedarPolicyRoutes) enable(w http.ResponseWriter, r *http.Request) {
	rt.setEnabled(w, r, true)
}

// POST /api/policies/{id}/disable — 200. Disabling never validates, so this cannot 400 on source.
//
// 🔒 `CedarPolicyRoutesTest` case 4 — "enable and disable remain available for SYSTEM policies",
// which is why neither of these goes through the immutability guard PUT and DELETE hit. A toggle is
// the ONE mutation a migration-owned row admits, and INV-A2-22's sentinel audit row is the price.
func (rt *CedarPolicyRoutes) disable(w http.ResponseWriter, r *http.Request) {
	rt.setEnabled(w, r, false)
}

func (rt *CedarPolicyRoutes) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	updatedBy, ok := rt.updatedBy(w, r)
	if !ok {
		return
	}
	toggled, err := rt.management.SetPolicyEnabled(r.Context(), id, enabled, updatedBy)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, toggled)
}

// ---------------------------------------------------------------------------------------------

// idParam is `val id = call.idParam() ?: return@put call.badId()`.
func (rt *CedarPolicyRoutes) idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return 0, false
	}
	return *id, true
}

// receiveInput is `call.receive<CedarPolicyInput>()`.
//
// ⚠️ A malformed body — bad JSON, or a MISSING required `name`/`cedarSrc` — is 500 common.fallback,
// NOT 400. kotlinx throws MissingFieldException, the route does not catch it, and App.kt:460's
// `exception<Throwable>` answers the fallback. 01-bootstrap.md §3 records the same behaviour for
// /api/ingest/decision. REPRODUCE: turning it into a 400 here would be a fix, and the web would stop
// being able to tell "the server rejected my body" from "the server broke".
//
// ⚠️ D6 DIVERGENCE, PINNED NOT FIXED: Go's decoder is LOOSER than kotlinx about a missing
// non-defaulted field. `{"cedarSrc":"permit(…);"}` with no `name` decodes cleanly to Name:"" here and
// creates a policy named "" (201), where kotlinx throws MissingFieldException and the Kotlin answers
// 500 common.fallback. Fixing it needs a required-field check encoding/json cannot express, and
// inventing one would change WHICH status a bad body gets on ~120 routes at once, so it is recorded
// as one divergence rather than patched per-DTO. TestCreatePolicyWithNoNameFieldIsAcceptedByGo pins
// the Go behaviour so the day A1 adds required-field decoding, this test is what changes.
//
//	TODO(A1): a shared required-field decode for the whole port — 01-bootstrap.md §3. Note
//	internal/types.ApiError.UnmarshalJSON already does exactly this by hand for one field, which is
//	the shape the shared helper should generalise.
func (rt *CedarPolicyRoutes) receiveInput(w http.ResponseWriter, r *http.Request) (CedarPolicyInput, bool) {
	// 🔒 The zero value is NOT the Kotlin default: `enabled: Boolean = true`. Seeding from
	// NewCedarPolicyInput would be redundant with CedarPolicyInput.UnmarshalJSON, which already
	// applies the default for an absent key — but only that method knows the key was absent, so the
	// decode target must be the struct and not a map.
	var input CedarPolicyInput
	if err := httpapi.Receive(r, &input); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return CedarPolicyInput{}, false
	}
	return input, true
}

// updatedBy is the principal recorded on the row and, for a SYSTEM toggle, in INV-A2-22's sentinel
// audit record.
//
// 🔒 IT IS NULLABLE ON PURPOSE. Under PM_AUTH_DEBUG requireAdmin returns true without ever reading a
// session, so there is no principal to record and the column stays NULL — which is exactly why the
// sentinel row's principal is `updatedBy ?: "unknown"` (INV-A2-22) rather than a plain read.
// Substituting a "debug-user" literal here (as A7's query-history routes legitimately do) would put
// a fabricated identity on an audit row that exists to answer "who turned off a shipped security
// rule".
//
// The bool is "keep going": a resolver failure (the database down mid-request) has already answered
// the StatusPages fallback, exactly as httpapi.Gates does on the same failure, and the handler must
// return rather than write a second response over it.
func (rt *CedarPolicyRoutes) updatedBy(w http.ResponseWriter, r *http.Request) (*string, bool) {
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return nil, false
	}
	if sess == nil {
		return nil, true
	}
	return &sess.Principal, true
}

// fail is the routes' two-arm catch, in the Kotlin's order.
//
// 🔒 THE VALIDATION ARM COMES FIRST AND ANSWERS A BARE MAP. 02-authz.md:511 — "the validation-error
// body is `{errors: [...]}` — a **bare map**, not `ApiError`. An exception to INV-A1-13; the messages
// are Cedar's own compiler output. Preserve the shape." The policy editor renders one line per
// message; an ApiError with a joined `detail` would collapse them and would file Cedar prose under
// an i18n key that does not exist.
func (rt *CedarPolicyRoutes) fail(w http.ResponseWriter, r *http.Request, err error) {
	var validation *CedarValidationError
	if errors.As(err, &validation) {
		if werr := httpapi.RespondJSON(w, http.StatusBadRequest, CedarPolicyErrors{Errors: validation.Errors}); werr != nil {
			rt.log.Error("failed to write policy validation errors", "err", werr)
		}
		return
	}
	var management *ManagementError
	if errors.As(err, &management) {
		if werr := httpapi.RespondManagementError(w, management.Err); werr != nil {
			rt.log.Error("failed to write management error", "code", management.Err.Code, "err", werr)
		}
		return
	}
	// Neither arm: a store failure or a bug. The Kotlin has no catch for it, so it reaches
	// StatusPages as 500 common.fallback.
	httpapi.RespondFallback(w, r, rt.log, err)
}

func (rt *CedarPolicyRoutes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *CedarPolicyRoutes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}
