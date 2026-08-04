package access

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// The three route-specific ApiError codes `accessRoutes` emits. Every one is a stable i18n key, never
// English prose (INV-A1-13).
const (
	// CodeRequestNotPermitted is `POST /api/access-requests`' 403 when `task.request` on the named
	// datasource denies.
	CodeRequestNotPermitted = "approval.request_not_permitted"
	// CodeUseQueryApprovalEndpoint is the 400 both decision routes answer for a non-ROLE request:
	// a QUERY task is decided through `/api/approvals/{id}/…`, which A7 owns.
	CodeUseQueryApprovalEndpoint = "approval.use_query_approval_endpoint"
	// CodeNotApprover is the 403 both decision routes answer when `task.approve` denies.
	//
	// 🔒 INV-A6-30 — this code is reached ONLY through Cedar. There is no hardcoded self-approval
	// rule anywhere in this file; the `no-self-approval` forbid (V11 seed) is the whole mechanism,
	// and a deployment may disable it for dev/eval.
	CodeNotApprover = "approval.not_approver"
)

// The two `notFound(resource)` params. Kept as constants so the two call sites of each cannot drift.
const (
	// NotFoundRequest is `notFound("access request")` — the missing-row 404 AND the 404
	// [Store.Approve] answers when the request has no `roleId` to elevate.
	NotFoundRequest = "access request"
	// NotFoundGrant is `notFound("access grant")` — the missing-row 404 and the lost-race 404 from a
	// second revoke.
	NotFoundGrant = "access grant"
)

// DebugPrincipal is the `?: "debug-user"` fallback `POST /api/access-requests` and both decision
// routes use when there is no session.
//
// ⚠️ It is the SAME literal Tokens.kt:267 and Datasources.kt:752 declare independently — three
// file-private copies in the Kotlin, and DeviceAuth.kt has a fourth that is dead (OMITted in
// internal/device). Duplicated here rather than shared, matching the Kotlin: a shared constant would
// be a refactor, and the port's job is to reproduce.
const DebugPrincipal = "debug-user"

// Authorizer is the slice of `Authz` accessRoutes uses — FOUR methods, and the count is the point.
//
// 🔒 [httpapi.Authorizer] is DELIBERATELY one method wide, so the three context-aware entry points
// this file needs cannot come through the gates. They are named here instead, on an interface this
// package owns, exactly as internal/app/authroutes.go keeps `evaluatesInCedar` as a second field
// beside its one-method `httpapi.Authorizer`.
//
// The value wired in MUST be the SAME *authz.Authz the gates hold (INV-A1-1, one Cedar graph): the
// revoke route decides through [httpapi.Gates.RequireAuthz] while the list routes decide through
// [Authorizer.Authorize], and two graphs would let those two answers disagree about one policy set.
type Authorizer interface {
	// Authorize is the forward-filter's per-row decision. Note the EMPTY context: Kotlin's
	// `authorize(caller, action, resource)` takes `context: AuthzContext = AuthzContext()`, so the
	// two list routes decide with no requester_ip and no tags at all (Authz.kt:323-328). That is a
	// real asymmetry with the approve/reject routes below, which DO thread the request context —
	// reproduced, not smoothed over.
	Authorize(principal string, action authz.AuthzAction, resource authz.AuthzResource,
		context authz.AuthzContext) authz.AuthzDecision

	// ResolveContextTags is pass 1 of the two-pass tag mechanism, called explicitly by
	// `POST /api/access-requests` (the only accessRoutes call site that runs the two passes by hand
	// rather than through AuthorizeWithContext).
	ResolveContextTags(principal string, roles []string, datasourceName string,
		raw authz.AuthzContext, datasourceTags []string) []string

	// AuthorizeDatasourceAction is the datasource-scoped `task.request` gate.
	AuthorizeDatasourceAction(principal string, roles []string, action authz.AuthzAction,
		datasourceName string, context authz.AuthzContext, datasourceTags []string) authz.AuthzDecision

	// AuthorizeWithContext is the coherent non-query decision both approve and reject make — one role
	// snapshot through both passes (INV-A2-10), tags derived only when a datasource is in scope
	// (INV-A2-14).
	AuthorizeWithContext(principal string, action authz.AuthzAction, resource authz.AuthzResource,
		raw authz.AuthzContext, datasourceName *string, datasourceTags []string) authz.AuthzDecision
}

// Datasources is the slice of A5's `DatasourceStore` these routes call — ONE method, `get(id)`.
// *datasource.DatasourceStore satisfies it directly.
type Datasources interface {
	Get(ctx context.Context, id int64) (datasource.Datasource, bool, error)
}

// RoleResolver is the slice of A3's `RoleResolver` `POST /api/access-requests` uses.
//
// ⚠️ It is the UNION resolver (direct + group + live JIT grants), not `DirectRoles`: the roles the
// `task.request` decision runs under must be the roles a query would run under, or a principal could
// be refused a request for a role they already effectively hold.
type RoleResolver interface {
	Resolve(ctx context.Context, principal string) ([]string, error)
}

// Routes is `Route.accessRoutes(config, store, authz, datasourceStore, roleResolver)`
// (Access.kt:567-713) — the SIX endpoints of the ROLE-elevation lifecycle.
//
// # The gate map, and why no two rows are alike (06-query-decision.md §6)
//
//	GET  /api/access-requests             requireApi + FORWARD-FILTER each row by task.read
//	POST /api/access-requests             requireApi + task.request on the named datasource, if any
//	POST /api/access-requests/{id}/approve requireApi + task.approve  (403 approval.not_approver)
//	POST /api/access-requests/{id}/reject  requireApi + task.approve  (the SAME action)
//	GET  /api/access-grants               requireApi + FORWARD-FILTER each row by task.read
//	POST /api/access-grants/{id}/revoke   requireAuthz(grant.revoke) — NO requireApi at all
//
// 🔒 INV-A6-28 — THE TWO LIST ROUTES FORWARD-FILTER PER ROW RATHER THAN TRUSTING A QUERY PARAMETER.
// `?principal=` on `/api/access-grants` reaches the STORE, so the SQL happily returns another
// principal's rows; what stops the leak is that every returned row is then re-decided against the
// CALLER. A port that pushed the filter into the WHERE clause would look equivalent and would not be:
// the oversight seeds (`system:auditor`, `system:token-admin`) are exactly the principals who SHOULD
// see other people's rows, and only Cedar knows which those are.
//
// Under `authDebug` there is no session, `caller` is nil, and the FULL list is returned unfiltered —
// matching requireApi's own dev bypass. That is the one branch where "no principal" means "see
// everything" rather than "see nothing", and it is deliberate.
//
// 🔒 INV-A6-29 — `/api/access-grants/{id}/revoke` LOADS THE GRANT BEFORE THE GATE, and is the one
// route here that calls requireAuthz instead of requireApi. Reading first is what lets Cedar decide
// against the grant's OWNER; without it the only fact available at gate time is an id the caller
// chose, and any authenticated principal could revoke anyone's grant by enumeration.
//
// 🔒 INV-A6-30 — self-approval is governed ENTIRELY by Cedar. See [CodeNotApprover].
type Routes struct {
	// gates carries Config (for the three authDebug branches), Sessions (for `call.userSession()`),
	// the requireApi/requireAuthz gates, and A12's request-context seam.
	//
	// ⚠️ AuthDebug is read from `gates.Config` rather than from a copy on this struct, on purpose.
	// internal/audit measured the failure mode of the two-field shape (routes.go:49-60): a gate and a
	// handler that disagree about the bypass answer 500 on a live surface. The Kotlin passes ONE
	// `config` to both `requireApi(config)` and the `if (!config.authDebug)` branches, and reading
	// through the gates is how Go keeps that single source.
	gates *httpapi.Gates
	store *Store
	// authz MUST be the same Cedar graph gates.Authz holds — see [Authorizer].
	authz       Authorizer
	datasources Datasources
	roles       RoleResolver
	log         *slog.Logger
}

// NewRoutes builds the group. A nil logger defaults to slog.Default().
func NewRoutes(
	gates *httpapi.Gates, store *Store, az Authorizer, datasources Datasources, roles RoleResolver, log *slog.Logger,
) *Routes {
	if log == nil {
		log = slog.Default()
	}
	return &Routes{gates: gates, store: store, authz: az, datasources: datasources, roles: roles, log: log}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the six patterns. None ends in `/` — see httpapi.Router's divergence 1.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/access-requests", rt.listRequests)
	mux.HandleFunc("POST /api/access-requests", rt.createRequest)
	mux.HandleFunc("POST /api/access-requests/{id}/approve", rt.approve)
	mux.HandleFunc("POST /api/access-requests/{id}/reject", rt.reject)
	mux.HandleFunc("GET /api/access-grants", rt.listGrants)
	mux.HandleFunc("POST /api/access-grants/{id}/revoke", rt.revokeGrant)
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

// listRequests is `GET /api/access-requests?status=` — 200 `[AccessRequest]`.
//
// 🔒 INV-A6-28. The resource is `ApprovalRequest(requester, approver, executedBy, datasourceName,
// roleName)` — all five fields, and each one is a policy hook: `requester` carries the self seed,
// `approver`/`executedBy` let a policy scope by who decided or ran it, and the two names attach the
// Datasource and Role Cedar PARENTS so a per-datasource or per-role read grant matches (A2's
// marshalResource).
func (rt *Routes) listRequests(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	caller, ok := rt.caller(w, r)
	if !ok {
		return
	}

	rows, err := rt.store.ListRequests(r.Context(), queryParam(r, "status"))
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if caller != nil {
		// `rows.filter { … }` — a NEW list, never nil. INV-A1-4 puts `[]` on the wire for an empty one.
		kept := make([]AccessRequest, 0, len(rows))
		for _, row := range rows {
			d := rt.authz.Authorize(*caller, authz.ActionTaskRead, authz.ResourceApprovalRequest{
				Requester:      row.Principal,
				Approver:       row.DecidedBy,
				ExecutedBy:     row.ExecutedBy,
				DatasourceName: row.DatasourceName,
				RoleName:       row.RoleName,
			}, authz.AuthzContext{})
			if d.Allowed {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	rt.respond(w, r, http.StatusOK, rows)
}

// createRequest is `POST /api/access-requests` — **201** `AccessRequest`.
//
// The gate is CONDITIONAL, and every clause of the condition is behaviour:
//
//   - `input.datasourceId` nil ⇒ NO Cedar decision at all. A pure role elevation targets no
//     datasource, there is no Datasource resource to decide against, and authentication alone admits
//     it (Access.kt:589-591).
//   - the id names no row ⇒ `datasourceStore.get` returns null ⇒ ALSO no decision. ⚠️ That is a
//     REPRODUCED oddity: an unknown datasourceId skips the gate rather than 404ing, and the insert
//     then fails on the foreign key. The route answers 500 common.fallback, not 404. Reproduced —
//     turning it into a 404 would be a fix.
//   - `config.authDebug` ⇒ skipped, matching every other bypass in the file.
//
// The two-pass is spelled out HERE rather than delegated to AuthorizeWithContext because the resource
// is the DATASOURCE itself (INV-A2-2 keys it by NAME), which AuthorizeWithContext cannot express: it
// takes an AuthzResource, and there is no ResourceDatasource. So the route resolves tags with pass 1
// and then calls the datasource-scoped gate with `raw.copy(tags = tags)` — the same shape, unrolled.
func (rt *Routes) createRequest(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principalOr(w, r, DebugPrincipal)
	if !ok {
		return
	}

	var input AccessRequestInput
	if err := httpapi.Receive(r, &input); err != nil {
		// `call.receive<AccessRequestInput>()` is a BARE receive: a malformed body escapes to
		// StatusPages, which answers 500 common.fallback (01-bootstrap.md §3). See
		// CedarPolicyRoutes.receiveInput for the D6 divergence on a missing required field.
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}

	if input.DatasourceID != nil && !rt.gates.Config.AuthDebug {
		ds, found, err := rt.datasources.Get(r.Context(), *input.DatasourceID)
		if err != nil {
			httpapi.RespondFallback(w, r, rt.log, err)
			return
		}
		if found {
			roles, err := rt.roles.Resolve(r.Context(), principal)
			if err != nil {
				httpapi.RespondFallback(w, r, rt.log, err)
				return
			}
			raw := rt.gates.AuthzContext(r)
			tags := rt.authz.ResolveContextTags(principal, roles, ds.Name, raw, ds.Tags)
			decision := rt.authz.AuthorizeDatasourceAction(
				principal, roles, authz.ActionTaskRequest, ds.Name, raw.WithTags(tags), ds.Tags)
			if !decision.Allowed {
				rt.respondError(w, types.ErrorResponse{
					Status: http.StatusForbidden,
					Body:   types.ApiError{Code: CodeRequestNotPermitted},
				})
				return
			}
		}
	}

	created, err := rt.store.CreateRequest(r.Context(), principal, input)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if created == nil {
		// Unreachable: createRequest re-reads the row it just inserted. Kotlin's return type is
		// non-null, so a nil here is a broken postcondition, not a 404.
		httpapi.RespondFallback(w, r, rt.log, errCreatedRequestVanished)
		return
	}
	rt.respond(w, r, http.StatusCreated, *created)
}

// approve is `POST /api/access-requests/{id}/approve` — 200 `AccessRequest`.
//
// Order, and every step of it is observable:
//
//  1. requireApi
//  2. bad id ⇒ 400 common.bad_id
//  3. missing row ⇒ 404 `access request`
//  4. `kind != "ROLE"` ⇒ **400** approval.use_query_approval_endpoint
//  5. unless authDebug: `task.approve` ⇒ 403 approval.not_approver
//  6. the body — TOLERANT, see below
//  7. `store.approve(id, durationSec, approver)`; nil ⇒ 404 `access request`
//
// ⚠️ Step 6 reads `runCatching { call.receive<ApproveInput>() }.getOrDefault(ApproveInput())`
// (Access.kt:641): a MISSING OR MALFORMED BODY IS TOLERATED and falls back to the requester's own
// `requestedDurationSec`. [Routes.reject] uses a bare receive and therefore 500s on the same input.
// Asymmetric but intentional — the reason is mandatory, the duration is not — and reproduced as two
// different decode call sites rather than one shared helper, because a shared helper is how the two
// would silently converge.
//
// ⚠️ Step 6 runs AFTER step 5, so an unauthorized approver never learns whether their body parsed.
//
// 🔒 INV-A6-30 — `roleName` is passed into the Cedar resource so a policy can scope approval by the
// ROLE BEING REQUESTED (`resource in Role::"…"`). Drop it and that capability becomes unreachable
// from this route: the Role parent is the only place the requested role appears in the decision.
func (rt *Routes) approve(w http.ResponseWriter, r *http.Request) {
	req, approver, ok := rt.decisionPreamble(w, r)
	if !ok {
		return
	}

	var body ApproveInput
	// `runCatching { … }.getOrDefault(ApproveInput())`. The error is deliberately dropped: a garbage
	// body leaves DurationSec nil, which [Store.Approve] resolves to the requested window.
	_ = httpapi.Receive(r, &body)

	approved, err := rt.store.Approve(r.Context(), req.ID, body.DurationSec, approver)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if approved == nil {
		// `?: call.notFound("access request")`. Reached when the row lost its roleId between the
		// preamble's read and the approve — [Store.Approve] returns null for a request with no role
		// to elevate, and the route reports that as a 404 rather than a 409.
		rt.respondError(w, types.NotFound(NotFoundRequest))
		return
	}
	rt.respond(w, r, http.StatusOK, *approved)
}

// reject is `POST /api/access-requests/{id}/reject` — 200 `AccessRequest`.
//
// Identical to [Routes.approve] through step 5 — the SAME `task.approve` action, so a role-scoped
// approval policy governs reject too — and different only in step 6:
//
// ⚠️ `call.receive<RejectInput>()` is BARE (Access.kt:672). A missing or malformed body is NOT
// tolerated; it escapes to StatusPages as 500 common.fallback. Contrast approve's runCatching.
//
// ⚠️ D6 DIVERGENCE, inherited from CedarPolicyRoutes.receiveInput: `{}` decodes cleanly here to
// `Reason: ""` where kotlinx throws MissingFieldException, so Go answers 200 having written a blank
// rejection reason where the Kotlin answers 500. Recorded once for the whole port rather than patched
// per-DTO; TestRejectWithNoReasonFieldIsAcceptedAsBlankD6Divergence pins it.
//
// ⚠️ [Store.Reject]'s UPDATE is UNGUARDED (F11) — rejecting an already-APPROVED request silently
// overwrites it. That defect lives in the store and is pinned there; this route just forwards.
func (rt *Routes) reject(w http.ResponseWriter, r *http.Request) {
	req, approver, ok := rt.decisionPreamble(w, r)
	if !ok {
		return
	}

	var body RejectInput
	if err := httpapi.Receive(r, &body); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}

	rejected, err := rt.store.Reject(r.Context(), req.ID, body.Reason, approver)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if rejected == nil {
		rt.respondError(w, types.NotFound(NotFoundRequest))
		return
	}
	rt.respond(w, r, http.StatusOK, *rejected)
}

// decisionPreamble is steps 1-5, shared verbatim by approve and reject.
//
// The Kotlin repeats all five in both handlers, comment blocks included (Access.kt:610-640 and
// :663-671). Sharing them here is a Go structural choice, not a behaviour change — the two paths
// were byte-identical — and it is what guarantees the reject route keeps asking `task.approve`
// rather than drifting to a `task.reject` that no seed policy grants.
func (rt *Routes) decisionPreamble(w http.ResponseWriter, r *http.Request) (*AccessRequest, string, bool) {
	if !rt.gates.RequireAPI(w, r) {
		return nil, "", false
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return nil, "", false
	}
	req, err := rt.store.GetRequest(r.Context(), *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return nil, "", false
	}
	if req == nil {
		rt.respondError(w, types.NotFound(NotFoundRequest))
		return nil, "", false
	}
	if req.Kind != DefaultKind {
		// `if (req.kind != "ROLE")` — a QUERY task belongs to A7's /api/approvals surface, whose
		// decide path guards on status and writes an audit row. Deciding one here would flip its
		// status with neither.
		rt.respondError(w, types.ErrorResponse{
			Status: http.StatusBadRequest,
			Body:   types.ApiError{Code: CodeUseQueryApprovalEndpoint},
		})
		return nil, "", false
	}

	approver, ok := rt.principalOr(w, r, DebugPrincipal)
	if !ok {
		return nil, "", false
	}

	if !rt.gates.Config.AuthDebug {
		// `req.datasourceId?.let(datasourceStore::get)?.tags.orEmpty()` — the tags of the datasource
		// the request targets, or none. Note the id, not the name, is what is looked up, while the
		// NAME is what scopes the tag derivation: the row carries both and they are read from
		// different columns of the same join.
		var tags []string
		if req.DatasourceID != nil {
			ds, found, err := rt.datasources.Get(r.Context(), *req.DatasourceID)
			if err != nil {
				httpapi.RespondFallback(w, r, rt.log, err)
				return nil, "", false
			}
			if found {
				tags = ds.Tags
			}
		}
		decision := rt.authz.AuthorizeWithContext(
			approver, authz.ActionTaskApprove,
			authz.ResourceApprovalRequest{
				Requester:      req.Principal,
				Approver:       req.DecidedBy,
				ExecutedBy:     req.ExecutedBy,
				DatasourceName: req.DatasourceName,
				RoleName:       req.RoleName,
			},
			rt.gates.AuthzContext(r), req.DatasourceName, tags,
		)
		if !decision.Allowed {
			rt.respondError(w, types.ErrorResponse{
				Status: http.StatusForbidden,
				Body:   types.ApiError{Code: CodeNotApprover},
			})
			return nil, "", false
		}
	}
	return req, approver, true
}

// ---------------------------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------------------------

// listGrants is `GET /api/access-grants?principal=&active=` — 200 `[AccessGrant]`.
//
// 🔒 INV-A6-28 again, and this is the route the invariant is NAMED for: `?principal=` is passed
// STRAIGHT INTO THE SQL, so the store really does return another principal's grants — and then every
// row is re-decided against the caller and dropped unless `task.read` allows it. The parameter is a
// convenience filter, never an authorization statement.
//
// ⚠️ `?active=` is `toBoolean()`, which in Kotlin is `equalsIgnoreCase("true")` and NEVER throws:
// `?active=yes`, `?active=1` and `?active=` are all FALSE. Go's strconv.ParseBool would accept "1"
// and error on "yes", so it is not used here — see [parseKotlinBoolean].
func (rt *Routes) listGrants(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	caller, ok := rt.caller(w, r)
	if !ok {
		return
	}

	rows, err := rt.store.ListGrants(r.Context(), queryParam(r, "principal"), parseKotlinBoolean(queryParam(r, "active")))
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if caller != nil {
		kept := make([]AccessGrant, 0, len(rows))
		for _, row := range rows {
			d := rt.authz.Authorize(*caller, authz.ActionTaskRead, authz.ResourceAccessGrant{
				Owner: row.Principal,
				ID:    row.ID,
				// roleName only — the Kotlin passes NO datasourceName here, so a grant carries the
				// Role Cedar parent but never a Datasource one. A JIT grant is not datasource-scoped.
				RoleName: types.Ptr(row.RoleName),
			}, authz.AuthzContext{})
			if d.Allowed {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	rt.respond(w, r, http.StatusOK, rows)
}

// revokeGrant is `POST /api/access-grants/{id}/revoke` — **204**, no body.
//
// 🔒 INV-A6-29 — THE READ PRECEDES THE GATE, AND THE ORDER IS THE SECURITY CONTROL. Steps:
//
//  1. bad id ⇒ 400 common.bad_id  (note: BEFORE any authentication — a malformed id is answered to
//     an anonymous caller, which is a disclosure of nothing)
//  2. missing grant ⇒ 404 `access grant` — also before authorization, so the 404 leaks the
//     non-existence of an id to any caller. The Kotlin accepts that and so does this port.
//  3. requireAuthz(grant.revoke, AccessGrant(owner = grant.principal, …))
//  4. `store.revoke(id)` ⇒ 204, or 404 on a grant already revoked
//
// This is the ONLY route in the file with no requireApi call. It is not ungated — requireAuthz
// subsumes it (401 for no session, then the Cedar decision) — but a reader grepping for requireApi
// will not find it, which is why the absence is stated here rather than left to be noticed.
//
// ⚠️ Step 4's 404-on-second-revoke comes from the store's `AND revoked_at IS NULL` guard, so the
// route is NOT idempotent the way the editor's DELETEs are: revoke twice and the second answers 404,
// not 204.
func (rt *Routes) revokeGrant(w http.ResponseWriter, r *http.Request) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	grant, err := rt.store.GetGrant(r.Context(), *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if grant == nil {
		rt.respondError(w, types.NotFound(NotFoundGrant))
		return
	}
	if !rt.gates.RequireAuthz(w, r, authz.ActionGrantRevoke, authz.ResourceAccessGrant{
		Owner:    grant.Principal,
		ID:       grant.ID,
		RoleName: types.Ptr(grant.RoleName),
	}) {
		return
	}
	revoked, err := rt.store.Revoke(r.Context(), *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !revoked {
		rt.respondError(w, types.NotFound(NotFoundGrant))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------

// caller is `call.userSession()?.principal` for the two forward-filtering list routes: a nil result
// means "no session", which under authDebug is the UNFILTERED branch (INV-A6-28).
//
// ⚠️ It is read AFTER requireApi and independently of it. Under authDebug requireApi never touches
// the session, but this call still does — so a debug request that HAPPENS to carry a valid cookie
// gets the FILTERED list, exactly as the Kotlin does. The bypass is not "always show everything"; it
// is "there is no session to filter by".
func (rt *Routes) caller(w http.ResponseWriter, r *http.Request) (*string, bool) {
	if rt.gates.Sessions == nil {
		return nil, true
	}
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

// principalOr is `call.userSession()?.principal ?: "debug-user"`.
func (rt *Routes) principalOr(w http.ResponseWriter, r *http.Request, fallback string) (string, bool) {
	caller, ok := rt.caller(w, r)
	if !ok {
		return "", false
	}
	if caller == nil {
		return fallback, true
	}
	return *caller, true
}

// queryParam is Ktor's `queryParameters["name"]`: nil when the key is ABSENT, a pointer to "" when it
// is present-but-empty.
//
// The distinction is load-bearing on all three uses. `?status=` filters on the empty status and
// returns nothing, while no `status` at all returns every row; same for `?principal=`. Go's
// `Query().Get()` collapses the two into "", so Has() is what keeps them apart — the same trap
// internal/policy's listAssignments documents.
func queryParam(r *http.Request, name string) *string {
	q := r.URL.Query()
	if !q.Has(name) {
		return nil
	}
	v := q.Get(name)
	return &v
}

// parseKotlinBoolean is `String?.toBoolean() ?: false`.
//
// Kotlin's `String.toBoolean()` is `equalsIgnoreCase("true")` and cannot fail: EVERY other value,
// including "1", "yes" and "", is false. strconv.ParseBool accepts "1"/"t"/"T"/"TRUE" and returns an
// error for the rest, so using it here would both widen the accepted set and introduce an error path
// the Kotlin does not have.
func parseKotlinBoolean(raw *string) bool {
	return raw != nil && strings.EqualFold(*raw, "true")
}

func (rt *Routes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *Routes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}

// errCreatedRequestVanished names a broken postcondition: [Store.CreateRequest] re-reads by the id it
// just inserted, so nil is impossible without the row having disappeared inside the same call. It
// exists so the log line says which invariant broke rather than showing a nil dereference.
var errCreatedRequestVanished = errors.New("createRequest returned no row for the id it just inserted")
