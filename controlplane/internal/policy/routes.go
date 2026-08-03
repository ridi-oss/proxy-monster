package policy

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/authz"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/types"
)

// Routes is `Route.policyRoutes(config, authz, management)` (Policies.kt:150) — A9's eleven
// endpoints over roles, direct role assignments and mask functions.
//
// 🔴 THIS AREA HAS ZERO INHERITED TEST COVERAGE. 09-policies.md §4 verified it by search: no Kotlin
// test HTTP-calls `/api/roles`, `/api/role-assignments` or `/api/mask-fns`, and neither INV-A9-3 nor
// INV-A9-4 — the two deliberate inconsistencies below — has a single assertion anywhere. So the area
// doc is the sole specification and every test in routes_db_test.go is NEW, written to §4.3's own
// list: "11 route tests (gate + status + shape) … and the two flagged inconsistencies (INV-A9-3,
// INV-A9-4) so they become deliberate rather than incidental."
//
// # The gate map, and why it is not uniform
//
//	GET    /api/roles                    requireApi           🔒 INV-A9-3 — see below
//	POST   /api/roles                    ADMIN_POLICIES
//	PUT    /api/roles/{id}               ADMIN_POLICIES
//	DELETE /api/roles/{id}               ADMIN_POLICIES
//	GET    /api/role-assignments         ADMIN_IDENTITY
//	POST   /api/role-assignments         ADMIN_IDENTITY
//	DELETE /api/role-assignments/{id}    ADMIN_IDENTITY
//	GET    /api/mask-fns                 ADMIN_POLICIES
//	POST   /api/mask-fns                 ADMIN_POLICIES
//	PUT    /api/mask-fns/{id}            ADMIN_POLICIES
//	DELETE /api/mask-fns/{id}            ADMIN_POLICIES
//
// Note the split by RESOURCE, not by file: roles and mask functions are `admin.policies`, assignments
// are `admin.identity`. An assignment is a statement about a PERSON, so it belongs to whoever
// administers the directory, and that is the same action A3's user and group routes take.
type Routes struct {
	gates      *httpapi.Gates
	management *PolicyManagement
	log        *slog.Logger
}

// NewRoutes builds the group. A nil logger defaults to slog.Default().
func NewRoutes(gates *httpapi.Gates, management *PolicyManagement, log *slog.Logger) *Routes {
	if log == nil {
		log = slog.Default()
	}
	return &Routes{gates: gates, management: management, log: log}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the eleven patterns. No pattern ends in `/` — see CedarPolicyRoutes.Register.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/roles", rt.listRoles)
	mux.HandleFunc("POST /api/roles", rt.createRole)
	mux.HandleFunc("PUT /api/roles/{id}", rt.updateRole)
	mux.HandleFunc("DELETE /api/roles/{id}", rt.deleteRole)

	mux.HandleFunc("GET /api/role-assignments", rt.listAssignments)
	mux.HandleFunc("POST /api/role-assignments", rt.createAssignment)
	mux.HandleFunc("DELETE /api/role-assignments/{id}", rt.deleteAssignment)

	mux.HandleFunc("GET /api/mask-fns", rt.listMaskFns)
	mux.HandleFunc("POST /api/mask-fns", rt.createMaskFn)
	mux.HandleFunc("PUT /api/mask-fns/{id}", rt.updateMaskFn)
	mux.HandleFunc("DELETE /api/mask-fns/{id}", rt.deleteMaskFn)
}

// ---------------------------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------------------------

// listRoles is `GET /api/roles` — 200 `[Role]`.
//
// 🔒 INV-A9-3 — THIS ROUTE IS `requireApi`, NOT `requireAdmin`, AND THAT IS DELIBERATE. Any
// authenticated session can list every role name and description, while every other route in this
// file is admin-gated — `GET /api/mask-fns` right below IS `ADMIN_POLICIES`.
//
// 09-policies.md:129-136 verified the reason rather than assuming one: `web/src/lib/hooks.ts:131`'s
// `useRoles()` is consumed by two NON-ADMIN surfaces —
// `components/query/request-access-dialog.tsx:58` and
// `components/workflows/role-request-composer.tsx:51` — where an ordinary user picks the role to
// request elevation TO. Tightening this to requireAdmin breaks JIT elevation for every non-admin
// user, which is the product. The MCP asymmetry is correct too: A11's `list_roles` tool requires
// ADMIN_POLICIES because it is an admin MANAGEMENT tool. Two gates over the same data because there
// are two callers with different legitimate needs.
//
// 🔴 The Kotlin has NO comment saying any of that, which is why 00-INDEX.md F5 originally filed it as
// a gap before closing it as by-design. 09-policies.md:138 makes writing the missing comment an
// explicit PORT ACTION — "preserve both gates exactly, and add the doc comment this route is
// missing". This paragraph is that action.
//
// What leaks is a role's NAME and DESCRIPTION, nothing more: no membership, no policy source, no
// principal. An authenticated user learning that a role called `pii-accessor` exists is the price of
// being able to request it.
func (rt *Routes) listRoles(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	roles, err := rt.management.ListRoles(r.Context())
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, roles)
}

// createRole is `POST /api/roles` — **201**.
func (rt *Routes) createRole(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	var input RoleInput
	if !rt.receive(w, r, &input) {
		return
	}
	created, err := rt.management.CreateRole(r.Context(), input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// updateRole is `PUT /api/roles/{id}` — 200; 409 `role.system_immutable` for a SYSTEM role
// (INV-A11-30), 404 `common.not_found{resource: role}` for an unknown id.
//
// The body is bound to a local BEFORE the management call, unlike `PUT /api/mask-fns/{id}` below.
// 09-policies.md:150-152 flags the difference as a route-level quirk worth reproducing: same
// behaviour, but the deserialization error surfaces from a different point in the handler.
func (rt *Routes) updateRole(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input RoleInput
	if !rt.receive(w, r, &input) {
		return
	}
	updated, err := rt.management.UpdateRole(r.Context(), id, input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, updated)
}

// deleteRole is `DELETE /api/roles/{id}` — **204**, no body.
func (rt *Routes) deleteRole(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if err := rt.management.DeleteRole(r.Context(), id); err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------
// Role assignments
// ---------------------------------------------------------------------------------------------

// listAssignments is `GET /api/role-assignments?principal=&roleId=` — 200 `[RoleAssignment]`.
//
// ⚠️ INV-A9-4 — A MALFORMED `roleId` ANSWERS `[]`, NOT `400 common.bad_id`. The Kotlin is one line:
//
//	if (roleIdRaw != null && roleId == null) return@get call.respond(emptyList<RoleAssignment>())
//
// Every other id-taking route in the port answers `common.bad_id` for exactly this input, so this is
// a real inconsistency in the wire contract and 09-policies.md:141-147 says so: "An inconsistency in
// the wire contract. `web/` may depend on it. Replicate, flag, do not 'fix' during the port."
//
// The distinction is PRESENCE, not emptiness: `?roleId=abc` is present-and-unparseable ⇒ `[]`, while
// no `roleId` at all ⇒ unfiltered list. Go's `Query().Get()` collapses those two (it returns "" for
// both), so this uses `Has()` — using Get alone would turn "no filter" into "empty filter" and
// silently answer `[]` to the console's unfiltered list.
//
// ⚠️ The same presence-vs-value split applies to `principal`, and there the Kotlin does NOT special-case
// anything: `?principal=` (present, empty) filters on the empty string and legitimately returns `[]`,
// because no assignment has a blank principal. Reproduced by the same Has/Get pair.
//
//	TODO(A9): 09-policies.md Q3 — confirm `web/` actually depends on the `[]` before anyone is tempted
//	to align this with common.bad_id. TestListAssignmentsAnswersEmptyForMalformedRoleId is the pin a
//	deliberate fix must change.
func (rt *Routes) listAssignments(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminIdentity) {
		return
	}
	q := r.URL.Query()

	var principal *string
	if q.Has("principal") {
		v := q.Get("principal")
		principal = &v
	}

	var roleID *int64
	if q.Has("roleId") {
		parsed, err := strconv.ParseInt(q.Get("roleId"), 10, 64)
		if err != nil {
			// INV-A9-4. `[]` and not nil: INV-A1-4 makes an empty list `[]` on the wire, and this is
			// the one route where the empty list is the ANSWER rather than an incidental result.
			rt.respond(w, r, http.StatusOK, []RoleAssignment{})
			return
		}
		roleID = &parsed
	}

	assignments, err := rt.management.ListAssignments(r.Context(), principal, roleID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, assignments)
}

// createAssignment is `POST /api/role-assignments` — **201**.
//
// 🔒 INV-A9-2 — IDEMPOTENT. Re-posting an existing (principal, roleId) pair answers 201 with the
// EXISTING row's id rather than a conflict, because the store's `ON CONFLICT … DO UPDATE SET
// principal=EXCLUDED.principal RETURNING id` absorbs it. The console's "grant role" button is
// therefore safe to double-click, and that is the behaviour, not an accident of the upsert.
func (rt *Routes) createAssignment(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminIdentity) {
		return
	}
	var input RoleAssignmentInput
	if !rt.receive(w, r, &input) {
		return
	}
	created, err := rt.management.CreateAssignment(r.Context(), input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// deleteAssignment is `DELETE /api/role-assignments/{id}` — **204**.
//
// ⚠️ Revoking a direct assignment does NOT end the principal's live sessions or tokens: A3's
// deprovision path is what revokes credentials, and this route deliberately does not take the
// per-principal advisory lock those paths share. The next decision re-resolves roles, so the effect
// is immediate for QUERIES but not for anything already granted. REPRODUCE — adding the lock here
// would be a behaviour change dressed as a fix.
func (rt *Routes) deleteAssignment(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminIdentity) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if err := rt.management.DeleteAssignment(r.Context(), id); err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------
// Mask functions
// ---------------------------------------------------------------------------------------------

// listMaskFns is `GET /api/mask-fns` — 200 `[MaskFn]`, `ADMIN_POLICIES`.
//
// The contrast with [Routes.listRoles] is the whole of INV-A9-3: two list routes in one file, one
// open to any session and one admin-only, because only one of them has a non-admin consumer.
func (rt *Routes) listMaskFns(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	fns, err := rt.management.ListMaskFns(r.Context())
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, fns)
}

// createMaskFn is `POST /api/mask-fns` — **201**.
func (rt *Routes) createMaskFn(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	var input MaskFnInput
	if !rt.receive(w, r, &input) {
		return
	}
	created, err := rt.management.CreateMaskFn(r.Context(), input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// updateMaskFn is `PUT /api/mask-fns/{id}` — 200.
//
// ⚠️ The Kotlin calls `call.receive()` INLINE as an argument here (`management.updateMaskFn(id,
// call.receive())`) rather than binding it first, unlike `PUT /api/roles/{id}`
// (09-policies.md:150-152). Go has no expression form that reproduces the difference — a decode
// needs a destination — so the two handlers read alike. The observable behaviour is identical
// (either way the decode failure precedes the management call and answers the same fallback); the
// only thing lost is WHERE the failure surfaces in a stack trace.
func (rt *Routes) updateMaskFn(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input MaskFnInput
	if !rt.receive(w, r, &input) {
		return
	}
	updated, err := rt.management.UpdateMaskFn(r.Context(), id, input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, updated)
}

// deleteMaskFn is `DELETE /api/mask-fns/{id}` — **204**.
func (rt *Routes) deleteMaskFn(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r, authz.ActionAdminPolicies) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if err := rt.management.DeleteMaskFn(r.Context(), id); err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------

func (rt *Routes) admin(w http.ResponseWriter, r *http.Request, action authz.AuthzAction) bool {
	return rt.gates.RequireAdmin(w, r, action)
}

// idParam is `val id = call.idParam() ?: return@put call.badId()`.
func (rt *Routes) idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id := httpapi.IDParam(r)
	if id == nil {
		if err := httpapi.RespondAPIError(w, types.BadID()); err != nil {
			rt.log.Error("failed to write bad_id", "err", err)
		}
		return 0, false
	}
	return *id, true
}

// receive is `call.receive<T>()`; a malformed body is 500 common.fallback, not 400 — see
// CedarPolicyRoutes.receiveInput for why, and for the D6 divergence on a MISSING required field.
func (rt *Routes) receive(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpapi.Receive(r, dst); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return false
	}
	return true
}

// fail is `catch (e: ManagementException) { call.respondManagementError(e) }` — 09-policies.md:108.
//
// There is no CedarValidationManagementException arm here: nothing in A9 validates Cedar. That is
// the ONE structural difference from CedarPolicyRoutes.fail, and it is why the two are separate
// functions rather than one shared helper — a shared one would invite adding the validation arm to
// routes that cannot produce it, and then nobody could tell which routes really answer the bare map.
func (rt *Routes) fail(w http.ResponseWriter, r *http.Request, err error) {
	var management *ManagementError
	if errors.As(err, &management) {
		if werr := httpapi.RespondManagementError(w, management.Err); werr != nil {
			rt.log.Error("failed to write management error", "code", management.Err.Code, "err", werr)
		}
		return
	}
	httpapi.RespondFallback(w, r, rt.log, err)
}

func (rt *Routes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}
