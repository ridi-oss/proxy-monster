package identity

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// Management is the slice of A11's `IdentityManagementService` the fourteen admin routes call
// (ManagementServices.kt:513).
//
// 🔴 IT IS AN INTERFACE BECAUSE THE CONCRETE SERVICE LIVES IN internal/management, WHICH IMPORTS
// THIS PACKAGE. Depending on it directly would be an import cycle, and the alternative — hosting
// A3's routes in internal/management — would put the route table somewhere other than the package
// that owns `Users.kt`. This is the "define a narrow interface for what a sibling owns" rule, applied
// to the one seam where the dependency genuinely runs the other way.
//
// The method set is exactly the fourteen routes' needs and nothing more: the name-keyed MCP overloads
// (`updateGroup(currentName, …)`, `addGroupMember(groupName, principal)`, `setGroupRoles`) are A11's
// tool surface and are deliberately absent, so this interface cannot be mistaken for the service.
//
// *management.IdentityService satisfies it.
type Management interface {
	ListUsers(ctx context.Context) ([]AppUser, error)
	CreateUser(ctx context.Context, input AppUserInput) (AppUser, error)
	UpdateUser(ctx context.Context, id int64, input AppUserInput) (AppUser, error)
	DeprovisionUserByID(ctx context.Context, id int64) (policy.DeleteResult, error)

	ListGroups(ctx context.Context) ([]AppGroup, error)
	CreateGroup(ctx context.Context, input AppGroupInput) (AppGroup, error)
	UpdateGroupByID(ctx context.Context, id int64, input AppGroupInput) (AppGroup, error)
	DeleteGroupByID(ctx context.Context, id int64) (policy.DeleteResult, error)

	AddGroupMemberByID(ctx context.Context, groupID, userID int64) (GroupMemberEntry, error)
	RemoveGroupMemberByID(ctx context.Context, groupID, userID int64) (policy.DeleteResult, error)
	AddGroupRole(ctx context.Context, groupID, roleID int64) (GroupRoleEntry, error)
	RemoveGroupRole(ctx context.Context, groupID, roleID int64) (policy.DeleteResult, error)
}

// Routes is `Route.userGroupRoutes(config, authz, store, tokenStore, accessStore,
// daemonSessionStore, management)` (Users.kt:894) — the local-admin directory surface.
//
// # One gate, fourteen routes
//
//	GET    /api/users                              requireAdmin(ADMIN_IDENTITY)
//	POST   /api/users                              ↑   201
//	PUT    /api/users/{id}                         ↑
//	DELETE /api/users/{id}                         ↑   204
//	GET    /api/groups                             ↑
//	POST   /api/groups                             ↑   201
//	PUT    /api/groups/{id}                        ↑
//	DELETE /api/groups/{id}                        ↑   204
//	GET    /api/groups/{id}/members                ↑
//	POST   /api/groups/{id}/members                ↑   201
//	DELETE /api/groups/{id}/members/{userId}       ↑   204
//	GET    /api/groups/{id}/roles                  ↑
//	POST   /api/groups/{id}/roles                  ↑   201
//	DELETE /api/groups/{id}/roles/{roleId}         ↑   204
//
// Uniform, unlike A9's split — every route on this surface administers the DIRECTORY, so every route
// asks for `admin.identity`. docs/authz-model.md:345.
//
// # Why these routes thread the credential stores at all
//
// A rename or an active-flip here goes through the SAME atomic, per-principal-locked teardown as a
// SCIM rename/deactivate: [UserGroupStore.UpdateUser] and [UserGroupStore.SetActiveByID]. That is
// INV-A3-6 — the directory write and the credential revoke are ONE committed transaction — and it is
// why the local-admin surface cannot be a thin CRUD wrapper.
//
// ⚠️ TWO READ SUB-ROUTES BYPASS THE MANAGEMENT LAYER ENTIRELY. `GET /{id}/members` and
// `GET /{id}/roles` call `store.getGroup` / `store.listMembers` / `store.listGroupRoles` DIRECTLY,
// which makes them the only identity routes not funnelled through A11 — and the only two that build
// their own 404. Harmless (a read needs no SYSTEM guard) but reproduced, because routing them through
// the service would change which error shape they can produce.
//
// ⚠️ `userGroupRoutes`' `management` parameter has a DEFAULT that builds a fresh
// `IdentityManagementService` over a NEW `PolicyStore` (Users.kt:899-901); App.kt:633-635 passes the
// shared one explicitly, so the default is test-only. NOT reproduced: Go has no default arguments,
// and 03-identity-scim.md:252 says not to reproduce it "without checking that whatever it constructs
// is cache-free". A nil Management here is a programming error, not a fallback.
type Routes struct {
	gates      *httpapi.Gates
	store      *UserGroupStore
	management Management
	log        *slog.Logger
}

// NewRoutes builds the group. A nil logger defaults to slog.Default().
func NewRoutes(gates *httpapi.Gates, s *UserGroupStore, management Management, log *slog.Logger) *Routes {
	if log == nil {
		log = slog.Default()
	}
	return &Routes{gates: gates, store: s, management: management, log: log}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the fourteen patterns. No pattern ends in `/` — a trailing-slash pattern would make
// ServeMux create a subtree match plus a redirect, and Ktor's IgnoreTrailingSlash is not installed
// (httpapi.Router's divergence 1).
func (rt *Routes) Register(mux *http.ServeMux) {
	admin := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, rt.gates.Admin(authz.ActionAdminIdentity, h))
	}

	admin("GET /api/users", rt.listUsers)
	admin("POST /api/users", rt.createUser)
	admin("PUT /api/users/{id}", rt.updateUser)
	admin("DELETE /api/users/{id}", rt.deleteUser)

	admin("GET /api/groups", rt.listGroups)
	admin("POST /api/groups", rt.createGroup)
	admin("PUT /api/groups/{id}", rt.updateGroup)
	admin("DELETE /api/groups/{id}", rt.deleteGroup)

	admin("GET /api/groups/{id}/members", rt.listMembers)
	admin("POST /api/groups/{id}/members", rt.addMember)
	admin("DELETE /api/groups/{id}/members/{userId}", rt.removeMember)

	admin("GET /api/groups/{id}/roles", rt.listGroupRoles)
	admin("POST /api/groups/{id}/roles", rt.addGroupRole)
	admin("DELETE /api/groups/{id}/roles/{roleId}", rt.removeGroupRole)
}

// ---- Users --------------------------------------------------------------------------------------

// listUsers is `GET /api/users` — 200 `[AppUser]`, `[]` when the directory is empty.
func (rt *Routes) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := rt.management.ListUsers(r.Context())
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, users)
}

// createUser is `POST /api/users` — **201** `AppUser`.
//
// 400 `common.field_required{fields: principal}` on a blank principal, 409 (via `unique`) on a
// duplicate. ⚠️ Note the resource literals do NOT match: a duplicate says
// `common.already_exists{resource: principal}` while a 404 elsewhere says `{resource: user}`. Two
// different i18n keys for one table, and both are wire-visible.
//
// 🔒 A body that omits `active` creates an ACTIVE user — [AppUserInput.UnmarshalJSON] carries the
// Kotlin default. Go's zero value is the opposite, and because `active=false` on create ALSO revokes
// that principal's pre-existing credentials (INV-A3-18), getting it wrong would tear down credentials
// the caller never asked to touch.
func (rt *Routes) createUser(w http.ResponseWriter, r *http.Request) {
	var input AppUserInput
	if !rt.receive(w, r, &input) {
		return
	}
	created, err := rt.management.CreateUser(r.Context(), input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// updateUser is `PUT /api/users/{id}` — 200 `AppUser`.
//
// The id is parsed BEFORE the body is read, so `PUT /api/users/abc` with a malformed body answers
// `400 common.bad_id` rather than the 500 the decode would produce. Order reproduced.
//
// 🔒 A rename or an active-flip true→false lands in [UserGroupStore.UpdateUser]'s locked, atomic
// teardown — and INV-A3-16's two branches are INDEPENDENT, so a rename-and-deactivate retires BOTH
// principal strings.
func (rt *Routes) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input AppUserInput
	if !rt.receive(w, r, &input) {
		return
	}
	updated, err := rt.management.UpdateUser(r.Context(), id, input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, updated)
}

// deleteUser is `DELETE /api/users/{id}` — **204**, no body.
//
// 🔒 INV-A3-19 — DEPROVISION, NOT HARD-DELETE: the row survives with `active=false` so audit history
// keeps resolving the principal, and the credential teardown commits in the same transaction. The
// `DeleteResult` the service returns is DISCARDED here — the route answers 204 whether or not a row
// changed, and a nonexistent id is already a 404 from the service's own existence check.
func (rt *Routes) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if _, err := rt.management.DeprovisionUserByID(r.Context(), id); err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Groups -------------------------------------------------------------------------------------

// listGroups is `GET /api/groups` — 200 `[AppGroup]`.
func (rt *Routes) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := rt.management.ListGroups(r.Context())
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, groups)
}

// createGroup is `POST /api/groups` — **201** `AppGroup`.
//
// There is no SYSTEM guard on create: a new group is LOCAL by construction, and a name collision with
// a seeded SYSTEM group is caught by `app_group.name UNIQUE` as `common.already_exists`.
func (rt *Routes) createGroup(w http.ResponseWriter, r *http.Request) {
	var input AppGroupInput
	if !rt.receive(w, r, &input) {
		return
	}
	created, err := rt.management.CreateGroup(r.Context(), input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// updateGroup is `PUT /api/groups/{id}` — 200; **409 `group.system_immutable`** for a SYSTEM group.
//
// 🔒 The guard order inside the service is load-bearing: resolve ⇒ 404, THEN reject SYSTEM ⇒ 409,
// THEN validate the name ⇒ 400. A SYSTEM group renamed to the empty string answers
// `group.system_immutable`, not `common.field_required` — the caller has no business editing that row
// and telling them their name is blank invites a retry.
func (rt *Routes) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input AppGroupInput
	if !rt.receive(w, r, &input) {
		return
	}
	updated, err := rt.management.UpdateGroupByID(r.Context(), id, input)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, updated)
}

// deleteGroup is `DELETE /api/groups/{id}` — **204**; 409 `group.system_immutable`.
//
// ⚠️ F26 — `deleteGroup` is a HARD delete and `group_member`/`group_role` are `ON DELETE CASCADE`, so
// this silently revokes the group's roles from every member with no audit record and no undo — while
// users are never hard-deleted. The only hard delete in the area.
func (rt *Routes) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if _, err := rt.management.DeleteGroupByID(r.Context(), id); err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Members ------------------------------------------------------------------------------------

// listMembers is `GET /api/groups/{id}/members` — 200 `[GroupMemberEntry]`.
//
// ⚠️ One of the two routes that go STRAIGHT TO THE STORE, so its 404 is built here rather than by
// `notFound("group")` in the service. Same code, same params, different author — reproduced.
func (rt *Routes) listMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if !rt.requireGroup(w, r, id) {
		return
	}
	members, err := rt.store.ListMembers(r.Context(), id)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, members)
}

// addMember is `POST /api/groups/{id}/members` — **201** `GroupMemberEntry`.
//
// 404 `{resource: group}` or `{resource: user}`, 409 `group.system_immutable` (A11's `rejectSystem`,
// which is a plain read with NO row lock — INV-A11-32's guard #1).
//
// 🔒 Re-adding an existing member is a SUCCESS, not a 409: the store's `ON CONFLICT DO NOTHING` makes
// it idempotent and the service re-reads the member list either way. INV-A3-35.
func (rt *Routes) addMember(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input GroupMemberInput
	if !rt.receive(w, r, &input) {
		return
	}
	added, err := rt.management.AddGroupMemberByID(r.Context(), id, input.UserID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, added)
}

// removeMember is `DELETE /api/groups/{id}/members/{userId}` — **204**, or 404
// `common.not_found{resource: "group member"}` when nothing matched.
//
// ⚠️ Note the resource literal: `group member`, with a SPACE, and it is the only place that string
// appears. Both ids answer the SAME `common.bad_id` when unparseable, so a caller cannot tell which
// one was wrong.
func (rt *Routes) removeMember(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	userID, ok := rt.namedIDParam(w, r, "userId")
	if !ok {
		return
	}
	result, err := rt.management.RemoveGroupMemberByID(r.Context(), id, userID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if !result.Deleted {
		rt.notFound(w, r, "group member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Group → role mappings ------------------------------------------------------------------------

// listGroupRoles is `GET /api/groups/{id}/roles` — 200 `[GroupRoleEntry]`. The second store-direct
// read; see [Routes.listMembers].
func (rt *Routes) listGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	if !rt.requireGroup(w, r, id) {
		return
	}
	roles, err := rt.store.ListGroupRoles(r.Context(), id)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, roles)
}

// addGroupRole is `POST /api/groups/{id}/roles` — **201** `GroupRoleEntry`.
//
// 🔒 THIS ROUTE'S SYSTEM GUARD IS A DIFFERENT MECHANISM FROM THE MEMBERS ROUTES', and the difference
// is a concurrency one a port must keep. `/members` uses `rejectSystem` → `isSystemGroup(id, c)`, a
// plain read on the transaction's connection; `/roles` uses `lockMutableGroup(id, c)` →
// `SELECT source FROM app_group WHERE id = ? FOR UPDATE`, which both existence-checks (404
// `{resource: group}`) and SYSTEM-checks UNDER A ROW LOCK. Two guards for one rule, only one of them
// hardened — INV-A3-45 one layer up, and UserAdminDeprovisionDbTest case 10's two-thread race is what
// exercises the lock.
func (rt *Routes) addGroupRole(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input GroupRoleInput
	if !rt.receive(w, r, &input) {
		return
	}
	added, err := rt.management.AddGroupRole(r.Context(), id, input.RoleID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, added)
}

// removeGroupRole is `DELETE /api/groups/{id}/roles/{roleId}` — **204**, or 404
// `common.not_found{resource: "group role mapping"}`. Another single-use resource literal.
func (rt *Routes) removeGroupRole(w http.ResponseWriter, r *http.Request) {
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	roleID, ok := rt.namedIDParam(w, r, "roleId")
	if !ok {
		return
	}
	result, err := rt.management.RemoveGroupRole(r.Context(), id, roleID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	if !result.Deleted {
		rt.notFound(w, r, "group role mapping")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- shared handler plumbing ----------------------------------------------------------------------

// idParam is `val id = call.idParam() ?: return call.respond(400, ApiError("common.bad_id"))`.
//
// ⚠️ Contrast the SCIM routes, where an unparseable id is 404 and never 400. Same store, same table,
// two deliberately different answers, because one caller is a console and the other is an IdP.
func (rt *Routes) idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	return rt.namedIDParam(w, r, "id")
}

func (rt *Routes) namedIDParam(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id := httpapi.NamedIDParam(r, name)
	if id == nil {
		if err := httpapi.RespondAPIError(w, types.BadID()); err != nil {
			rt.log.Error("failed to write bad_id", "err", err)
		}
		return 0, false
	}
	return *id, true
}

// requireGroup is the existence check the two store-direct reads make for themselves.
func (rt *Routes) requireGroup(w http.ResponseWriter, r *http.Request, id int64) bool {
	group, err := rt.store.GetGroup(r.Context(), id)
	if err != nil {
		rt.fail(w, r, err)
		return false
	}
	if group == nil {
		rt.notFound(w, r, "group")
		return false
	}
	return true
}

func (rt *Routes) notFound(w http.ResponseWriter, r *http.Request, resource string) {
	if err := httpapi.RespondAPIError(w, types.NotFound(resource)); err != nil {
		rt.log.Error("failed to write not_found", "path", r.URL.Path, "err", err)
	}
}

// receive is `call.receive<T>()`; a malformed body is 500 `common.fallback`, not 400 — the Kotlin
// never wraps `receive` in a try on this surface.
func (rt *Routes) receive(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpapi.Receive(r, dst); err != nil {
		// 415 before 400: an unusable Content-Type is ContentNegotiation answering before the route sees
		// the body. Measured — see internal/conformance/differential.
		if errors.Is(err, httpapi.ErrUnsupportedMediaType) {
			httpapi.RespondUnsupportedMediaType(w)
			return false
		}
		httpapi.RespondFallback(w, r, rt.log, err)
		return false
	}
	return true
}

// fail is `catch (e: ManagementException) { call.respondManagementError(e) }`.
//
// 🔒 The switch it delegates to answers 404 for `common.not_found`, 409 for the three
// `*.system_immutable` codes, 502 for `datasource.table_introspection_failed`, and **400 for
// everything else** — including `common.already_exists`, which is therefore a 400 here and not the
// 409 a route responding with types.AlreadyExists directly would give.
func (rt *Routes) fail(w http.ResponseWriter, r *http.Request, err error) {
	var management *policy.ManagementError
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
