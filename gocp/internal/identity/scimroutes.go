package identity

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ScimRoutes is `Route.scimRoutes(config, userGroupStore, tokenStore, accessStore,
// daemonSessionStore, log)` (Scim.kt:320) — SCIM 2.0 provisioning, IdP → local directory.
//
// # The gate, and the two things about it a port gets wrong
//
// Every one of the fifteen routes is [httpapi.Gates.Scim] — bearer + TLS, NEVER requireAdmin/Cedar:
// there is no user session here, this is a standing service-to-service integration.
//
// 🔒 F33 / INV-A3-38 — THERE IS NO PM_AUTH_DEBUG BYPASS, while `AGENTS.md` and
// `docs/authz-model.md:363` both claim "PM_AUTH_DEBUG short-circuits all four". THE CODE IS RIGHT AND
// THE DOCS ARE WRONG: ScimAuthTest runs all six of its cases with `authDebug = true` and still expects
// 501/403/401. A port that implements the documentation makes a dev-mode control plane accept
// unauthenticated directory writes over plaintext. The gate itself lives in internal/httpapi and
// httpapi.TestRequireScimAuthHasNoAuthDebugBypass pins the absence; scimroutes_db_test.go's fixture
// additionally runs the whole suite with AuthDebug=true so that adding a bypass breaks these routes
// too.
//
// 🔒 INV-A3-2 / INV-A1-13 — this file is the ONE documented exemption from the ApiError envelope. Every
// deliberate error path answers a [httpapi.ScimError] with English prose in `detail`, because the
// consumer is an IdP with no locale to look a code up in.
//
// ⚠️ F41 / F30 — the exemption is NOT airtight. StatusPages' catch-all answers
// `ApiError("common.fallback")` for ANY uncaught error, including on `/api/scim/v2/**` — so a
// malformed body, or the SQLSTATE 23503 an unknown member id raises, reaches the IdP as an ApiError
// on a SCIM route, exactly where it is least able to parse it. REPRODUCED (it is A1's middleware
// behaviour, not something this file can decide) and pinned by
// TestScimFallbackAnswersAnApiErrorNotAScimError.
//
// # `{id}` that does not parse is 404, NEVER 400
//
// ⚠️ Every route here does `parameters["id"]?.toLongOrNull()` and falls into the not-found branch.
// Deliberate: RFC 7644 addresses resources by an opaque id, so "not a number" and "no such resource"
// are the same answer to an IdP. It diverges from the admin REST routes in routes.go, which answer
// `400 common.bad_id` for the same input — the divergence is the contract.
//
// # Two more F33 interop deviations, reproduced
//
// Content type is `application/json`, NOT RFC 7644's `application/scim+json`, and a `201 Created`
// carries NO `Location` header. Both are what Okta already accepts.
type ScimRoutes struct {
	gates *httpapi.Gates
	store *UserGroupStore
	// creds is the three credential stores the Kotlin threads through every write, collapsed to the
	// one function they are only ever passed to. 🔒 A nil here makes every SCIM deactivate/rename
	// commit its directory write with NO credential teardown — INV-A3-6's failure mode. Production
	// wiring must pass the real *Credentials.
	creds CredentialTeardown
	log   *slog.Logger
}

// NewScimRoutes builds the group. A nil logger defaults to slog.Default().
func NewScimRoutes(gates *httpapi.Gates, s *UserGroupStore, creds CredentialTeardown, log *slog.Logger) *ScimRoutes {
	if log == nil {
		log = slog.Default()
	}
	return &ScimRoutes{gates: gates, store: s, creds: creds, log: log}
}

var _ httpapi.RouteGroup = (*ScimRoutes)(nil)

// Register mounts the fifteen patterns, each behind [httpapi.Gates.Scim].
//
// Wrapping at registration rather than calling the gate as the first line of every handler is the
// same choice internal/policy makes for its admin routes: AGENTS.md's "a route states its requirement
// by which gate helper it calls" stays true — the requirement is visible on the pattern line — and it
// makes an ungated SCIM route impossible to write by forgetting a line.
func (rt *ScimRoutes) Register(mux *http.ServeMux) {
	scim := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, rt.gates.Scim(h))
	}

	scim("GET /api/scim/v2/ServiceProviderConfig", rt.serviceProviderConfig)
	scim("GET /api/scim/v2/ResourceTypes", rt.resourceTypes)
	scim("GET /api/scim/v2/Schemas", rt.schemas)

	scim("GET /api/scim/v2/Users", rt.listUsers)
	scim("POST /api/scim/v2/Users", rt.createUser)
	scim("GET /api/scim/v2/Users/{id}", rt.getUser)
	scim("PUT /api/scim/v2/Users/{id}", rt.replaceUser)
	scim("PATCH /api/scim/v2/Users/{id}", rt.patchUser)
	scim("DELETE /api/scim/v2/Users/{id}", rt.deleteUser)

	scim("GET /api/scim/v2/Groups", rt.listGroups)
	scim("POST /api/scim/v2/Groups", rt.createGroup)
	scim("GET /api/scim/v2/Groups/{id}", rt.getGroup)
	scim("PUT /api/scim/v2/Groups/{id}", rt.replaceGroup)
	scim("PATCH /api/scim/v2/Groups/{id}", rt.patchGroup)
	scim("DELETE /api/scim/v2/Groups/{id}", rt.deleteGroup)
}

// ---- discovery ------------------------------------------------------------------------------

func (rt *ScimRoutes) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	rt.raw(w, r, ServiceProviderConfigJSON)
}

func (rt *ScimRoutes) resourceTypes(w http.ResponseWriter, r *http.Request) {
	rt.raw(w, r, ResourceTypesJSON)
}

func (rt *ScimRoutes) schemas(w http.ResponseWriter, r *http.Request) {
	rt.raw(w, r, SchemasJSON)
}

// ---- Users ------------------------------------------------------------------------------------

// listUsers is `GET /api/scim/v2/Users` — 200 `ScimListResponse<ScimUser>`.
//
// ⚠️ UNBOUNDED. There is no `startIndex`/`count`/`filter` and no pagination in the envelope: the
// entire directory comes back in one response. `ServiceProviderConfig` advertises
// `filter.supported = false` honestly, so an IdP has no reason to send one. REPRODUCE — adding
// pagination would make Okta start sending parameters this route ignores.
func (rt *ScimRoutes) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := rt.store.ListUsers(r.Context())
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	resources := make([]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, u.ToScim())
	}
	rt.respond(w, r, http.StatusOK, NewScimListResponse(resources))
}

// createUser is `POST /api/scim/v2/Users` — **201** `ScimUser`.
//
// Validation order, and it is observable: `externalId` blank/absent ⇒ 400 FIRST, then
// `principal = body.userName.ifBlank { body.primaryEmail().orEmpty() }` ⇒ 400 when still blank. Note
// the EMAIL FALLBACK — PUT deliberately does not have it.
//
// The 409 has a reason worth keeping, quoted from Scim.kt:377-379: "a POST whose externalId is new but
// whose email/principal match resolves to a row already owning a DIFFERENT external_id collides here
// rather than silently producing a split-brain external_id."
func (rt *ScimRoutes) createUser(w http.ResponseWriter, r *http.Request) {
	var body ScimUser
	if !rt.receive(w, r, &body) {
		return
	}
	if body.ExternalID == nil || strings.TrimSpace(*body.ExternalID) == "" {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required")
		return
	}
	externalID := *body.ExternalID

	principal := body.UserName
	if strings.TrimSpace(principal) == "" {
		// `.orEmpty()` — a nil primary email becomes "", which then fails the blank check below.
		if email := body.PrimaryEmail(); email != nil {
			principal = *email
		} else {
			principal = ""
		}
	}
	if strings.TrimSpace(principal) == "" {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidValue"), "userName is required")
		return
	}

	var displayName *string
	if body.Name != nil {
		displayName = body.Name.Formatted
	}

	user, err := rt.store.UpsertScimUser(
		r.Context(), externalID, principal, body.PrimaryEmail(), displayName, body.Active, rt.creds)
	if err != nil {
		if store.IsUniqueViolation(err) {
			rt.scimError(w, r, http.StatusConflict, types.Ptr("uniqueness"),
				"principal or externalId already in use")
			return
		}
		rt.fallback(w, r, err)
		return
	}
	rt.log.Info("SCIM: provisioned user", "principal", user.Principal, "externalId", externalID)
	rt.respond(w, r, http.StatusCreated, user.ToScim())
}

// getUser is `GET /api/scim/v2/Users/{id}` — 200, or 404 with `scimType` NULL and detail
// "no such user". The elvis covers both an unparseable id and a missing row.
func (rt *ScimRoutes) getUser(w http.ResponseWriter, r *http.Request) {
	user, ok := rt.lookupUser(w, r)
	if !ok {
		return
	}
	rt.respond(w, r, http.StatusOK, user.ToScim())
}

// replaceUser is `PUT /api/scim/v2/Users/{id}` — 200 `ScimUser`.
//
// It is a MERGE for the four scalar fields and a VERBATIM REPLACE for `active`:
//
//	externalId  = body.externalId ?: existing.externalId   (blank ⇒ 400)
//	principal   = body.userName.ifBlank { existing.principal }   — NO email fallback, unlike POST
//	email       = body.primaryEmail() ?: existing.email
//	displayName = body.name?.formatted ?: existing.displayName
//	active      = body.active            — taken verbatim, and ITS DEFAULT IS TRUE
//
// 🔒 F22 — THE HIGHEST-RANKED LIVE GAP IN THE AREA, AND IT IS REPRODUCED DELIBERATELY. A PUT body that
// OMITS `active` silently REACTIVATES a deprovisioned user: [ScimUser]'s Kotlin default is `true`, this
// route passes it through unchanged, and because the value went from false to true the store's
// deactivate branch never fires — so the credential teardown is not re-run either. A routine Okta
// full-resource PUT therefore un-deprovisions an account. Untested in the Kotlin; PINNED here by
// TestScimPutOmittingActiveSilentlyReactivatesADeprovisionedUser, which asserts the BUGGY behaviour so
// that fixing it is a deliberate, reviewable change (03-identity-scim.md Q1).
//
// 🔒 INV-A3-32 — this route calls [UserGroupStore.ReplaceScimUserByID], which addresses THIS id and
// never re-discovers another row by externalId/email/principal the way the POST upsert does.
func (rt *ScimRoutes) replaceUser(w http.ResponseWriter, r *http.Request) {
	existing, ok := rt.lookupUser(w, r)
	if !ok {
		return
	}
	// The body is decoded AFTER the existence check — the Kotlin's order, so a PUT to a missing id
	// answers 404 even when the body is malformed.
	var body ScimUser
	if !rt.receive(w, r, &body) {
		return
	}

	externalID := body.ExternalID
	if externalID == nil {
		externalID = existing.ExternalID
	}
	if externalID == nil || strings.TrimSpace(*externalID) == "" {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required")
		return
	}

	principal := body.UserName
	if strings.TrimSpace(principal) == "" {
		principal = existing.Principal
	}
	email := body.PrimaryEmail()
	if email == nil {
		email = existing.Email
	}
	var displayName *string
	if body.Name != nil {
		displayName = body.Name.Formatted
	}
	if displayName == nil {
		displayName = existing.DisplayName
	}

	updated, err := rt.store.ReplaceScimUserByID(
		r.Context(), existing.ID, principal, email, displayName, *externalID, body.Active, rt.creds)
	if err != nil {
		if store.IsUniqueViolation(err) {
			rt.scimError(w, r, http.StatusConflict, types.Ptr("uniqueness"),
				"externalId already belongs to a different user")
			return
		}
		rt.fallback(w, r, err)
		return
	}
	if updated == nil {
		rt.notFoundUser(w, r)
		return
	}
	rt.respond(w, r, http.StatusOK, updated.ToScim())
}

// patchUser is `PATCH /api/scim/v2/Users/{id}` — 200 `ScimUser`.
//
// 🔒 INV-A3-44 — a `MemberOp` here is 400 `invalidPath` "path 'members' is only valid on Groups". The
// validator is resource-agnostic; this branch is the Users half of the pairing and must not be
// dropped.
//
// The SetActive arm goes through [UserGroupStore.SetActiveByID], which re-reads the row's CURRENT
// principal under the per-principal advisory lock — so a concurrent rename cannot make this act on a
// stale pre-lock snapshot — and, on `active=false`, revokes that principal's credentials in the SAME
// committed transaction. The log line fires only when DEACTIVATING.
func (rt *ScimRoutes) patchUser(w http.ResponseWriter, r *http.Request) {
	existing, ok := rt.lookupUser(w, r)
	if !ok {
		return
	}
	action, ok := rt.validatePatch(w, r)
	if !ok {
		return
	}

	if action.MemberOp != nil {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidPath"),
			"path 'members' is only valid on Groups")
		return
	}

	updated, err := rt.store.SetActiveByID(r.Context(), existing.ID, *action.SetActive, rt.creds)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if updated == nil {
		rt.notFoundUser(w, r)
		return
	}
	if !*action.SetActive {
		rt.log.Info("SCIM: deactivated user", "principal", updated.Principal)
	}
	rt.respond(w, r, http.StatusOK, updated.ToScim())
}

// deleteUser is `DELETE /api/scim/v2/Users/{id}` — **204**, no body.
//
// 🔒 INV-A3-19 — DEPROVISION, NEVER HARD-DELETE: the row survives with `active=false` so audit history
// keeps resolving the principal. Contrast [ScimRoutes.deleteGroup], which really does DELETE.
//
// The Kotlin is one elvis covering both an unparseable id and a missing row, and the log line uses the
// RE-READ principal — the string the row actually carried at teardown time, not whatever the caller
// might have assumed.
func (rt *ScimRoutes) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.notFoundUser(w, r)
		return
	}
	deprovisioned, err := rt.store.SetActiveByID(r.Context(), *id, false, rt.creds)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if deprovisioned == nil {
		rt.notFoundUser(w, r)
		return
	}
	rt.log.Info("SCIM: deprovisioned user", "principal", deprovisioned.Principal)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Groups -------------------------------------------------------------------------------------

// listGroups is `GET /api/scim/v2/Groups` — 200 `ScimListResponse<ScimGroup>`.
//
// ⚠️ N+1: one `listMembers` query PER GROUP, on top of the three `listGroups` already runs, and no
// pagination. REPRODUCE (03-identity-scim.md Q9).
func (rt *ScimRoutes) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := rt.store.ListGroups(r.Context())
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	resources := make([]any, 0, len(groups))
	for _, g := range groups {
		members, err := rt.store.ListMembers(r.Context(), g.ID)
		if err != nil {
			rt.fallback(w, r, err)
			return
		}
		resources = append(resources, GroupToScim(g, members))
	}
	rt.respond(w, r, http.StatusOK, NewScimListResponse(resources))
}

// createGroup is `POST /api/scim/v2/Groups` — **201** `ScimGroup`.
//
// 🔒 INV-A3-33 / INV-A3-45 — THE SYSTEM GUARD LIVES INSIDE THE STORE, not here. Scim.kt:494-497 says
// why in as many words: "A route-level pre-check on a separate connection was defeatable by a
// concurrent PUT that re-pointed an external_id between the check and the write — so the store throws
// instead." The three sibling Group mutations below DO use a route-level `isSystemGroup`; that
// asymmetry is INV-A3-45 and a port must not unify it by hoisting this check up here.
//
// ⚠️ The member adds run OUTSIDE the try, ONE STATEMENT PER MEMBER, NOT in a transaction, and they are
// ADD-ONLY — a POST onto an existing group never removes anyone. A numeric-but-nonexistent member id
// therefore raises SQLSTATE 23503 out here where nothing catches it, and reaches the IdP as a 500
// `ApiError` on a SCIM route (F29 + F30). Both halves reproduced.
//
// ⚠️ The response re-reads the MEMBER LIST after the adds but keeps the PRE-ADD `AppGroup` scalars
// (including a now-stale `memberCount`). Only id/externalId/displayName survive into `ScimGroup`, so
// the staleness is invisible on the wire today — and stops being invisible the moment `ScimGroup`
// grows a `meta`.
func (rt *ScimRoutes) createGroup(w http.ResponseWriter, r *http.Request) {
	var body ScimGroup
	if !rt.receive(w, r, &body) {
		return
	}
	if body.ExternalID == nil || strings.TrimSpace(*body.ExternalID) == "" {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required")
		return
	}
	if strings.TrimSpace(body.DisplayName) == "" {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidValue"), "displayName is required")
		return
	}

	group, err := rt.store.UpsertScimGroup(r.Context(), *body.ExternalID, body.DisplayName)
	if err != nil {
		var immutable *SystemGroupImmutableError
		if errors.As(err, &immutable) {
			rt.scimError(w, r, http.StatusConflict, types.Ptr("mutability"),
				"system-managed group is immutable")
			return
		}
		if store.IsUniqueViolation(err) {
			rt.scimError(w, r, http.StatusConflict, types.Ptr("uniqueness"),
				"name or externalId already in use")
			return
		}
		rt.fallback(w, r, err)
		return
	}

	for _, m := range body.Members {
		userID, err := strconv.ParseInt(m.Value, 10, 64)
		if err != nil {
			// ⚠️ INV-A3-46 — a NON-NUMERIC member id is SILENTLY DROPPED by `toLongOrNull()`.
			continue
		}
		if _, err := rt.store.AddMember(r.Context(), group.ID, userID); err != nil {
			rt.fallback(w, r, err)
			return
		}
	}

	rt.log.Info("SCIM: provisioned group", "name", group.Name, "externalId", *body.ExternalID)
	members, err := rt.store.ListMembers(r.Context(), group.ID)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, GroupToScim(group, members))
}

// getGroup is `GET /api/scim/v2/Groups/{id}` — 200, or 404 "no such group".
func (rt *ScimRoutes) getGroup(w http.ResponseWriter, r *http.Request) {
	group, ok := rt.lookupGroup(w, r)
	if !ok {
		return
	}
	members, err := rt.store.ListMembers(r.Context(), group.ID)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, GroupToScim(*group, members))
}

// replaceGroup is `PUT /api/scim/v2/Groups/{id}` — 200 `ScimGroup`.
//
// Scalars MERGE (`externalId ?: existing.externalId`, blank ⇒ 400; `displayName.ifBlank {
// existing.name }`) while membership is a TRUE REPLACE: `desired - current` added,
// `current - desired` removed.
//
// ⚠️ So a PUT that OMITS `members` reconciles to the EMPTY set and removes everyone, while its scalar
// fields merge. Both halves are real and both are reproduced exactly — this is the group-side twin of
// F22's asymmetry, and it is the reason a partial PUT from an IdP can silently empty a group.
//
// The SYSTEM check here is route-level on a separate connection — INV-A3-45's weaker half. See
// [UserGroupStore.ReplaceScimGroupByID].
func (rt *ScimRoutes) replaceGroup(w http.ResponseWriter, r *http.Request) {
	existing, ok := rt.lookupGroup(w, r)
	if !ok {
		return
	}
	if !rt.rejectSystemGroup(w, r, existing.ID, types.Ptr("mutability")) {
		return
	}
	var body ScimGroup
	if !rt.receive(w, r, &body) {
		return
	}

	externalID := body.ExternalID
	if externalID == nil {
		externalID = existing.ExternalID
	}
	if externalID == nil || strings.TrimSpace(*externalID) == "" {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidValue"), "externalId is required")
		return
	}
	displayName := body.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = existing.Name
	}

	group, err := rt.store.ReplaceScimGroupByID(r.Context(), existing.ID, *externalID, displayName)
	if err != nil {
		if store.IsUniqueViolation(err) {
			rt.scimError(w, r, http.StatusConflict, types.Ptr("uniqueness"),
				"externalId already belongs to a different group")
			return
		}
		rt.fallback(w, r, err)
		return
	}
	if group == nil {
		rt.notFoundGroup(w, r)
		return
	}

	desired := map[int64]struct{}{}
	for _, m := range body.Members {
		if id, err := strconv.ParseInt(m.Value, 10, 64); err == nil {
			desired[id] = struct{}{}
		}
	}
	members, err := rt.store.ListMembers(r.Context(), group.ID)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	current := map[int64]struct{}{}
	for _, m := range members {
		current[m.UserID] = struct{}{}
	}
	for id := range desired {
		if _, already := current[id]; already {
			continue
		}
		if _, err := rt.store.AddMember(r.Context(), group.ID, id); err != nil {
			rt.fallback(w, r, err)
			return
		}
	}
	for id := range current {
		if _, keep := desired[id]; keep {
			continue
		}
		if _, err := rt.store.RemoveMember(r.Context(), group.ID, id); err != nil {
			rt.fallback(w, r, err)
			return
		}
	}

	after, err := rt.store.ListMembers(r.Context(), group.ID)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, GroupToScim(*group, after))
}

// patchGroup is `PATCH /api/scim/v2/Groups/{id}` — 200 `ScimGroup`.
//
// 🔒 INV-A3-44 — a `SetActive` here is 400 `invalidPath` "path 'active' is only valid on Users".
//
// ⚠️ The response is built from `existing` — the PRE-MUTATION group row — with a FRESHLY re-read
// member list. Scalars are stale-by-one, members are fresh. Harmless today (PATCH cannot change a
// scalar) but do not "tidy" it into re-reading the row without checking `web/`.
func (rt *ScimRoutes) patchGroup(w http.ResponseWriter, r *http.Request) {
	existing, ok := rt.lookupGroup(w, r)
	if !ok {
		return
	}
	if !rt.rejectSystemGroup(w, r, existing.ID, types.Ptr("mutability")) {
		return
	}
	action, ok := rt.validatePatch(w, r)
	if !ok {
		return
	}
	if action.SetActive != nil {
		rt.scimError(w, r, http.StatusBadRequest, types.Ptr("invalidPath"),
			"path 'active' is only valid on Users")
		return
	}

	for _, raw := range action.MemberOp.Values {
		userID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			// ⚠️ INV-A3-46 — silently dropped.
			continue
		}
		if action.MemberOp.Op == "add" {
			_, err = rt.store.AddMember(r.Context(), existing.ID, userID)
		} else {
			_, err = rt.store.RemoveMember(r.Context(), existing.ID, userID)
		}
		if err != nil {
			rt.fallback(w, r, err)
			return
		}
	}

	members, err := rt.store.ListMembers(r.Context(), existing.ID)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, GroupToScim(*existing, members))
}

// deleteGroup is `DELETE /api/scim/v2/Groups/{id}` — **204**.
//
// 🔒 F42 / F26 — THIS ONE REALLY DELETES. `deleteGroup` is the only hard delete in the area and
// `group_member.group_id` / `group_role.group_id` are both `ON DELETE CASCADE`
// (V1__identity.sql:45,52), so an IdP group delete silently revokes the group's roles from every
// member, with no audit record and no undo — while users are NEVER hard-deleted (INV-A3-19). The
// asymmetry is the finding; REPRODUCE.
//
// ⚠️ F26 also covers the 409 here: it carries `scimType = null` where every sibling sets
// `"mutability"`. Reproduced, and pinned, because an IdP branching on scimType sees a different shape
// from this one route.
//
// Note the ORDER: the SYSTEM check runs against the raw id BEFORE any existence check, so a SYSTEM id
// answers 409 and a nonexistent id falls through to the `deleteGroup` false branch ⇒ 404.
func (rt *ScimRoutes) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.notFoundGroup(w, r)
		return
	}
	if !rt.rejectSystemGroup(w, r, *id, nil) {
		return
	}
	deleted, err := rt.store.DeleteGroup(r.Context(), *id)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if !deleted {
		rt.notFoundGroup(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- shared handler plumbing --------------------------------------------------------------------

// lookupUser is `val id = parameters["id"]?.toLongOrNull(); id?.let { getUser(it) } ?: 404`.
func (rt *ScimRoutes) lookupUser(w http.ResponseWriter, r *http.Request) (*AppUser, bool) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.notFoundUser(w, r)
		return nil, false
	}
	user, err := rt.store.GetUser(r.Context(), *id)
	if err != nil {
		rt.fallback(w, r, err)
		return nil, false
	}
	if user == nil {
		rt.notFoundUser(w, r)
		return nil, false
	}
	return user, true
}

// lookupGroup is the Groups twin of [ScimRoutes.lookupUser].
func (rt *ScimRoutes) lookupGroup(w http.ResponseWriter, r *http.Request) (*AppGroup, bool) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.notFoundGroup(w, r)
		return nil, false
	}
	group, err := rt.store.GetGroup(r.Context(), *id)
	if err != nil {
		rt.fallback(w, r, err)
		return nil, false
	}
	if group == nil {
		rt.notFoundGroup(w, r)
		return nil, false
	}
	return group, true
}

// rejectSystemGroup is the route-level `if (isSystemGroup(id)) 409` the PUT, PATCH and DELETE Group
// routes share. scimType is `"mutability"` for PUT/PATCH and NIL for DELETE — F26.
//
// ⚠️ It reads on its OWN connection with NO row lock: INV-A3-45's weaker half, safe only because it
// addresses an immutable id rather than re-resolving. Do not add a lock here without deciding
// 03-identity-scim.md Q2.
func (rt *ScimRoutes) rejectSystemGroup(
	w http.ResponseWriter, r *http.Request, id int64, scimType *string,
) bool {
	system, err := rt.store.IsSystemGroup(r.Context(), id)
	if err != nil {
		rt.fallback(w, r, err)
		return false
	}
	if system {
		rt.scimError(w, r, http.StatusConflict, scimType, "system-managed group is immutable")
		return false
	}
	return true
}

// validatePatch decodes the body and runs [ValidateScimPatch], answering the validator's own
// scimType/detail on failure.
func (rt *ScimRoutes) validatePatch(w http.ResponseWriter, r *http.Request) (ScimPatchAction, bool) {
	var body ScimPatchOp
	if !rt.receive(w, r, &body) {
		return ScimPatchAction{}, false
	}
	action, err := ValidateScimPatch(body.Operations)
	if err != nil {
		var invalid *ScimPatchInvalidError
		if errors.As(err, &invalid) {
			rt.scimError(w, r, http.StatusBadRequest, &invalid.ScimType, invalid.Detail)
			return ScimPatchAction{}, false
		}
		rt.fallback(w, r, err)
		return ScimPatchAction{}, false
	}
	return action, true
}

func (rt *ScimRoutes) notFoundUser(w http.ResponseWriter, r *http.Request) {
	rt.scimError(w, r, http.StatusNotFound, nil, "no such user")
}

func (rt *ScimRoutes) notFoundGroup(w http.ResponseWriter, r *http.Request) {
	rt.scimError(w, r, http.StatusNotFound, nil, "no such group")
}

func (rt *ScimRoutes) scimError(
	w http.ResponseWriter, r *http.Request, status int, scimType *string, detail string,
) {
	if err := httpapi.RespondScimError(w, status, scimError(status, scimType, detail)); err != nil {
		rt.log.Error("failed to write SCIM error", "path", r.URL.Path, "status", status, "err", err)
	}
}

// raw serves a static discovery document byte for byte. It bypasses [httpapi.RespondJSON] because
// there is nothing to marshal: the Kotlin holds a pre-built JsonObject and ContentNegotiation writes
// it out unchanged.
func (rt *ScimRoutes) raw(w http.ResponseWriter, r *http.Request, body string) {
	w.Header().Set("Content-Type", httpapi.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(body)); err != nil {
		rt.log.Error("failed to write SCIM discovery document", "path", r.URL.Path, "err", err)
	}
}

func (rt *ScimRoutes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

// receive is `call.receive<T>()`.
//
// ⚠️ F41 — a malformed body escapes to StatusPages, which answers 500 `ApiError("common.fallback")`
// EVEN ON A SCIM ROUTE, breaking the SCIM error-body exemption exactly where an IdP is least able to
// parse it. That is A1's middleware behaviour, not something this file can override, and it is
// reproduced rather than special-cased.
func (rt *ScimRoutes) receive(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpapi.Receive(r, dst); err != nil {
		// 415 before the SCIM error body: ContentNegotiation answers before Scim.kt runs, so this is NOT
		// one of INV-A1-13's SCIM-shaped exemptions.
		if errors.Is(err, httpapi.ErrUnsupportedMediaType) {
			httpapi.RespondUnsupportedMediaType(w)
			return false
		}
		rt.fallback(w, r, err)
		return false
	}
	return true
}

// fallback is the uncaught-error path: 500 `ApiError("common.fallback")`, ApiError-shaped even here.
func (rt *ScimRoutes) fallback(w http.ResponseWriter, r *http.Request, err error) {
	httpapi.RespondFallback(w, r, rt.log, err)
}
