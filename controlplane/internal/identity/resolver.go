package identity

import (
	"context"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// AccessGrants is the narrow slice of A6's `AccessStore` that [RoleResolver] depends on. A6 is not
// ported yet, so this is the seam rather than a concrete type — internal/identity must not learn
// A6's `AccessGrant` DTO to resolve a role name.
//
// ListGrantRoles must reproduce `AccessStore.listGrants(principal, activeOnly).map { it.roleName }`
// (Access.kt:486-495) exactly, and three details of it are load-bearing:
//
//  1. activeOnly is a PARAMETER, not baked in. [RoleResolver.Resolve] passes true, and that literal
//     is the whole content of ResolveRolesTest cases 2 and 3 (a revoked grant and an expired grant
//     must both drop out). Keeping it in the signature keeps the call site readable as the assertion
//     it is.
//  2. activeOnly=true means `ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())`.
//     Note `expires_at IS NULL` counts as ACTIVE — a grant with no expiry never lapses.
//  3. The order is `ORDER BY ag.granted_at DESC`, and it is observable: these names become the
//     SECOND arm of [EffectiveRoles], whose first-occurrence order reaches the wire (doc.go).
//
// TODO(A6): satisfy this from AccessStore directly — either by adding a ListGrantRoles method there
// or with a one-line adapter that keeps the `.map { roleName }` on A6's side.
type AccessGrants interface {
	ListGrantRoles(ctx context.Context, principal string, activeOnly bool) ([]string, error)
}

// RoleResolver is the port of `class RoleResolver(dataSource, userGroupStore, accessStore)`
// (RoleResolver.kt:13-17) — the Layer-1 identity resolver of docs/authz-model.md: identity, no
// Cedar.
//
// 🔒 It is constructed ONCE (ControlPlaneCore.kt:31) and shared by the HTTP and gRPC surfaces. Do
// not build a second one per request: A2's engine caches its compiled PolicySet per instance, and
// INV-A1-1 requires one object graph for both surfaces.
type RoleResolver struct {
	db             store.DB
	userGroupStore *UserGroupStore
	accessGrants   AccessGrants
}

// NewRoleResolver wires the resolver. All three Kotlin constructor params are `private val`; the
// same three are unexported fields here.
func NewRoleResolver(db store.DB, userGroupStore *UserGroupStore, accessGrants AccessGrants) *RoleResolver {
	return &RoleResolver{db: db, userGroupStore: userGroupStore, accessGrants: accessGrants}
}

// DirectRoles is `directRoles(principal)` (RoleResolver.kt:19): the role names this principal holds
// through a direct `principal_role` assignment.
//
// ⚠️ There is NO active/expiry filter of any kind on this source, and none is missing —
// [RoleResolver.Resolve]'s deactivation short-circuit is the ONLY gate on it. Adding a filter here
// would double-guard the direct source and silently change what A4's web-session routes see, since
// they call this method directly (`WebSessionRoutesDbTest`).
//
// No ORDER BY, deliberately: this is the FIRST arm of [EffectiveRoles] and its order reaches the
// wire (doc.go).
func (r *RoleResolver) DirectRoles(ctx context.Context, principal string) ([]string, error) {
	rows, err := r.db.Query(ctx,
		`SELECT r.name
               FROM principal_role pr
               JOIN app_role r ON r.id = pr.role_id
               WHERE pr.principal = $1`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Resolve is `resolve(principal)` (RoleResolver.kt:48) — **the sole source of truth for effective
// roles.**
//
// Contract: the principal's complete effective role set — direct `principal_role` ∪ active JIT grant
// roles ∪ group-derived roles — resolved server-side, or the empty set when nothing applies. It
// never errors for an unknown principal; the three sources simply return nothing, and no role is
// invented from thin air.
//
// 🔒 INV-A3-9 — deprovisioning short-circuits ALL role sources, not just the directory one. The
// IsDeactivated check runs BEFORE any role read and returns immediately, so a deactivated principal
// gets the empty set regardless of any direct assignment, group membership or JIT grant. Both of the
// other two sources are keyed on the principal STRING and are independent of `app_user` entirely, so
// without this line a deprovisioned user would keep every direct and JIT role. DeprovisionDbTest
// case 6 pins all three at once; resolver_db_test.go ports it.
//
// 🔒 INV-A3-10 — a principal with no `app_user` row at all is NOT deactivated and keeps its direct
// roles. That is [UserGroupStore.IsDeactivated]'s contract, not a special case here.
//
// ⚠️ INV-A3-11 / F31 — REPRODUCED: this is NOT transactional. The four reads run on separate pooled
// connections, so a deactivation committing mid-resolve yields a torn view. Wrapping them in one
// transaction would close the window and is a deliberate behaviour change for after cutover, not
// part of the port (03-identity-scim.md Q4).
//
// Returns an order-preserving, deduplicated []string rather than a map: the order is on the wire.
// See doc.go.
func (r *RoleResolver) Resolve(ctx context.Context, principal string) ([]string, error) {
	deactivated, err := r.userGroupStore.IsDeactivated(ctx, principal)
	if err != nil {
		return nil, err
	}
	if deactivated {
		return nil, nil
	}

	direct, err := r.DirectRoles(ctx, principal)
	if err != nil {
		return nil, err
	}
	grantRoles, err := r.accessGrants.ListGrantRoles(ctx, principal, true)
	if err != nil {
		return nil, err
	}
	groupRoles, err := r.userGroupStore.RolesForPrincipal(ctx, principal)
	if err != nil {
		return nil, err
	}
	return EffectiveRoles(direct, grantRoles, groupRoles), nil
}

// HasActiveAssignee is `hasActiveAssignee(roleName)` (RoleResolver.kt:63): whether at least one
// ACTIVE principal can reach roleName through the same three-way union [RoleResolver.Resolve] uses.
//
// Its only consumer is `/health`'s readiness diagnostics (App.kt:563 →
// "system:admin role has no active assignee").
//
// One SQL statement, three EXISTS arms OR'd, roleName bound three times. **Do not decompose it into
// three round trips** — the point is a single readiness probe (03-identity-scim.md "Go shape").
//
//  1. DIRECT — `principal_role ⋈ app_role(name=?)` LEFT JOIN `app_user` with
//     `u.id IS NULL OR u.active`: a direct principal with NO `app_user` row counts, mirroring
//     INV-A3-10; an inactive directory user does not.
//  2. GROUP — `group_role ⋈ app_role(name=?) ⋈ group_member ⋈ app_user(u.active)`, an INNER join.
//     🔒 INV-A3-12 — the INNER join is ON PURPOSE. The shipped seed installs the `system:admin`
//     group with a `group_role` link and ZERO members (V8__seed.sql:48-74), so counting the bare
//     link as an assignee would report a fresh install as "admin is reachable" when nobody can
//     actually log in as one.
//  3. JIT — `access_grant ⋈ app_role(name=?)` with `revoked_at IS NULL AND (expires_at IS NULL OR
//     expires_at > now())`, plus the same LEFT JOIN / `u.id IS NULL OR u.active` rule as arm 1.
//
// 🔒 INV-A3-13 — this is a SECOND, independent implementation of Resolve's union, and drift between
// them is the risk. The mirrored test is the only thing holding them together. Keep it.
func (r *RoleResolver) HasActiveAssignee(ctx context.Context, roleName string) (bool, error) {
	var out bool
	err := r.db.QueryRow(ctx,
		`SELECT
                   EXISTS (
                       SELECT 1
                       FROM principal_role pr
                       JOIN app_role r ON r.id = pr.role_id AND r.name = $1
                       LEFT JOIN app_user u ON u.principal = pr.principal
                       WHERE u.id IS NULL OR u.active
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM group_role gr
                       JOIN app_role r ON r.id = gr.role_id AND r.name = $2
                       JOIN group_member gm ON gm.group_id = gr.group_id
                       JOIN app_user u ON u.id = gm.user_id AND u.active
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM access_grant ag
                       JOIN app_role r ON r.id = ag.role_id AND r.name = $3
                       LEFT JOIN app_user u ON u.principal = ag.principal
                       WHERE ag.revoked_at IS NULL
                         AND (ag.expires_at IS NULL OR ag.expires_at > now())
                         AND (u.id IS NULL OR u.active)
                   )`, roleName, roleName, roleName).Scan(&out)
	if err != nil {
		return false, err
	}
	return out, nil
}

// EffectiveRoles is `effectiveRoles(baseRoles, grantRoles, groupRoles): Set<String>` — the pure
// union of a principal's three role sources.
//
// ⚠️ In the Kotlin this lives in `Query.kt:197` (A6), NOT in `RoleResolver.kt`. It is hosted in this
// package because [RoleResolver.Resolve] is its sole production caller and A6 imports this package
// anyway; putting it in A6's package would make internal/identity depend on internal/query, which
// inverts how the two relate. It is a pure function with no dependencies — if A6 would rather own
// it, move it and take effectiveroles_test.go along unchanged. Recorded in doc.go.
//
// The Kotlin body is `(baseRoles + grantRoles + groupRoles).toSet()`. `toSet()` builds a
// LinkedHashSet, so the result is deduplicated AND ordered by first occurrence — base first, then
// grants, then groups. `Query.kt:366` turns it straight into the `effectiveRoles: List<String>` the
// decision DTO, the audit record and the gRPC response all carry, so that order is on the wire and
// this function reproduces it. Returning a Go map here would randomise it.
//
// It is kept separate from Resolve purely so the union stays unit-testable without a database, which
// is exactly what `EffectiveRolesTest` (4 cases, no DB) exercises.
func EffectiveRoles(baseRoles, grantRoles, groupRoles []string) []string {
	seen := make(map[string]struct{}, len(baseRoles)+len(grantRoles)+len(groupRoles))
	var out []string
	for _, src := range [][]string{baseRoles, grantRoles, groupRoles} {
		for _, name := range src {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}
