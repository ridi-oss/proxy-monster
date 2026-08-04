package policy

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The first slice of `PolicyManagementService` — management/ManagementServices.kt:208-460
//
// 🔴 THIS IS NOT A11's PORT. It is the ONE method A1's `/auth/debug` cannot be written without
// (App.kt:715), landed here so it sits next to the store it drives rather than being open-coded in
// the composition root, where A11 would later find a second, silently diverging definition of
// "replace this principal's direct roles".
//
//	TODO(A11): the other ~30 methods of PolicyManagementService, plus CedarValidationManagementException
//	           and the `isSystemRole` guards at ManagementServices.kt:362,370,382,389 that F19 records
//	           as the largest untested surface in the control plane. EXTEND [PolicyManagement]; do not
//	           declare a second service type, and do not declare a second [ManagementError].
// ---------------------------------------------------------------------------------------------

// ManagementError is `class ManagementException(val error: ApiError) : RuntimeException(error.code)`
// (ManagementServices.kt:47) — "a transport-neutral management failure represented only by a stable
// API code and parameters".
//
// 🔴 IT IS AN ALIAS OF [types.ManagementError], NOT A SECOND DECLARATION. The declaration moved to
// the leaf package so that internal/datasource's A5 route group can name it (and [DeleteResult])
// without importing internal/policy — that edge closed an import cycle through internal/dbtest. See
// types/management.go for the full reasoning. An alias means `policy.ManagementError`,
// `management.Error` and `types.ManagementError` are ONE type: every existing `errors.As` across the
// three packages still matches, which a structurally-identical second struct would silently break.
type ManagementError = types.ManagementError

// managementNotFound is `private fun notFound(resource: String): Nothing` (ManagementServices.kt:720).
func managementNotFound(resource string) *ManagementError {
	return &ManagementError{Err: types.ApiError{
		Code:   "common.not_found",
		Params: map[string]string{"resource": resource},
	}}
}

// managementRequired is `private fun required(field, value)` (ManagementServices.kt:716).
//
// Kotlin's `String.isBlank()` is "empty or all whitespace", where whitespace is Character.isWhitespace
// — strings.TrimSpace's set is unicode.IsSpace, which differs on a handful of exotic code points
// (Character.isWhitespace excludes NBSP; unicode.IsSpace includes it). Unreachable for a principal
// name and narrower in the rejecting direction, so it is not worth a hand-rolled predicate here.
func managementRequired(field, value string) *ManagementError {
	if strings.TrimSpace(value) != "" {
		return nil
	}
	return &ManagementError{Err: types.ApiError{
		Code:   "common.field_required",
		Params: map[string]string{"fields": field},
	}}
}

// PolicyManagement is `class PolicyManagementService(policyStore: CedarPolicyStore, store: PolicyStore)`
// (ManagementServices.kt:208).
//
// Both fields are carried even though [PolicyManagement.ReplaceDirectRolesOn] uses only the second:
// the constructor shape is A11's and reproducing it now means A11 adds methods rather than changing
// every construction site. `policies` may be nil until a method that needs it lands.
type PolicyManagement struct {
	policies *CedarPolicyStore
	store    *PolicyStore
}

// NewPolicyManagement is the constructor, argument order included.
func NewPolicyManagement(policies *CedarPolicyStore, store *PolicyStore) *PolicyManagement {
	return &PolicyManagement{policies: policies, store: store}
}

// ReplaceDirectRolesOn is `fun replaceDirectRoles(principal, roleNames, c: Connection)`
// (ManagementServices.kt:430-435). It makes roleNames the principal's COMPLETE set of direct
// `principal_role` rows.
//
// The four steps, in the Kotlin's order, and every one of them is load-bearing:
//
//  1. `required("principal", principal)` — a blank principal is 400 common.field_required, not a
//     silently-created assignment on the empty string.
//  2. 🔒 `c.advisoryLockPrincipal(principal)` — the SAME per-principal lock deprovisioning and SCIM
//     take. `inTx` alone is NOT enough, and the Kotlin's own comment says why: at READ COMMITTED a
//     list-delete-insert is a read-modify-write, so two concurrent replacements each delete only the
//     ids THEY listed and then insert their own, committing the UNION rather than either caller's
//     set. "The claim is the whole intended set" is only true if the sequence cannot interleave.
//  3. 🔒 EVERY NAME IS RESOLVED BEFORE ANYTHING IS DELETED. An unknown name leaves the existing set
//     untouched rather than stripping a principal's roles and then failing. Unknown names are
//     REJECTED, never created — a typo that silently became a real role would resolve fine and then
//     deny every query, since no policy references it.
//  4. delete every existing direct assignment, then insert one per resolved role.
//
// The rejection names the OFFENDING ROLE (`role 'no-such-role'`), not just `role`: the caller asked
// for a set and the whole request fails on any one member, so it needs to know which.
// WebSessionRoutesDbTest.kt:197 asserts the offending name appears in the 404 body.
//
// Only direct rows are touched. Group-derived roles and active JIT grants are separate sources that
// identity.RoleResolver.Resolve unions in, and are deliberately left alone.
//
// It takes a [store.Queryer] so a caller that must land another write atomically with the
// replacement composes both onto ONE transaction under ONE lock rather than committing twice. That
// caller is 🔒 INV-A1-6, `/auth/debug`, which mints a session for exactly these roles.
func (m *PolicyManagement) ReplaceDirectRolesOn(
	ctx context.Context, c store.Queryer, principal string, roleNames []string,
) ([]RoleAssignment, error) {
	if err := managementRequired("principal", principal); err != nil {
		return nil, err
	}
	if err := store.AdvisoryLockPrincipal(ctx, c, principal); err != nil {
		return nil, err
	}

	roles := make([]Role, 0, len(roleNames))
	for _, name := range roleNames {
		role, err := m.store.GetRoleByNameOn(ctx, c, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, managementNotFound("role '" + name + "'")
		}
		roles = append(roles, *role)
	}

	existing, err := m.store.ListAssignmentsOn(ctx, c, &principal, nil)
	if err != nil {
		return nil, err
	}
	for _, a := range existing {
		if _, err := m.store.DeleteAssignmentOn(ctx, c, a.ID); err != nil {
			return nil, err
		}
	}

	// `emptyList()` on the wire, never nil — INV-A1-4. An empty claim is a deliberate WIPE of the
	// direct set (WebSessionRoutesDbTest.kt:216-220), not a no-op, so the empty result is a real
	// answer rather than an absence.
	out := make([]RoleAssignment, 0, len(roles))
	for _, role := range roles {
		created, err := m.store.CreateAssignmentOn(ctx, c, RoleAssignmentInput{Principal: principal, RoleID: role.ID})
		if err != nil {
			return nil, err
		}
		out = append(out, created)
	}
	return out, nil
}

// ReplaceDirectRoles is `fun replaceDirectRoles(principal, roleNames)` (ManagementServices.kt:438) —
// the same work on its own transaction, for a caller with nothing to compose.
func (m *PolicyManagement) ReplaceDirectRoles(
	ctx context.Context, principal string, roleNames []string,
) ([]RoleAssignment, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) ([]RoleAssignment, error) {
		return m.ReplaceDirectRolesOn(ctx, tx, principal, roleNames)
	})
}
