package policy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// The NAME-KEYED half of `PolicyManagementService` — ManagementServices.kt:208-508.
//
// A11 §8: "~28 methods over Cedar policies, roles, assignments, and mask functions — each in
// name-keyed, id-keyed, and connection-taking variants (the MCP surface is name-keyed, REST is
// id-keyed)." management_crud.go holds the id-keyed half; this file holds the other two.
//
// 🔴 WHY IT IS HERE AND NOT IN internal/management. Go can only declare a method in the package that
// declares the receiver's type, and [PolicyManagement] is declared in management.go — which states
// the rule outright: "EXTEND [PolicyManagement]; do not declare a second service type, and do not
// declare a second [ManagementError]." internal/management therefore aliases this type rather than
// wrapping it, so a caller still imports one package for all three A11 §8 services. See
// internal/management/doc.go.
//
// The duplication between a name-keyed and an id-keyed variant of the same operation is the
// Kotlin's, and it is REPRODUCE: the two differ in which lookup can 404 and in which `required`
// field name a blank value reports, both of which are on the wire.
// ---------------------------------------------------------------------------------------------

// DeleteResult is `@Serializable data class DeleteResult(val deleted: Boolean)`
// (ManagementServices.kt:53) — the body every NAME-KEYED management delete returns.
//
// 🔴 AN ALIAS OF [types.DeleteResult], for exactly the reason [ManagementError] is one: three
// packages have to name it (internal/policy declares the methods that return it, internal/management
// aliases it, and internal/datasource's route group names it in the interface
// `*management.DatasourceService` satisfies structurally), and interface satisfaction is by TYPE
// IDENTITY. A second structurally-identical struct anywhere would compile and then fail to satisfy.
// The declaration sits in the leaf package so internal/datasource can reach it without importing
// internal/policy; see types/management.go.
//
// The id-keyed variants in management_crud.go return a bare error instead, because their REST routes
// answer 204 and discard the body — that asymmetry is the Kotlin's too.
//
// ⚠️ `deleted: false` is a SUCCESS. A name-keyed delete that matched no row still commits and still
// answers 200 with this body; only the paths that resolve the row first can 404.
type DeleteResult = types.DeleteResult

// ---- Cedar policies: name-keyed --------------------------------------------------------------

// GetPolicyByName is `fun getPolicy(name): CedarPolicy` (ManagementServices.kt:214).
func (m *PolicyManagement) GetPolicyByName(ctx context.Context, name string) (CedarPolicy, error) {
	return m.GetPolicyByNameOn(ctx, m.store.DB(), name)
}

// GetPolicyByNameOn is `fun getPolicy(name, c)` (ManagementServices.kt:216).
//
// ⚠️ Neither overload calls `required("name", name)` — a blank name is a plain 404, not a 400. The
// mutating name-keyed methods below all DO require it. Reproduced as-is.
func (m *PolicyManagement) GetPolicyByNameOn(
	ctx context.Context, c store.Queryer, name string,
) (CedarPolicy, error) {
	row, err := m.policies.GetByNameOn(ctx, c, name)
	if err != nil {
		return CedarPolicy{}, err
	}
	if row == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	return *row, nil
}

// CreatePolicyByName is `fun createPolicy(name, cedarSrc, enabled, principal)`
// (ManagementServices.kt:239).
//
// 🔒 INV-A11-31 — `markCommittedMutation()` runs AFTER the transaction commits, never inside it.
// [CedarPolicyStore.Bump] is that call. Bumping inside would publish a cache invalidation for a
// rollback that never happened, and the shared engine would rebuild its PolicySet from rows that no
// longer exist and then never rebuild again.
func (m *PolicyManagement) CreatePolicyByName(
	ctx context.Context, name, cedarSrc string, enabled bool, principal *string,
) (CedarPolicy, error) {
	created, err := store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (CedarPolicy, error) {
		return m.CreatePolicyByNameOn(ctx, tx, name, cedarSrc, enabled, principal)
	})
	if err != nil {
		return CedarPolicy{}, err
	}
	m.policies.Bump()
	return created, nil
}

// CreatePolicyByNameOn is `fun createPolicy(name, cedarSrc, enabled, principal, c)`
// (ManagementServices.kt:245). It does NOT bump — its caller owns the transaction and must bump once
// the OUTER one commits.
func (m *PolicyManagement) CreatePolicyByNameOn(
	ctx context.Context, c store.Queryer, name, cedarSrc string, enabled bool, principal *string,
) (CedarPolicy, error) {
	if err := managementRequired("name", name); err != nil {
		return CedarPolicy{}, err
	}
	if err := managementRequired("cedarSrc", cedarSrc); err != nil {
		return CedarPolicy{}, err
	}
	created, err := m.policies.CreateOn(ctx, c, CedarPolicyInput{Name: name, CedarSrc: cedarSrc, Enabled: enabled}, principal)
	if err != nil {
		return CedarPolicy{}, mapPolicyErrors(err, &name)
	}
	return created, nil
}

// UpdatePolicyByName is `fun updatePolicy(currentName, newName, cedarSrc, enabled, principal)`
// (ManagementServices.kt:251).
func (m *PolicyManagement) UpdatePolicyByName(
	ctx context.Context, currentName string, newName *string, cedarSrc string, enabled bool, principal *string,
) (CedarPolicy, error) {
	updated, err := store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (CedarPolicy, error) {
		return m.UpdatePolicyByNameOn(ctx, tx, currentName, newName, cedarSrc, enabled, principal)
	})
	if err != nil {
		return CedarPolicy{}, err
	}
	m.policies.Bump()
	return updated, nil
}

// UpdatePolicyByNameOn is `fun updatePolicy(currentName, newName, cedarSrc, enabled, principal, c)`
// (ManagementServices.kt:281).
//
// ⚠️ `newName ?: current.name` — the fallback reads the RESOLVED ROW's name, not `currentName`. The
// two are equal in every reachable case, and the difference is reproduced rather than collapsed
// because it is what the Kotlin wrote.
func (m *PolicyManagement) UpdatePolicyByNameOn(
	ctx context.Context, c store.Queryer,
	currentName string, newName *string, cedarSrc string, enabled bool, principal *string,
) (CedarPolicy, error) {
	if err := managementRequired("name", currentName); err != nil {
		return CedarPolicy{}, err
	}
	if err := managementRequired("cedarSrc", cedarSrc); err != nil {
		return CedarPolicy{}, err
	}
	current, err := m.policies.GetByNameOn(ctx, c, currentName)
	if err != nil {
		return CedarPolicy{}, err
	}
	if current == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	target := current.Name
	if newName != nil {
		target = *newName
	}
	if err := managementRequired("newName", target); err != nil {
		return CedarPolicy{}, err
	}
	updated, err := m.policies.UpdateOn(ctx, c, current.ID,
		CedarPolicyInput{Name: target, CedarSrc: cedarSrc, Enabled: enabled}, principal)
	if err != nil {
		return CedarPolicy{}, mapPolicyErrors(err, &target)
	}
	if updated == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	return *updated, nil
}

// SetPolicyEnabledByName is `fun setPolicyEnabled(name, enabled, principal)`
// (ManagementServices.kt:300).
func (m *PolicyManagement) SetPolicyEnabledByName(
	ctx context.Context, name string, enabled bool, principal *string,
) (CedarPolicy, error) {
	updated, err := store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (CedarPolicy, error) {
		return m.SetPolicyEnabledByNameOn(ctx, tx, name, enabled, principal)
	})
	if err != nil {
		return CedarPolicy{}, err
	}
	m.policies.Bump()
	return updated, nil
}

// SetPolicyEnabledByNameOn is `fun setPolicyEnabled(name, enabled, principal, c)`
// (ManagementServices.kt:315).
//
// 🔒 The ENABLE direction can fail INV-A2-21's revalidate-on-enable, which mapPolicyErrors turns into
// the `{errors: […]}` body — the same shape a create or update rejection produces.
func (m *PolicyManagement) SetPolicyEnabledByNameOn(
	ctx context.Context, c store.Queryer, name string, enabled bool, principal *string,
) (CedarPolicy, error) {
	if err := managementRequired("name", name); err != nil {
		return CedarPolicy{}, err
	}
	current, err := m.policies.GetByNameOn(ctx, c, name)
	if err != nil {
		return CedarPolicy{}, err
	}
	if current == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	toggled, err := m.policies.SetEnabledOn(ctx, c, current.ID, enabled, principal)
	if err != nil {
		return CedarPolicy{}, mapPolicyErrors(err, nil)
	}
	if toggled == nil {
		return CedarPolicy{}, managementNotFound(ResourcePolicy)
	}
	return *toggled, nil
}

// DeletePolicyByName is `fun deletePolicy(name): DeleteResult` (ManagementServices.kt:321).
//
// 🔒 INV-A11-31, second half — this one bumps ONLY WHEN A ROW WAS ACTUALLY DELETED. The other three
// mutations bump unconditionally. The difference is cited per-method in the area doc and is
// reproduced literally.
func (m *PolicyManagement) DeletePolicyByName(ctx context.Context, name string) (DeleteResult, error) {
	out, err := store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return m.DeletePolicyByNameOn(ctx, tx, name)
	})
	if err != nil {
		return DeleteResult{}, err
	}
	if out.Deleted {
		m.policies.Bump()
	}
	return out, nil
}

// DeletePolicyByNameOn is `fun deletePolicy(name, c): DeleteResult` (ManagementServices.kt:340).
//
// ⚠️ It catches ONLY SystemPolicyImmutableException, not the full mapPolicyErrors set — a delete
// cannot fail validation or hit a unique constraint. Reproduced narrowly rather than widened to
// mapPolicyErrors, which would change nothing today and silently swallow a future 23505.
func (m *PolicyManagement) DeletePolicyByNameOn(
	ctx context.Context, c store.Queryer, name string,
) (DeleteResult, error) {
	if err := managementRequired("name", name); err != nil {
		return DeleteResult{}, err
	}
	current, err := m.policies.GetByNameOn(ctx, c, name)
	if err != nil {
		return DeleteResult{}, err
	}
	if current == nil {
		return DeleteResult{}, managementNotFound(ResourcePolicy)
	}
	deleted, err := m.policies.DeleteOn(ctx, c, current.ID)
	if err != nil {
		return DeleteResult{}, mapSystemPolicyImmutable(err)
	}
	return DeleteResult{Deleted: deleted}, nil
}

// mapSystemPolicyImmutable is `catch (_: SystemPolicyImmutableException)` on its own — the delete
// paths' single-arm subset of mapPolicyErrors.
func mapSystemPolicyImmutable(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSystemPolicyImmutable) {
		return &ManagementError{Err: types.ApiError{Code: "policy.system_immutable"}}
	}
	return err
}

// ---- Roles: name-keyed, and 🔒 INV-A11-30's other two call sites -------------------------------

// GetRoleByName is `fun getRole(name): Role` (ManagementServices.kt:227).
func (m *PolicyManagement) GetRoleByName(ctx context.Context, name string) (Role, error) {
	return m.GetRoleByNameManaged(ctx, m.store.DB(), name)
}

// GetRoleByNameManaged is `fun getRole(name, c)` (ManagementServices.kt:228). The awkward name is
// forced: [PolicyStore.GetRoleByNameOn] is the STORE's read and this is the management wrapper that
// turns nil into `common.not_found{resource: role}`.
func (m *PolicyManagement) GetRoleByNameManaged(
	ctx context.Context, c store.Queryer, name string,
) (Role, error) {
	role, err := m.store.GetRoleByNameOn(ctx, c, name)
	if err != nil {
		return Role{}, err
	}
	if role == nil {
		return Role{}, managementNotFound(ResourceRole)
	}
	return *role, nil
}

// CreateRoleByName is `fun createRole(name, description): Role` (ManagementServices.kt:350).
func (m *PolicyManagement) CreateRoleByName(ctx context.Context, name string, description *string) (Role, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (Role, error) {
		return m.CreateRoleByNameOn(ctx, tx, name, description)
	})
}

// CreateRoleByNameOn is `fun createRole(name, description, c)` (ManagementServices.kt:352).
func (m *PolicyManagement) CreateRoleByNameOn(
	ctx context.Context, c store.Queryer, name string, description *string,
) (Role, error) {
	if err := managementRequired("name", name); err != nil {
		return Role{}, err
	}
	created, err := m.store.CreateRoleOn(ctx, c, RoleInput{Name: name, Description: description})
	if err != nil {
		if store.IsUniqueViolation(err) {
			return Role{}, managementAlreadyExists(ResourceRole, &name)
		}
		return Role{}, err
	}
	return created, nil
}

// UpdateRoleByName is `fun updateRole(currentName, newName, description): Role`
// (ManagementServices.kt:357).
func (m *PolicyManagement) UpdateRoleByName(
	ctx context.Context, currentName string, newName, description *string,
) (Role, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (Role, error) {
		return m.UpdateRoleByNameOn(ctx, tx, currentName, newName, description)
	})
}

// UpdateRoleByNameOn is `fun updateRole(currentName, newName, description, c)`
// (ManagementServices.kt:367) — 🔒 INV-A11-30's SECOND call site (ManagementServices.kt:370).
//
// 🔒 F6 was raised because `Policies.kt` declares `isSystemRole` and never calls it; A11 closed it by
// finding all FOUR call sites here — :362 and :382 are the id-keyed pair in management_crud.go, :370
// and :389 are this method and [PolicyManagement.DeleteRoleByNameOn]. Without the guard a system
// role (one granted by a `source='SYSTEM'` group, e.g. `system:admin`) is renameable through the
// API, and renaming it silently detaches every Cedar policy that names it — the policies keep
// referring to a role nothing grants any more, so every decision that depended on it starts denying.
//
// 🔒 INV-A9-1 — "system role" is DERIVED, not a column: the guard asks whether any `source='SYSTEM'`
// group grants this role, so a role STOPS being protected the moment the last SYSTEM group mapping
// is removed. Do not add an `app_role.is_system` column; that would change the semantics.
//
// The order is the Kotlin's: required(name) ⇒ resolve/404 ⇒ 🔒 SYSTEM/409 ⇒ required(newName) ⇒
// unique. A SYSTEM role renamed to blank answers `role.system_immutable`, not
// `common.field_required`.
//
// ⚠️ The guard and the update share ONE transaction but NOT one lock: `isSystemRole` reads
// `group_role`/`app_group`, not `app_role`, so there is no single row for a `SELECT … FOR UPDATE` —
// unlike A11's group paths (INV-A11-32). A concurrent SYSTEM mapping insert can still race a rename.
// REPRODUCE; closing it needs a lock the Kotlin does not take.
func (m *PolicyManagement) UpdateRoleByNameOn(
	ctx context.Context, c store.Queryer, currentName string, newName, description *string,
) (Role, error) {
	if err := managementRequired("name", currentName); err != nil {
		return Role{}, err
	}
	current, err := m.store.GetRoleByNameOn(ctx, c, currentName)
	if err != nil {
		return Role{}, err
	}
	if current == nil {
		return Role{}, managementNotFound(ResourceRole)
	}
	system, err := m.store.IsSystemRoleOn(ctx, c, current.ID)
	if err != nil {
		return Role{}, err
	}
	if system {
		return Role{}, roleSystemImmutable()
	}
	target := currentName
	if newName != nil {
		target = *newName
	}
	if err := managementRequired("newName", target); err != nil {
		return Role{}, err
	}
	updated, err := m.store.UpdateRoleOn(ctx, c, current.ID, RoleInput{Name: target, Description: description})
	if err != nil {
		if store.IsUniqueViolation(err) {
			return Role{}, managementAlreadyExists(ResourceRole, &target)
		}
		return Role{}, err
	}
	if updated == nil {
		return Role{}, managementNotFound(ResourceRole)
	}
	return *updated, nil
}

// DeleteRoleByName is `fun deleteRole(name): DeleteResult` (ManagementServices.kt:378).
func (m *PolicyManagement) DeleteRoleByName(ctx context.Context, name string) (DeleteResult, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return m.DeleteRoleByNameOn(ctx, tx, name)
	})
}

// DeleteRoleByNameOn is `fun deleteRole(name, c): DeleteResult` (ManagementServices.kt:386) —
// 🔒 INV-A11-30's FOURTH call site (ManagementServices.kt:389).
//
// ⚠️ Deleting a role that IS deletable cascades: `principal_role.role_id` and `group_role.role_id`
// are both `ON DELETE CASCADE` (V1__identity.sql:52,62), so every direct assignment and every group
// mapping goes with it, silently. That is why the SYSTEM guard matters more on delete than on
// rename.
func (m *PolicyManagement) DeleteRoleByNameOn(
	ctx context.Context, c store.Queryer, name string,
) (DeleteResult, error) {
	if err := managementRequired("name", name); err != nil {
		return DeleteResult{}, err
	}
	current, err := m.store.GetRoleByNameOn(ctx, c, name)
	if err != nil {
		return DeleteResult{}, err
	}
	if current == nil {
		return DeleteResult{}, managementNotFound(ResourceRole)
	}
	system, err := m.store.IsSystemRoleOn(ctx, c, current.ID)
	if err != nil {
		return DeleteResult{}, err
	}
	if system {
		return DeleteResult{}, roleSystemImmutable()
	}
	deleted, err := m.store.DeleteRoleOn(ctx, c, current.ID)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: deleted}, nil
}

// ---- Role assignments: name-keyed ---------------------------------------------------------------

// ListAssignmentsByRoleName is `fun listAssignments(principal?, roleName?)`
// (ManagementServices.kt:230).
//
// ⚠️ An unknown roleName is `common.not_found{resource: role}` (404), NOT an empty list. Filtering by
// a role that does not exist is a caller error, not a query that legitimately matched nothing.
func (m *PolicyManagement) ListAssignmentsByRoleName(
	ctx context.Context, principal, roleName *string,
) ([]RoleAssignment, error) {
	var roleID *int64
	if roleName != nil {
		role, err := m.store.GetRoleByName(ctx, *roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, managementNotFound(ResourceRole)
		}
		roleID = &role.ID
	}
	return m.ListAssignments(ctx, principal, roleID)
}

// AssignRoleByName is `fun assignRole(principal, roleName): RoleAssignment`
// (ManagementServices.kt:393).
func (m *PolicyManagement) AssignRoleByName(
	ctx context.Context, principal, roleName string,
) (RoleAssignment, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (RoleAssignment, error) {
		return m.AssignRoleByNameOn(ctx, tx, principal, roleName)
	})
}

// AssignRoleByNameOn is `fun assignRole(principal, roleName, c)` (ManagementServices.kt:401).
//
// 🔒 INV-A9-2 — the store's `ON CONFLICT (principal, role_id) DO UPDATE … RETURNING id` makes this
// IDEMPOTENT: re-assigning an existing pair returns the EXISTING row's id, not a conflict. There is
// no `unique(...)` wrapper here and there must not be one.
func (m *PolicyManagement) AssignRoleByNameOn(
	ctx context.Context, c store.Queryer, principal, roleName string,
) (RoleAssignment, error) {
	if err := managementRequired("principal", principal); err != nil {
		return RoleAssignment{}, err
	}
	if err := managementRequired("roleName", roleName); err != nil {
		return RoleAssignment{}, err
	}
	role, err := m.store.GetRoleByNameOn(ctx, c, roleName)
	if err != nil {
		return RoleAssignment{}, err
	}
	if role == nil {
		return RoleAssignment{}, managementNotFound(ResourceRole)
	}
	return m.store.CreateAssignmentOn(ctx, c, RoleAssignmentInput{Principal: principal, RoleID: role.ID})
}

// AssignRoleByID is `fun assignRole(principal, roleId): RoleAssignment`
// (ManagementServices.kt:395).
//
// ⚠️ Unlike [PolicyManagement.CreateAssignment] — the raw id-keyed REST method in
// management_crud.go, which has no existence check and lets an unknown role id reach the FK as a
// 23503/500 — this overload DOES resolve the role first and answers 404. Two id-keyed assignment
// paths with different answers for the same bad input is the Kotlin's, and both are reproduced.
func (m *PolicyManagement) AssignRoleByID(
	ctx context.Context, principal string, roleID int64,
) (RoleAssignment, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (RoleAssignment, error) {
		if err := managementRequired("principal", principal); err != nil {
			return RoleAssignment{}, err
		}
		role, err := m.store.GetRoleOn(ctx, tx, roleID)
		if err != nil {
			return RoleAssignment{}, err
		}
		if role == nil {
			return RoleAssignment{}, managementNotFound(ResourceRole)
		}
		return m.store.CreateAssignmentOn(ctx, tx, RoleAssignmentInput{Principal: principal, RoleID: roleID})
	})
}

// UnassignRoleByName is `fun unassignRole(principal, roleName): DeleteResult`
// (ManagementServices.kt:441).
func (m *PolicyManagement) UnassignRoleByName(
	ctx context.Context, principal, roleName string,
) (DeleteResult, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return m.UnassignRoleByNameOn(ctx, tx, principal, roleName)
	})
}

// UnassignRoleByNameOn is `fun unassignRole(principal, roleName, c)` (ManagementServices.kt:451) —
// keyed on the PAIR, not on the assignment id.
func (m *PolicyManagement) UnassignRoleByNameOn(
	ctx context.Context, c store.Queryer, principal, roleName string,
) (DeleteResult, error) {
	if err := managementRequired("principal", principal); err != nil {
		return DeleteResult{}, err
	}
	if err := managementRequired("roleName", roleName); err != nil {
		return DeleteResult{}, err
	}
	role, err := m.store.GetRoleByNameOn(ctx, c, roleName)
	if err != nil {
		return DeleteResult{}, err
	}
	if role == nil {
		return DeleteResult{}, managementNotFound(ResourceRole)
	}
	deleted, err := m.store.DeleteAssignmentByPrincipalRoleOn(ctx, c, principal, role.ID)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: deleted}, nil
}

// UnassignRoleByID is `fun unassignRole(id): DeleteResult` (ManagementServices.kt:443) — resolve
// first so an unknown id is 404 rather than `deleted: false`.
func (m *PolicyManagement) UnassignRoleByID(ctx context.Context, id int64) (DeleteResult, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		existing, err := m.store.GetAssignmentOn(ctx, tx, id)
		if err != nil {
			return DeleteResult{}, err
		}
		if existing == nil {
			return DeleteResult{}, managementNotFound(ResourceRoleAssignment)
		}
		deleted, err := m.store.DeleteAssignmentOn(ctx, tx, id)
		if err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{Deleted: deleted}, nil
	})
}

// ---- Mask functions: name-keyed -----------------------------------------------------------------

// GetMaskFnByName is `fun getMaskFn(name): MaskFn` (ManagementServices.kt:236).
func (m *PolicyManagement) GetMaskFnByName(ctx context.Context, name string) (MaskFn, error) {
	return m.GetMaskFnByNameManaged(ctx, m.store.DB(), name)
}

// GetMaskFnByNameManaged is `fun getMaskFn(name, c)` (ManagementServices.kt:237).
func (m *PolicyManagement) GetMaskFnByNameManaged(
	ctx context.Context, c store.Queryer, name string,
) (MaskFn, error) {
	fn, err := m.store.GetMaskFnByNameOn(ctx, c, name)
	if err != nil {
		return MaskFn{}, err
	}
	if fn == nil {
		return MaskFn{}, managementNotFound(ResourceMaskFn)
	}
	return *fn, nil
}

// CreateMaskFnOn is `fun createMaskFn(input, c): MaskFn` (ManagementServices.kt:460).
func (m *PolicyManagement) CreateMaskFnOn(
	ctx context.Context, c store.Queryer, input MaskFnInput,
) (MaskFn, error) {
	if err := managementRequired("name", input.Name); err != nil {
		return MaskFn{}, err
	}
	if err := managementRequired("kind", input.Kind); err != nil {
		return MaskFn{}, err
	}
	created, err := m.store.CreateMaskFnOn(ctx, c, input)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return MaskFn{}, managementAlreadyExists(ResourceMaskFn, &input.Name)
		}
		return MaskFn{}, err
	}
	return created, nil
}

// UpdateMaskFnByName is `fun updateMaskFn(currentName, input): MaskFn`
// (ManagementServices.kt:466).
func (m *PolicyManagement) UpdateMaskFnByName(
	ctx context.Context, currentName string, input MaskFnInput,
) (MaskFn, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (MaskFn, error) {
		return m.UpdateMaskFnByNameOn(ctx, tx, currentName, input)
	})
}

// UpdateMaskFnByNameOn is `fun updateMaskFn(currentName, input, c)` (ManagementServices.kt:475).
//
// ⚠️ The blank-name failure here reports the field as **newName**, while the id-keyed overload
// reports it as **name** for the same input field (ManagementServices.kt:471 vs :478). Two spellings
// of one validation, both on the wire as `{fields}`. REPRODUCE.
func (m *PolicyManagement) UpdateMaskFnByNameOn(
	ctx context.Context, c store.Queryer, currentName string, input MaskFnInput,
) (MaskFn, error) {
	if err := managementRequired("name", currentName); err != nil {
		return MaskFn{}, err
	}
	current, err := m.store.GetMaskFnByNameOn(ctx, c, currentName)
	if err != nil {
		return MaskFn{}, err
	}
	if current == nil {
		return MaskFn{}, managementNotFound(ResourceMaskFn)
	}
	if err := managementRequired("newName", input.Name); err != nil {
		return MaskFn{}, err
	}
	if err := managementRequired("kind", input.Kind); err != nil {
		return MaskFn{}, err
	}
	updated, err := m.store.UpdateMaskFnOn(ctx, c, current.ID, input)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return MaskFn{}, managementAlreadyExists(ResourceMaskFn, &input.Name)
		}
		return MaskFn{}, err
	}
	if updated == nil {
		return MaskFn{}, managementNotFound(ResourceMaskFn)
	}
	return *updated, nil
}

// DeleteMaskFnByName is `fun deleteMaskFn(name): DeleteResult` (ManagementServices.kt:483).
func (m *PolicyManagement) DeleteMaskFnByName(ctx context.Context, name string) (DeleteResult, error) {
	return store.InTx(ctx, m.store.DB(), func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return m.DeleteMaskFnByNameOn(ctx, tx, name)
	})
}

// DeleteMaskFnByNameOn is `fun deleteMaskFn(name, c)` (ManagementServices.kt:490).
func (m *PolicyManagement) DeleteMaskFnByNameOn(
	ctx context.Context, c store.Queryer, name string,
) (DeleteResult, error) {
	if err := managementRequired("name", name); err != nil {
		return DeleteResult{}, err
	}
	current, err := m.store.GetMaskFnByNameOn(ctx, c, name)
	if err != nil {
		return DeleteResult{}, err
	}
	if current == nil {
		return DeleteResult{}, managementNotFound(ResourceMaskFn)
	}
	deleted, err := m.store.DeleteMaskFnOn(ctx, c, current.ID)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: deleted}, nil
}
