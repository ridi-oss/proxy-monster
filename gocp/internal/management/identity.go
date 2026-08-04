package management

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/identity"
	"github.com/ridi-oss/proxy-monster/gocp/internal/policy"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// `IdentityManagementService` — ManagementServices.kt:513-714.
// ---------------------------------------------------------------------------------------------

// Credentials is `Deprovision.kt`'s `revokeActiveCredentialsTx(principal, c, tokenStore, accessStore,
// daemonSessionStore)` (Deprovision.kt:70) as ONE seam, rather than three store fields threaded
// through every write.
//
// The Kotlin passes the three stores individually because `UserGroupStore.createUser` /
// `updateUser` / `deleteUser` each call the free function with them. Collapsing them to the function
// they are only ever passed to changes nothing observable and keeps this package from importing
// internal/token, internal/access and internal/session for three method references.
//
//	TODO(A3): the concrete implementation belongs next to the rest of Deprovision.kt.
type Credentials interface {
	// RevokeActiveCredentialsOn kills every currently-active credential for principal — wire tokens,
	// JIT access grants, daemon session windows and web sessions — on the CALLER's transaction, under
	// the per-principal advisory lock it takes itself. Returns the total revoked.
	RevokeActiveCredentialsOn(ctx context.Context, c store.Queryer, principal string) (int64, error)
}

// GroupRolesResult is `@Serializable data class GroupRolesResult(group, roleNames)`
// (ManagementServices.kt:511) — what `setGroupRoles` returns.
type GroupRolesResult struct {
	Group string `json:"group"`
	// RoleNames is the RE-READ list, in `ORDER BY r.name` order; `[]`, never null.
	RoleNames []string `json:"roleNames"`
}

// MarshalJSON normalises RoleNames to `[]` rather than `null` — INV-A1-4. A group whose roles were
// all removed answers `{"group":"x","roleNames":[]}`, and a console that got `null` there would
// render "no data" instead of "no roles".
func (r GroupRolesResult) MarshalJSON() ([]byte, error) {
	type alias GroupRolesResult
	a := alias(r)
	if a.RoleNames == nil {
		a.RoleNames = []string{}
	}
	return types.MarshalWire(a)
}

// IdentityService is
// `class IdentityManagementService(dataSource, store, policyStore, tokenStore, accessStore, daemonSessionStore)`
// (ManagementServices.kt:513).
//
// ⚠️ credentials may be nil, and the group surface — where all three of INV-A11-32's guards live —
// never touches it. But the USER surface does: a nil there makes every create-inactive, rename and
// deprovision commit its directory write with NO credential teardown, which is INV-A3-6's failure
// mode. Production wiring must pass the real identity.Credentials.
type IdentityService struct {
	db          store.DB
	store       *identity.UserGroupStore
	policies    *policy.PolicyStore
	credentials Credentials
}

// 🔒 Compile-time proof that this service is what A3's fourteen admin routes bind to. The route
// group declares `identity.Management` — a narrow interface — because internal/management imports
// internal/identity and the reverse would be a cycle. This assertion is what keeps the two in step:
// drop a method here and the ROUTES stop compiling, which is the failure everyone wants.
var _ identity.Management = (*IdentityService)(nil)

// NewIdentityService is the constructor. The argument order is the Kotlin's, with its three
// credential stores collapsed into [Credentials].
func NewIdentityService(
	db store.DB, s *identity.UserGroupStore, policies *policy.PolicyStore, credentials Credentials,
) *IdentityService {
	return &IdentityService{db: db, store: s, policies: policies, credentials: credentials}
}

// ---- Reads --------------------------------------------------------------------------------------

// ListUsers is `fun listUsers(): List<AppUser>`.
func (s *IdentityService) ListUsers(ctx context.Context) ([]identity.AppUser, error) {
	return s.store.ListUsers(ctx)
}

// ListGroups is `fun listGroups(): List<AppGroup>`.
func (s *IdentityService) ListGroups(ctx context.Context) ([]identity.AppGroup, error) {
	return s.store.ListGroups(ctx)
}

// GetUser is `fun getUser(principal): AppUser` — `notFound("user")` when absent.
func (s *IdentityService) GetUser(ctx context.Context, principal string) (identity.AppUser, error) {
	return s.GetUserOn(ctx, s.db, principal)
}

// GetUserOn is `fun getUser(principal, c)`.
func (s *IdentityService) GetUserOn(
	ctx context.Context, c store.Queryer, principal string,
) (identity.AppUser, error) {
	user, err := s.store.GetUserByPrincipalOn(ctx, c, principal)
	if err != nil {
		return identity.AppUser{}, err
	}
	if user == nil {
		return identity.AppUser{}, NotFound(ResourceUser)
	}
	return *user, nil
}

// GetGroup is `fun getGroup(name): AppGroup` — `notFound("group")` when absent.
func (s *IdentityService) GetGroup(ctx context.Context, name string) (identity.AppGroup, error) {
	return s.GetGroupOn(ctx, s.db, name)
}

// GetGroupOn is `fun getGroup(name, c)` — and `private fun group(name, c)`, which is the same
// lookup under a different name (ManagementServices.kt:526,701). Two Kotlin declarations, one
// behaviour; the duplication is not observable, so one function serves both.
func (s *IdentityService) GetGroupOn(
	ctx context.Context, c store.Queryer, name string,
) (identity.AppGroup, error) {
	group, err := s.store.GetGroupByNameOn(ctx, c, name)
	if err != nil {
		return identity.AppGroup{}, err
	}
	if group == nil {
		return identity.AppGroup{}, NotFound(ResourceGroup)
	}
	return *group, nil
}

// ---- Users: writes ------------------------------------------------------------------------------

// The three methods below were reserved as `ErrUserWritesNotPorted` stubs until A3's
// principal-mutating writes existed, because writing a second, A11-side version of
// `lockCurrentPrincipal` / `releaseTombstone` / `deactivatePrincipalTombstone` would have been "a
// security guard written outside the area that owns it". They now delegate to
// internal/identity, which is where that ordering lives.
//
// Each is one line of management logic — `required`, `unique`, `notFound` — wrapped around ONE store
// call inside ONE transaction. The transaction boundary is the management layer's, not the store's:
// the `…On` store overloads exist precisely so the validation and the write share it.
//
//	TODO(A11): the NAME-KEYED overloads `updateUser(currentPrincipal, newPrincipal, …)`
//	           (ManagementServices.kt:544) and their MCP tool call sites. A3's fourteen REST routes
//	           use only the id-keyed forms, so they are not needed to close the route table.

// CreateUser is `fun createUser(input): AppUser` (ManagementServices.kt:529).
//
// ⚠️ The `unique` resource literal is `principal`, NOT `user` — `unique("principal", …)` and
// `notFound("user")` are two different call sites and reach the console as two different i18n keys.
// See [ResourcePrincipal].
func (s *IdentityService) CreateUser(
	ctx context.Context, input identity.AppUserInput,
) (identity.AppUser, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.AppUser, error) {
		return s.CreateUserOn(ctx, tx, input)
	})
}

// CreateUserOn is `fun createUser(input, c)` (ManagementServices.kt:531).
//
// 🔒 A blank principal is rejected BEFORE the store is reached, so an `app_user` row on the empty
// string cannot be created — and, because `createUser(active=false)` revokes that principal's
// credentials (INV-A3-18), a blank one would have torn down every credential keyed on "".
func (s *IdentityService) CreateUserOn(
	ctx context.Context, c store.Queryer, input identity.AppUserInput,
) (identity.AppUser, error) {
	if err := Required("principal", input.Principal); err != nil {
		return identity.AppUser{}, err
	}
	created, err := s.store.CreateUserOn(ctx, c, input, s.credentials)
	if err != nil {
		return identity.AppUser{}, Unique(err, ResourcePrincipal, &input.Principal)
	}
	return created, nil
}

// UpdateUser is `fun updateUser(id, input): AppUser` (ManagementServices.kt:551) — the id-keyed REST
// overload.
//
// The order is the Kotlin's: existence ⇒ 404, THEN `required("principal")` ⇒ 400, THEN the write.
// ⚠️ Unlike the group overload there is NO system guard here — `app_user` has no immutable rows; the
// seeded SYSTEM rows are all groups.
func (s *IdentityService) UpdateUser(
	ctx context.Context, id int64, input identity.AppUserInput,
) (identity.AppUser, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.AppUser, error) {
		existing, err := s.store.GetUserOn(ctx, tx, id)
		if err != nil {
			return identity.AppUser{}, err
		}
		if existing == nil {
			return identity.AppUser{}, NotFound(ResourceUser)
		}
		if err := Required("principal", input.Principal); err != nil {
			return identity.AppUser{}, err
		}
		updated, err := s.store.UpdateUserOn(ctx, tx, id, input, s.credentials)
		if err != nil {
			return identity.AppUser{}, Unique(err, ResourcePrincipal, &input.Principal)
		}
		if updated == nil {
			return identity.AppUser{}, NotFound(ResourceUser)
		}
		return *updated, nil
	})
}

// UpdateUserByPrincipal is `fun updateUser(currentPrincipal, newPrincipal, displayName, email,
// active): AppUser` (ManagementServices.kt:537) — the NAME-KEYED overload, discharging this file's
// `TODO(A11)`. Its only caller is the MCP `update_user` tool; A3's fourteen REST routes use
// [IdentityService.UpdateUser], the id-keyed form.
func (s *IdentityService) UpdateUserByPrincipal(
	ctx context.Context, currentPrincipal string, newPrincipal, displayName, email *string, active bool,
) (identity.AppUser, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.AppUser, error) {
		return s.UpdateUserByPrincipalOn(ctx, tx, currentPrincipal, newPrincipal, displayName, email, active)
	})
}

// UpdateUserByPrincipalOn is `fun updateUser(currentPrincipal, newPrincipal, displayName, email,
// active, c)` (ManagementServices.kt:544).
//
// The order is the Kotlin's and every step is observable:
//
//  1. `required("principal", currentPrincipal)` — 400 BEFORE the lookup, so a blank principal is a
//     field error rather than a 404.
//  2. resolve by principal ⇒ `notFound("user")`.
//  3. ⚠️ `targetPrincipal = newPrincipal ?: currentPrincipal` — OMITTING newPrincipal is a rename to
//     the SAME principal, not "leave the principal alone". Observably identical, but it means
//     `required("newPrincipal")` can only fire for an EXPLICITLY BLANK newPrincipal, since
//     currentPrincipal was already required non-blank one step earlier.
//  4. 🔒 The write goes to the ID resolved in step 2, never to the principal string. The store then
//     re-reads that row's CURRENT principal under the per-principal advisory lock, so a concurrent
//     rename cannot make this update land on a different identity than the one it read.
//  5. 23505 ⇒ `common.already_exists{resource: principal}` — the `unique` resource literal is
//     `principal`, NOT `user`, matching [IdentityService.CreateUserOn].
//
// ⚠️ Unlike the group overloads there is NO system guard: `app_user` has no immutable rows.
//
// ⚠️ `displayName` and `email` are POINTERS and a nil one CLEARS the column — the MCP tool decides
// between "clear" and "preserve" before it gets here, using INV-A11-17's has()/string() pair. This
// layer cannot tell the two apart and must not try.
func (s *IdentityService) UpdateUserByPrincipalOn(
	ctx context.Context, c store.Queryer,
	currentPrincipal string, newPrincipal, displayName, email *string, active bool,
) (identity.AppUser, error) {
	if err := Required("principal", currentPrincipal); err != nil {
		return identity.AppUser{}, err
	}
	current, err := s.store.GetUserByPrincipalOn(ctx, c, currentPrincipal)
	if err != nil {
		return identity.AppUser{}, err
	}
	if current == nil {
		return identity.AppUser{}, NotFound(ResourceUser)
	}
	targetPrincipal := currentPrincipal
	if newPrincipal != nil {
		targetPrincipal = *newPrincipal
	}
	if err := Required("newPrincipal", targetPrincipal); err != nil {
		return identity.AppUser{}, err
	}
	input := identity.AppUserInput{
		Principal: targetPrincipal, DisplayName: displayName, Email: email, Active: active,
	}
	updated, err := s.store.UpdateUserOn(ctx, c, current.ID, input, s.credentials)
	if err != nil {
		return identity.AppUser{}, Unique(err, ResourcePrincipal, &input.Principal)
	}
	if updated == nil {
		return identity.AppUser{}, NotFound(ResourceUser)
	}
	return *updated, nil
}

// DeprovisionUser is `fun deprovisionUser(principal): DeleteResult` (ManagementServices.kt:571) — the
// name-keyed MCP overload.
//
// 🔒 It never hard-deletes: [identity.UserGroupStore.DeleteUserOn] flips `active=false` and revokes
// the principal's credentials in the same transaction (INV-A3-19), so audit history keeps resolving
// the principal.
func (s *IdentityService) DeprovisionUser(ctx context.Context, principal string) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return s.DeprovisionUserOn(ctx, tx, principal)
	})
}

// DeprovisionUserOn is `fun deprovisionUser(principal, c)` (ManagementServices.kt:579).
func (s *IdentityService) DeprovisionUserOn(
	ctx context.Context, c store.Queryer, principal string,
) (DeleteResult, error) {
	if err := Required("principal", principal); err != nil {
		return DeleteResult{}, err
	}
	current, err := s.store.GetUserByPrincipalOn(ctx, c, principal)
	if err != nil {
		return DeleteResult{}, err
	}
	if current == nil {
		return DeleteResult{}, NotFound(ResourceUser)
	}
	deleted, err := s.store.DeleteUserOn(ctx, c, current.ID, s.credentials)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: deleted}, nil
}

// DeprovisionUserByID is `fun deprovisionUser(id: Long): DeleteResult`
// (ManagementServices.kt:573) — the overload `DELETE /api/users/{id}` calls.
//
// 🔒 ID-STABILITY IS THE POINT: it resolves by id and the store then re-reads the row's CURRENT
// principal under the advisory lock, so a rename that commits between the console rendering the list
// and the operator clicking delete still deprovisions the RIGHT identity.
// UserAdminDeprovisionDbTest case 9 is exactly that scenario.
//
// ⚠️ Note it does NOT call `required(...)` — there is no string to validate — and that its existence
// check is a separate statement from the store's own. Both reproduced.
func (s *IdentityService) DeprovisionUserByID(ctx context.Context, id int64) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		existing, err := s.store.GetUserOn(ctx, tx, id)
		if err != nil {
			return DeleteResult{}, err
		}
		if existing == nil {
			return DeleteResult{}, NotFound(ResourceUser)
		}
		deleted, err := s.store.DeleteUserOn(ctx, tx, id, s.credentials)
		if err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{Deleted: deleted}, nil
	})
}

// ---- Groups: writes, and guard #1 ---------------------------------------------------------------

// CreateGroup is `fun createGroup(input): AppGroup` (ManagementServices.kt:584).
//
// There is NO system guard on create: a new group is LOCAL by construction, and the name collision
// with a seeded SYSTEM group is caught by `app_group.name UNIQUE` as `common.already_exists`.
func (s *IdentityService) CreateGroup(
	ctx context.Context, input identity.AppGroupInput,
) (identity.AppGroup, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.AppGroup, error) {
		return s.CreateGroupOn(ctx, tx, input)
	})
}

// CreateGroupOn is `fun createGroup(input, c)`.
func (s *IdentityService) CreateGroupOn(
	ctx context.Context, c store.Queryer, input identity.AppGroupInput,
) (identity.AppGroup, error) {
	if err := Required("name", input.Name); err != nil {
		return identity.AppGroup{}, err
	}
	created, err := s.store.CreateGroupOn(ctx, c, input)
	if err != nil {
		return identity.AppGroup{}, Unique(err, ResourceGroup, &input.Name)
	}
	return created, nil
}

// UpdateGroupByID is `fun updateGroup(id, input): AppGroup` (ManagementServices.kt:594) — the
// id-keyed REST overload.
//
// 🔒 INV-A11-32, GUARD #1 (`rejectSystem`). The order is load-bearing and is the Kotlin's:
// resolve ⇒ 404, THEN reject SYSTEM ⇒ 409, THEN validate the name ⇒ 400. A SYSTEM group renamed to
// the empty string must answer `group.system_immutable`, not `common.field_required` — the caller
// has no business editing that row at all and telling them their name is blank invites a retry.
func (s *IdentityService) UpdateGroupByID(
	ctx context.Context, id int64, input identity.AppGroupInput,
) (identity.AppGroup, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.AppGroup, error) {
		current, err := s.store.GetGroupOn(ctx, tx, id)
		if err != nil {
			return identity.AppGroup{}, err
		}
		if current == nil {
			return identity.AppGroup{}, NotFound(ResourceGroup)
		}
		if err := s.rejectSystem(ctx, tx, current.ID); err != nil {
			return identity.AppGroup{}, err
		}
		if err := Required("name", input.Name); err != nil {
			return identity.AppGroup{}, err
		}
		updated, err := s.store.UpdateGroupOn(ctx, tx, id, input)
		if err != nil {
			return identity.AppGroup{}, Unique(err, ResourceGroup, &input.Name)
		}
		if updated == nil {
			return identity.AppGroup{}, NotFound(ResourceGroup)
		}
		return *updated, nil
	})
}

// UpdateGroupByName is `fun updateGroup(currentName, newName, description): AppGroup`
// (ManagementServices.kt:591) — the name-keyed MCP overload.
func (s *IdentityService) UpdateGroupByName(
	ctx context.Context, currentName string, newName, description *string,
) (identity.AppGroup, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.AppGroup, error) {
		return s.UpdateGroupByNameOn(ctx, tx, currentName, newName, description)
	})
}

// UpdateGroupByNameOn is `fun updateGroup(currentName, newName, description, c)`
// (ManagementServices.kt:601).
//
// ⚠️ `newName ?: currentName` — omitting newName is a rename to the SAME name, not "leave the name
// alone and only change the description". Observably identical here, but it means `required("newName")`
// can only fire for an explicitly-blank newName, since currentName was already required non-blank.
// Both `required` calls are reproduced anyway, in the Kotlin's order.
func (s *IdentityService) UpdateGroupByNameOn(
	ctx context.Context, c store.Queryer, currentName string, newName, description *string,
) (identity.AppGroup, error) {
	if err := Required("name", currentName); err != nil {
		return identity.AppGroup{}, err
	}
	current, err := s.GetGroupOn(ctx, c, currentName)
	if err != nil {
		return identity.AppGroup{}, err
	}
	if err := s.rejectSystem(ctx, c, current.ID); err != nil {
		return identity.AppGroup{}, err
	}
	target := currentName
	if newName != nil {
		target = *newName
	}
	if err := Required("newName", target); err != nil {
		return identity.AppGroup{}, err
	}
	updated, err := s.store.UpdateGroupOn(ctx, c, current.ID, identity.AppGroupInput{
		Name: target, Description: description,
	})
	if err != nil {
		return identity.AppGroup{}, Unique(err, ResourceGroup, &target)
	}
	if updated == nil {
		return identity.AppGroup{}, NotFound(ResourceGroup)
	}
	return *updated, nil
}

// DeleteGroupByID is `fun deleteGroup(id): DeleteResult` (ManagementServices.kt:614).
func (s *IdentityService) DeleteGroupByID(ctx context.Context, id int64) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		current, err := s.store.GetGroupOn(ctx, tx, id)
		if err != nil {
			return DeleteResult{}, err
		}
		if current == nil {
			return DeleteResult{}, NotFound(ResourceGroup)
		}
		if err := s.rejectSystem(ctx, tx, current.ID); err != nil {
			return DeleteResult{}, err
		}
		deleted, err := s.store.DeleteGroupOn(ctx, tx, id)
		if err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{Deleted: deleted}, nil
	})
}

// DeleteGroupByName is `fun deleteGroup(name): DeleteResult` (ManagementServices.kt:612).
func (s *IdentityService) DeleteGroupByName(ctx context.Context, name string) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return s.DeleteGroupByNameOn(ctx, tx, name)
	})
}

// DeleteGroupByNameOn is `fun deleteGroup(name, c): DeleteResult` (ManagementServices.kt:620).
func (s *IdentityService) DeleteGroupByNameOn(
	ctx context.Context, c store.Queryer, name string,
) (DeleteResult, error) {
	if err := Required("name", name); err != nil {
		return DeleteResult{}, err
	}
	current, err := s.GetGroupOn(ctx, c, name)
	if err != nil {
		return DeleteResult{}, err
	}
	if err := s.rejectSystem(ctx, c, current.ID); err != nil {
		return DeleteResult{}, err
	}
	deleted, err := s.store.DeleteGroupOn(ctx, c, current.ID)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: deleted}, nil
}

// ---- Members — also guard #1 --------------------------------------------------------------------

// AddGroupMemberByID is `fun addGroupMember(groupId, userId): GroupMemberEntry`
// (ManagementServices.kt:630).
//
// ⚠️ The Kotlin ends with `store.listMembers(groupId, c).first { it.userId == userId }` — a `first`
// with NO default, which throws NoSuchElementException if the member is somehow absent after the
// insert. Reproduced as an explicit error rather than a panic: the JVM's would surface as 500
// common.fallback, and so does this.
func (s *IdentityService) AddGroupMemberByID(
	ctx context.Context, groupID, userID int64,
) (identity.GroupMemberEntry, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.GroupMemberEntry, error) {
		group, err := s.store.GetGroupOn(ctx, tx, groupID)
		if err != nil {
			return identity.GroupMemberEntry{}, err
		}
		if group == nil {
			return identity.GroupMemberEntry{}, NotFound(ResourceGroup)
		}
		if err := s.rejectSystem(ctx, tx, group.ID); err != nil {
			return identity.GroupMemberEntry{}, err
		}
		user, err := s.store.GetUserOn(ctx, tx, userID)
		if err != nil {
			return identity.GroupMemberEntry{}, err
		}
		if user == nil {
			return identity.GroupMemberEntry{}, NotFound(ResourceUser)
		}
		return s.addMember(ctx, tx, groupID, userID)
	})
}

// AddGroupMemberByName is `fun addGroupMember(groupName, principal): GroupMemberEntry`
// (ManagementServices.kt:627).
func (s *IdentityService) AddGroupMemberByName(
	ctx context.Context, groupName, principal string,
) (identity.GroupMemberEntry, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.GroupMemberEntry, error) {
		return s.AddGroupMemberByNameOn(ctx, tx, groupName, principal)
	})
}

// AddGroupMemberByNameOn is `fun addGroupMember(groupName, principal, c)`
// (ManagementServices.kt:638).
func (s *IdentityService) AddGroupMemberByNameOn(
	ctx context.Context, c store.Queryer, groupName, principal string,
) (identity.GroupMemberEntry, error) {
	if err := Required("groupName", groupName); err != nil {
		return identity.GroupMemberEntry{}, err
	}
	if err := Required("principal", principal); err != nil {
		return identity.GroupMemberEntry{}, err
	}
	group, err := s.GetGroupOn(ctx, c, groupName)
	if err != nil {
		return identity.GroupMemberEntry{}, err
	}
	if err := s.rejectSystem(ctx, c, group.ID); err != nil {
		return identity.GroupMemberEntry{}, err
	}
	user, err := s.store.GetUserByPrincipalOn(ctx, c, principal)
	if err != nil {
		return identity.GroupMemberEntry{}, err
	}
	if user == nil {
		return identity.GroupMemberEntry{}, NotFound(ResourceUser)
	}
	return s.addMember(ctx, c, group.ID, user.ID)
}

func (s *IdentityService) addMember(
	ctx context.Context, c store.Queryer, groupID, userID int64,
) (identity.GroupMemberEntry, error) {
	if _, err := s.store.AddMemberOn(ctx, c, groupID, userID); err != nil {
		return identity.GroupMemberEntry{}, err
	}
	members, err := s.store.ListMembersOn(ctx, c, groupID)
	if err != nil {
		return identity.GroupMemberEntry{}, err
	}
	for _, m := range members {
		if m.UserID == userID {
			return m, nil
		}
	}
	return identity.GroupMemberEntry{}, errors.New(
		"management: member disappeared between INSERT and re-read (Kotlin's `first {}` would throw here)")
}

// RemoveGroupMemberByID is `fun removeGroupMember(groupId, userId): DeleteResult`
// (ManagementServices.kt:651).
func (s *IdentityService) RemoveGroupMemberByID(ctx context.Context, groupID, userID int64) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		group, err := s.store.GetGroupOn(ctx, tx, groupID)
		if err != nil {
			return DeleteResult{}, err
		}
		if group == nil {
			return DeleteResult{}, NotFound(ResourceGroup)
		}
		if err := s.rejectSystem(ctx, tx, group.ID); err != nil {
			return DeleteResult{}, err
		}
		user, err := s.store.GetUserOn(ctx, tx, userID)
		if err != nil {
			return DeleteResult{}, err
		}
		if user == nil {
			return DeleteResult{}, NotFound(ResourceUser)
		}
		removed, err := s.store.RemoveMemberOn(ctx, tx, groupID, userID)
		if err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{Deleted: removed}, nil
	})
}

// RemoveGroupMemberByName is `fun removeGroupMember(groupName, principal): DeleteResult`
// (ManagementServices.kt:648).
func (s *IdentityService) RemoveGroupMemberByName(
	ctx context.Context, groupName, principal string,
) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		return s.RemoveGroupMemberByNameOn(ctx, tx, groupName, principal)
	})
}

// RemoveGroupMemberByNameOn is `fun removeGroupMember(groupName, principal, c)`
// (ManagementServices.kt:658).
func (s *IdentityService) RemoveGroupMemberByNameOn(
	ctx context.Context, c store.Queryer, groupName, principal string,
) (DeleteResult, error) {
	if err := Required("groupName", groupName); err != nil {
		return DeleteResult{}, err
	}
	if err := Required("principal", principal); err != nil {
		return DeleteResult{}, err
	}
	group, err := s.GetGroupOn(ctx, c, groupName)
	if err != nil {
		return DeleteResult{}, err
	}
	if err := s.rejectSystem(ctx, c, group.ID); err != nil {
		return DeleteResult{}, err
	}
	user, err := s.store.GetUserByPrincipalOn(ctx, c, principal)
	if err != nil {
		return DeleteResult{}, err
	}
	if user == nil {
		return DeleteResult{}, NotFound(ResourceUser)
	}
	removed, err := s.store.RemoveMemberOn(ctx, c, group.ID, user.ID)
	if err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Deleted: removed}, nil
}

// ---- Group → role mappings — guards #2 and #3 -----------------------------------------------------

// AddGroupRole is `fun addGroupRole(groupId, roleId): GroupRoleEntry` (ManagementServices.kt:670).
//
// 🔒 INV-A11-32, GUARD #2 (`lockMutableGroup`). Note what changes relative to `rejectSystem`: the
// group is not read as an AppGroup at all, only its `source` — under `FOR UPDATE`. The whole method
// is one transaction, so the lock is held from the check through the INSERT and a concurrent
// transaction cannot flip `source` to SYSTEM in between.
//
// ⚠️ The role is resolved AFTER the lock. An unknown role therefore holds the group's row lock for
// the (short) remainder of the transaction before answering 404. Reproduced.
func (s *IdentityService) AddGroupRole(ctx context.Context, groupID, roleID int64) (identity.GroupRoleEntry, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (identity.GroupRoleEntry, error) {
		if err := s.lockMutableGroup(ctx, tx, groupID); err != nil {
			return identity.GroupRoleEntry{}, err
		}
		role, err := s.policies.GetRoleOn(ctx, tx, roleID)
		if err != nil {
			return identity.GroupRoleEntry{}, err
		}
		if role == nil {
			return identity.GroupRoleEntry{}, NotFound(ResourceRole)
		}
		if _, err := s.store.AddGroupRoleOn(ctx, tx, groupID, roleID); err != nil {
			return identity.GroupRoleEntry{}, err
		}
		// The Kotlin returns the RESOLVED role, not a re-read of `group_role` — so an idempotent
		// re-add answers exactly the same body as the first add.
		return identity.GroupRoleEntry{RoleID: role.ID, RoleName: role.Name}, nil
	})
}

// RemoveGroupRole is `fun removeGroupRole(groupId, roleId): DeleteResult`
// (ManagementServices.kt:677) — the same guard #2, same order.
func (s *IdentityService) RemoveGroupRole(ctx context.Context, groupID, roleID int64) (DeleteResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (DeleteResult, error) {
		if err := s.lockMutableGroup(ctx, tx, groupID); err != nil {
			return DeleteResult{}, err
		}
		role, err := s.policies.GetRoleOn(ctx, tx, roleID)
		if err != nil {
			return DeleteResult{}, err
		}
		if role == nil {
			return DeleteResult{}, NotFound(ResourceRole)
		}
		removed, err := s.store.RemoveGroupRoleOn(ctx, tx, groupID, roleID)
		if err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{Deleted: removed}, nil
	})
}

// SetGroupRoles is `fun setGroupRoles(groupName, roleNames): GroupRolesResult`
// (ManagementServices.kt:667).
func (s *IdentityService) SetGroupRoles(
	ctx context.Context, groupName string, roleNames []string,
) (GroupRolesResult, error) {
	return store.InTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) (GroupRolesResult, error) {
		return s.SetGroupRolesOn(ctx, tx, groupName, roleNames)
	})
}

// SetGroupRolesOn is `fun setGroupRoles(groupName, roleNames, c): GroupRolesResult`
// (ManagementServices.kt:683) — and it is THREE separate invariants stacked in one method.
//
// 🔒 INV-A11-32, GUARD #3. It inlines its OWN `SELECT id, source FROM app_group WHERE name = ? FOR
// UPDATE` rather than calling `lockMutableGroup`, because it needs the id as well and is keyed on the
// NAME. Three guards, three mechanisms — see doc.go on why they are not unified.
//
// 🔒 IT IS A DIFF, NOT A REPLACE. The Kotlin removes `current - requested` and adds
// `requested - current`; it does NOT delete every mapping and re-insert. The difference is
// observable: a role already mapped keeps its existing `group_role` row, so nothing downstream sees
// a momentary window in which the group grants nothing. A delete-all-then-insert-all inside the same
// transaction would be invisible to a reader outside it but would churn every row on every call.
//
// 🔒 EVERY NAME IS RESOLVED BEFORE ANYTHING IS MUTATED, same as replaceDirectRoles: one unknown name
// ⇒ `common.not_found{resource: role}` and the group's mappings are untouched.
//
// ⚠️ Unlike replaceDirectRoles, the failure says just `role` — NOT `role '<name>'`. The caller gets
// no indication of WHICH name was wrong. That is the Kotlin's (`notFound("role")`,
// ManagementServices.kt:694) and it is a genuine inconsistency between two methods that do the same
// resolve-all-first job. REPRODUCE, and do not tidy: the string is an i18n interpolation the console
// renders.
//
// 🔒 `roleNames` is a Kotlin `Set<String>`, so duplicates are impossible there. A Go slice can carry
// them; the resolution map dedups exactly as `associateWith` does, and the diff is computed over
// unique names either way.
func (s *IdentityService) SetGroupRolesOn(
	ctx context.Context, c store.Queryer, groupName string, roleNames []string,
) (GroupRolesResult, error) {
	if err := Required("groupName", groupName); err != nil {
		return GroupRolesResult{}, err
	}
	for _, name := range roleNames {
		if err := Required("roleNames", name); err != nil {
			return GroupRolesResult{}, err
		}
	}

	groupID, source, found, err := s.store.LockMutableGroupSourceByName(ctx, c, groupName)
	if err != nil {
		return GroupRolesResult{}, err
	}
	if !found {
		return GroupRolesResult{}, NotFound(ResourceGroup)
	}
	if source == identity.SystemSource {
		return GroupRolesResult{}, Fail(CodeGroupSystemImmutable, nil)
	}

	// Resolve every name first. `requestedOrder` keeps the caller's order so the ADD loop is
	// deterministic; Kotlin's LinkedHashSet does the same.
	requested := map[string]policy.Role{}
	requestedOrder := make([]string, 0, len(roleNames))
	for _, name := range roleNames {
		if _, seen := requested[name]; seen {
			continue
		}
		role, err := s.policies.GetRoleByNameOn(ctx, c, name)
		if err != nil {
			return GroupRolesResult{}, err
		}
		if role == nil {
			return GroupRolesResult{}, NotFound(ResourceRole)
		}
		requested[name] = *role
		requestedOrder = append(requestedOrder, name)
	}

	// `store.listGroupRoles(...).associateBy(GroupRoleEntry::roleName)`, in ORDER BY r.name order.
	entries, err := s.store.ListGroupRolesOn(ctx, c, groupID)
	if err != nil {
		return GroupRolesResult{}, err
	}
	current := make(map[string]identity.GroupRoleEntry, len(entries))
	for _, e := range entries {
		current[e.RoleName] = e
	}

	// current − requested.
	for _, e := range entries {
		if _, keep := requested[e.RoleName]; keep {
			continue
		}
		if _, err := s.store.RemoveGroupRoleOn(ctx, c, groupID, e.RoleID); err != nil {
			return GroupRolesResult{}, err
		}
	}
	// requested − current.
	for _, name := range requestedOrder {
		if _, already := current[name]; already {
			continue
		}
		if _, err := s.store.AddGroupRoleOn(ctx, c, groupID, requested[name].ID); err != nil {
			return GroupRolesResult{}, err
		}
	}

	// The RE-READ is the answer, not the request — so it reflects what the table actually holds.
	after, err := s.store.ListGroupRolesOn(ctx, c, groupID)
	if err != nil {
		return GroupRolesResult{}, err
	}
	names := make([]string, 0, len(after))
	for _, e := range after {
		names = append(names, e.RoleName)
	}
	return GroupRolesResult{Group: groupName, RoleNames: names}, nil
}

// ---- The two private guards ----------------------------------------------------------------------

// rejectSystem is `private fun rejectSystem(group: AppGroup, c: Connection)`
// (ManagementServices.kt:711).
//
// 🔒 INV-A11-32, GUARD #1 — `store.isSystemGroup(group.id, c)` ⇒ `group.system_immutable`.
//
// ⚠️ IT TAKES NO ROW LOCK, and that is the asymmetry 11-mcp-oauth-management.md Q4 raises: the other
// two guards use `SELECT … FOR UPDATE` precisely so a concurrent transaction cannot flip `source`
// between the check and the mutation, and this one — which guards update-group, delete-group and
// both membership paths — does not. REPRODUCE. Adding a lock here would be a fix during a port, and
// the port policy is explicit that it is not this change's job. Recorded so the eventual fix is a
// deliberate, reviewable edit rather than an accident of translation.
//
// It takes the id rather than the AppGroup because that is all the Kotlin reads off it, and passing
// the whole struct would suggest the check consults fields it does not.
func (s *IdentityService) rejectSystem(ctx context.Context, c store.Queryer, groupID int64) error {
	system, err := s.store.IsSystemGroupOn(ctx, c, groupID)
	if err != nil {
		return err
	}
	if system {
		return Fail(CodeGroupSystemImmutable, nil)
	}
	return nil
}

// lockMutableGroup is `private fun lockMutableGroup(id: Long, c: Connection)`
// (ManagementServices.kt:703).
//
// 🔒 INV-A11-32, GUARD #2 — `SELECT source FROM app_group WHERE id = ? FOR UPDATE`, throwing
// `group.system_immutable` on SYSTEM and `common.not_found{resource: group}` on no row.
//
// The `FOR UPDATE` is what distinguishes it from [IdentityService.rejectSystem] and it must not be
// dropped: it holds the row for the rest of the caller's transaction, so the source cannot change
// between this check and the group_role write that follows.
func (s *IdentityService) lockMutableGroup(ctx context.Context, c store.Queryer, id int64) error {
	source, found, err := s.store.LockMutableGroupSource(ctx, c, id)
	if err != nil {
		return err
	}
	if !found {
		return NotFound(ResourceGroup)
	}
	if source == identity.SystemSource {
		return Fail(CodeGroupSystemImmutable, nil)
	}
	return nil
}
