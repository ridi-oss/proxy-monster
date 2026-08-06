package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ridi-oss/proxy-monster/gocp/internal/instant"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
)

// ---------------------------------------------------------------------------------------------
// The plain user/group reads and the GROUP writes of `UserGroupStore` — Users.kt:75-330,568-612.
//
// 🔴 SCOPE. This discharges the FIRST half of doc.go's `TODO(A3): the rest of UserGroupStore`,
// because A11 §8's `IdentityManagementService` cannot exist without it: all three of INV-A11-32's
// SYSTEM-immutability guards read or lock `app_group`, and `setGroupRoles` diffs `group_role`.
//
// The PRINCIPAL-MUTATING writes this file deliberately left out now live in usergroupwrites.go, and
// the SCIM upsert family in scimstore.go. `provisionFromOidc` is still owed — see doc.go.
//
// The Kotlin's non-`c` overloads each take their own pooled connection; the `…On` overloads take the
// caller's. That split is reproduced verbatim because it decides which reads are inside a caller's
// transaction — and for the group guards, which reads are inside the transaction holding the row
// lock.
// ---------------------------------------------------------------------------------------------

// ---- Users: reads ----------------------------------------------------------------------------

// ListUsers is `listUsers()` (Users.kt:75), ordered by principal, with each user's groups joined in.
//
// ⚠️ Two statements, no transaction — the group map is read first and the user rows second, exactly
// as the Kotlin does (`userGroups(null)` opens its own connection). A membership committing between
// them yields a user row whose `groups` predates it. REPRODUCE.
func (s *UserGroupStore) ListUsers(ctx context.Context) ([]AppUser, error) {
	return s.ListUsersOn(ctx, s.db)
}

// ListUsersOn is [UserGroupStore.ListUsers] on the caller's handle.
func (s *UserGroupStore) ListUsersOn(ctx context.Context, c store.Queryer) ([]AppUser, error) {
	groupsByUser, err := userGroups(ctx, c, nil)
	if err != nil {
		return nil, err
	}
	rows, err := c.Query(ctx, userProjection+` FROM app_user ORDER BY principal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// `[]`, never nil — INV-A1-4. `query { … }` returns an empty list, and the route marshals it.
	out := []AppUser{}
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		user.Groups = groupsByUser[user.ID]
		out = append(out, user)
	}
	return out, rows.Err()
}

// GetUser is `getUser(id)` (Users.kt:82); nil ⇒ no such row.
func (s *UserGroupStore) GetUser(ctx context.Context, id int64) (*AppUser, error) {
	return s.GetUserOn(ctx, s.db, id)
}

// GetUserOn is `getUser(id, c)`.
func (s *UserGroupStore) GetUserOn(ctx context.Context, c store.Queryer, id int64) (*AppUser, error) {
	groups, err := userGroups(ctx, c, &id)
	if err != nil {
		return nil, err
	}
	rows, err := c.Query(ctx, userProjection+` FROM app_user WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	user, err := scanUser(rows)
	if err != nil {
		return nil, err
	}
	user.Groups = groups[id]
	return &user, nil
}

// GetUserByPrincipal is `getUserByPrincipal(principal)` (Users.kt:94); nil ⇒ no such row.
func (s *UserGroupStore) GetUserByPrincipal(ctx context.Context, principal string) (*AppUser, error) {
	return s.GetUserByPrincipalOn(ctx, s.db, principal)
}

// GetUserByPrincipalOn is `getUserByPrincipal(principal, c)` — an id lookup followed by
// [UserGroupStore.GetUserOn], the Kotlin's own two-step, not a single joined query.
func (s *UserGroupStore) GetUserByPrincipalOn(
	ctx context.Context, c store.Queryer, principal string,
) (*AppUser, error) {
	var id int64
	err := c.QueryRow(ctx, `SELECT id FROM app_user WHERE principal=$1`, principal).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetUserOn(ctx, c, id)
}

// ---- Groups: reads ---------------------------------------------------------------------------

// ListGroups is `listGroups()` (Users.kt:245), ordered by name, with member counts and roles joined.
func (s *UserGroupStore) ListGroups(ctx context.Context) ([]AppGroup, error) {
	return s.ListGroupsOn(ctx, s.db)
}

// ListGroupsOn is [UserGroupStore.ListGroups] on the caller's handle.
func (s *UserGroupStore) ListGroupsOn(ctx context.Context, c store.Queryer) ([]AppGroup, error) {
	counts, err := memberCounts(ctx, c, nil)
	if err != nil {
		return nil, err
	}
	rolesByGroup, err := groupRoleRefs(ctx, c, nil)
	if err != nil {
		return nil, err
	}
	rows, err := c.Query(ctx, groupProjection+` FROM app_group ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AppGroup{}
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		group.MemberCount = counts[group.ID]
		group.Roles = rolesByGroup[group.ID]
		out = append(out, group)
	}
	return out, rows.Err()
}

// GetGroup is `getGroup(id)` (Users.kt:253); nil ⇒ no such row.
func (s *UserGroupStore) GetGroup(ctx context.Context, id int64) (*AppGroup, error) {
	return s.GetGroupOn(ctx, s.db, id)
}

// GetGroupOn is `getGroup(id, c)`.
//
// The Kotlin reads the member COUNT and the roles BEFORE the row itself and keeps them even when the
// row turns out not to exist. Reproduced: the two extra queries run unconditionally.
func (s *UserGroupStore) GetGroupOn(ctx context.Context, c store.Queryer, id int64) (*AppGroup, error) {
	var count int32
	if err := c.QueryRow(ctx, `SELECT COUNT(*) FROM group_member WHERE group_id=$1`, id).Scan(&count); err != nil {
		return nil, err
	}
	entries, err := s.ListGroupRolesOn(ctx, c, id)
	if err != nil {
		return nil, err
	}
	roles := make([]GroupRef, 0, len(entries))
	for _, e := range entries {
		roles = append(roles, GroupRef{ID: e.RoleID, Name: e.RoleName})
	}

	rows, err := c.Query(ctx, groupProjection+` FROM app_group WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	group, err := scanGroup(rows)
	if err != nil {
		return nil, err
	}
	group.MemberCount = count
	group.Roles = roles
	return &group, nil
}

// GetGroupByName is `getGroupByName(name)` (Users.kt:266); nil ⇒ no such row.
func (s *UserGroupStore) GetGroupByName(ctx context.Context, name string) (*AppGroup, error) {
	return s.GetGroupByNameOn(ctx, s.db, name)
}

// GetGroupByNameOn is `getGroupByName(name, c)`.
func (s *UserGroupStore) GetGroupByNameOn(ctx context.Context, c store.Queryer, name string) (*AppGroup, error) {
	var id int64
	err := c.QueryRow(ctx, `SELECT id FROM app_group WHERE name=$1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetGroupOn(ctx, c, id)
}

// ---- Groups: writes --------------------------------------------------------------------------
//
// None of these guards SYSTEM. `provisionFromOidc` manages `system:admin` membership by calling
// straight through here (Users.kt:305's kdoc), so the immutability guard lives at the MANAGEMENT
// layer — INV-A11-32 — and a store that refused SYSTEM rows would break OIDC group sync.

// CreateGroup is `createGroup(input)` (Users.kt:275).
func (s *UserGroupStore) CreateGroup(ctx context.Context, input AppGroupInput) (AppGroup, error) {
	return s.CreateGroupOn(ctx, s.db, input)
}

// CreateGroupOn is `createGroup(input, c)`. `source` is left to the column default ('LOCAL').
//
// A duplicate name raises SQLSTATE 23505 on `app_group.name UNIQUE`; the management layer's
// `unique("group", name)` turns that into `common.already_exists`.
func (s *UserGroupStore) CreateGroupOn(
	ctx context.Context, c store.Queryer, input AppGroupInput,
) (AppGroup, error) {
	var id int64
	err := c.QueryRow(ctx,
		`INSERT INTO app_group (name, description) VALUES ($1, $2) RETURNING id`,
		input.Name, input.Description).Scan(&id)
	if err != nil {
		return AppGroup{}, err
	}
	group, err := s.GetGroupOn(ctx, c, id)
	if err != nil {
		return AppGroup{}, err
	}
	if group == nil {
		return AppGroup{}, errors.New("identity: app_group row disappeared between INSERT and re-read")
	}
	return *group, nil
}

// UpdateGroup is `updateGroup(id, input)` (Users.kt:285); nil ⇒ no such row.
func (s *UserGroupStore) UpdateGroup(ctx context.Context, id int64, input AppGroupInput) (*AppGroup, error) {
	return s.UpdateGroupOn(ctx, s.db, id, input)
}

// UpdateGroupOn is `updateGroup(id, input, c)` — an existence read, the UPDATE, then a re-read.
func (s *UserGroupStore) UpdateGroupOn(
	ctx context.Context, c store.Queryer, id int64, input AppGroupInput,
) (*AppGroup, error) {
	current, err := s.GetGroupOn(ctx, c, id)
	if err != nil || current == nil {
		return nil, err
	}
	if _, err := c.Exec(ctx,
		`UPDATE app_group SET name=$1, description=$2 WHERE id=$3`,
		input.Name, input.Description, id); err != nil {
		return nil, err
	}
	return s.GetGroupOn(ctx, c, id)
}

// DeleteGroup is `deleteGroup(id)` (Users.kt:295); false ⇒ no row matched.
func (s *UserGroupStore) DeleteGroup(ctx context.Context, id int64) (bool, error) {
	return s.DeleteGroupOn(ctx, s.db, id)
}

// DeleteGroupOn is `deleteGroup(id, c)`.
//
// ⚠️ `group_member.group_id` and `group_role.group_id` are both `ON DELETE CASCADE`
// (V1__identity.sql:45,52), so this silently drops every membership and every role mapping the group
// carried. That is the migration's behaviour and it is why the SYSTEM guard above this matters.
func (s *UserGroupStore) DeleteGroupOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	tag, err := c.Exec(ctx, `DELETE FROM app_group WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// IsSystemGroup is `isSystemGroup(id)` (Users.kt:305).
//
// 🔒 F34 / INV-A11-32 — the predicate keys on the `source` COLUMN, never on the string
// `"system:admin"`. `V8__seed.sql` seeds SEVEN `source='SYSTEM'` groups, so a name-based guard would
// protect one of them and leave six mutable.
//
// A missing row is FALSE, not an error: `rs.next() && rs.getBoolean(1)`. Callers check existence
// separately, and the management layer always has already.
func (s *UserGroupStore) IsSystemGroup(ctx context.Context, id int64) (bool, error) {
	return s.IsSystemGroupOn(ctx, s.db, id)
}

// IsSystemGroupOn is `isSystemGroup(id, c)`.
//
// ⚠️ It takes NO row lock — see management.IdentityService's `rejectSystem`, which is the asymmetry
// 11-mcp-oauth-management.md Q4 raises.
func (s *UserGroupStore) IsSystemGroupOn(ctx context.Context, c store.Queryer, id int64) (bool, error) {
	var out bool
	err := c.QueryRow(ctx, `SELECT source = 'SYSTEM' FROM app_group WHERE id = $1`, id).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return out, nil
}

// IsSystemGroupByName is `isSystemGroupByName(name)` (Users.kt:319) — the SCIM POST upsert's guard,
// which matches an existing group BY NAME and would otherwise flip a seeded SYSTEM group to
// source=SCIM and defeat every other immutability guard.
func (s *UserGroupStore) IsSystemGroupByName(ctx context.Context, name string) (bool, error) {
	var out bool
	err := s.db.QueryRow(ctx, `SELECT source = 'SYSTEM' FROM app_group WHERE name = $1`, name).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return out, nil
}

// LockMutableGroupSource is the `SELECT source FROM app_group WHERE id = ? FOR UPDATE` half of
// `lockMutableGroup` (ManagementServices.kt:703-709), WITHOUT its throw.
//
// 🔒 INV-A11-32 — the `FOR UPDATE` is the whole point and must not be dropped. It exists so a
// concurrent transaction cannot flip `source` between the check and the mutation: with a plain read,
// a SCIM or seed write could turn the group SYSTEM after this returned 'LOCAL' and the caller would
// then mutate a system group. It also blocks a concurrent DELETE of the row for the rest of the
// transaction.
//
// It lives in the store rather than in the management service because the statement is SQL against
// `app_group`, which is this package's table; the `group.system_immutable` decision stays at the
// management layer where the error code belongs. found=false ⇒ no such row.
func (s *UserGroupStore) LockMutableGroupSource(
	ctx context.Context, c store.Queryer, id int64,
) (source string, found bool, err error) {
	err = c.QueryRow(ctx, `SELECT source FROM app_group WHERE id = $1 FOR UPDATE`, id).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return source, true, nil
}

// LockMutableGroupSourceByName is `setGroupRoles`' OWN inline
// `SELECT id, source FROM app_group WHERE name = ? FOR UPDATE` (ManagementServices.kt:686).
//
// ⚠️ It is a THIRD, separate statement from [UserGroupStore.LockMutableGroupSource] — keyed on the
// NAME, and returning the id as well. The Kotlin inlines it in the service rather than reusing
// `lockMutableGroup`, so the two are free to drift; they are kept as two here for the same reason
// (INV-A11-32 counts three distinct mechanisms, not one shared helper).
func (s *UserGroupStore) LockMutableGroupSourceByName(
	ctx context.Context, c store.Queryer, name string,
) (id int64, source string, found bool, err error) {
	err = c.QueryRow(ctx, `SELECT id, source FROM app_group WHERE name = $1 FOR UPDATE`, name).Scan(&id, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return id, source, true, nil
}

// SystemSource is the `source` value that makes a group immutable through the API — the literal all
// three of INV-A11-32's guards compare against.
const SystemSource = "SYSTEM"

// ---- Members ---------------------------------------------------------------------------------

// ListMembers is `listMembers(groupId)` (Users.kt:568), ordered by principal.
func (s *UserGroupStore) ListMembers(ctx context.Context, groupID int64) ([]GroupMemberEntry, error) {
	return s.ListMembersOn(ctx, s.db, groupID)
}

// ListMembersOn is `listMembers(groupId, c)`.
func (s *UserGroupStore) ListMembersOn(
	ctx context.Context, c store.Queryer, groupID int64,
) ([]GroupMemberEntry, error) {
	rows, err := c.Query(ctx,
		`SELECT u.id AS user_id, u.principal, u.display_name
		   FROM group_member gm JOIN app_user u ON u.id = gm.user_id
		  WHERE gm.group_id = $1 ORDER BY u.principal`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []GroupMemberEntry{}
	for rows.Next() {
		var e GroupMemberEntry
		if err := rows.Scan(&e.UserID, &e.Principal, &e.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddMember is `addMember(groupId, userId)` (Users.kt:580).
func (s *UserGroupStore) AddMember(ctx context.Context, groupID, userID int64) (bool, error) {
	return s.AddMemberOn(ctx, s.db, groupID, userID)
}

// AddMemberOn is `addMember(groupId, userId, c)`.
//
// `ON CONFLICT DO NOTHING` makes it idempotent, and the false it then returns means "already a
// member", not "failed". The management layer discards the boolean and re-reads the member list, so
// re-adding an existing member is a success — reproduce that, do not turn it into a 409.
func (s *UserGroupStore) AddMemberOn(ctx context.Context, c store.Queryer, groupID, userID int64) (bool, error) {
	tag, err := c.Exec(ctx,
		`INSERT INTO group_member (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, groupID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RemoveMember is `removeMember(groupId, userId)` (Users.kt:585).
func (s *UserGroupStore) RemoveMember(ctx context.Context, groupID, userID int64) (bool, error) {
	return s.RemoveMemberOn(ctx, s.db, groupID, userID)
}

// RemoveMemberOn is `removeMember(groupId, userId, c)`.
func (s *UserGroupStore) RemoveMemberOn(ctx context.Context, c store.Queryer, groupID, userID int64) (bool, error) {
	tag, err := c.Exec(ctx, `DELETE FROM group_member WHERE group_id=$1 AND user_id=$2`, groupID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ---- Group → role mappings ---------------------------------------------------------------------

// ListGroupRoles is `listGroupRoles(groupId)` (Users.kt:590), ordered by role name.
func (s *UserGroupStore) ListGroupRoles(ctx context.Context, groupID int64) ([]GroupRoleEntry, error) {
	return s.ListGroupRolesOn(ctx, s.db, groupID)
}

// ListGroupRolesOn is `listGroupRoles(groupId, c)`.
//
// The `ORDER BY r.name` is load-bearing beyond cosmetics: `setGroupRoles` builds its "current" map
// from this list and returns the re-read names in this order, so the wire order of `roleNames` is
// alphabetical by role name.
func (s *UserGroupStore) ListGroupRolesOn(
	ctx context.Context, c store.Queryer, groupID int64,
) ([]GroupRoleEntry, error) {
	rows, err := c.Query(ctx,
		`SELECT r.id AS role_id, r.name AS role_name
		   FROM group_role gr JOIN app_role r ON r.id = gr.role_id
		  WHERE gr.group_id = $1 ORDER BY r.name`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []GroupRoleEntry{}
	for rows.Next() {
		var e GroupRoleEntry
		if err := rows.Scan(&e.RoleID, &e.RoleName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddGroupRole is `addGroupRole(groupId, roleId)` (Users.kt:602).
func (s *UserGroupStore) AddGroupRole(ctx context.Context, groupID, roleID int64) (bool, error) {
	return s.AddGroupRoleOn(ctx, s.db, groupID, roleID)
}

// AddGroupRoleOn is `addGroupRole(groupId, roleId, c)`; idempotent via `ON CONFLICT DO NOTHING`.
func (s *UserGroupStore) AddGroupRoleOn(ctx context.Context, c store.Queryer, groupID, roleID int64) (bool, error) {
	tag, err := c.Exec(ctx,
		`INSERT INTO group_role (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, groupID, roleID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RemoveGroupRole is `removeGroupRole(groupId, roleId)` (Users.kt:607).
func (s *UserGroupStore) RemoveGroupRole(ctx context.Context, groupID, roleID int64) (bool, error) {
	return s.RemoveGroupRoleOn(ctx, s.db, groupID, roleID)
}

// RemoveGroupRoleOn is `removeGroupRole(groupId, roleId, c)`.
func (s *UserGroupStore) RemoveGroupRoleOn(ctx context.Context, c store.Queryer, groupID, roleID int64) (bool, error) {
	tag, err := c.Exec(ctx, `DELETE FROM group_role WHERE group_id=$1 AND role_id=$2`, groupID, roleID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ---- Row mappers and the three join helpers -----------------------------------------------------

const userProjection = `SELECT id, principal, display_name, email, source, external_id, active, created_at`

const groupProjection = `SELECT id, name, description, source, external_id`

func scanUser(row pgx.Row) (AppUser, error) {
	var u AppUser
	var createdAt time.Time
	if err := row.Scan(&u.ID, &u.Principal, &u.DisplayName, &u.Email,
		&u.Source, &u.ExternalID, &u.Active, &createdAt); err != nil {
		return AppUser{}, err
	}
	// `getTimestamp(...).toInstant().toString()` — ISO_INSTANT, which omits trailing zeros in the
	// fractional second. instant.Format is the port of exactly that rendering.
	u.CreatedAt = instant.Format(createdAt)
	return u, nil
}

func scanGroup(row pgx.Row) (AppGroup, error) {
	var g AppGroup
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Source, &g.ExternalID); err != nil {
		return AppGroup{}, err
	}
	return g, nil
}

// userGroups is `private fun userGroups(userId: Long?, c: Connection)` (Users.kt:689) — group refs
// keyed by user id, for ALL users when userID is nil.
func userGroups(ctx context.Context, c store.Queryer, userID *int64) (map[int64][]GroupRef, error) {
	sql := `SELECT gm.user_id, g.id, g.name FROM group_member gm JOIN app_group g ON g.id = gm.group_id`
	args := []any{}
	if userID != nil {
		sql += ` WHERE gm.user_id = $1`
		args = append(args, *userID)
	}
	sql += ` ORDER BY g.name`
	return refsByOwner(ctx, c, sql, args)
}

// groupRoleRefs is `private fun groupRoles(groupId: Long?)` (Users.kt:721) — role refs keyed by
// group id. Distinct from [UserGroupStore.ListGroupRoles], which yields GroupRoleEntry for one group.
func groupRoleRefs(ctx context.Context, c store.Queryer, groupID *int64) (map[int64][]GroupRef, error) {
	sql := `SELECT gr.group_id, r.id, r.name FROM group_role gr JOIN app_role r ON r.id = gr.role_id`
	args := []any{}
	if groupID != nil {
		sql += ` WHERE gr.group_id = $1`
		args = append(args, *groupID)
	}
	sql += ` ORDER BY r.name`
	return refsByOwner(ctx, c, sql, args)
}

func refsByOwner(ctx context.Context, c store.Queryer, sql string, args []any) (map[int64][]GroupRef, error) {
	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[int64][]GroupRef{}
	for rows.Next() {
		var owner int64
		var ref GroupRef
		if err := rows.Scan(&owner, &ref.ID, &ref.Name); err != nil {
			return nil, err
		}
		out[owner] = append(out[owner], ref)
	}
	return out, rows.Err()
}

// memberCounts is `private fun memberCounts(groupId: Long?)` (Users.kt:704). A group with no members
// is ABSENT from the map (`GROUP BY` emits no row), which is why the caller reads it as `?: 0`.
func memberCounts(ctx context.Context, c store.Queryer, groupID *int64) (map[int64]int32, error) {
	sql := `SELECT group_id, COUNT(*) AS member_count FROM group_member`
	args := []any{}
	if groupID != nil {
		sql += ` WHERE group_id = $1`
		args = append(args, *groupID)
	}
	sql += ` GROUP BY group_id`

	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[int64]int32{}
	for rows.Next() {
		var id int64
		var count int32
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		out[id] = count
	}
	return out, rows.Err()
}
