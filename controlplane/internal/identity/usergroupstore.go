package identity

import (
	"context"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/store"
)

// UserGroupStore is the port of `class UserGroupStore(internal val dataSource: DataSource)`
// (Users.kt:74). ⚠️ THIS INCREMENT PORTS ONLY THE READS RoleResolver AND ITS CONSUMERS NEED —
// [UserGroupStore.IsDeactivated] (both forms) and [UserGroupStore.RolesForPrincipal]. See doc.go for
// the full list of what is still missing and who needs it.
//
// The Kotlin's `dataSource` is `internal` rather than private because `userGroupRoutes`' default
// `management` parameter reads it (Users.kt:900). DB() is that accessor.
type UserGroupStore struct {
	db store.DB
}

// NewUserGroupStore builds the store over the shared control-plane handle.
func NewUserGroupStore(db store.DB) *UserGroupStore { return &UserGroupStore{db: db} }

// DB exposes the underlying handle, reproducing `internal val dataSource`.
//
// TODO(A3): the intended caller is `userGroupRoutes`' default management parameter (Users.kt:900).
func (s *UserGroupStore) DB() store.DB { return s.db }

// IsDeactivated is `isDeactivated(principal)` (Users.kt:647).
//
// 🔒 Contract: **true iff a row exists AND it is inactive.** No row ⇒ FALSE (INV-A3-10). This only
// fires deprovisioning for principals the directory actually tracks; a purely local
// `principal_role`-only identity is not deactivated, because there is nothing to deactivate.
func (s *UserGroupStore) IsDeactivated(ctx context.Context, principal string) (bool, error) {
	return s.IsDeactivatedOn(ctx, s.db, principal)
}

// IsDeactivatedOn is `isDeactivated(principal, c)` (Users.kt:654) — the same read on the CALLER's
// handle.
//
// 🔒 This overload is not a convenience. It exists so a locked renewal check reads on the
// transaction that holds the per-principal advisory lock, rather than on a separate connection that
// could race a concurrent commit. That is `mintForActivePrincipalLocked`'s call site and the
// mechanism INV-A3-7 rests on: the check and the mint must be on ONE transaction under ONE lock, or
// a teardown can slip its revoke between the check and the INSERT and leave a credential that
// outlives deprovisioning.
//
// The SQL is a single EXISTS, so "no row" and "row, active" are indistinguishable at the call site —
// deliberately, per INV-A3-10.
func (s *UserGroupStore) IsDeactivatedOn(ctx context.Context, c store.Queryer, principal string) (bool, error) {
	var out bool
	err := c.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM app_user WHERE principal=$1 AND NOT active)`, principal).Scan(&out)
	if err != nil {
		return false, err
	}
	return out, nil
}

// RolesForPrincipal is `rolesForPrincipal(principal)` (Users.kt:613): the role names this principal
// gets via GROUP MEMBERSHIP. The IdP never mints a role — its group claim provisions local
// `app_group` membership and `group_role` is what turns a group into roles (V1__identity.sql).
//
// 🔒 INV-A3-15 — this fails closed on its own. The joins start FROM `app_user` and are all INNER,
// plus `AND u.active`, so an unknown or inactive principal yields zero rows without any help from
// Resolve's short-circuit. The group source is therefore guarded TWICE; the direct and JIT sources
// only once.
//
// ⚠️ There is no `(principal, c)` overload in the Kotlin and none here. The only caller is
// [RoleResolver.Resolve], which is deliberately non-transactional (INV-A3-11) — adding a
// caller's-handle form would invite closing that window by accident.
//
// `SELECT DISTINCT` is the Kotlin's, so a principal in two groups that both grant the same role gets
// one entry. There is no ORDER BY: the result order is whatever Postgres returns, and
// [EffectiveRoles] preserves it as the third arm of the union. Do not add one — it would change the
// wire order of `effectiveRoles` (see doc.go).
func (s *UserGroupStore) RolesForPrincipal(ctx context.Context, principal string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT r.name
                   FROM app_user u
                   JOIN group_member gm ON gm.user_id = u.id
                   JOIN group_role gr ON gr.group_id = gm.group_id
                   JOIN app_role r ON r.id = gr.role_id
                  WHERE u.principal = $1 AND u.active`, principal)
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
