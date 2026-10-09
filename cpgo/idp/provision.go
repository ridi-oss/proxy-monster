package idp

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// Provision is JIT directory reconciliation on login: the app_user row exists (a SCIM-owned row keeps its
// source and is never reactivated), and the user's group memberships become exactly the mapped IdP groups.
func Provision(ctx context.Context, pool *pgxpool.Pool, principal string, email *string, groups []string, mapping GroupMapping) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		q := db.New(tx)
		if err := q.ProvisionUser(ctx, db.ProvisionUserParams{Principal: principal, Email: email}); err != nil {
			return err
		}
		user, err := q.UserIDByPrincipal(ctx, principal)
		if err != nil {
			return err
		}
		var target []int64
		for _, name := range mapping.Resolve(groups) {
			id, err := q.ProvisionGroup(ctx, name)
			if err != nil {
				return err
			}
			if !slices.Contains(target, id) {
				target = append(target, id)
			}
		}
		current, err := q.GroupIDsOfUser(ctx, user)
		if err != nil {
			return err
		}
		for _, id := range target {
			if !slices.Contains(current, id) {
				if _, err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: id, UserID: user}); err != nil {
					return err
				}
			}
		}
		for _, id := range current {
			if !slices.Contains(target, id) {
				if _, err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: id, UserID: user}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
