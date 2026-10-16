package policies

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// mutate runs change in one transaction with its audit rows, then afterCommit, then answers status with its
// result, or returns the error.
func (p policies) mutate(w http.ResponseWriter, r *http.Request, status int, change func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error), afterCommit ...func(context.Context) error) error {
	ctx := r.Context()
	actor := audit.Actor{Principal: api.Principal(ctx), ClientAddr: api.RequesterIP(ctx), Channel: "console"}
	var out any
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var err error
		out, err = change(ctx, tx, actor)
		return err
	})
	for _, f := range afterCommit {
		if err == nil {
			err = api.Notify(ctx, f)
		}
	}
	switch {
	case err != nil:
		return err
	case out == nil:
		w.WriteHeader(status)
	default:
		api.WriteJSON(w, status, out)
	}
	return nil
}

type roleInput struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

func getRole(ctx context.Context, tx pgx.Tx, id int64) (*role, error) {
	row, err := db.New(tx).Role(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, api.NotFound("role")
	}
	r := role(row)
	return &r, err
}

func systemRoleGuard(ctx context.Context, tx pgx.Tx, id int64) error {
	system, err := db.New(tx).IsSystemRole(ctx, id)
	if err != nil {
		return err
	}
	if system {
		return api.CodeRoleSystemImmutable.Err()
	}
	return nil
}

func (p policies) createRole(w http.ResponseWriter, r *http.Request) error {
	var in roleInput
	decodeErr := api.DecodeBody(r, &in)
	return p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := api.Required("name", in.Name); err != nil {
			return nil, err
		}
		row, err := db.New(tx).CreateRole(ctx, db.CreateRoleParams{Name: in.Name, Description: in.Description})
		created := role(row)
		if err != nil {
			return nil, api.Unique(err, "role", in.Name)
		}
		return created, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Role", created.Name), "create role '"+created.Name+"'")
	})
}

func (p policies) updateRole(w http.ResponseWriter, r *http.Request, id int64) error {
	var in roleInput
	decodeErr := api.DecodeBody(r, &in)
	return p.mutate(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		current, err := getRole(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := systemRoleGuard(ctx, tx, id); err != nil {
			return nil, err
		}
		if err := api.Required("name", in.Name); err != nil {
			return nil, err
		}
		if err := db.New(tx).UpdateRole(ctx, db.UpdateRoleParams{Name: in.Name, Description: in.Description, ID: id}); err != nil {
			return nil, api.Unique(err, "role", in.Name)
		}
		updated, err := getRole(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return updated, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Role", updated.Name), api.UpdateSummary("role", current.Name, updated.Name))
	})
}

func (p policies) deleteRole(w http.ResponseWriter, r *http.Request, id int64) error {
	return p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		current, err := getRole(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := systemRoleGuard(ctx, tx, id); err != nil {
			return nil, err
		}
		n, err := db.New(tx).DeleteRole(ctx, id)
		if err != nil || n == 0 {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Role", current.Name), "delete role '"+current.Name+"'")
	})
}

func (p policies) assignRole(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Principal string `json:"principal"`
		RoleID    int64  `json:"roleId"`
	}
	decodeErr := api.DecodeBody(r, &in)
	return p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := api.Required("principal", in.Principal); err != nil {
			return nil, err
		}
		role, err := getRole(ctx, tx, in.RoleID)
		if err != nil {
			return nil, err
		}
		q := db.New(tx)
		existed, err := q.RoleAssigned(ctx, db.RoleAssignedParams{Principal: in.Principal, RoleID: in.RoleID})
		if err != nil {
			return nil, err
		}
		id, err := q.AssignRole(ctx, db.AssignRoleParams{Principal: in.Principal, RoleID: in.RoleID})
		if err != nil {
			return nil, err
		}
		out := roleAssignment{ID: id, Principal: in.Principal, RoleID: in.RoleID, RoleName: role.Name}
		if existed {
			return out, nil
		}
		return out, audit.Admin(ctx, tx, actor, "admin.identity", audit.Entity("Role", role.Name),
			"assign role '"+role.Name+"' to '"+in.Principal+"'")
	})
}

func (p policies) unassignRole(w http.ResponseWriter, r *http.Request, id int64) error {
	return p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		q := db.New(tx)
		a, err := q.RoleAssignment(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, api.NotFound("role assignment")
		}
		if err != nil {
			return nil, err
		}
		n, err := q.UnassignRole(ctx, id)
		if err != nil || n == 0 {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.identity", audit.Entity("Role", a.RoleName),
			"unassign role '"+a.RoleName+"' from '"+a.Principal+"'")
	})
}

type maskFnInput struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func getMaskFn(ctx context.Context, tx pgx.Tx, id int64) (*maskFn, error) {
	row, err := db.New(tx).MaskFn(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, api.NotFound("mask function")
	}
	m := maskFn(row)
	return &m, err
}

func (p policies) createMaskFn(w http.ResponseWriter, r *http.Request) error {
	var in maskFnInput
	decodeErr := api.DecodeBody(r, &in)
	return p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := api.Required("name", in.Name); err != nil {
			return nil, err
		}
		if err := api.Required("kind", in.Kind); err != nil {
			return nil, err
		}
		row, err := db.New(tx).CreateMaskFn(ctx, db.CreateMaskFnParams{Name: in.Name, Kind: in.Kind})
		created := maskFn(row)
		if err != nil {
			return nil, api.Unique(err, "mask function", in.Name)
		}
		return created, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("MaskFn", created.Name), "create mask function '"+created.Name+"'")
	})
}

func (p policies) updateMaskFn(w http.ResponseWriter, r *http.Request, id int64) error {
	var in maskFnInput
	decodeErr := api.DecodeBody(r, &in)
	return p.mutate(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		current, err := getMaskFn(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := api.Required("name", in.Name); err != nil {
			return nil, err
		}
		if err := api.Required("kind", in.Kind); err != nil {
			return nil, err
		}
		if err := db.New(tx).UpdateMaskFn(ctx, db.UpdateMaskFnParams{Name: in.Name, Kind: in.Kind, ID: id}); err != nil {
			return nil, api.Unique(err, "mask function", in.Name)
		}
		updated, err := getMaskFn(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return updated, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("MaskFn", updated.Name), api.UpdateSummary("mask function", current.Name, updated.Name))
	})
}

func (p policies) deleteMaskFn(w http.ResponseWriter, r *http.Request, id int64) error {
	return p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		current, err := getMaskFn(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		n, err := db.New(tx).DeleteMaskFn(ctx, id)
		if err != nil || n == 0 {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("MaskFn", current.Name), "delete mask function '"+current.Name+"'")
	})
}
