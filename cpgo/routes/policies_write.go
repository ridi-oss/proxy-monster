package routes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// managementError is Kotlin's ManagementException: an ApiError whose code picks the status, as
// respondManagementError does.
type managementError struct {
	code   string
	params api.Params
}

func (e *managementError) Error() string { return e.code }

func required(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return &managementError{"common.field_required", api.Params{{"fields", field}}}
	}
	return nil
}

func notFound(resource string) error {
	return &managementError{"common.not_found", api.Params{{"resource", resource}}}
}

// unique turns a unique-constraint violation into common.already_exists, as Kotlin's unique() does.
func unique(err error, resource, name string) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return &managementError{"common.already_exists", api.Params{{"resource", resource}, {"name", name}}}
	}
	return err
}

func updateSummary(typ, before, after string) string {
	if before == after {
		return "update " + typ + " '" + before + "'"
	}
	return "update " + typ + " '" + before + "' -> '" + after + "'"
}

// cedarErrors is a policy source the validator rejected; Kotlin answers it as 400 {"errors": [...]}.
type cedarErrors []string

func (cedarErrors) Error() string { return "invalid cedar policy" }

// mutate runs change in one transaction with its audit rows, then afterCommit, then answers status with its
// result, or the management error it returned.
func (p policies) mutate(w http.ResponseWriter, r *http.Request, status int, change func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error), afterCommit ...func(context.Context) error) {
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
			err = f(ctx)
		}
	}
	var me *managementError
	var ce cedarErrors
	switch {
	case errors.As(err, &ce):
		api.WriteJSON(w, http.StatusBadRequest, map[string][]string{"errors": ce})
	case errors.As(err, &me):
		code := http.StatusBadRequest
		switch me.code {
		case "common.not_found":
			code = http.StatusNotFound
		case "role.system_immutable", "policy.system_immutable":
			code = http.StatusConflict
		}
		api.WriteErrorParams(w, code, me.code, me.params)
	case err != nil:
		fail(w, err)
	case out == nil:
		w.WriteHeader(status)
	default:
		api.WriteJSON(w, status, out)
	}
}

// decodeBody reads exactly one JSON value; anything after it fails the request before it changes anything.
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil || dec.More() {
		return &managementError{"common.invalid_value", api.Params{{"field", "body"}}}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &managementError{"common.invalid_value", api.Params{{"field", "body"}}}
	}
	return nil
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// withID answers a non-numeric {id} with 400 common.bad_id before anything else, as Kotlin's idParam does.
func withID(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(r)
		if !ok {
			api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
			return
		}
		next(w, r, id)
	}
}

type roleInput struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

func getRole(ctx context.Context, tx pgx.Tx, id int64) (*role, error) {
	row, err := db.New(tx).Role(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("role")
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
		return &managementError{"role.system_immutable", nil}
	}
	return nil
}

func (p policies) createRole(w http.ResponseWriter, r *http.Request) {
	var in roleInput
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := required("name", in.Name); err != nil {
			return nil, err
		}
		row, err := db.New(tx).CreateRole(ctx, db.CreateRoleParams{Name: in.Name, Description: in.Description})
		created := role(row)
		if err != nil {
			return nil, unique(err, "role", in.Name)
		}
		return created, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Role", created.Name), "create role '"+created.Name+"'")
	})
}

func (p policies) updateRole(w http.ResponseWriter, r *http.Request, id int64) {
	var in roleInput
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
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
		if err := required("name", in.Name); err != nil {
			return nil, err
		}
		if err := db.New(tx).UpdateRole(ctx, db.UpdateRoleParams{Name: in.Name, Description: in.Description, ID: id}); err != nil {
			return nil, unique(err, "role", in.Name)
		}
		updated, err := getRole(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return updated, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("Role", updated.Name), updateSummary("role", current.Name, updated.Name))
	})
}

func (p policies) deleteRole(w http.ResponseWriter, r *http.Request, id int64) {
	p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
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

func (p policies) assignRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Principal string `json:"principal"`
		RoleID    int64  `json:"roleId"`
	}
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := required("principal", in.Principal); err != nil {
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

func (p policies) unassignRole(w http.ResponseWriter, r *http.Request, id int64) {
	p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		q := db.New(tx)
		a, err := q.RoleAssignment(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("role assignment")
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
		return nil, notFound("mask function")
	}
	m := maskFn(row)
	return &m, err
}

func (p policies) createMaskFn(w http.ResponseWriter, r *http.Request) {
	var in maskFnInput
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := required("name", in.Name); err != nil {
			return nil, err
		}
		if err := required("kind", in.Kind); err != nil {
			return nil, err
		}
		row, err := db.New(tx).CreateMaskFn(ctx, db.CreateMaskFnParams{Name: in.Name, Kind: in.Kind})
		created := maskFn(row)
		if err != nil {
			return nil, unique(err, "mask function", in.Name)
		}
		return created, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("MaskFn", created.Name), "create mask function '"+created.Name+"'")
	})
}

func (p policies) updateMaskFn(w http.ResponseWriter, r *http.Request, id int64) {
	var in maskFnInput
	decodeErr := decodeBody(r, &in)
	p.mutate(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if decodeErr != nil {
			return nil, decodeErr
		}
		current, err := getMaskFn(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := required("name", in.Name); err != nil {
			return nil, err
		}
		if err := required("kind", in.Kind); err != nil {
			return nil, err
		}
		if err := db.New(tx).UpdateMaskFn(ctx, db.UpdateMaskFnParams{Name: in.Name, Kind: in.Kind, ID: id}); err != nil {
			return nil, unique(err, "mask function", in.Name)
		}
		updated, err := getMaskFn(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return updated, audit.Admin(ctx, tx, actor, "admin.policies", audit.Entity("MaskFn", updated.Name), updateSummary("mask function", current.Name, updated.Name))
	})
}

func (p policies) deleteMaskFn(w http.ResponseWriter, r *http.Request, id int64) {
	p.mutate(w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
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
