package routes

import (
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

type policies struct {
	pool  *pgxpool.Pool
	authz api.Authorizer
}

type role struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

type roleAssignment struct {
	ID        int64  `json:"id"`
	Principal string `json:"principal"`
	RoleID    int64  `json:"roleId"`
	RoleName  string `json:"roleName"`
}

type maskFn struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type cedarPolicy struct {
	ID        int64   `json:"id"`
	Origin    string  `json:"origin"`
	SystemKey *string `json:"systemKey,omitempty"`
	Name      string  `json:"name"`
	CedarSrc  string  `json:"cedarSrc"`
	Enabled   bool    `json:"enabled"`
	UpdatedBy *string `json:"updatedBy,omitempty"`
	UpdatedAt string  `json:"updatedAt"`
}

func (p policies) roles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.New(p.pool).Roles(r.Context())
	writeRows(w, rows, err, func(r db.RolesRow) role { return role(r) })
}

// roleAssignments filters by principal and roleId when given; a roleId that is not a number matches nothing.
func (p policies) roleAssignments(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var roleID int64
	if q.Has("roleId") {
		id, err := strconv.ParseInt(q.Get("roleId"), 10, 64)
		if err != nil {
			api.WriteJSON(w, http.StatusOK, []roleAssignment{})
			return
		}
		roleID = id
	}
	queries, ctx := db.New(p.pool), r.Context()
	switch {
	case q.Has("principal") && q.Has("roleId"):
		rows, err := queries.RoleAssignmentsOfPrincipalRole(ctx, db.RoleAssignmentsOfPrincipalRoleParams{Principal: q.Get("principal"), RoleID: roleID})
		writeRows(w, rows, err, func(r db.RoleAssignmentsOfPrincipalRoleRow) roleAssignment { return roleAssignment(r) })
	case q.Has("principal"):
		rows, err := queries.RoleAssignmentsOfPrincipal(ctx, q.Get("principal"))
		writeRows(w, rows, err, func(r db.RoleAssignmentsOfPrincipalRow) roleAssignment { return roleAssignment(r) })
	case q.Has("roleId"):
		rows, err := queries.RoleAssignmentsOfRole(ctx, roleID)
		writeRows(w, rows, err, func(r db.RoleAssignmentsOfRoleRow) roleAssignment { return roleAssignment(r) })
	default:
		rows, err := queries.RoleAssignments(ctx)
		writeRows(w, rows, err, func(r db.RoleAssignmentsRow) roleAssignment { return roleAssignment(r) })
	}
}

func (p policies) maskFns(w http.ResponseWriter, r *http.Request) {
	rows, err := db.New(p.pool).MaskFns(r.Context())
	writeRows(w, rows, err, func(r db.MaskFnsRow) maskFn { return maskFn(r) })
}

func (p policies) policies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.New(p.pool).Policies(r.Context())
	writeRows(w, rows, err, func(r db.PoliciesRow) cedarPolicy {
		return cedarPolicy{ID: r.ID, Origin: r.Origin, SystemKey: r.SystemKey, Name: r.Name, CedarSrc: r.CedarSrc,
			Enabled: r.Enabled, UpdatedBy: r.UpdatedBy, UpdatedAt: javaInstant(r.UpdatedAt)}
	})
}

// writeRows answers with every row as a JSON array, [] when there are none.
func writeRows[R, T any](w http.ResponseWriter, rows []R, err error, to func(R) T) {
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		out = append(out, to(r))
	}
	api.WriteJSON(w, http.StatusOK, out)
}
