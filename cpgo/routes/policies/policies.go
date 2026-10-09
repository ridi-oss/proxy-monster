package policies

import (
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) {
	p := policies{pool: pool, authz: gate.Authz, kotlin: gate.Kotlin}
	mux.HandleFunc("GET /api/roles", gate.RequireAPI(p.roles))
	mux.HandleFunc("GET /api/role-assignments", gate.RequireAdmin("admin.identity", p.roleAssignments))
	mux.HandleFunc("GET /api/mask-fns", gate.RequireAdmin("admin.policies", p.maskFns))
	mux.HandleFunc("GET /api/policies", gate.RequireAdmin("admin.policies", p.policies))
	mux.HandleFunc("POST /api/roles", gate.RequireAdmin("admin.policies", p.createRole))
	mux.HandleFunc("PUT /api/roles/{id}", gate.RequireAdmin("admin.policies", api.WithID(p.updateRole)))
	mux.HandleFunc("DELETE /api/roles/{id}", gate.RequireAdmin("admin.policies", api.WithID(p.deleteRole)))
	mux.HandleFunc("POST /api/role-assignments", gate.RequireAdmin("admin.identity", p.assignRole))
	mux.HandleFunc("DELETE /api/role-assignments/{id}", gate.RequireAdmin("admin.identity", api.WithID(p.unassignRole)))
	mux.HandleFunc("POST /api/mask-fns", gate.RequireAdmin("admin.policies", p.createMaskFn))
	mux.HandleFunc("PUT /api/mask-fns/{id}", gate.RequireAdmin("admin.policies", api.WithID(p.updateMaskFn)))
	mux.HandleFunc("DELETE /api/mask-fns/{id}", gate.RequireAdmin("admin.policies", api.WithID(p.deleteMaskFn)))
	mux.HandleFunc("POST /api/policies", gate.RequireAdmin("admin.policies", p.createPolicy))
	mux.HandleFunc("PUT /api/policies/{id}", gate.RequireAdmin("admin.policies", api.WithID(p.updatePolicy)))
	mux.HandleFunc("DELETE /api/policies/{id}", gate.RequireAdmin("admin.policies", api.WithID(p.deletePolicy)))
	mux.HandleFunc("POST /api/policies/{id}/enable", gate.RequireAdmin("admin.policies", api.WithID(p.setPolicyEnabled(true))))
	mux.HandleFunc("POST /api/policies/{id}/disable", gate.RequireAdmin("admin.policies", api.WithID(p.setPolicyEnabled(false))))
	mux.HandleFunc("POST /api/policies/validate", gate.RequireAdmin("admin.policies", p.validatePolicy))
	mux.HandleFunc("GET /api/me/permissions", gate.RequireAPI(permissions(gate.Authz)))
}

type policies struct {
	pool   *pgxpool.Pool
	authz  api.Authorizer
	kotlin api.Kotlin
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
	api.WriteRows(w, rows, err, func(r db.RolesRow) role { return role(r) })
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
		api.WriteRows(w, rows, err, func(r db.RoleAssignmentsOfPrincipalRoleRow) roleAssignment { return roleAssignment(r) })
	case q.Has("principal"):
		rows, err := queries.RoleAssignmentsOfPrincipal(ctx, q.Get("principal"))
		api.WriteRows(w, rows, err, func(r db.RoleAssignmentsOfPrincipalRow) roleAssignment { return roleAssignment(r) })
	case q.Has("roleId"):
		rows, err := queries.RoleAssignmentsOfRole(ctx, roleID)
		api.WriteRows(w, rows, err, func(r db.RoleAssignmentsOfRoleRow) roleAssignment { return roleAssignment(r) })
	default:
		rows, err := queries.RoleAssignments(ctx)
		api.WriteRows(w, rows, err, func(r db.RoleAssignmentsRow) roleAssignment { return roleAssignment(r) })
	}
}

func (p policies) maskFns(w http.ResponseWriter, r *http.Request) {
	rows, err := db.New(p.pool).MaskFns(r.Context())
	api.WriteRows(w, rows, err, func(r db.MaskFnsRow) maskFn { return maskFn(r) })
}

func (p policies) policies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.New(p.pool).Policies(r.Context())
	api.WriteRows(w, rows, err, func(r db.PoliciesRow) cedarPolicy {
		return cedarPolicy{ID: r.ID, Origin: r.Origin, SystemKey: r.SystemKey, Name: r.Name, CedarSrc: r.CedarSrc,
			Enabled: r.Enabled, UpdatedBy: r.UpdatedBy, UpdatedAt: api.JavaInstant(r.UpdatedAt)}
	})
}
