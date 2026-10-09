package routes

import (
	"net/http"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
)

type mePermissions struct {
	IsAdmin         bool `json:"isAdmin"`
	CanReadAllAudit bool `json:"canReadAllAudit"`
	CanApprove      bool `json:"canApprove"`
}

// permissions is Kotlin's computeMePermissions: the console's coarse flags, each Cedar's own decision.
// UI guards are convenience only; every route still authorizes on its own.
func permissions(authz api.Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ask := func(action string, res bridge.Resource) (bool, error) {
			ok, _, err := authz.Authorize(ctx, api.Principal(ctx), action, res, api.RequesterIP(ctx))
			return ok, err
		}
		var out mePermissions
		for _, action := range []string{"admin.datasources", "admin.policies", "admin.identity"} {
			ok, err := ask(action, bridge.System)
			if err != nil {
				fail(w, err)
				return
			}
			out.IsAdmin = out.IsAdmin || ok
		}
		ok, err := ask("audit.read", bridge.AuditLog)
		if err != nil {
			fail(w, err)
			return
		}
		out.CanReadAllAudit = ok
		// task.approve is request-scoped, so there is no honest coarse System check yet.
		out.CanApprove = out.IsAdmin
		api.WriteJSON(w, http.StatusOK, out)
	}
}
