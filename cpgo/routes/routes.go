// Package routes holds the control-plane HTTP routes served in Go. Anything not registered here is
// forwarded to the Kotlin control plane.
package routes

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/access"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/auditlog"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/datasources"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/identity"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/me"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/policies"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/tokens"
	"github.com/ridi-oss/proxy-monster/cpgo/routes/websession"
)

// Register adds every Go-served route to mux.
func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate) {
	websession.Register(mux, pool, gate)
	me.Register(mux, pool, gate)
	auditlog.Register(mux, pool, gate)
	policies.Register(mux, pool, gate)
	access.Register(mux, pool, gate)
	tokens.Register(mux, pool, gate)
	identity.Register(mux, pool, gate)
	datasources.Register(mux, pool, gate)
	mux.Handle("GET /api/datasources/live", front.Kotlin{})
}
