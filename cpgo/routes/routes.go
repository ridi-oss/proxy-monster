// Package routes holds the control-plane HTTP routes served in Go. Anything not registered here is
// forwarded to the Kotlin control plane.
package routes

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/front"
	"github.com/ridi-oss/proxy-monster/cpgo/idp"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// locales is the closed set the message catalog carries (MessageCatalog.LOCALES).
var locales = []string{"en", "ko"}

// Register adds every Go-served route to mux.
// Login is the OIDC relying party; a nil Provider leaves OIDC login unconfigured (501).
type Login struct {
	Provider *idp.Provider
	Crypto   *idp.Crypto
}

func Register(mux *http.ServeMux, pool *pgxpool.Pool, gate api.Gate, login Login) {
	h := handlers{pool: pool}
	au := auth{pool: pool, sessions: gate.Sessions, kotlin: gate.Kotlin, edges: gate.Edges}
	mux.HandleFunc("GET /auth/config", au.config)
	mux.HandleFunc("POST /auth/debug", au.debugLogin)
	mux.HandleFunc("GET /auth/me", au.sessionGate(au.me))
	mux.HandleFunc("GET /auth/session/status", au.sessionGate(au.status))
	mux.HandleFunc("POST /auth/session/heartbeat", au.sessionGate(au.heartbeat))
	mux.HandleFunc("POST /auth/logout", au.logout)
	oi := oidcLogin{auth: au, provider: login.Provider, crypto: login.Crypto}
	mux.HandleFunc("GET /auth/oidc/login", oi.login)
	mux.HandleFunc("GET /auth/oidc/callback", oi.callback)
	mux.HandleFunc("PUT /api/me/locale", gate.RequireAPI(h.putLocale))
	mux.HandleFunc("GET /api/query-history", gate.RequireAPI(h.getQueryHistory))
	mux.HandleFunc("DELETE /api/query-history", gate.RequireAPI(h.deleteQueryHistory))
	a := auditLog{pool: pool, authz: gate.Authz}
	mux.HandleFunc("GET /api/audit", gate.RequireAPI(a.list))
	mux.HandleFunc("GET /api/audit/{id}", gate.RequireAPI(a.get))
	p := policies{pool: pool, authz: gate.Authz}
	mux.HandleFunc("GET /api/roles", gate.RequireAPI(p.roles))
	mux.HandleFunc("GET /api/role-assignments", gate.RequireAdmin("admin.identity", p.roleAssignments))
	mux.HandleFunc("GET /api/mask-fns", gate.RequireAdmin("admin.policies", p.maskFns))
	mux.HandleFunc("GET /api/policies", gate.RequireAdmin("admin.policies", p.policies))
	mux.HandleFunc("POST /api/roles", gate.RequireAdmin("admin.policies", p.createRole))
	mux.HandleFunc("PUT /api/roles/{id}", gate.RequireAdmin("admin.policies", withID(p.updateRole)))
	mux.HandleFunc("DELETE /api/roles/{id}", gate.RequireAdmin("admin.policies", withID(p.deleteRole)))
	mux.HandleFunc("POST /api/role-assignments", gate.RequireAdmin("admin.identity", p.assignRole))
	mux.HandleFunc("DELETE /api/role-assignments/{id}", gate.RequireAdmin("admin.identity", withID(p.unassignRole)))
	mux.HandleFunc("POST /api/mask-fns", gate.RequireAdmin("admin.policies", p.createMaskFn))
	mux.HandleFunc("PUT /api/mask-fns/{id}", gate.RequireAdmin("admin.policies", withID(p.updateMaskFn)))
	mux.HandleFunc("DELETE /api/mask-fns/{id}", gate.RequireAdmin("admin.policies", withID(p.deleteMaskFn)))
	mux.HandleFunc("POST /api/policies", gate.RequireAdmin("admin.policies", p.createPolicy))
	mux.HandleFunc("PUT /api/policies/{id}", gate.RequireAdmin("admin.policies", withID(p.updatePolicy)))
	mux.HandleFunc("DELETE /api/policies/{id}", gate.RequireAdmin("admin.policies", withID(p.deletePolicy)))
	mux.HandleFunc("POST /api/policies/{id}/enable", gate.RequireAdmin("admin.policies", withID(p.setPolicyEnabled(true))))
	mux.HandleFunc("POST /api/policies/{id}/disable", gate.RequireAdmin("admin.policies", withID(p.setPolicyEnabled(false))))
	mux.HandleFunc("POST /api/policies/validate", gate.RequireAdmin("admin.policies", p.validatePolicy))
	mux.HandleFunc("GET /api/me/permissions", gate.RequireAPI(permissions(gate.Authz)))
	ac := access{pool: pool, authz: gate.Authz}
	mux.HandleFunc("GET /api/access-requests", gate.RequireAPI(ac.requests))
	mux.HandleFunc("GET /api/access-grants", gate.RequireAPI(ac.grants))
	mux.HandleFunc("GET /api/approvals", gate.RequireAPI(ac.ownApprovals))
	mux.HandleFunc("POST /api/access-requests", gate.RequireAPI(ac.createRequest))
	mux.HandleFunc("POST /api/access-requests/rate-reset", gate.RequireAPI(ac.requestRateReset))
	mux.HandleFunc("POST /api/access/principals/{principal}/rate-reset", gate.RequireAdmin("admin.identity", ac.resetRate))
	mux.HandleFunc("GET /api/access/principals/{principal}/rate-reset", gate.RequireAdmin("admin.identity", ac.lastRateReset))
	mux.HandleFunc("POST /api/access-requests/{id}/approve", gate.RequireAPI(withID(ac.approve)))
	mux.HandleFunc("POST /api/access-requests/{id}/reject", gate.RequireAPI(withID(ac.reject)))
	mux.HandleFunc("POST /api/access-grants/{id}/revoke", gate.RequireAPIElse(ac.unauthenticatedRevoke, withID(ac.revokeGrant)))
	tk := tokens{pool: pool, authz: gate.Authz}
	mux.HandleFunc("POST /api/wire-tokens", gate.RequireAPI(tk.mintSession))
	mux.HandleFunc("GET /api/tokens", gate.RequireAPI(tk.list))
	mux.HandleFunc("POST /api/tokens", gate.RequireAPI(tk.mintUser))
	mux.HandleFunc("DELETE /api/tokens/{id}", gate.RequireAPIElse(tk.unauthenticatedRevoke, withID(tk.revoke)))
	id := identity{pool: pool, kotlin: gate.Kotlin, sessions: gate.Sessions}
	admin := func(h http.HandlerFunc) http.HandlerFunc { return gate.RequireAdmin("admin.identity", h) }
	mux.HandleFunc("GET /api/users", admin(id.listUsers))
	mux.HandleFunc("POST /api/users", admin(id.createUser))
	mux.HandleFunc("PUT /api/users/{id}", admin(withID(id.updateUser)))
	mux.HandleFunc("DELETE /api/users/{id}", admin(withID(id.deprovisionUser)))
	mux.HandleFunc("GET /api/groups", admin(id.listGroups))
	mux.HandleFunc("POST /api/groups", admin(id.createGroup))
	mux.HandleFunc("PUT /api/groups/{id}", admin(withID(id.updateGroup)))
	mux.HandleFunc("DELETE /api/groups/{id}", admin(withID(id.deleteGroup)))
	mux.HandleFunc("GET /api/groups/{id}/members", admin(withID(id.members)))
	mux.HandleFunc("POST /api/groups/{id}/members", admin(withID(id.addMember)))
	mux.HandleFunc("DELETE /api/groups/{id}/members/{userId}", admin(withID(id.removeMember)))
	mux.HandleFunc("GET /api/groups/{id}/roles", admin(withID(id.groupRoles)))
	mux.HandleFunc("POST /api/groups/{id}/roles", admin(withID(id.addGroupRole)))
	mux.HandleFunc("DELETE /api/groups/{id}/roles/{roleId}", admin(withID(id.removeGroupRole)))
	ds := datasources{pool: pool, authz: gate.Authz, kotlin: gate.Kotlin}
	mux.HandleFunc("POST /api/datasources", gate.RequireAdmin("admin.datasources", ds.create))
	mux.HandleFunc("PUT /api/datasources/{id}", gate.RequireAdmin("admin.datasources", withID(ds.update)))
	mux.HandleFunc("DELETE /api/datasources/{id}", gate.RequireAdmin("admin.datasources", withID(ds.delete)))
	mux.HandleFunc("PUT /api/datasources/{id}/classification", gate.RequireAdmin("admin.datasources", withID(ds.setClassification)))
	mux.HandleFunc("DELETE /api/datasources/{id}/classification", gate.RequireAdmin("admin.datasources", withID(ds.clearClassification)))
	mux.HandleFunc("GET /api/datasources", gate.RequireAPIOrBearer(ds.list))
	mux.HandleFunc("GET /api/datasources/{id}", gate.RequireAPIOrBearer(withID(ds.get)))
	mux.Handle("GET /api/datasources/live", front.Kotlin)
	mux.HandleFunc("GET /api/datasources/{id}/wire-cert", gate.RequireAPIOrBearer(withID(ds.wireCert)))
}

type handlers struct{ pool *pgxpool.Pool }

// putLocale stores the caller's display language, which notification delivery reads.
func (h handlers) putLocale(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Locale string `json:"locale"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "locale"})
		return
	}
	locale := strings.ToLower(strings.TrimSpace(in.Locale))
	if !slices.Contains(locales, locale) {
		api.WriteError(w, http.StatusBadRequest, "common.invalid_value", map[string]string{"field": "locale"})
		return
	}
	// A principal with no directory row keeps the instance default; that is not an error.
	if err := db.New(h.pool).SetLocale(r.Context(), db.SetLocaleParams{Locale: &locale, Principal: api.Principal(r.Context())}); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type historyEntry struct {
	SQL          string `json:"sql"`
	DatasourceID *int64 `json:"datasourceId,omitempty"`
	RanAt        string `json:"ranAt"`
}

// getQueryHistory returns the caller's most recent distinct queries, newest first.
func (h handlers) getQueryHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
		limit = min(max(n, 1), 200)
	}
	rows, err := db.New(h.pool).QueryHistory(r.Context(), db.QueryHistoryParams{Principal: api.Principal(r.Context()), Limit: int32(limit)})
	if err != nil {
		fail(w, err)
		return
	}
	out := []historyEntry{}
	for _, row := range rows {
		out = append(out, historyEntry{SQL: row.Sql, DatasourceID: row.DatasourceID, RanAt: javaInstant(row.CreatedAt)})
	}
	api.WriteJSON(w, http.StatusOK, out)
}

func (h handlers) deleteQueryHistory(w http.ResponseWriter, r *http.Request) {
	if err := db.New(h.pool).DeleteQueryHistory(r.Context(), api.Principal(r.Context())); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func fail(w http.ResponseWriter, err error) {
	slog.Error("routes: store query failed", "err", err)
	api.WriteError(w, http.StatusInternalServerError, "common.fallback", nil)
}

// javaInstant formats t like java.time.Instant.toString: UTC, fractional seconds in groups of three
// digits, none when zero.
func javaInstant(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	switch ns := t.Nanosecond(); {
	case ns == 0:
	case ns%1_000_000 == 0:
		s += "." + leftPad(ns/1_000_000, 3)
	case ns%1_000 == 0:
		s += "." + leftPad(ns/1_000, 6)
	default:
		s += "." + leftPad(ns, 9)
	}
	return s + "Z"
}

func leftPad(n, width int) string {
	s := strconv.Itoa(n)
	return strings.Repeat("0", width-len(s)) + s
}
