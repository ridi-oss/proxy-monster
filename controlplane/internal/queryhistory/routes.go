package queryhistory

import (
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/httpapi"
)

// DebugPrincipal is the `"debug-user"` fallback both routes use when PM_AUTH_DEBUG admitted a
// request with no session (07-tasks-approvals-results.md:631: "Both fall back to `"debug-user"`").
//
// ⚠️ Contrast internal/policy's `/api/policies` routes, which pass a NULL principal in the same
// situation rather than a literal. The difference is right: there, the principal lands on an audit
// row whose whole purpose is attribution (INV-A2-22), and a fabricated identity would be worse than
// none. Here it is a partition key for a convenience list, so a stable literal simply gives every
// debug session one shared history instead of dropping the feature.
const DebugPrincipal = "debug-user"

// Routes is `Route.queryHistoryRoutes(config, store)` — the two `/api/query-history` endpoints, both
// gated `requireApi(config)`.
//
//	GET    /api/query-history   `?limit=` default 50 coerced into [1, 200]
//	DELETE /api/query-history   **204**
//
// 🔒 BOTH ARE PRINCIPAL-SCOPED FROM THE SESSION AND ONLY FROM THE SESSION. There is no `principal`
// query parameter to honour, no admin view and no cross-principal read
// (07-tasks-approvals-results.md §9), and [Store] exposes no method that would allow one. requireApi
// is therefore the whole authorization: "is there a session" IS the question, because the session
// determines what the answer contains rather than merely whether one is given.
//
// ⚠️ Note the DELETE takes no id and has no confirmation step: it clears the caller's entire history.
// That is safe only because the table is explicitly convenience-only (V5__tasks.sql:104) — the
// security record is `audit_event`, which has no delete path at all.
type Routes struct {
	gates *httpapi.Gates
	store *Store
	log   *slog.Logger
}

// NewRoutes builds the group. A nil logger defaults to slog.Default().
func NewRoutes(gates *httpapi.Gates, store *Store, log *slog.Logger) *Routes {
	if log == nil {
		log = slog.Default()
	}
	return &Routes{gates: gates, store: store, log: log}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the two patterns. Same path, two methods — ServeMux gives 405 with
// `Allow: DELETE, GET, HEAD` for anything else, which Ktor gives too (it answers 405 for a path that
// matches with no method handler).
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/query-history", rt.list)
	mux.HandleFunc("DELETE /api/query-history", rt.clear)
}

// list is `GET /api/query-history` — 200 `[Entry]`, deduplicated by statement, newest first.
func (rt *Routes) list(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := CoerceLimit(q.Get("limit"), q.Has("limit"))

	entries, err := rt.store.Recent(r.Context(), principal, limit)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if err := httpapi.RespondJSON(w, http.StatusOK, entries); err != nil {
		rt.log.Error("failed to write query history", "err", err)
	}
}

// clear is `DELETE /api/query-history` — **204**, no body.
func (rt *Routes) clear(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}
	if err := rt.store.Clear(r.Context(), principal); err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// principal is `call.userSession()?.principal ?: "debug-user"`.
//
// The order matters and is the Kotlin's: the session is READ FIRST and the literal is the fallback,
// so a debug-mode request that DOES carry a session gets its real history rather than the shared
// debug one. Reversing it — branching on authDebug before looking — would make PM_AUTH_DEBUG silently
// merge every developer's history into one list.
//
// The bool is "keep going"; a resolver failure has already answered the StatusPages fallback.
func (rt *Routes) principal(w http.ResponseWriter, r *http.Request) (string, bool) {
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return "", false
	}
	if sess == nil {
		return DebugPrincipal, true
	}
	return sess.Principal, true
}
