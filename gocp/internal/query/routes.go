package query

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/datasource"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// DebugPrincipal is `call.userSession()?.principal ?: "debug-user"` — the PM_AUTH_DEBUG fallback this
// route shares with the editor and query-history groups.
const DebugPrincipal = "debug-user"

// Datasources is the one method this route needs from A5's store. *datasource.DatasourceStore
// satisfies it.
type Datasources interface {
	Get(ctx context.Context, id int64) (datasource.Datasource, bool, error)
}

// History is `historyStore.add(principal, id, req.sql)` — A7 §9's convenience list.
// *queryhistory.Store satisfies it.
//
// ⚠️ It is declared here rather than imported because internal/queryhistory imports internal/httpapi
// and would otherwise be a dependency of the decision package for one INSERT.
type History interface {
	Add(ctx context.Context, principal string, datasourceID *int64, sql string) error
}

// Routes is `Route.queryRoutes(config, datasourceStore, historyStore, runExecService)`
// (Query.kt:846-878) — ONE route.
//
//	POST /api/datasources/{id}/query   requireApi
//
// # Why it lives in internal/query and not internal/datasource
//
// The path sits under `/api/datasources/`, and A5 owns thirteen routes under that prefix — but this
// one is A6's (Query.kt), and internal/datasource/routes.go's Register says so explicitly: claiming a
// path another area owns would PANIC THE MUX AT BOOT the moment the owner registered it too. Go's
// ServeMux rejects duplicate patterns at registration rather than silently letting one win, so the two
// groups must not overlap.
//
// # It is a thin wrapper, and the thinness is the design
//
// Everything interesting happens inside [RunExec.Run]: mint, dial, per-statement decide over gRPC,
// enforced result, teardown. This handler resolves an id, records the SQL to history best-effort, and
// maps the four transport failures to their statuses. That is why the route and its transport landed
// together — there was nothing to port until RunExecService existed.
type Routes struct {
	gates   *httpapi.Gates
	store   Datasources
	history History
	runExec RunExec
	// exchangeMs is `exchangeTimeoutMs = config.queryExchangeTimeoutMs` — passed at the call site, NOT
	// defaulted, so a deployment's PM_QUERY_TIMEOUT actually bounds a synchronous query.
	exchangeMs int64
	log        *slog.Logger
}

// RouteDeps is [NewRoutes]'s parameter list.
type RouteDeps struct {
	Gates       *httpapi.Gates
	Datasources Datasources
	History     History
	RunExec     RunExec
	// ExchangeTimeoutMs is Config.QueryExchangeTimeoutMS(). Zero falls back to
	// config.ExchangeTimeoutMS inside the service.
	ExchangeTimeoutMs int64
	Log               *slog.Logger
}

// NewRoutes builds the group.
func NewRoutes(d RouteDeps) *Routes {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Routes{
		gates: d.Gates, store: d.Datasources, history: d.History, runExec: d.RunExec,
		exchangeMs: d.ExchangeTimeoutMs, log: log,
	}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the one pattern.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/datasources/{id}/query", rt.run)
}

// run is `POST /api/datasources/{id}/query` — the SYNCHRONOUS query path.
//
// The order is Query.kt:852-876's: gate → id → datasource → body → principal → history → run.
//
// ⚠️ IT IS SYNCHRONOUS, unlike the editor's 202-then-poll submit. The connection is held for the whole
// exchange, and the response IS the rows. Nothing is persisted: no task, no `query_result` child, no
// task-level audit row — the per-statement Decide the proxy makes during the run already wrote the real
// audit decision, and a second row here would duplicate it as a false ALLOW (the same reasoning as
// INV-A6-24).
func (rt *Routes) run(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}
	ds, found, err := rt.store.Get(r.Context(), *id)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if !found {
		rt.respondError(w, types.NotFound("datasource"))
		return
	}
	body, err := readRawBody(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	req, err := DecodeQueryRequest(body)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}

	// `runCatching { historyStore.add(principal, id, req.sql) }` — auto-save to the principal's editor
	// history, BEST-EFFORT.
	//
	// 🔒 A history failure must never block or fail the query. The table is explicitly
	// convenience-only; the security record is `audit_event`, written by the decide the run triggers.
	// A blank statement is skipped inside Add, so nothing here needs to check it.
	if rt.history != nil {
		if err := rt.history.Add(r.Context(), principal, id, req.SQL); err != nil {
			rt.log.Warn("query history add failed", "principal", principal, "err", err)
		}
	}

	response, err := rt.runExec.Run(r.Context(), RunInput{
		Principal:   principal,
		Datasource:  ds,
		SQL:         req.SQL,
		MaxRows:     req.MaxRows,
		RequesterIP: rt.gates.AuthzContext(r).RequesterIP,
		// ⚠️ approverExec=false, assumeRoles empty, taskId nil, preflight nil — ALL Kotlin defaults.
		// This route mints an EDITOR token and decides under the caller's OWN server-resolved roles.
		// There is no elevation path here: execute-under-R is `/api/approvals/{id}/execute`'s.
		ExchangeTimeoutMs: rt.exchangeMs,
	})
	if err != nil {
		rt.respondRunExecError(w, r, err)
		return
	}
	if err := httpapi.RespondJSON(w, http.StatusOK, response); err != nil {
		rt.log.Error("failed to write query response", "path", r.URL.Path, "err", err)
	}
}

// respondRunExecError is Query.kt:868-876's four catch arms:
//
//	NoProxyAttached    ⇒ 503 query.no_proxy_attached
//	ProxyStreamWedged  ⇒ 503 query.proxy_stream_wedged   🔒 INV-A7-34 — distinct from the above
//	ProxyRunTimeout    ⇒ 504 query.proxy_timeout
//	ProxyRunError      ⇒ 502 query.failed{detail}
//
// It is byte-for-byte the mapping approval.EditorRoutes.respondRunExecError carries, and the
// duplication is deliberate: internal/query cannot import internal/approval (that package imports
// this one), and the alternative — hoisting a shared responder — would put HTTP status choices in the
// transport contract, where a route-level decision does not belong.
//
// ⚠️ `detail` is the exception's own English MESSAGE on the wire (`e.message ?: ""`), which sits
// uneasily with INV-A1-13's "never English prose on the wire". REPRODUCE — same disposition as F13's
// denyReason.
//
// ⚠️ ErrRunCanceledBeforeStart has NO arm, in the Kotlin or here. This route passes no taskId, so no
// cancel gate is ever registered for it and the sentinel cannot arise. Were one to arrive it would
// fall through to RespondFallback's 500, which is the honest answer to an impossible state.
func (rt *Routes) respondRunExecError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNoProxyAttached):
		rt.respondCode(w, http.StatusServiceUnavailable, "query.no_proxy_attached", nil)
	case errors.Is(err, ErrProxyStreamWedged):
		rt.respondCode(w, http.StatusServiceUnavailable, "query.proxy_stream_wedged", nil)
	case errors.Is(err, ErrProxyRunTimeout):
		rt.respondCode(w, http.StatusGatewayTimeout, "query.proxy_timeout", nil)
	default:
		var pre *ProxyRunError
		if errors.As(err, &pre) {
			rt.respondCode(w, http.StatusBadGateway, "query.failed", map[string]string{"detail": pre.Message})
			return
		}
		// Not a RunExecException at all — a bug or a store failure. The Kotlin lets it reach
		// StatusPages, and so does this.
		httpapi.RespondFallback(w, r, rt.log, err)
	}
}

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

func (rt *Routes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}

func (rt *Routes) respondCode(w http.ResponseWriter, status int, code string, params map[string]string) {
	rt.respondError(w, types.ErrorResponse{Status: status, Body: types.ApiError{Code: code, Params: params}})
}

// readRawBody defers decoding so [DecodeQueryRequest] can apply Kotlin's `maxRows: Int = 500`
// default, which encoding/json cannot express on a plain int field.
// ⚠️ The destination is json.RawMessage, NOT []byte: encoding/json decodes a []byte from a base64
// STRING, so `var raw []byte` would reject every object body with "cannot unmarshal object into
// []uint8" and turn a valid query into a 500.
func readRawBody(r *http.Request) ([]byte, error) {
	var raw json.RawMessage
	if err := httpapi.Receive(r, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
