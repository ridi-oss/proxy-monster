package audit

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// NotFoundResource is the `resource` param on both 404s: `notFound("audit record")`
// (08-audit.md §3).
//
// 🔒 INV-A8-6 — IT IS THE SAME STRING FOR BOTH FAILURES. A record that does not exist and a record
// the caller may not see answer byte-identical bodies, so no caller can probe for the existence of
// another principal's audit rows. It is a const rather than two literals so that a future edit to
// one call site cannot accidentally split them.
const NotFoundResource = "audit record"

// Routes is `Route.auditRoutes(config, authz, auditStore)` (AuditRoutes.kt, 67 LOC) — the two read
// endpoints, both gated `requireApi(config)`.
//
//	GET /api/audit        the collection, `?limit=` default 100 coerced into [1, 500]
//	GET /api/audit/{id}   one record
//
// 🔒 requireApi, NOT requireAdmin, and that is the two-tier visibility model rather than a loose
// gate: authorization happens INSIDE, per read, in [Reader]. An admin gate here would make the whole
// audit trail invisible to the ordinary user whose own rows it is — and "a user can always see what
// was decided about them" is the contract INV-A8-7 exists to state.
//
// This type owns only the HTTP mechanics. Every decision — who sees the collection, who sees a
// record, and the deliberate indistinguishability of denied and missing — is [Reader]'s, and was
// already landed and tested (read_db_test.go). 08-audit.md §4's three route-only cases are the ones
// that live here: case 1 (unauthenticated non-debug list), case 3 (non-numeric id is a bad id, not a
// lookup) and case 4 (the old /api/decisions route stays removed).
type Routes struct {
	gates  *httpapi.Gates
	reader *Reader
	log    *slog.Logger
}

// NewRoutes builds the group over an already-constructed [Reader]. A nil logger defaults to
// slog.Default().
//
// The Reader carries AuthDebug itself (INV-A8-8), so THIS TYPE never reads config.
//
// ⚠️ THAT IS NOT THE SAME AS "there is only one place to get it wrong", and an earlier revision of
// this comment claimed it was. `Routes` reads only the Reader's copy, but the GATE in front of it
// reads `httpapi.Gates.Config.AuthDebug` — two fields, no enforced agreement. Measured:
//
//	gate ON  + reader OFF ⇒ a sessionless request is ADMITTED and then cannot be served; the
//	                        postcondition below fires and the handler answers 500 common.fallback.
//	                        Fail-closed (no rows leak) but a 500 on a live surface.
//	gate OFF + reader ON  ⇒ harmless: requireApi demands a session, and the Reader then ignores the
//	                        principal it was handed.
//
// TestTheGateAndTheReaderMustAgreeAboutAuthDebug pins the first, and internal/app's
// TestAuditRoutesGetOneAuthDebugValue pins the wiring line that must pass `cfg.AuthDebug` to both.
func NewRoutes(gates *httpapi.Gates, reader *Reader, log *slog.Logger) *Routes {
	if log == nil {
		log = slog.Default()
	}
	return &Routes{gates: gates, reader: reader, log: log}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the two patterns.
//
// ⚠️ 08-audit.md §4 case 4 is a NEGATIVE route test — "old decisions route is removed" — and the way
// a Go port keeps it is by never registering `/api/decisions` and asserting the 404. Easy to lose:
// nothing fails when a route is absent, so the assertion has to be written on purpose.
// TestOldDecisionsRouteStaysRemoved is it.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/audit", rt.list)
	mux.HandleFunc("GET /api/audit/{id}", rt.detail)
}

// list is `GET /api/audit`.
//
//  1. requireApi
//  2. `limit` = query param or 100, `coerceIn(1, 500)` — [CoerceLimit]
//  3. authDebug ⇒ the whole log with no session and no authorization (INV-A8-8)
//  4. else AUDIT_READ on AuthzResource.AuditLog: Allow ⇒ whole log, Deny ⇒ the caller's OWN rows
//
// 🔒 INV-A8-7 — STEP 4's DENY BRANCH IS NOT A 403. A caller with no audit grant gets their own rows,
// which is the two-tier model the console is built on: own rows always, the whole log by grant. A
// port that "tightened" this to a 403 would take away every ordinary user's view of what was decided
// about them.
//
// INV-A8-8 — the debug bypass short-circuits BEFORE any session resolution, mirroring requireApi.
// The Kotlin's `requireNotNull(call.userSession())` after the bypass carries the message "audit list
// admitted a non-debug request without a UserSession"; it asserts requireApi's POSTCONDITION and is
// not a reachable user-facing error. Here it is a nil check that answers the StatusPages fallback —
// same unreachability, same loudness if the postcondition ever breaks.
func (rt *Routes) list(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	raw, present := queryParam(r, "limit")
	limit := CoerceLimit(raw, present)

	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}

	events, err := rt.reader.List(r.Context(), limit, principal, rt.authzContext(r))
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	// `[]`, never nil — INV-A1-4. An empty feed is `[]` and the console renders `.length` on it.
	if events == nil {
		events = []types.AuditEvent{}
	}
	rt.respond(w, r, http.StatusOK, events)
}

// detail is `GET /api/audit/{id}`.
//
//  1. requireApi
//  2. bad id ⇒ `badId()` — 🔒 08-audit.md §4 case 3: "non-numeric audit id is a bad id, NOT a
//     lookup". The parse failure answers before the store is touched, so `/api/audit/abc` is a 400
//     and never a 404, and it never costs a query.
//  3. missing row ⇒ `notFound("audit record")`
//  4. authDebug ⇒ respond
//  5. else AUDIT_READ on AuthzResource.AuditRecord(record.principal): Allow ⇒ respond,
//     Deny ⇒ `notFound("audit record")`
//
// 🔒 INV-A8-6 — STEPS 3 AND 5 ANSWER THE SAME BODY. [Reader.Detail] returns (nil, nil) for both, so
// this handler is STRUCTURALLY unable to tell them apart — the guarantee is enforced by the return
// type rather than by remembering to write the same literal twice. `AuditReadRoutesDbTest` case 2
// pins it.
func (rt *Routes) detail(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return
	}

	principal, ok := rt.principal(w, r)
	if !ok {
		return
	}

	record, err := rt.reader.Detail(r.Context(), *id, principal, rt.authzContext(r))
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return
	}
	if record == nil {
		rt.respondError(w, types.NotFound(NotFoundResource))
		return
	}
	rt.respond(w, r, http.StatusOK, *record)
}

// ---------------------------------------------------------------------------------------------

// principal resolves the caller for the two [Reader] calls.
//
// Under AuthDebug the Reader IGNORES this value (INV-A8-8), so the session is not read at all — the
// same short-circuit requireApi took a moment earlier, and the reason a debug request needs no
// session to read the whole log.
//
// The empty-string return when there is no session is unreachable in a non-debug request, because
// requireApi already rejected it; it is the Kotlin's `requireNotNull(...)` postcondition, and if it
// ever fires the empty principal matches no rows rather than matching all of them.
func (rt *Routes) principal(w http.ResponseWriter, r *http.Request) (string, bool) {
	if rt.reader.AuthDebug {
		return "", true
	}
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		httpapi.RespondFallback(w, r, rt.log, err)
		return "", false
	}
	if sess == nil {
		// requireApi's postcondition broke. Answer the fallback rather than reading the log as "".
		httpapi.RespondFallback(w, r, rt.log, errAuditSessionMissing)
		return "", false
	}
	return sess.Principal, true
}

// authzContext is `call.httpAuthzContext(config)` — the request-scoped Cedar context.
//
// 🔴 IT IS EMPTY UNTIL A12 LANDS, and for these two routes that is a REAL divergence, not a
// theoretical one: `AuditReadRoutesDbTest` case 7 is "`requester_ip` from a trusted edge gates the
// audit-collection read", so a deployment whose `audit.read` grant is ip-conditioned will fall
// through to own-rows here where the Kotlin returns the whole log. Fail-closed (INV-A2-8 — a policy
// conditioning on an absent attribute does not fire) and INV-A8-7 makes the failure a narrower view
// rather than an error, which is why this is survivable in the interim.
//
// It reads through httpapi.Gates.Context rather than keeping its own seam, so the day A12 wires the
// real context in ONE place both the gates and these routes get it.
//
//	TODO(A12): 12-request-context.md §2.
func (rt *Routes) authzContext(r *http.Request) authz.AuthzContext {
	if rt.gates.Context == nil {
		return authz.AuthzContext{}
	}
	return rt.gates.Context(r)
}

// queryParam is Ktor's `queryParameters["name"]`: the value plus whether the key was there at all.
//
// The pair matters because [CoerceLimit] folds absent and unparseable into the same default, and
// Go's Query().Get() returns "" for both "absent" and "?limit=" — which are the same answer HERE
// only by luck. Keeping the presence bit explicit means the next caller of this helper does not have
// to rediscover the distinction.
func queryParam(r *http.Request, name string) (string, bool) {
	q := r.URL.Query()
	if !q.Has(name) {
		return "", false
	}
	return q.Get(name), true
}

func (rt *Routes) respond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpapi.RespondJSON(w, status, body); err != nil {
		rt.log.Error("failed to write response", "path", r.URL.Path, "status", status, "err", err)
	}
}

func (rt *Routes) respondError(w http.ResponseWriter, e types.ErrorResponse) {
	if err := httpapi.RespondAPIError(w, e); err != nil {
		rt.log.Error("failed to write error response", "code", e.Body.Code, "err", err)
	}
}

// errAuditSessionMissing is the Kotlin's `requireNotNull(call.userSession()) { "audit list admitted a
// non-debug request without a UserSession" }` message, verbatim (08-audit.md:126-128). It is
// unreachable — requireApi rejects a sessionless non-debug request before either handler runs — and
// exists so that if it ever DOES fire, the log line names the broken postcondition rather than
// showing a nil dereference.
var errAuditSessionMissing = errors.New("audit list admitted a non-debug request without a UserSession")
