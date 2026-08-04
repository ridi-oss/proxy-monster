package datasource

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ridi-oss/proxy-monster/gocp/internal/authz"
	"github.com/ridi-oss/proxy-monster/gocp/internal/engine"
	"github.com/ridi-oss/proxy-monster/gocp/internal/httpapi"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// A5's HTTP surface — `fun Route.datasourceRoutes(...)` (Datasources.kt:759-968), thirteen routes.
// ---------------------------------------------------------------------------------------------
//
//	GET    /api/datasources                     requireApiOrBearer      200 Datasource[]
//	GET    /api/datasources/live                requireApi              200 string[]
//	POST   /api/datasources/{id}/refresh        ADMIN_DATASOURCES       200 RefreshResult
//	POST   /api/datasources                     ADMIN_DATASOURCES       201 Datasource
//	GET    /api/datasources/{id}                requireApi              200 Datasource
//	PUT    /api/datasources/{id}                ADMIN_DATASOURCES       200 Datasource
//	DELETE /api/datasources/{id}                ADMIN_DATASOURCES       204
//	POST   /api/datasources/{id}/test           ADMIN_DATASOURCES       200 TestResult
//	GET    /api/datasources/{id}/catalog        requireApiOrBearer + mayConnect   200 CatalogColumn[]
//	GET    /api/datasources/{id}/wire-cert      requireApiOrBearer + mayConnect   200 application/x-pem-file
//	GET    /api/datasources/{id}/table-detail   ADMIN_DATASOURCES       200 TableDetail
//	PUT    /api/datasources/{id}/classification ADMIN_DATASOURCES       200 Classification
//	DELETE /api/datasources/{id}/classification ADMIN_DATASOURCES       204
//
// 🔒 DELIBERATE OPENNESS OF LIST + DETAIL (Datasources.kt:783-787, quoted): "The datasource list +
// detail stay open to every authenticated principal: the SQL editor's picker, JIT-request compose
// (which must show datasources you CANNOT yet connect to, precisely so they can be requested), and
// token generation all need it — not an admin action." `?connectable=true` narrows the LIST; the
// CATALOG and the CERTIFICATE are connect-gated. Only mutation/config routes require
// admin.datasources.

// Management is the slice of `DatasourceManagementService` (A11, ManagementServices.kt:73) these
// routes call.
//
// 🔴 IT IS AN INTERFACE BECAUSE OF THE IMPORT GRAPH, NOT BECAUSE THE ROUTES WANT A SEAM.
// internal/management imports THIS package (it is built on DatasourceStore), so this package cannot
// import it back. *management.DatasourceService satisfies this structurally — every method below is
// its exact signature, and internal/app passes the real service. The Kotlin's default argument
// (`management: DatasourceManagementService = DatasourceManagementService(store, eventsHub,
// tableDetailService)`) has no Go equivalent; the wiring site constructs it.
//
// The set is exactly the five methods `datasourceRoutes` reaches — no more, so a route cannot quietly
// grow a management call the route table does not list. `getDatasourceLiveness` is the sixth and is
// NOT here: its return type is declared in internal/management, so it cannot be named from this
// package. It arrives as [LivenessFunc] instead.
type Management interface {
	// ListDatasources is `management.listDatasources()`.
	ListDatasources(ctx context.Context) ([]Datasource, error)
	// BrowseCatalog is `management.browseCatalog(name)` — resolve by NAME, then read the catalog.
	BrowseCatalog(ctx context.Context, name string) ([]CatalogColumn, error)
	// GetTableDetail is `management.getTableDetail(name, schema, table)`.
	GetTableDetail(ctx context.Context, name, schema, table string) (engine.TableDetail, error)
	// SetColumnClassificationByID is the id-keyed `management.setColumnClassification(id, …)`
	// overload — the one the REST route uses (ManagementServices.kt:122).
	SetColumnClassificationByID(
		ctx context.Context, id int64, schema *string, table, column string, tags []string, maskFnID *int64,
	) (Classification, error)
	// ClearColumnClassificationByID is `management.clearColumnClassification(id, …)`
	// (ManagementServices.kt:172). The route DISCARDS the result — see [Routes.clearClassification].
	//
	// types.DeleteResult, not management.DeleteResult, because the latter is an ALIAS for the former
	// (internal/management declares `type DeleteResult = policy.DeleteResult` and internal/policy in
	// turn aliases `types.DeleteResult`). ONE type, three names; naming the LEAF one is what keeps
	// this package free of an internal/policy import — that edge closed an import cycle through
	// internal/dbtest (audit/policy internal tests → dbtest → datasource → policy → audit). See
	// types/management.go.
	ClearColumnClassificationByID(
		ctx context.Context, id int64, schema *string, table, column string,
	) (types.DeleteResult, error)
}

// LivenessFunc is `management.getDatasourceLiveness(name).attached` — the ONE field
// `POST {id}/test` reads off the liveness DTO.
//
// 🔴 A FUNCTION RATHER THAN A METHOD ON [Management] because `management.DatasourceLiveness` is
// declared in internal/management, which imports this package: Go has no way to name it here, and a
// second struct of the same shape would not satisfy the interface. internal/app wires it as the
// one-line adapter
//
//	func(ctx context.Context, name string) (bool, error) {
//	    l, err := mgmt.GetDatasourceLiveness(ctx, name)
//	    return l.Attached, err
//	}
//
// so the real management call — including its by-NAME re-lookup, which raises
// `common.not_found{resource: datasource}` if the row vanished between `store.get(id)` and here —
// still runs. That error is UNCAUGHT by the Kotlin `{id}/test` route (it catches nothing), so it
// reaches StatusPages as 500 common.fallback; [Routes.test] reproduces that by handing any error to
// the fallback rather than to respondManagementError.
type LivenessFunc func(ctx context.Context, name string) (attached bool, err error)

// ProxyEvents is the slice of `ProxyEventsHub` (A10, ProxyEventsHub.kt) A5's routes use.
//
// TODO(A10): ProxyEventsHub is not ported. Two methods, both trivially real once it is:
//   - `attached(): Set<String>` — datasource names with at least one open Events stream
//     (ProxyEventsHub.kt:134). A `map[string]struct{}` for the same reason internal/management's
//     ProxyAttachments uses one: membership is all that is ever asked.
//   - `requestRefresh(name): Int` — trySend a RefreshCatalog control event to every stream for the
//     name and count the successes; 0 for an unknown name (ProxyEventsHub.kt:53-59).
type ProxyEvents interface {
	Attached() map[string]struct{}
	RequestRefresh(name string) int
}

// RoleResolver is `roleResolver.resolve(principal)` (A3) — the ONE method [Routes.mayConnect] needs.
// *identity.RoleResolver satisfies it.
type RoleResolver interface {
	Resolve(ctx context.Context, principal string) ([]string, error)
}

// ConnectAuthorizer is the two-pass datasource decision A2 exposes, and the ONLY part of Authz these
// routes may reach.
//
// 🔒 It is deliberately NOT httpapi.Authorizer (one `Authorize`) and deliberately NOT *authz.Authz
// (the whole query surface). `mayConnect` is the one route-level caller in the port that needs the
// two-pass path — pass 1 derives context tags, pass 2 decides — because it must run the SAME
// name-keyed `datasource.connect` decision the proxy runs at connect time (INV-A5-2). Widening this
// to *authz.Authz would put AuthorizeColumns within reach of a route handler.
//
// *authz.Authz satisfies it.
type ConnectAuthorizer interface {
	ResolveContextTags(
		principal string, roles []string, datasource string, rawContext authz.AuthzContext, datasourceTags []string,
	) []string
	AuthorizeDatasourceAction(
		principal string, roles []string, action authz.AuthzAction, datasource string,
		context authz.AuthzContext, datasourceTags []string,
	) authz.AuthzDecision
}

// TokenResolver is `tokenStore.resolve(token)` (A4) — the read-only, no-`last_used_at`-write path.
// *token.Store satisfies it; the returned value is nil when the token does not resolve.
//
// It is an interface (rather than *token.Store) only to keep the Bearer path's dependency to its one
// method, matching [RoleResolver]. There is no import cycle here — internal/token does not import
// this package — so the seam is a scoping choice, not a forced one.
type TokenResolver interface {
	Resolve(ctx context.Context, tok string) (*WireTokenIdentity, error)
}

// WireTokenIdentity is `TokenIdentity(principal, roles, kind)` (Tokens.kt) reduced to what
// [Routes.bearerWirePrincipal] reads. It is structurally identical to token.Identity; internal/app
// adapts, since Go interface satisfaction is by signature and *token.Store returns its own type.
//
// TODO(A1): when a shared identity type lands, collapse this into it. Two-field duplication is
// cheaper than making internal/token depend on A5.
type WireTokenIdentity struct {
	Principal string
	Kind      string
}

// DeactivationSource is `userGroupStore.isDeactivated(principal)` (A3) — INV-A5-21's fail-closed
// check. *identity.UserGroupStore satisfies it.
type DeactivationSource interface {
	IsDeactivated(ctx context.Context, principal string) (bool, error)
}

// TrustChainInspector is `inspectTrustChain(pem)` (A10, ControlPlaneGrpcService.kt:556), already
// ported as grpcsvc.InspectTrustChain — reached as a function because internal/grpcsvc imports THIS
// package.
//
// 🔒 INV-A5-22 — IT REPORTS; IT NEVER GATES. The wire-cert route logs the reason and serves the bytes
// regardless. A nil inspector therefore changes nothing observable: it only silences the warning.
type TrustChainInspector func(pemChain string) (reason string, bad bool)

// RouteDeps is `datasourceRoutes`'s parameter list.
//
// A struct rather than eleven positional parameters: the Kotlin takes nine and the Go port adds two
// seams ([LivenessFunc], [TrustChainInspector]) that only exist because of the import graph. The
// other route groups in the port take three positional arguments and that reads fine; eleven would
// not, and a mis-ordered `TokenResolver`/`DeactivationSource` pair would compile.
type RouteDeps struct {
	Gates             *httpapi.Gates
	Authz             ConnectAuthorizer
	RoleResolver      RoleResolver
	Store             *DatasourceStore
	Events            ProxyEvents
	Tokens            TokenResolver
	Users             DeactivationSource
	Management        Management
	Liveness          LivenessFunc
	InspectTrustChain TrustChainInspector
	// Log defaults to slog.Default(). It is `datasourceLog` — "used only for the inspectTrustChain
	// warning on the wire-cert route" (Datasources.kt:756) — plus the port's write-failure logging.
	Log *slog.Logger
}

// Routes is the mounted group.
type Routes struct {
	gates      *httpapi.Gates
	authz      ConnectAuthorizer
	roles      RoleResolver
	store      *DatasourceStore
	events     ProxyEvents
	tokens     TokenResolver
	users      DeactivationSource
	management Management
	liveness   LivenessFunc
	inspect    TrustChainInspector
	log        *slog.Logger
}

// NewRoutes builds the group.
func NewRoutes(deps RouteDeps) *Routes {
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &Routes{
		gates: deps.Gates, authz: deps.Authz, roles: deps.RoleResolver, store: deps.Store,
		events: deps.Events, tokens: deps.Tokens, users: deps.Users, management: deps.Management,
		liveness: deps.Liveness, inspect: deps.InspectTrustChain, log: log,
	}
}

var _ httpapi.RouteGroup = (*Routes)(nil)

// Register mounts the thirteen patterns.
//
// ⚠️ `GET /api/datasources/live` and `GET /api/datasources/{id}` overlap. Go 1.22+ patterns resolve
// that by SPECIFICITY (the literal segment wins), which is not a conflict and does not panic —
// TestLiveIsNotSwallowedByTheIdWildcard pins it, because Ktor resolves the same pair by
// registration order and a port that relied on order would break the moment a mount site was
// reshuffled.
//
// ⚠️ No pattern ends in `/` — see httpapi.Router's divergence 1.
//
// ⚠️ NOT REGISTERED HERE: `POST /api/datasources/{id}/query` is A6's (Query.kt), even though it sits
// under this prefix. A6 HAS landed — internal/query's query.Routes mounts it — so adding it here now
// PANICS ServeMux.Handle at boot on the duplicate pattern rather than silently letting one win. The
// warning is kept in the present tense because that is the failure it prevents.
func (rt *Routes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/datasources", rt.list)
	mux.HandleFunc("GET /api/datasources/live", rt.live)
	mux.HandleFunc("POST /api/datasources/{id}/refresh", rt.refresh)
	mux.HandleFunc("POST /api/datasources", rt.create)
	mux.HandleFunc("GET /api/datasources/{id}", rt.get)
	mux.HandleFunc("PUT /api/datasources/{id}", rt.update)
	mux.HandleFunc("DELETE /api/datasources/{id}", rt.delete)
	mux.HandleFunc("POST /api/datasources/{id}/test", rt.test)
	mux.HandleFunc("GET /api/datasources/{id}/catalog", rt.catalog)
	mux.HandleFunc("GET /api/datasources/{id}/wire-cert", rt.wireCert)
	mux.HandleFunc("GET /api/datasources/{id}/table-detail", rt.tableDetail)
	mux.HandleFunc("PUT /api/datasources/{id}/classification", rt.setClassification)
	mux.HandleFunc("DELETE /api/datasources/{id}/classification", rt.clearClassification)
}

// ---------------------------------------------------------------------------------------------
// The routes
// ---------------------------------------------------------------------------------------------

// list is `GET /api/datasources` — 200 `Datasource[]`.
//
// The discovery route: the `pmon` daemon reads it (with a Bearer wire token) to learn each
// datasource's engine + advertised proxy address, so it can open a local broker port per datasource.
//
// 🔒 `?connectable=true` NARROWS; the default is UNFILTERED, and that is the product requirement, not
// laziness — JIT-request compose must show datasources you cannot yet connect to so they can be
// requested. Pinned by TestTheListIsFilteredByConnectOnlyWhenConnectableIsRequested, the port of
// `ElevationContextRouteAuthzDbTest` case 8.
//
// ⚠️ The predicate is `queryParameters["connectable"].equals("true", ignoreCase = true)` on a
// NULLABLE string: absent ⇒ false, `?connectable=TRUE` ⇒ true, `?connectable=1` ⇒ FALSE. Go's
// `Query().Get()` yields "" for absent, and EqualFold("", "true") is false, so the collapse of
// absent-vs-empty is behaviour-preserving HERE (unlike the presence-sensitive params elsewhere in
// the port).
//
// ⚠️ strings.EqualFold is Unicode SIMPLE case-folding while Java's ignoreCase is per-char
// upper/lower, and they disagree on a handful of code points (U+212A KELVIN SIGN folds to `k`,
// U+017F LATIN SMALL LETTER LONG S folds to `s`). None of `t`, `r`, `u`, `e` is one of them, so for
// this literal the two are identical. Noted rather than worked around, because the same helper on a
// different literal would need checking.
func (rt *Routes) list(w http.ResponseWriter, r *http.Request) {
	principal, ok := rt.requireAPIOrBearer(w, r)
	if !ok {
		return
	}
	all, err := rt.management.ListDatasources(r.Context())
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if !strings.EqualFold(r.URL.Query().Get("connectable"), "true") {
		rt.respond(w, r, http.StatusOK, all)
		return
	}
	// `[]`, never nil — INV-A1-4. Filtering everything out must answer `[]`.
	connectable := []Datasource{}
	for _, ds := range all {
		may, err := rt.mayConnect(r, principal, ds)
		if err != nil {
			rt.fallback(w, r, err)
			return
		}
		if may {
			connectable = append(connectable, ds)
		}
	}
	rt.respond(w, r, http.StatusOK, connectable)
}

// live is `GET /api/datasources/live` — 200 `string[]`, `requireApi`.
//
// Which datasources currently have a proxy attached (an open Events stream) — the admin liveness
// view. Read-only.
//
// ⚠️ `eventsHub.attached()` is a `Set<String>` and its wire ORDER IS UNSPECIFIED in the Kotlin (a
// ConcurrentHashMap key order, filtered and re-collected). This emits Go map-iteration order, which
// is randomized per call. That is a DETERMINISM divergence, not a contract one, and sorting here
// would invent an ordering guarantee no client is owed and some client would then start depending
// on. Tests sort before comparing, exactly as a client must.
//
// ⚠️ requireApi, NOT requireApiOrBearer: the Bearer path is wired into the datasource GETs that
// serve `pmon`, and this is the admin console's view (INV-A5-20 — the Bearer surface is deliberately
// minimal). And NOT admin either — 05-datasources-catalog.md's route table says `requireApi`.
func (rt *Routes) live(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	attached := rt.events.Attached()
	names := make([]string, 0, len(attached))
	for name := range attached {
		names = append(names, name)
	}
	rt.respond(w, r, http.StatusOK, names)
}

// refresh is `POST /api/datasources/{id}/refresh` — 200 `RefreshResult`.
//
// Admin "re-introspect now": push a RefreshCatalog down the datasource's open Events stream(s).
//
// 🔒 The response reports how many proxy streams were notified, and **0 means no proxy attached,
// reported honestly** rather than dressed up as an error (A12 INV-A12-14's honesty rule surfaced at
// the REST layer). A port that 404'd or 503'd on zero would hide the one fact the operator opened
// the page for.
func (rt *Routes) refresh(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	ds, ok := rt.mustGet(w, r, id)
	if !ok {
		return
	}
	rt.respond(w, r, http.StatusOK, RefreshResult{Notified: rt.events.RequestRefresh(ds.Name)})
}

// create is `POST /api/datasources` — **201** `Datasource`.
//
// Only `name` is required: this is optional pre-provisioning (the proxy's Register fills in the
// advisory host/port/db_name and is authoritative). No credential fields exist.
//
// 🔒 INV-A5-7 / Datasources.kt:819-823, quoted: the engine is canonicalized through
// `engineFromWireOrNull` BEFORE storing because "a non-canonical value (e.g. 'Postgres', 'psql')
// would be stored verbatim and then LOCKED by the engine-immutability guard, so the datasource can
// never be adopted by its proxy … unusable until deletion." Exactly two spellings, case-insensitive,
// no aliases — `postgresql` is REJECTED.
//
// ⚠️ REPRODUCED DEFECT (§10 Q12) — A DUPLICATE `name` IS AN UNMAPPED 500, NOT A 409. `store.create`
// does no uniqueness check and this route catches nothing, so the `datasource_name_key` UNIQUE
// violation reaches StatusPages as `common.fallback`. TestADuplicateNameIsAnUnmapped500 pins it so a
// deliberate change to 409 `datasource.name_taken` has to change a test rather than slip through.
//
// ⚠️ D6 DIVERGENCE (same as every other route in the port): kotlinx throws MissingFieldException for
// an ABSENT `name` and answers 500; Go decodes it to "" and this route's own blank check answers 400
// `common.field_required{fields: name}`. Recorded once, not patched per-DTO.
func (rt *Routes) create(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	input, ok := rt.receiveDatasourceInput(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		rt.respondError(w, types.FieldRequired("name"))
		return
	}
	eng, ok := EngineFromWireOrNull(input.Engine)
	if !ok {
		rt.respondError(w, invalidEngine(input.Engine))
		return
	}
	// `input.copy(engine = engine.wireName)` — the canonical string is what is stored.
	input.Engine = MustWireName(eng)
	created, err := rt.store.Create(r.Context(), input)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusCreated, created)
}

// get is `GET /api/datasources/{id}` — 200 `Datasource`, `requireApi`.
//
// 🔒 requireApi and NOT requireApiOrBearer, unlike the LIST directly above it. `pmon` discovers
// through the list; the detail route is the console's. Reproduced as the asymmetry it is.
func (rt *Routes) get(w http.ResponseWriter, r *http.Request) {
	if !rt.gates.RequireAPI(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	ds, ok := rt.mustGet(w, r, id)
	if !ok {
		return
	}
	rt.respond(w, r, http.StatusOK, ds)
}

// update is `PUT /api/datasources/{id}` — 200 `Datasource`.
//
// 🔒 INV-A5-9 — ENGINE IS IMMUTABLE, and the reason is a four-way fail-open: flipping it would
// repoint every FK keyed off `datasource_id` (catalog_column, column_classification, query_history,
// access_request) at a schema from a different dialect, and the analyzer / system-classification
// manifest resolution keyed off engine would go stale. A PUT that changes it is **409
// `datasource.engine_immutable`**, mirroring gRPC Register's FAILED_PRECONDITION.
//
// The canonicalization above it is what keeps that guard from firing spuriously: "otherwise a PUT
// carrying 'Postgres', 'postgresql', or the DatasourceInput default 'postgres' would be compared
// verbatim against the stored canonical engine and spuriously trip the immutability guard."
//
// ⚠️ 🔴 F21 — REPRODUCED GAP, NOT FIXED. This clears the PERSISTED catalog on a db_name change (in
// the store) and NEVER calls `connectionCatalog.invalidateDatasource`, not even on a RENAME. Only
// gRPC Register invalidates, and only under `priorDbName != null && priorDbName != ds.dbName`
// (ControlPlaneGrpcService.kt:363) — so a datasource registering under a name with no prior row
// skips invalidation entirely and INHERITS the freed name's authoritative entries. On MySQL
// (`catalogIsConnectionIndependent = true`) the next connection ADOPTS them with no fetch. The
// route has no reference to the registry and deliberately keeps none: wiring one in here would hide
// a possible live defect behind a port. §10 Q1 is open.
func (rt *Routes) update(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	input, ok := rt.receiveDatasourceInput(w, r)
	if !ok {
		return
	}
	eng, ok := EngineFromWireOrNull(input.Engine)
	if !ok {
		rt.respondError(w, invalidEngine(input.Engine))
		return
	}
	input.Engine = MustWireName(eng)
	updated, found, err := rt.store.Update(r.Context(), id, input)
	if err != nil {
		var conflict *EngineConflictError
		if errors.As(err, &conflict) {
			// 409 with NO params — the Kotlin body is a bare `ApiError("datasource.engine_immutable")`,
			// so the offending engines are logged (in the exception message) and never put on the wire.
			rt.respondError(w, engineImmutable())
			return
		}
		rt.fallback(w, r, err)
		return
	}
	if !found {
		rt.respondError(w, types.NotFound(ResourceDatasource))
		return
	}
	rt.respond(w, r, http.StatusOK, updated)
}

// delete is `DELETE /api/datasources/{id}` — **204**, no body; 404 when nothing was deleted.
//
// ⚠️ F21 again: this frees the datasource NAME while the in-memory authoritative entries keyed by
// that name stay live. See [Routes.update].
func (rt *Routes) delete(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	deleted, err := rt.store.Delete(r.Context(), id)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	if !deleted {
		rt.respondError(w, types.NotFound(ResourceDatasource))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// test is `POST /api/datasources/{id}/test` — 200 `TestResult`.
//
// 🔒 A CREDS-FREE LIVENESS REPORT, NOT A DIAL. The control plane holds no target credential and never
// dials a target; "test connection" reports whether a proxy is attached plus the catalog/last-seen
// state. `ok` is `proxyAttached`, nothing more.
//
// ⚠️ The `attached` bit comes from `management.getDatasourceLiveness(ds.name).attached` — a SECOND,
// by-NAME lookup of the row this handler already holds. Redundant, and reproduced: see [LivenessFunc]
// for why the redundant lookup's 404-on-race is a 500 here (this route catches no
// ManagementException).
func (rt *Routes) test(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	ds, ok := rt.mustGet(w, r, id)
	if !ok {
		return
	}
	attached, err := rt.liveness(r.Context(), ds.Name)
	if err != nil {
		// NOT respondManagementError: the Kotlin route has no catch, so a ManagementException from the
		// re-lookup reaches App.kt's `exception<Throwable>` as 500 common.fallback.
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, rt.store.Test(ds, attached))
}

// catalog is `GET /api/datasources/{id}/catalog` — 200 `CatalogColumn[]`.
//
// 🔒 INV-A5-2 — SCHEMA VISIBILITY TRACKS CONNECT AUTHORITY, NOT SESSION EXISTENCE. The route runs the
// same name-keyed `datasource.connect` Cedar decision, with two-pass derived context tags, that the
// proxy runs at connect time: "browsing the catalog needs the same datasource.connect authority as
// opening a session." Deny ⇒ **403 `datasource.not_connectable`**.
//
// 🔒 INV-A5-3, in the route's own words (Datasources.kt:863-866): "a wire-token caller has no
// session, so resolving the principal from the session alone would fall through to the literal
// `debug-user` and run the Cedar check against a synthetic identity. The helper hands back whichever
// identity authenticated, and only answers `debug-user` when PM_AUTH_DEBUG actually says so."
//
// ⚠️ ORDER: the 401 precedes the bad-id parse, which precedes the 404, which precedes the 403. An
// unauthenticated request to a nonexistent id is 401, and an unauthorized one is 404 — the caller
// learns the id does not exist BEFORE the connect check. Reproduced verbatim.
//
// ⚠️ NO `catch (e: ManagementException)` HERE, unlike `{id}/table-detail` and the two classification
// routes — the Kotlin's line is a bare `call.respond(management.browseCatalog(datasource.name))`. So
// `browseCatalog`'s by-NAME re-lookup raising `common.not_found` (the row vanished between
// `store.get(id)` and here) answers **500 common.fallback**, not 404. [Routes.fallback], not
// [Routes.fail], is what reproduces that — using `fail` here would quietly turn one route's race
// into a 404 the Kotlin never sends.
func (rt *Routes) catalog(w http.ResponseWriter, r *http.Request) {
	ds, ok := rt.connectGated(w, r)
	if !ok {
		return
	}
	columns, err := rt.management.BrowseCatalog(r.Context(), ds.Name)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, columns)
}

// wireCert is `GET /api/datasources/{id}/wire-cert` — 200, body = the raw PEM.
//
// The certificate chain to trust for this datasource's proxy, leaf first — the same bytes the
// datasource list already carries, offered as a downloadable file for psql/mysql/DataGrip to point
// `sslrootcert` / `--ssl-ca` at with `verify-full`. A self-signed proxy cert is the one-element case.
//
// 🔒 NOT A SECRET — these are the certificates the proxy already presents to every TLS client — so
// the gate is `datasource.connect`, the same authority `{id}/catalog` needs: whoever may open a
// session may fetch what they need to open it safely.
//
// 🔒 INV-A5-3 is THE regression this route's test suite exists for (`WireCertRouteDbTest.kt:42-47`):
// the route "reveals WHICH datasources exist and which address they answer on, and it previously
// resolved its principal as `userSession()?.principal ?: \"debug-user\"` — an unauthenticated caller
// silently became `debug-user` and got whatever that identity could connect to."
//
// 🔒 INV-A5-22 — TRUST MATERIAL IS INSPECTED AND SERVED, NEVER WITHHELD. `inspectTrustChain` logs a
// warning and the bytes go out anyway: "The client verifies, and it is the only party that can report
// a meaningful error about its own trust store — withholding the file just leaves the operator with
// nothing to install and no way to see why."
//
// ⚠️ 🔴 THE KOTLIN ROUTE'S OWN KDOC (Datasources.kt:888-890) IS WRONG AND IS NOT PORTED (§10 Q7). It
// describes a re-validation answering "409 rather than 500" that does not exist, on the premise that
// "Registration already refuses a chain that does not chain" — also false
// (ControlPlaneGrpcService.kt:325-341 warns and registers anyway).
// `TrustChainInspectionTest.kt:9` states the rule flatly: "inspectTrustChain REPORTS on trust
// material; it never gates." The stale paragraph is dropped, deliberately, rather than reproduced.
//
// ⚠️ Content-Type is `application/x-pem-file` via `ContentType.parse` — NOT a `text/*` type, so
// Ktor's `withCharsetIfNeeded` appends no charset (Datasources.kt:922).
//
// ⚠️ 404 `datasource.no_wire_cert` is DELIBERATELY DISTINCT from 404 `common.not_found`, so the
// console can say "this proxy has no wire TLS" instead of "no such datasource" — and an unknown id
// must NOT report `no_wire_cert`, because that would confirm the id exists. Both directions pinned
// (WireCertRouteDbTest cases 4 and 5).
func (rt *Routes) wireCert(w http.ResponseWriter, r *http.Request) {
	ds, ok := rt.connectGated(w, r)
	if !ok {
		return
	}
	// `store.wireCertChain(id)` — the redundant second read of a column the list projection already
	// carries (INV-A5-10's self-contradiction, §10 Q5). Kept redundant.
	chain, err := rt.store.WireCertChain(r.Context(), ds.ID)
	if err != nil {
		rt.fallback(w, r, err)
		return
	}
	// `chain.isNullOrBlank()` — a PRESENT-but-empty chain (which register's INSERT arm can store as
	// `''`, §10 Q6) is treated as no chain, exactly as the Kotlin does.
	if chain == nil || strings.TrimSpace(*chain) == "" {
		rt.respondError(w, noWireCert())
		return
	}
	if rt.inspect != nil {
		if reason, bad := rt.inspect(*chain); bad {
			rt.log.Warn("serving datasource wire cert chain that may not verify",
				"datasource", ds.Name, "reason", reason)
		}
	}
	// 🔒 FILENAME FROM THE NUMERIC ID, NOT THE NAME: "a datasource name is barely constrained, and a
	// quote or CRLF in one would be header injection here." Pinned by WireCertRouteDbTest case 3.
	w.Header().Set("Content-Disposition",
		"attachment; filename=\"datasource-"+itoa(ds.ID)+"-wire-cert.pem\"")
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(*chain)); err != nil {
		rt.log.Error("failed to write wire cert chain", "datasource", ds.Name, "err", err)
	}
}

// tableDetail is `GET /api/datasources/{id}/table-detail` — 200 `TableDetail`.
//
// The live, never-persisted introspection: indexes, foreign keys, metadata, fetched on demand over a
// dedicated proxy stream.
//
// ⚠️ THE ID GUARD IS `call.idParam()?.takeIf { it > 0 }` — the ONE route in the file where a
// non-positive id is `common.bad_id` rather than a 404. `/table-detail?id=0` and `?id=-1` are 400s
// here and 404s everywhere else. Reproduced, and pinned, because it is a real inconsistency.
//
// ⚠️ `common.field_required` here carries `{fields: "schema, table"}` — ONE param holding TWO comma-
// separated names, not two params and not two errors. Wire-visible (web/ interpolates `{fields}`).
// It fires when EITHER is missing or blank, and it names both regardless of which was absent.
//
// 🔒 The 502: `datasource.table_introspection_failed` is the honest status for "we asked the proxy
// and the proxy failed" — the control plane is a gateway to the target here, and a 500 would blame
// the wrong component. It comes out of [httpapi.RespondManagementError]'s switch.
func (rt *Routes) tableDetail(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id := httpapi.IDParam(r)
	if id == nil || *id <= 0 {
		rt.respondError(w, types.BadID())
		return
	}
	q := r.URL.Query()
	schema, table := q.Get("schema"), q.Get("table")
	// `schema.isNullOrBlank() || table.isNullOrBlank()`. Ktor's absent param is null and Go's is "";
	// both are blank, so the collapse is behaviour-preserving.
	if strings.TrimSpace(schema) == "" || strings.TrimSpace(table) == "" {
		rt.respondError(w, types.FieldRequired("schema, table"))
		return
	}
	ds, ok := rt.mustGet(w, r, *id)
	if !ok {
		return
	}
	detail, err := rt.management.GetTableDetail(r.Context(), ds.Name, schema, table)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, detail)
}

// setClassification is `PUT /api/datasources/{id}/classification` — 200 `Classification`.
//
// 🔒 INV-A11-28 — a `system:`-prefixed tag is refused with `datasource.reserved_tag{tag}` (400),
// reporting the FIRST offender and storing NONE of the list. The management layer owns that check
// (and the store owns a second copy as a backstop, INV-A5-19); this route only maps it.
//
// 🔒 INV-A11-29 — a null `schema` with no resolvable default schema is `datasource.schema_required`
// (400), never a silent write to a fallback schema. A classification landing on the wrong schema is a
// masking rule that never fires.
//
// ⚠️ The route passes the raw path `id` straight to the management service — it does NOT pre-resolve
// the datasource, so the 404 `common.not_found{resource: datasource}` comes from inside the
// transaction that will do the write.
func (rt *Routes) setClassification(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var input ClassificationInput
	if !rt.receive(w, r, &input) {
		return
	}
	classification, err := rt.management.SetColumnClassificationByID(
		r.Context(), id, input.Schema, input.Table, input.Column, input.Tags, input.MaskFnID)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	rt.respond(w, r, http.StatusOK, classification)
}

// clearClassification is `DELETE /api/datasources/{id}/classification` — **204**.
//
// 🔒 UNCONDITIONALLY 204 (§10 Q13). The route DISCARDS `clearColumnClassification`'s `DeleteResult`
// (Datasources.kt:961-962), so deleting a classification that does not exist is 204, never 404. The
// information is available at both the store and the management layer and is deliberately dropped
// here. A port that 404s on zero rows turns an idempotent surface into a failing one —
// TestClearingAClassificationThatDoesNotExistIsStill204 is the pin a deliberate change must break.
//
// The 400s and the 404 still apply: a blank table/column, an unresolvable default schema, and an
// unknown datasource id all come back through respondManagementError exactly as on the PUT.
func (rt *Routes) clearClassification(w http.ResponseWriter, r *http.Request) {
	if !rt.admin(w, r) {
		return
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return
	}
	var body ClassificationDelete
	if !rt.receive(w, r, &body) {
		return
	}
	// The `DeleteResult` is discarded on purpose. `_ =` rather than dropping the binding, so the
	// discard is visible at the call site and cannot be mistaken for a method that returns only error.
	_, err := rt.management.ClearColumnClassificationByID(r.Context(), id, body.Schema, body.Table, body.Column)
	if err != nil {
		rt.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------
// Gates and helpers
// ---------------------------------------------------------------------------------------------

// admin is the shared first line of the seven admin routes:
// `if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@…`.
func (rt *Routes) admin(w http.ResponseWriter, r *http.Request) bool {
	return rt.gates.RequireAdmin(w, r, authz.ActionAdminDatasources)
}

// bearerWirePrincipal is `private fun ApplicationCall.bearerWirePrincipal(tokenStore,
// userGroupStore): String?` (Datasources.kt:729-746).
//
// 🔒 INV-A5-20 — THE BEARER PATH IS DISCOVERY-ONLY AND CANNOT BOOTSTRAP CREDENTIALS. Quoted: "Only
// native-wire kinds (SESSION/USER) count, and this is wired ONLY into the read-only datasource GET
// routes — never mutations or token mint — so a leaked wire token cannot bootstrap more credentials
// through the API. Roles are still resolved server-side per principal, so this is a new
// AUTHENTICATION surface, not a privilege grant."
//
// 🔒 BOTH THIS AND [Routes.requireAPIOrBearer] ARE PRIVATE BY DESIGN — "so no other route file can
// reach it (compiler-enforced scope)". They are unexported methods on an unexported-behaviour type
// for exactly that reason; do not export either, and do not hoist them into internal/httpapi the way
// requireApi was hoisted. requireApi is generic plumbing used by eight files; this is A5's alone.
//
//  1. Authorization header absent ⇒ nil.
//  2. Not `Bearer ` ⇒ nil. ⚠️ CASE-INSENSITIVE here, unlike the SCIM gate's case-SENSITIVE
//     `removePrefix("Bearer ")` (httpapi.Gates.RequireScimAuth). The inconsistency is real and is
//     reproduced on both sides.
//  3. `substring(7).trim()`, blank ⇒ nil. Note the substring is a FIXED 7 characters taken after a
//     case-insensitive prefix test, so `bearer  tok` yields ` tok` before the trim — reproduced by
//     slicing, not by TrimPrefix.
//  4. `tokenStore.resolve(token)` ⇒ nil if unresolvable (A4 also enforces not-revoked, not-expired).
//  5. kind must be SESSION or USER — NOT EDITOR / APPROVER_EXEC.
//  6. 🔒 INV-A5-21 — a DEACTIVATED principal fails closed even with a live token row: "matches the
//     gRPC decide path (a SCIM active=false push or a failed IdP liveness recheck can mark the
//     app_user inactive without the credential revoke having raced in yet)."
//
// The error return has no Kotlin counterpart (a JDBC failure throws there); it is threaded so a
// database error becomes 500 common.fallback rather than a silent 401.
func (rt *Routes) bearerWirePrincipal(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", nil
	}
	const scheme = "Bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", nil
	}
	tok := strings.TrimSpace(header[len(scheme):])
	if tok == "" {
		return "", nil
	}
	if rt.tokens == nil {
		return "", nil
	}
	id, err := rt.tokens.Resolve(r.Context(), tok)
	if err != nil || id == nil {
		return "", err
	}
	// `TokenKind.fromWire(id.kind)` — an unrecognized kind is null and fails both comparisons.
	if id.Kind != wireKindSession && id.Kind != wireKindUser {
		return "", nil
	}
	if rt.users != nil {
		deactivated, err := rt.users.IsDeactivated(r.Context(), id.Principal)
		if err != nil {
			return "", err
		}
		if deactivated {
			return "", nil
		}
	}
	return id.Principal, nil
}

// The two `TokenKind` names the Bearer path accepts. Literals rather than an import of
// internal/token: this package is imported BY the areas that own tokens, and a one-way dependency on
// two enum spellings is cheaper than the coupling. They are the enum MEMBER NAMES, which is what
// `TokenKind.fromWire` matches and what the `proxy_token.kind` column stores.
const (
	wireKindSession = "SESSION"
	wireKindUser    = "USER"
)

// requireAPIOrBearer is `private suspend fun ApplicationCall.requireApiOrBearer(config, tokenStore,
// userGroupStore): String?` (Datasources.kt:754-760):
//
//	userSession()?.principal → bearerWirePrincipal(...) → if (config.authDebug) "debug-user"
//	→ else respond(401, ApiError("common.unauthenticated")); null
//
// 🔒 INV-A5-3 — IT RETURNS THE PRINCIPAL THAT AUTHENTICATED, and it answers `"debug-user"` ONLY when
// `config.authDebug` is actually on. A port must not reintroduce a `?: "debug-user"` fallback at any
// call site. `WireCertRouteDbTest` case 1 is the regression test.
//
// ⚠️ THE ORDER DIFFERS FROM requireApi's. requireApi short-circuits on authDebug FIRST and never
// reads the session; this reads the session first, so under authDebug a request WITH a session gets
// its real principal and only a request without one becomes "debug-user". That difference is
// observable in the Cedar decision mayConnect then makes, and it is deliberate.
func (rt *Routes) requireAPIOrBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	sess, err := rt.gates.Sessions.UserSession(r)
	if err != nil {
		rt.fallback(w, r, err)
		return "", false
	}
	if sess != nil {
		return sess.Principal, true
	}
	principal, err := rt.bearerWirePrincipal(r)
	if err != nil {
		rt.fallback(w, r, err)
		return "", false
	}
	if principal != "" {
		return principal, true
	}
	if rt.gates.Config.AuthDebug {
		return DebugPrincipal, true
	}
	rt.respondError(w, types.Unauthenticated())
	return "", false
}

// DebugPrincipal is the literal `"debug-user"` requireApiOrBearer answers under PM_AUTH_DEBUG.
//
// Exported so a test can assert the exact string rather than re-spelling it: INV-A5-3 is a claim
// about this literal never appearing on a NON-debug path, and a test that re-typed it could drift.
const DebugPrincipal = "debug-user"

// mayConnect is the local closure `fun mayConnect(call, principal, ds): Boolean` inside
// `datasourceRoutes` (Datasources.kt:770-780).
//
//  1. config.authDebug ⇒ true.
//  2. roles = roleResolver.resolve(principal); raw = call.httpAuthzContext(config).
//  3. tags = authz.resolveContextTags(principal, roles, ds.name, raw, ds.tags)  — A2 pass 1.
//  4. authz.authorizeDatasourceAction(principal, roles, DATASOURCE_CONNECT, ds.name,
//     raw.copy(tags = tags), ds.tags) !is AuthzDecision.Deny.
//
// 🔒 INV-A2-10 — roles are resolved ONCE and the same snapshot is threaded through BOTH passes. A
// role revoked, or a JIT grant expiring, between the two passes can then never earn a context tag the
// final decision no longer sees.
//
// 🔒 INV-A2-2 — the Cedar resource is keyed off the datasource NAME, never its numeric id. That is
// what makes this the SAME decision the proxy runs at connect time.
//
// ⚠️ `!is AuthzDecision.Deny` is `.Allowed` here: the Kotlin sealed class has exactly Allow and Deny,
// so the negation is total. Written as `.Allowed` rather than `!isDeny` because Go has no sealed
// hierarchy to make the two provably equivalent, and `.Allowed` is the fail-closed spelling — an
// unexpected third state would deny.
//
// 🔴 `httpAuthzContext` IS EMPTY UNTIL A12 LANDS (httpapi.Gates.Context's TODO). For this gate that
// means a deployment whose `datasource.connect` grant is `requester_ip`-conditioned is DENIED here
// where the Kotlin allows — fail-closed, per INV-A2-8, but a real divergence. It reads through
// gates.AuthzContext rather than keeping its own seam so A12 fixes the gates and this together.
func (rt *Routes) mayConnect(r *http.Request, principal string, ds Datasource) (bool, error) {
	if rt.gates.Config.AuthDebug {
		return true, nil
	}
	roles, err := rt.roles.Resolve(r.Context(), principal)
	if err != nil {
		return false, err
	}
	raw := rt.gates.AuthzContext(r)
	tags := rt.authz.ResolveContextTags(principal, roles, ds.Name, raw, ds.Tags)
	decision := rt.authz.AuthorizeDatasourceAction(
		principal, roles, authz.ActionDatasourceConnect, ds.Name, raw.WithTags(tags), ds.Tags)
	return decision.Allowed, nil
}

// connectGated is the shared prologue of `{id}/catalog` and `{id}/wire-cert`, which are
// character-for-character identical up to the point they diverge:
//
//	requireApiOrBearer → idParam/badId → store.get/404 → mayConnect/403 datasource.not_connectable
//
// Shared because the two routes' gate sequences MUST stay identical: INV-A5-2's claim is that the
// certificate and the catalog need the same authority, and two hand-copied prologues are how one of
// them silently loses a step.
// It does NOT return the principal: neither route uses it after the gate (the Kotlin's `principal`
// local is consumed entirely by `mayConnect`), and handing it back would invite a handler to start
// making its own decision with an identity the gate already spent.
func (rt *Routes) connectGated(w http.ResponseWriter, r *http.Request) (Datasource, bool) {
	principal, ok := rt.requireAPIOrBearer(w, r)
	if !ok {
		return Datasource{}, false
	}
	id, ok := rt.idParam(w, r)
	if !ok {
		return Datasource{}, false
	}
	ds, ok := rt.mustGet(w, r, id)
	if !ok {
		return Datasource{}, false
	}
	may, err := rt.mayConnect(r, principal, ds)
	if err != nil {
		rt.fallback(w, r, err)
		return Datasource{}, false
	}
	if !may {
		rt.respondError(w, notConnectable())
		return Datasource{}, false
	}
	return ds, true
}

// mustGet is `store.get(id) ?: return call.respond(404, ApiError("common.not_found",
// mapOf("resource" to "datasource")))` — the five routes that resolve the row before acting.
func (rt *Routes) mustGet(w http.ResponseWriter, r *http.Request, id int64) (Datasource, bool) {
	ds, found, err := rt.store.Get(r.Context(), id)
	if err != nil {
		rt.fallback(w, r, err)
		return Datasource{}, false
	}
	if !found {
		rt.respondError(w, types.NotFound(ResourceDatasource))
		return Datasource{}, false
	}
	return ds, true
}

// idParam is `val id = call.idParam() ?: return@… call.respond(400, ApiError("common.bad_id"))`.
func (rt *Routes) idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id := httpapi.IDParam(r)
	if id == nil {
		rt.respondError(w, types.BadID())
		return 0, false
	}
	return *id, true
}

// receiveDatasourceInput is `call.receive<DatasourceInput>()` with kotlinx's `engine: String =
// "postgres"` default applied — see [DecodeDatasourceInput], which encoding/json cannot express.
func (rt *Routes) receiveDatasourceInput(w http.ResponseWriter, r *http.Request) (DatasourceInput, bool) {
	raw, err := readBody(r)
	if err != nil {
		rt.fallback(w, r, err)
		return DatasourceInput{}, false
	}
	input, err := DecodeDatasourceInput(raw)
	if err != nil {
		rt.fallback(w, r, err)
		return DatasourceInput{}, false
	}
	return input, true
}

// receive is `call.receive<T>()`; a malformed body is 500 common.fallback, not 400 — the Kotlin
// route catches nothing and App.kt's `exception<Throwable>` answers the fallback.
func (rt *Routes) receive(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpapi.Receive(r, dst); err != nil {
		// 415 before 400: an unusable Content-Type is ContentNegotiation answering before the route sees
		// the body. Measured — see internal/conformance/differential.
		if errors.Is(err, httpapi.ErrUnsupportedMediaType) {
			httpapi.RespondUnsupportedMediaType(w)
			return false
		}
		rt.fallback(w, r, err)
		return false
	}
	return true
}

// fail is `catch (e: ManagementException) { call.respondManagementError(e) }`.
//
// 🔒 [httpapi.RespondManagementError] carries the FULL four-arm mapping — not_found ⇒ 404,
// table_introspection_failed ⇒ **502**, the three *.system_immutable ⇒ 409, everything else ⇒ 400.
// A5 is where the 502 arm is actually reachable (`{id}/table-detail`), so a truncated copy of that
// switch would be visible here first.
//
// It unwraps *types.ManagementError, which is the SAME TYPE as policy.ManagementError and
// management.Error (both aliases) — the reason errors.As matches across the package boundary at all.
func (rt *Routes) fail(w http.ResponseWriter, r *http.Request, err error) {
	var management *types.ManagementError
	if errors.As(err, &management) {
		if werr := httpapi.RespondManagementError(w, management.Err); werr != nil {
			rt.log.Error("failed to write management error", "code", management.Err.Code, "err", werr)
		}
		return
	}
	rt.fallback(w, r, err)
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

func (rt *Routes) fallback(w http.ResponseWriter, r *http.Request, cause error) {
	httpapi.RespondFallback(w, r, rt.log, cause)
}

// readBody is [httpapi.Receive]'s body half, for the one DTO that cannot be decoded straight into a
// destination: [DecodeDatasourceInput] has to seed `engine: "postgres"` before unmarshalling, which
// needs the bytes rather than a decoder. Same 8 MiB bound, for the same reason.
func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, httpapi.MaxRequestBodyBytes))
}

// itoa is strconv.FormatInt, named for the one place it is used — the Content-Disposition filename,
// where the value is the numeric id and NEVER the datasource name (header-injection guard).
func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// ---- The four A5-specific ApiError codes -------------------------------------------------------
//
// Declared as builders rather than inline literals so the strings appear exactly once: each is an
// i18n key `web/messages/<locale>/` must carry, and a typo is a silent untranslated string rather
// than a compile error.

// ResourceDatasource is the `{resource}` param on every 404 in this file: `notFound("datasource")`.
// The same literal internal/management uses, and it is wire-visible — web/ interpolates it.
const ResourceDatasource = "datasource"

// invalidEngine is 400 `datasource.invalid_engine{engine}` — the REJECTED spelling is echoed back so
// the console can say which value it was.
func invalidEngine(engine string) types.ErrorResponse {
	return types.ErrorResponse{
		Status: http.StatusBadRequest,
		Body:   types.ApiError{Code: "datasource.invalid_engine", Params: map[string]string{"engine": engine}},
	}
}

// engineImmutable is 409 `datasource.engine_immutable`, with NO params (INV-A5-9).
func engineImmutable() types.ErrorResponse {
	return types.ErrorResponse{
		Status: http.StatusConflict,
		Body:   types.ApiError{Code: "datasource.engine_immutable"},
	}
}

// notConnectable is 403 `datasource.not_connectable` (INV-A5-2), with no params: the route says the
// caller may not connect, never why, and never which policy decided it.
func notConnectable() types.ErrorResponse {
	return types.ErrorResponse{
		Status: http.StatusForbidden,
		Body:   types.ApiError{Code: "datasource.not_connectable"},
	}
}

// noWireCert is 404 `datasource.no_wire_cert` — deliberately distinct from `common.not_found`.
func noWireCert() types.ErrorResponse {
	return types.ErrorResponse{
		Status: http.StatusNotFound,
		Body:   types.ApiError{Code: "datasource.no_wire_cert"},
	}
}
